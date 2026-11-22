#!/usr/bin/env python3
"""
FuzzForge — AI-generated, target-aware wordlists for ffuf.

Instead of throwing a generic 50,000-line wordlist at a target, FuzzForge
reads the target's own homepage (title, nav, visible text, tech hints from
response headers) and asks an LLM to generate a short, plausible wordlist
of paths, parameter names, and virtual-host names *for that specific site*
— then, optionally, runs ffuf with it directly, using the same
baseline-then-filter workflow a human would use by hand.

Works with any OpenAI-compatible chat-completions endpoint: OpenAI, Groq,
OpenRouter, a local Ollama server, etc. — set --api-base/--api-key/--model
(or the FUZZFORGE_API_BASE / FUZZFORGE_API_KEY / FUZZFORGE_MODEL env vars).
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

CATEGORIES = ("paths", "params", "vhosts")

PROMPT_TEMPLATE = """You are helping generate a wordlist for authorized web \
application fuzzing (the user owns this target or is explicitly authorized \
to test it). Based on the site context below, suggest plausible hidden \
{category} an app like this might have -- names a developer on this \
specific project would plausibly have used, not a generic list.

Site context:
- URL: {url}
- Title: {title}
- Meta description: {description}
- Visible nav links: {nav_links}
- Sample body text (truncated): {body_text}
- Server/tech hints: {tech_hints}

Respond with ONLY a JSON array of {count} short strings, nothing else. \
Each string should be a bare {category_singular} name with no slashes, \
no query strings, no explanation -- just the name itself.
Example format: ["name-one", "name-two", "name-three"]
"""

CATEGORY_SINGULAR = {"paths": "path segment", "params": "parameter name", "vhosts": "subdomain label"}


def fetch_context(url: str, timeout: float = 10.0) -> dict:
    """Fetch the target's homepage and pull out context an LLM can use."""
    resp = requests.get(url, timeout=timeout)
    soup = BeautifulSoup(resp.text, "html.parser")

    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    meta_desc_tag = soup.find("meta", attrs={"name": "description"})
    description = meta_desc_tag["content"].strip() if meta_desc_tag and meta_desc_tag.get("content") else ""

    nav_links = []
    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True)
        if text:
            nav_links.append(text)
    nav_links = list(dict.fromkeys(nav_links))[:20]  # dedupe, cap

    for tag in soup(["script", "style"]):
        tag.decompose()
    body_text = " ".join(soup.get_text(separator=" ").split())[:800]

    tech_hints = []
    for header in ("Server", "X-Powered-By", "X-Generator"):
        if header in resp.headers:
            tech_hints.append(f"{header}: {resp.headers[header]}")

    return {
        "url": url,
        "title": title,
        "description": description,
        "nav_links": nav_links,
        "body_text": body_text,
        "tech_hints": tech_hints,
    }


def build_prompt(context: dict, category: str, count: int) -> str:
    return PROMPT_TEMPLATE.format(
        category=category,
        category_singular=CATEGORY_SINGULAR[category],
        url=context["url"],
        title=context["title"] or "(none)",
        description=context["description"] or "(none)",
        nav_links=", ".join(context["nav_links"]) or "(none found)",
        body_text=context["body_text"] or "(none)",
        tech_hints=", ".join(context["tech_hints"]) or "(none)",
        count=count,
    )


def call_llm(prompt: str, api_base: str, api_key: str, model: str, timeout: float = 30.0) -> str:
    """Call an OpenAI-compatible chat-completions endpoint, return raw text."""
    resp = requests.post(
        f"{api_base.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.9,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def parse_wordlist_response(raw_text: str) -> list:
    """
    Parse the LLM's reply into a clean list of strings. Tries strict JSON
    first; if the model wrapped it in prose or a code fence, falls back to
    extracting the first [...] array-looking substring.
    """
    text = raw_text.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return _clean_entries(parsed)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, list):
                return _clean_entries(parsed)
        except json.JSONDecodeError:
            pass

    raise ValueError(f"could not parse a wordlist out of model output: {raw_text[:200]!r}")


def _clean_entries(entries: list) -> list:
    cleaned = []
    for entry in entries:
        if not isinstance(entry, str):
            continue
        value = entry.strip().strip("/").strip()
        value = value.lstrip("?")
        if value and value not in cleaned:
            cleaned.append(value)
    return cleaned


def write_wordlist(entries: list, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(entries) + ("\n" if entries else ""))
    return out_path


def baseline_for_template(
    url_template: str, extra_header: str | None = None, timeout: float = 10.0
) -> requests.Response:
    """
    Fingerprint a "miss" for this specific category by substituting FUZZ
    with a near-certainly-bogus token -- in the *same* template that will
    be fuzzed for real, not a generic unrelated probe. This matters: for
    paths, a random path at the target is a fine stand-in for a miss, but
    for params/vhosts the only meaningful baseline is "this exact
    URL/header shape, with a parameter or subdomain name real wordlists
    won't contain" -- an unrelated 404 has nothing to do with what a
    non-matching parameter name or vhost actually looks like.
    """
    token = f"fuzzforge_probe_{uuid.uuid4().hex[:12]}"
    probe_url = url_template.replace("FUZZ", token)
    headers = {}
    if extra_header:
        name, _, value = extra_header.partition(":")
        headers[name.strip()] = value.replace("FUZZ", token).strip()
    return requests.get(probe_url, headers=headers or None, timeout=timeout)


def run_ffuf(
    wordlist_path: Path,
    url_template: str,
    filter_size: int,
    extra_header: str | None = None,
    timeout: float = 120.0,
) -> list:
    """
    Run ffuf against url_template (containing the literal FUZZ keyword),
    filtering out responses matching filter_size (the baseline miss size).
    Returns the list of result dicts from ffuf's JSON output.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        "ffuf",
        "-w", str(wordlist_path),
        "-u", url_template,
        "-mc", "all",  # we already filter by response size below; ffuf's
                       # default status-code matcher silently excludes
                       # codes like 308 (a redirect to a trailing-slash
                       # route), which would otherwise hide a real hit
        "-fs", str(filter_size),
        "-of", "json",
        "-o", out_path,
        "-s",
    ]
    if extra_header:
        cmd += ["-H", extra_header]

    subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

    try:
        with open(out_path) as f:
            data = json.load(f)
        return data.get("results", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)


def generate_wordlists(
    url: str,
    categories: list,
    api_base: str,
    api_key: str,
    model: str,
    count: int,
    out_dir: Path,
) -> dict:
    context = fetch_context(url)
    results = {}
    for category in categories:
        prompt = build_prompt(context, category, count)
        raw = call_llm(prompt, api_base, api_key, model)
        entries = parse_wordlist_response(raw)
        path = write_wordlist(entries, out_dir / f"{category}.txt")
        results[category] = {"entries": entries, "path": path}
    return results


def url_template_for_category(base_url: str, category: str, param_value: str = "1") -> tuple:
    """
    Returns (url_template, extra_header) for the given fuzz category.

    Note on params: a parameter's *name* is what's being fuzzed here, with
    its value fixed at param_value for every candidate. A real app can
    gate behavior on a specific value (e.g. only "true", not "1") -- the
    right name alone won't trip it. If paths/vhosts find nothing but you
    suspect a parameter is close, rerun with --param-value to try another
    value against the same name list.
    """
    base_url = base_url.rstrip("/")
    if category == "paths":
        return f"{base_url}/FUZZ", None
    if category == "params":
        # No inserted slash: base_url may already be an exact path (e.g.
        # ".../dashboard"), and adding one would silently 404 on an app
        # that routes "/dashboard" and "/dashboard/" differently.
        return f"{base_url}?FUZZ={param_value}", None
    if category == "vhosts":
        parsed = urlparse(base_url)
        root_domain = ".".join(parsed.hostname.split(".")[-2:]) if parsed.hostname else "FUZZ"
        return base_url + "/", f"Host: FUZZ.{root_domain}"
    raise ValueError(f"unknown category: {category}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzforge",
        description="AI-generated, target-aware wordlists for ffuf.",
    )
    parser.add_argument("url", help="Target base URL, e.g. https://target.test")
    parser.add_argument(
        "--categories", default="paths,params,vhosts",
        help="Comma-separated: paths,params,vhosts (default: all three)",
    )
    parser.add_argument("--count", type=int, default=25, help="Wordlist entries per category (default: 25)")
    parser.add_argument("--out", default="./fuzzforge-out", help="Output directory for wordlists")
    parser.add_argument("--model", default=None, help="Model name (or FUZZFORGE_MODEL)")
    parser.add_argument("--api-base", default=None, help="OpenAI-compatible API base URL (or FUZZFORGE_API_BASE)")
    parser.add_argument("--api-key", default=None, help="API key (or FUZZFORGE_API_KEY)")
    parser.add_argument("--run", action="store_true", help="Also run ffuf against the target with each wordlist")
    parser.add_argument(
        "--param-value", default="1",
        help="Value to pair with each candidate parameter name (default: 1). "
             "Try a different one (e.g. 'true') if params finds nothing.",
    )
    return parser


def main(argv=None):
    import os

    args = build_arg_parser().parse_args(argv)
    api_base = args.api_base or os.environ.get("FUZZFORGE_API_BASE")
    api_key = args.api_key or os.environ.get("FUZZFORGE_API_KEY")
    model = args.model or os.environ.get("FUZZFORGE_MODEL")

    if not (api_base and api_key and model):
        print(
            "error: need --api-base/--api-key/--model, or FUZZFORGE_API_BASE/"
            "FUZZFORGE_API_KEY/FUZZFORGE_MODEL set.",
            file=sys.stderr,
        )
        return 2

    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    for c in categories:
        if c not in CATEGORIES:
            print(f"error: unknown category {c!r}, must be one of {CATEGORIES}", file=sys.stderr)
            return 2

    out_dir = Path(args.out)
    print(f"[*] Fetching context from {args.url} ...")
    wordlists = generate_wordlists(args.url, categories, api_base, api_key, model, args.count, out_dir)

    for category, result in wordlists.items():
        print(f"[+] {category}: {len(result['entries'])} entries -> {result['path']}")

    if args.run:
        for category, result in wordlists.items():
            url_template, extra_header = url_template_for_category(args.url, category, args.param_value)
            print(f"\n[*] Baselining a known-miss for {category} ({url_template}) ...")
            baseline = baseline_for_template(url_template, extra_header)
            print(f"[*] Baseline size: {len(baseline.content)} bytes (status {baseline.status_code})")

            print(f"[*] Running ffuf for {category} ...")
            hits = run_ffuf(result["path"], url_template, len(baseline.content), extra_header)
            if not hits:
                print(f"    no hits for {category}")
            for hit in hits:
                print(f"    HIT  {hit.get('input', {}).get('FUZZ', '?')}  "
                      f"[status {hit.get('status')}, {hit.get('length')} bytes]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
