# FuzzForge

[![CI](https://github.com/ZProtons/fuzzforge/actions/workflows/ci.yml/badge.svg)](https://github.com/ZProtons/fuzzforge/actions/workflows/ci.yml)

AI-generated, target-aware wordlists for [ffuf](https://github.com/ffuf/ffuf).

A generic 50,000-line wordlist finds generic things. FuzzForge reads the
target's own homepage — title, nav links, visible copy, tech hints from
response headers — and asks an LLM to generate a short wordlist of paths,
parameter names, and virtual-host names actually plausible for *that
specific site*, not a one-size-fits-all guess. Then, optionally, it runs
`ffuf` for you, using the same baseline-then-filter workflow from
[FUZZING.md](https://github.com/ZProtons/Fire-Labs/blob/main/labs/fuzz-lab/FUZZING.md):
hit a known-bad request first, fingerprint its shape, filter that shape out,
and only show what's actually different.

## Install

```sh
pip install -r requirements.txt
```

Needs `ffuf` on your PATH for `--run` (`apt install ffuf`, or see the
[ffuf repo](https://github.com/ffuf/ffuf) for other install options).

Works with any OpenAI-compatible chat-completions API — OpenAI, Groq,
OpenRouter, a local Ollama server, whatever you've got a key for.

## Usage

```sh
export FUZZFORGE_API_BASE="https://api.groq.com/openai/v1"
export FUZZFORGE_API_KEY="..."
export FUZZFORGE_MODEL="llama-3.1-8b-instant"

# Just generate wordlists
python3 fuzzforge.py https://target.test --categories paths,params,vhosts

# Generate and run ffuf immediately, with auto baseline-filtering
python3 fuzzforge.py https://target.test --run
```

```
[*] Fetching context from https://target.test ...
[+] paths: 25 entries -> ./fuzzforge-out/paths.txt
[+] params: 25 entries -> ./fuzzforge-out/params.txt
[+] vhosts: 25 entries -> ./fuzzforge-out/vhosts.txt

[*] Baselining a known-miss for paths (https://target.test/FUZZ) ...
[*] Baseline size: 1204 bytes (status 404)
[*] Running ffuf for paths ...
    HIT  staging-ops  [status 308, 255 bytes]
```

### Flags

| Flag | Default | What it does |
|---|---|---|
| `--categories` | `paths,params,vhosts` | Which wordlists to generate |
| `--count` | `25` | Entries per category |
| `--out` | `./fuzzforge-out` | Where wordlists get written |
| `--run` | off | Also run `ffuf` with each generated wordlist |
| `--param-value` | `1` | Value paired with each candidate param name (see below) |

### A real limitation, not hidden

Params mode fuzzes the parameter *name*, with its value fixed at
`--param-value` for every candidate (`1` by default). A real app can gate
behavior on one specific value (`true`, not `1`) — the right name alone
won't always trip it. If `--run` finds nothing on params but the context
makes you suspicious, rerun with `--param-value true` (or whatever else is
plausible) against the same name list before concluding there's nothing
there.

## How this was built

Built by Claude (Anthropic), on my instructions. Fully unit-tested with a
mocked LLM backend (23 tests, no network or API key required to run them),
then verified end-to-end against
[ClearDesk](https://github.com/ZProtons/Fire-Labs/tree/main/labs/fuzz-lab)
— my own ffuf lab from the day before — using a stub local LLM server and
the real `ffuf` binary. That real run caught three genuine bugs before
shipping: the baseline for params/vhosts was being fingerprinted against
the wrong kind of "miss" (a generic 404 instead of the same template being
fuzzed), the params URL template inserted a slash that silently 404'd on
an exact-path route, and ffuf's own default status-code matcher was quietly
excluding a 308-redirect hit that the size filter had already correctly
identified. All three are now covered by regression tests.
