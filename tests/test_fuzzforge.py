import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fuzzforge

# ---------------------------------------------------------------------------
# parse_wordlist_response
# ---------------------------------------------------------------------------

def test_parse_strict_json_array():
    raw = '["login", "admin", "export"]'
    assert fuzzforge.parse_wordlist_response(raw) == ["login", "admin", "export"]


def test_parse_json_wrapped_in_prose():
    raw = 'Sure! Here is the wordlist:\n\n["alpha", "beta"]\n\nHope that helps.'
    assert fuzzforge.parse_wordlist_response(raw) == ["alpha", "beta"]


def test_parse_json_in_code_fence():
    raw = '```json\n["one", "two", "three"]\n```'
    assert fuzzforge.parse_wordlist_response(raw) == ["one", "two", "three"]


def test_parse_cleans_slashes_and_query_markers():
    raw = '["/login/", "?debug", " spaced ", "dup", "dup"]'
    assert fuzzforge.parse_wordlist_response(raw) == ["login", "debug", "spaced", "dup"]


def test_parse_raises_on_garbage():
    with pytest.raises(ValueError):
        fuzzforge.parse_wordlist_response("not a list at all, sorry")


def test_parse_ignores_non_string_entries():
    raw = '["login", 42, null, "admin"]'
    assert fuzzforge.parse_wordlist_response(raw) == ["login", "admin"]


# ---------------------------------------------------------------------------
# build_prompt
# ---------------------------------------------------------------------------

def test_build_prompt_includes_context():
    context = {
        "url": "https://example.test",
        "title": "Example Co",
        "description": "An example company",
        "nav_links": ["Dashboard", "About"],
        "body_text": "Welcome to Example",
        "tech_hints": ["Server: nginx"],
    }
    prompt = fuzzforge.build_prompt(context, "paths", 10)
    assert "Example Co" in prompt
    assert "Dashboard, About" in prompt
    assert "nginx" in prompt
    assert "10" in prompt


def test_build_prompt_handles_missing_context_gracefully():
    context = {"url": "https://example.test", "title": "", "description": "",
               "nav_links": [], "body_text": "", "tech_hints": []}
    prompt = fuzzforge.build_prompt(context, "vhosts", 5)
    assert "(none)" in prompt
    assert "(none found)" in prompt


# ---------------------------------------------------------------------------
# write_wordlist
# ---------------------------------------------------------------------------

def test_write_wordlist_creates_file(tmp_path):
    out = fuzzforge.write_wordlist(["a", "b", "c"], tmp_path / "sub" / "paths.txt")
    assert out.read_text() == "a\nb\nc\n"


def test_write_wordlist_handles_empty_list(tmp_path):
    out = fuzzforge.write_wordlist([], tmp_path / "params.txt")
    assert out.read_text() == ""


# ---------------------------------------------------------------------------
# call_llm (mocked HTTP)
# ---------------------------------------------------------------------------

@patch("fuzzforge.requests.post")
def test_call_llm_returns_message_content(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "choices": [{"message": {"content": '["x", "y"]'}}]
    }
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    result = fuzzforge.call_llm("prompt text", "https://api.test/v1", "key123", "some-model")
    assert result == '["x", "y"]'

    called_kwargs = mock_post.call_args.kwargs
    assert called_kwargs["headers"]["Authorization"] == "Bearer key123"
    assert called_kwargs["json"]["model"] == "some-model"


# ---------------------------------------------------------------------------
# url_template_for_category
# ---------------------------------------------------------------------------

def test_url_template_paths():
    template, header = fuzzforge.url_template_for_category("https://target.test", "paths")
    assert template == "https://target.test/FUZZ"
    assert header is None


def test_url_template_params():
    template, _header = fuzzforge.url_template_for_category("https://target.test/", "params")
    assert template == "https://target.test?FUZZ=1"


def test_url_template_params_preserves_exact_path():
    # No inserted slash: "/dashboard" must stay "/dashboard", not
    # "/dashboard/", since a Flask-style route can 404 on the latter.
    template, _header = fuzzforge.url_template_for_category("https://target.test/dashboard", "params")
    assert template == "https://target.test/dashboard?FUZZ=1"


def test_url_template_params_custom_value():
    template, _header = fuzzforge.url_template_for_category(
        "https://target.test/dashboard", "params", param_value="true"
    )
    assert template == "https://target.test/dashboard?FUZZ=true"


def test_url_template_vhosts():
    template, header = fuzzforge.url_template_for_category("https://target.test", "vhosts")
    assert template == "https://target.test/"
    assert header == "Host: FUZZ.target.test"


def test_url_template_rejects_unknown_category():
    with pytest.raises(ValueError):
        fuzzforge.url_template_for_category("https://target.test", "bogus")


# ---------------------------------------------------------------------------
# baseline_for_template
# ---------------------------------------------------------------------------

@patch("fuzzforge.requests.get")
def test_baseline_for_template_substitutes_fuzz_in_url(mock_get):
    mock_get.return_value = MagicMock(content=b"not found")
    fuzzforge.baseline_for_template("https://target.test/FUZZ")
    called_url = mock_get.call_args.args[0]
    assert "FUZZ" not in called_url
    assert called_url.startswith("https://target.test/fuzzforge_probe_")


@patch("fuzzforge.requests.get")
def test_baseline_for_template_substitutes_fuzz_in_header(mock_get):
    mock_get.return_value = MagicMock(content=b"not found")
    fuzzforge.baseline_for_template("https://target.test/", extra_header="Host: FUZZ.target.test")
    called_headers = mock_get.call_args.kwargs["headers"]
    assert "FUZZ" not in called_headers["Host"]
    assert called_headers["Host"].endswith(".target.test")


@patch("fuzzforge.requests.get")
def test_baseline_for_template_no_header_when_none_given(mock_get):
    mock_get.return_value = MagicMock(content=b"not found")
    fuzzforge.baseline_for_template("https://target.test/FUZZ")
    assert mock_get.call_args.kwargs["headers"] is None


# ---------------------------------------------------------------------------
# generate_wordlists (fully mocked network, end-to-end through parsing)
# ---------------------------------------------------------------------------

def _fake_subprocess_run_writing(result_payload):
    """Builds a fake subprocess.run that writes ffuf's expected -o file."""

    def _run(cmd, **kwargs):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w") as f:
            json.dump({"results": result_payload}, f)
        return MagicMock(returncode=0)

    return _run


@patch("fuzzforge.subprocess.run")
def test_run_ffuf_always_passes_mc_all(mock_run, tmp_path):
    # ffuf's default -mc excludes codes like 308 (a redirect to a
    # trailing-slash route), which would otherwise hide a real hit even
    # though the size-based filter is doing its job correctly.
    mock_run.side_effect = _fake_subprocess_run_writing([])
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("admin\n")

    fuzzforge.run_ffuf(wordlist, "https://target.test/FUZZ", filter_size=636)

    cmd = mock_run.call_args.args[0]
    assert "-mc" in cmd
    assert cmd[cmd.index("-mc") + 1] == "all"


@patch("fuzzforge.subprocess.run")
def test_run_ffuf_parses_results(mock_run, tmp_path):
    mock_run.side_effect = _fake_subprocess_run_writing(
        [{"input": {"FUZZ": "staging-ops"}, "status": 308, "length": 255}]
    )
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("staging-ops\n")

    hits = fuzzforge.run_ffuf(wordlist, "https://target.test/FUZZ", filter_size=636)

    assert len(hits) == 1
    assert hits[0]["input"]["FUZZ"] == "staging-ops"


@patch("fuzzforge.call_llm")
@patch("fuzzforge.fetch_context")
def test_generate_wordlists_end_to_end(mock_fetch, mock_llm, tmp_path):
    mock_fetch.return_value = {
        "url": "https://target.test", "title": "T", "description": "",
        "nav_links": [], "body_text": "", "tech_hints": [],
    }
    mock_llm.return_value = '["login", "export"]'

    result = fuzzforge.generate_wordlists(
        "https://target.test", ["paths"], "https://api.test", "key", "model", 10, tmp_path
    )
    assert result["paths"]["entries"] == ["login", "export"]
    assert result["paths"]["path"].read_text() == "login\nexport\n"
