"""Polyglot prefilter: every language section must fire on its fixture file."""
from cerberus.tools.sast import regex_prefilter

ROOT = "tests/fixtures/polyglot"

EXPECT = {
    "js-exec": "vuln.js",
    "js-xss": "vuln.js",
    "java-exec": "Vuln.java",
    "java-sqli": "Vuln.java",
    "java-src": "Vuln.java",
    "go-exec": "main.go",
    "rb-exec": "vuln.rb",
    "rb-rails-sqli": "vuln.rb",
    "php-exec": "vuln.php",
    "php-sqli": "vuln.php",
    "c-banned": "vuln.c",
    "c-exec": "vuln.c",
    "rs-unsafe": "lib.rs",
    "cs-exec": "Program.cs",
    "tf-open": "main.tf",
    "docker-add": "Dockerfile",
    "tpl-xss": "xss.html",
    "hardcoded-secret": "vuln.js",
}


def _sections(text: str) -> dict[str, str]:
    out: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("## "):
            cur = line[3:].strip()
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def test_polyglot_sections_fire():
    secs = _sections(regex_prefilter.func(target=ROOT))
    missing = [s for s in EXPECT if s not in secs]
    assert not missing, f"sections with no hits: {missing}"
    wrong_file = [s for s, f in EXPECT.items() if f not in secs[s]]
    assert not wrong_file, f"sections not hitting expected file: {wrong_file}"


def test_prefilter_no_invalid_regex():
    for root in (ROOT, "tests/fixtures/pygoat-sample"):
        out = regex_prefilter.func(target=root)
        assert "ERROR: bad regex" not in out, root


def test_template_reflect_candidates(tmp_path, monkeypatch):
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    from cerberus.tools.sast import template_reflect_candidates
    (tmp_path / "f.html").write_text('<form action="/x">{{ name }}</form>')
    (tmp_path / "plain.html").write_text('<h1>static</h1>')
    out = template_reflect_candidates(str(tmp_path))
    assert len(out) == 1
    assert out[0]["cwe"] == "CWE-79" and out[0]["status"] == "needs-review"
    assert out[0]["path"].endswith("f.html")


# (A custom-rule claim reaching the LLM is asserted end-to-end in
# test_verify.py::test_custom_rule_faces_llm.)


def test_polyglot_routes():
    from cerberus.tools.codegraph import framework_routes
    # The grep fallback is gone (routes come from the index or the native
    # bridge now): an unindexed fixture returns the no-index guidance string —
    # an honest success-shaped answer, not scanner output.
    rt = framework_routes.func(root=ROOT)
    assert rt.startswith("(no codegraph index")
