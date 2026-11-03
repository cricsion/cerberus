import json
import xml.etree.ElementTree as ET

from cerberus.reporting.reports import (
    write_html,
    write_junit,
    write_markdown,
    write_sarif,
)

SAMPLE = [
    {
        "id": "1",
        "title": "SQL injection <b>&\"test\"",
        "cwe": "CWE-89",
        "severity": "critical",
        "confidence": 0.9,
        "path": "app.py",
        "start_line": 10,
        "end_line": 12,
        "snippet": "q = \"SELECT\" % user",
        "evidence": "evidence <&>",
        "patch_summary": "use params <&>",
        "status": "confirmed",
    },
    {
        "id": "2",
        "title": "XSS",
        "cwe": "CWE-79",
        "severity": "medium",
        "confidence": 0.5,
        "path": "xss.py",
        "start_line": 5,
        "end_line": 6,
        "snippet": "return name",
        "evidence": "e",
        "patch_summary": "f",
        "status": "needs-review",
    },
    {
        "id": "3",
        "title": "Info note",
        "cwe": "CWE-798",
        "severity": "info",
        "confidence": 0.1,
        "path": "auth.py",
        "start_line": 1,
        "end_line": 1,
        "snippet": "x",
        "evidence": "e",
        "patch_summary": "f",
        "status": "needs-review",
    },
]


def test_write_sarif(tmp_path):
    out = tmp_path / "results.sarif"
    write_sarif(SAMPLE, out)
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert "runs" in data and len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == len(SAMPLE)


def test_write_markdown(tmp_path):
    out = tmp_path / "report.md"
    write_markdown(SAMPLE, out)
    text = out.read_text()
    assert "# Cerberus Report" in text
    assert "Total findings: 3" in text


def test_write_html(tmp_path):
    out = tmp_path / "report.html"
    write_html(SAMPLE, out)
    text = out.read_text(encoding="utf-8")
    assert "<html" in text.lower()
    assert "<table" in text.lower()
    # Severity-sorted: critical before medium before info.
    assert text.index("critical") < text.index("medium") < text.index("info")
    # Escaping: raw "<b>" must not appear, escaped "&lt;b&gt;" must.
    assert "<b>" not in text
    assert "&lt;b&gt;" in text
    # Self-contained: no external JS/CSS references.
    assert 'src="http' not in text
    assert "href=\"http" not in text
    assert "<script src" not in text
    assert '<link rel="stylesheet"' not in text


def test_write_junit(tmp_path):
    out = tmp_path / "junit.xml"
    write_junit(SAMPLE, out)
    tree = ET.parse(str(out))
    root = tree.getroot()
    assert root.tag == "testsuite"
    cases = list(root.findall("testcase"))
    assert len(cases) == len(SAMPLE)
    # Only severity>=high (critical here) gets a failure child.
    failures = [c for c in cases if c.find("failure") is not None]
    assert len(failures) == 1
    assert failures[0].get("classname") == "CWE-89"
    assert root.get("failures") == "1"
    assert root.get("tests") == str(len(SAMPLE))


def test_write_html_marks_duplicate_rows(tmp_path):
    """F1(a): a `duplicate_of` row is marked in its Status cell; the primary
    keeps its "(+N duplicate(s))" title suffix."""
    sample = [dict(SAMPLE[0]),                            # id "1" (primary)
              dict(SAMPLE[1], id="4", duplicate_of="1")]  # duplicate of "1"
    out = tmp_path / "report.html"
    write_html(sample, out)
    text = out.read_text(encoding="utf-8")
    assert "(duplicate of 1)" in text
    assert "+1 duplicate" in text                         # primary suffix intact
    assert "(duplicate of 4)" not in text                 # primary unmarked


def test_write_markdown_neutralizes_injected_structure(tmp_path):
    """F3: untrusted fields cannot inject markdown structure — no field line
    leads with '#'/'>'/'|' and backticks are neutralized."""
    evil = dict(SAMPLE[0])
    evil.update(id="9", title="# Injected", path="evil.py",
                evidence="`x` | fake\n# Injected heading",
                patch_summary="ok")
    out = tmp_path / "report.md"
    write_markdown([evil], out)
    text = out.read_text(encoding="utf-8")
    assert "# Cerberus Report" in text                # own structure intact
    assert "# Injected" not in text                       # leading '#' neutralized
    assert "`x`" not in text                              # backticks neutralized
    assert not any(l.startswith(("#", ">", "|")) and "Injected heading" in l
                   for l in text.splitlines())


def test_write_reports_with_poc(tmp_path):
    sample = [
        {
            "id": "find-1",
            "title": "SQL Injection",
            "cwe": "CWE-89",
            "severity": "critical",
            "confidence": 0.95,
            "path": "app/db.py",
            "start_line": 20,
            "end_line": 25,
            "status": "confirmed",
            "patch_summary": "Use parameterized query via cursor.execute(query, params)",
            "patch": "--- a/app/db.py\n+++ b/app/db.py\n@@ -22,1 +22,1 @@\n-cursor.execute(f'SELECT * FROM users WHERE id={uid}')\n+cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
            "poc": {
                "status": "proven",
                "command": "python3 /work/_shared/poc/find-1/test_repro.py",
                "control": "--control",
                "filename": "test_repro.py",
                "script": "def test_vuln():\n    assert True",
                "receipt": {
                    "runs": 3,
                    "successes": 3,
                    "control_status": "passed",
                    "stamped_by": "cerberus",
                    "timestamp": "2026-11-02T12:00:00Z",
                },
            },
        },
        {
            "id": "find-2",
            "title": "XSS in profile",
            "cwe": "CWE-79",
            "severity": "medium",
            "confidence": 0.8,
            "path": "app/views.py",
            "start_line": 50,
            "end_line": 55,
            "status": "candidate",
            "poc": {
                "status": "attempted",
                "command": "python3 /work/_shared/poc/find-2/test_repro.py",
            },
        },
    ]

    # 1. SARIF
    sarif_file = tmp_path / "results.sarif"
    write_sarif(sample, sarif_file)
    sarif_data = json.loads(sarif_file.read_text())
    res1 = sarif_data["runs"][0]["results"][0]
    assert "[POC PROVEN]" in res1["message"]["text"]
    assert res1["properties"]["pocStatus"] == "proven"
    assert res1["properties"]["reproduced"] is True
    assert res1["properties"]["pocReceipt"]["successes"] == 3
    assert res1["properties"]["patch"].startswith("--- a/app/db.py")
    assert "parameterized query" in res1["properties"]["patchSummary"]

    res2 = sarif_data["runs"][0]["results"][1]
    assert res2["properties"]["pocStatus"] == "attempted"
    assert res2["properties"]["reproduced"] is False

    # 2. Markdown
    md_file = tmp_path / "report.md"
    write_markdown(sample, md_file)
    md_text = md_file.read_text()
    assert "Dynamic PoCs: 1 proven, 1 attempted" in md_text
    assert "**PROVEN** (3/3 exploit runs succeeded, control passed)" in md_text
    assert "Repro Command: `python3 /work/_shared/poc/find-1/test_repro.py`" in md_text
    assert "Control Command: `python3 /work/_shared/poc/find-1/test_repro.py --control`" in md_text
    assert "Stamped by cerberus at `2026-11-02T12:00:00Z`" in md_text
    assert "def test_vuln():" in md_text
    assert "**ATTEMPTED**" in md_text
    assert "- Patch:" in md_text
    assert "Summary**: Use parameterized query" in md_text
    assert "Diff**:" in md_text
    assert "cursor.execute('SELECT * FROM users WHERE id=%s'" in md_text

    # 3. HTML
    html_file = tmp_path / "report.html"
    write_html(sample, html_file)
    html_text = html_file.read_text()
    assert "badge-proven" in html_text
    assert "badge-attempted" in html_text
    assert "python3 /work/_shared/poc/find-1/test_repro.py" in html_text
    assert "def test_vuln():" in html_text
    assert "1 proven, 1 attempted" in html_text
    assert "<summary>Diff</summary>" in html_text
    assert "<th>Patch</th>" in html_text
    assert "cursor.execute" in html_text
