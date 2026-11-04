import json
import xml.etree.ElementTree as ET

from cerberus.reporting.reports import (
    write_html,
    write_json,
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
    assert "3 actionable" in text


def test_write_markdown_order_and_exclusion(tmp_path):
    """F1 ordering: confirmed tier leads, then needs-review; duplicates and
    FPs never appear; the header explains what was omitted."""
    sample = [
        dict(SAMPLE[0]),                                        # confirmed critical
        dict(SAMPLE[1], id="4", status="confirmed"),            # confirmed medium
        dict(SAMPLE[1], id="5"),                                # needs-review medium
        dict(SAMPLE[1], id="6", duplicate_of="1"),              # duplicate -> omitted
        dict(SAMPLE[1], id="7", status="fp"),                   # FP -> omitted
    ]
    out = tmp_path / "report.md"
    write_markdown(sample, out)
    text = out.read_text()
    assert "3 actionable" in text
    assert "- Omitted: 1 false positive and 1 duplicate" in text
    idx_crit = text.index("SQL injection")
    idx_medium = text.index("XSS", idx_crit)
    assert idx_crit < idx_medium                      # confirmed before needs-review
    assert "(duplicate of" not in text                # duplicate row dropped
    assert "## Confirmed (2)" in text and "## Needs review (1)" in text


def test_write_html(tmp_path):
    out = tmp_path / "report.html"
    write_html(SAMPLE, out)
    text = out.read_text(encoding="utf-8")
    assert "<html" in text.lower()
    # Expandable cards, not a table.
    assert "<table" not in text.lower()
    assert '<details class="finding"' in text
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
    """Duplicates are excluded from the HTML table; the collapsed duplicate
    count still shows as a suffix on the primary's title."""
    sample = [dict(SAMPLE[0]),                            # id "1" (primary)
              dict(SAMPLE[1], id="4", duplicate_of="1")]  # duplicate of "1"
    out = tmp_path / "report.html"
    write_html(sample, out)
    text = out.read_text(encoding="utf-8")
    assert "+1 duplicate" in text              # primary suffix intact
    assert "Duplicates collapsed here" in text
    assert "duplicate of" not in text          # duplicate row itself is gone


def test_write_html_suppressed_fp_and_header(tmp_path):
    """SARIF keeps FPs as accepted suppressions; HTML/markdown/JUnit drop them
    and say how many were omitted."""
    sample = [dict(SAMPLE[0]), dict(SAMPLE[1], id="5", status="fp")]
    md_out = tmp_path / "report.md"
    write_markdown(sample, md_out)
    md_text = md_out.read_text()
    assert "1 actionable" in md_text
    assert "1 false positive" in md_text

    html_out = tmp_path / "report.html"
    write_html(sample, html_out)
    html_text = html_out.read_text(encoding="utf-8")
    assert "SQL injection" in html_text and "XSS" not in html_text

    sarif_out = tmp_path / "results.sarif"
    write_sarif(sample, sarif_out)
    sarif_data = json.loads(sarif_out.read_text())
    results = sarif_data["runs"][0]["results"]
    assert len(results) == 2                      # FP kept, not dropped
    suppressed = [r for r in results if r.get("suppressions")]
    assert len(suppressed) == 1
    assert suppressed[0]["suppressions"][0]["status"] == "accepted"
    assert suppressed[0]["suppressions"][0]["kind"] == "external"


def test_poc_payload_renders_after_poc_hidden_removal(tmp_path):
    """Inverted 2026-11-04: the ≤1-line/no-sentinel withholding heuristic was
    deleted (it suppressed genuine one-line exploits); payload policy belongs
    to the validator, the report layer renders receipts. A one-liner PoC now
    renders in MD and HTML; the one-word patch summary still renders too."""
    sample = [dict(SAMPLE[0], id="9", patch="fix", patch_summary="fix summary",
                   poc={"status": "attempted", "command": "python3 x.py",
                        "script": "print(1)", "filename": "test_repro.py"})]
    md_out = tmp_path / "report.md"
    write_markdown(sample, md_out)
    md_text = md_out.read_text()
    assert "print(1)" in md_text

    html_out = tmp_path / "report.html"
    write_html(sample, html_out)
    html_text = html_out.read_text(encoding="utf-8")
    assert "print(1)" in html_text


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
    # Card structure: PoC command + full script live in expandable sections.
    assert "python3 /work/_shared/poc/find-1/test_repro.py" in html_text
    assert "Full script — test_repro.py" in html_text
    assert "def test_vuln():" in html_text
    assert "<summary>Diff</summary>" in html_text
    assert "<h3>Proposed patch</h3>" in html_text
    assert "cursor.execute" in html_text


def test_reports_render_blocked_poc_and_script_file(tmp_path):
    sample = [dict(SAMPLE[0], id="10",
                   poc={"status": "blocked", "blocker": "PoC agent result omitted this finding"})]
    md_out = tmp_path / "report.md"
    write_markdown(sample, md_out)
    md_text = md_out.read_text()
    assert "**BLOCKED** (PoC agent result omitted this finding)" in md_text

    html_out = tmp_path / "report.html"
    write_html(sample, html_out)
    html_text = html_out.read_text(encoding="utf-8")
    assert "badge-blocked" in html_text

    ok = [dict(SAMPLE[0], id="11",
               poc={"status": "attempted", "command": "python3 /work/_shared/poc/f/test_repro.py",
                    "host_path": ".cerberus/run/scratch/poc/f/test_repro.py",
                    "receipt": {"runs": 1, "successes": 0, "control_status": "invalid",
                                "outputs": ["STDOUT:\nTraceback..."], "stamped_by": "cerberus"}})]
    write_markdown(ok, md_out)
    md2 = md_out.read_text()
    assert "- Script file: `.cerberus/run/scratch/poc/f/test_repro.py`" in md2
    assert "Observed output (stamped receipt):" in md2


def test_write_json_enriches_id_and_cvss(tmp_path):
    sample = [
        {"title": "Missing ID Finding", "severity": "critical", "path": "app.py"},
        {"id": "custom-id-99", "title": "Has ID Finding", "severity": "medium", "cvss": 5.5,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", "path": "api.py"},
    ]
    out = tmp_path / "findings.json"
    write_json(sample, out)
    data = json.loads(out.read_text())
    assert len(data) == 2
    # Missing ID gets generated fallback
    assert data[0]["id"] == "cb-001"
    assert data[0]["cvss"] == 9.8
    assert "CVSS:3.1" in data[0]["cvss_vector"]
    # Existing ID and vector are preserved
    assert data[1]["id"] == "custom-id-99"
    assert data[1]["cvss"] == 5.5
    assert data[1]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"


def test_write_sarif_mitre_cwe_codeflows_and_fixes(tmp_path):
    sample = [
        {
            "id": "find-taint-1",
            "title": "SQL Injection",
            "cwe": "CWE-89",
            "severity": "critical",
            "confidence": 0.95,
            "path": "src/routers/user.js",
            "start_line": 213,
            "end_line": 217,
            "status": "confirmed",
            "taint": {
                "source": "req.query.name",
                "sink": "eval(req.query.name)",
                "path": [
                    "src/routers/user.js:213 - entry point",
                    "src/routers/user.js:215 - processing",
                ],
            },
            "patch": (
                "--- a/src/routers/user.js\n"
                "+++ b/src/routers/user.js\n"
                "@@ -215,1 +215,1 @@\n"
                "-eval(req.query.name)\n"
                "+sanitize(req.query.name)\n"
            ),
            "patch_summary": "Sanitize query param before evaluation",
        }
    ]
    out = tmp_path / "results.sarif"
    write_sarif(sample, out)
    data = json.loads(out.read_text())

    # Rules verification
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "CWE-89"
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"
    assert "https://cwe.mitre.org/data/definitions/89.html" in rule["help"]["markdown"]
    assert rule["properties"]["security-severity"] == "9.8"

    # Result verification
    result = data["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "9.8"
    assert "codeFlows" in result
    flow = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(flow) >= 3  # source, path hops, sink
    assert flow[0]["location"]["message"]["text"] == "Source: req.query.name"
    assert flow[-1]["location"]["message"]["text"] == "Sink: eval(req.query.name)"

    # Native fixes verification
    assert "fixes" in result
    fix = result["fixes"][0]
    assert fix["description"]["text"] == "Sanitize query param before evaluation"
    replacements = fix["artifactChanges"][0]["replacements"]
    assert len(replacements) == 1
    assert replacements[0]["deletedRegion"]["startLine"] == 215
    assert replacements[0]["insertedContent"]["text"] == "sanitize(req.query.name)"


def test_write_junit_suite_timestamp_and_testcase_properties(tmp_path):
    sample = [
        {
            "id": "1",
            "title": "SQL Injection",
            "cwe": "CWE-89",
            "severity": "critical",
            "confidence": 0.9,
            "path": "app.py",
            "start_line": 10,
            "end_line": 12,
            "status": "confirmed",
            "poc": {"status": "proven"},
            "patch_summary": "Use bind params",
        }
    ]
    out = tmp_path / "junit.xml"
    write_junit(sample, out)
    tree = ET.parse(str(out))
    root = tree.getroot()
    assert "timestamp" in root.attrib
    assert root.attrib["time"] == "0.000"

    case = root.find("testcase")
    props = case.find("properties")
    prop_dict = {p.attrib["name"]: p.attrib["value"] for p in props.findall("property")}
    assert prop_dict["poc_status"] == "proven"
    assert prop_dict["cvss"] == "9.8"
    assert prop_dict["confidence"] == "0.90"
    assert prop_dict["has_patch"] == "true"


def test_write_markdown_matrix_toc_taint_and_sanitization(tmp_path):
    sample = [
        {
            "id": "f1",
            "title": "SQL Injection",
            "cwe": "CWE-89",
            "severity": "critical",
            "confidence": 0.95,
            "path": "app/db.py",
            "start_line": 10,
            "end_line": 15,
            "status": "confirmed",
            "evidence": "src/routers/user.js:213-217 defines GET | omitted from batch reply | consensus: tie (0c/0f/1n) | triage: review",
            "taint": {
                "source": "req.query.name",
                "sink": "db.execute(sql)",
                "path": ["app/db.py:10", "app/db.py:12"],
            },
            "poc": {"status": "proven"},
            "patch_summary": "Use parameter binding",
            "patch": "--- a/app/db.py\n+++ b/app/db.py\n@@ -10,1 +10,1 @@\n-db.execute(raw)\n+db.execute(param)\n",
        }
    ]
    out = tmp_path / "report.md"
    write_markdown(sample, out)
    text = out.read_text(encoding="utf-8")

    # Executive matrix
    assert "| Severity | Count | Proven PoCs | Patched |" in text
    assert "| CRITICAL | 1 | 1 / 1 (100%) | 1 |" in text
    assert "| **TOTAL** | **1** | **1 / 1 (100%)** | **1** |" in text

    # Table of Contents
    assert "## Table of Contents" in text
    assert "[CRITICAL: SQL Injection (`app/db.py:10`)](#finding-1)" in text

    # CVSS in finding header
    assert "CVSS: **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)" in text

    # Taint flow
    assert "- Taint Flow:" in text
    assert "- **Source**: `req.query.name`" in text
    assert "- `app/db.py:10`" in text
    assert "- **Sink**: `db.execute(sql)`" in text

    # Evidence sanitization
    assert "Evidence: src/routers/user.js:213-217 defines GET" in text
    assert "omitted from batch reply" not in text.split("Evidence:")[1].splitlines()[0]
    assert "- Audit Trail:" in text


def test_write_html_kpis_diff_styling_search_and_no_expand_all(tmp_path):
    sample = [
        {
            "id": "f1",
            "title": "SQL Injection",
            "cwe": "CWE-89",
            "severity": "critical",
            "confidence": 0.95,
            "path": "app/db.py",
            "start_line": 10,
            "end_line": 15,
            "status": "confirmed",
            "evidence": "src/routers/user.js:213-217 defines GET | omitted from batch reply | consensus: tie",
            "taint": {
                "source": "req.query.name",
                "sink": "db.execute(sql)",
                "path": ["app/db.py:10"],
            },
            "poc": {"status": "proven"},
            "patch_summary": "Use parameter binding",
            "patch": (
                "--- a/app/db.py\n"
                "+++ b/app/db.py\n"
                "@@ -10,1 +10,1 @@\n"
                "-db.execute(raw)\n"
                "+db.execute(param)\n"
            ),
        }
    ]
    out = tmp_path / "report.html"
    write_html(sample, out)
    text = out.read_text(encoding="utf-8")

    # KPI header
    assert 'class="kpi-grid"' in text
    assert 'class="kpi-card"' in text
    assert "Actionable Findings" in text

    # Diff styling
    assert 'class="diff-hunk">@@ -10,1 +10,1 @@</span>' in text
    assert 'class="diff-del">-db.execute(raw)</span>' in text
    assert 'class="diff-add">+db.execute(param)</span>' in text

    # Search & filters
    assert 'id="search-box"' in text
    assert 'id="poc-filter"' in text
    assert 'data-poc="proven"' in text
    assert 'data-cvss="9.8"' in text

    # User constraint: NO Expand All / Collapse All button
    assert "Expand All" not in text
    assert "Collapse All" not in text
    assert "expand-all" not in text
    assert "collapse-all" not in text

    # Taint Data-Flow
    assert "<h3>Taint Data-Flow</h3>" in text
    assert "Source:</strong> <code>req.query.name</code>" in text
    assert "Sink:</strong> <code>db.execute(sql)</code>" in text

    # Sanitized evidence & collapsible audit trail
    assert "src/routers/user.js:213-217 defines GET" in text
    assert '<details class="audit-trail">' in text

