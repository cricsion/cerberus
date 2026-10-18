"""Minimal reporters: JSON + SARIF 2.1.0 + Markdown. No external deps."""
from __future__ import annotations

import html
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from harness.schemas import SEVERITY_ORDER, safe_float, safe_int

SEV_TO_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def write_json(findings: list[dict], out: Path) -> None:
    out.write_text(json.dumps(findings, indent=2))


def write_sarif(findings: list[dict], out: Path) -> None:
    rules = []
    seen: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = f.get("cwe") or f.get("title", "finding")
        if rule_id not in seen:
            seen[rule_id] = {"id": rule_id, "name": rule_id,
                             "shortDescription": {"text": f.get("title", rule_id)}}
            rules.append(seen[rule_id])
        results.append({
            "ruleId": rule_id,
            "level": SEV_TO_SARIF.get(f.get("severity", "medium"), "warning"),
            "message": {"text": f"{f.get('title')} (conf {f.get('confidence', 0)})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("path", "")},
                "region": {"startLine": max(1, safe_int(f.get("start_line", 1), 1)),
                           "endLine": max(1, safe_int(f.get("end_line", 1), 1)),
                           "snippet": {"text": f.get("snippet", "")[:2000]}}}}],
        })
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "vuln-harness", "rules": rules}}, "results": results}]}
    out.write_text(json.dumps(sarif, indent=2))


def write_markdown(findings: list[dict], out: Path,
                   coverage: list[str] | None = None) -> None:
    rows = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "medium"), 2), -(safe_float(f.get("confidence", 0)))))
    dupes: dict[str, list] = {}
    for f in rows:
        if f.get("duplicate_of"):
            dupes.setdefault(str(f["duplicate_of"]), []).append(f)
    primaries = [f for f in rows if not f.get("duplicate_of")]
    lines = ["# Vuln Harness Report", "", f"Total findings: {len(rows)}",
             f"Primaries: {len(primaries)} (+{len(rows) - len(primaries)} duplicates)", ""]
    for f in primaries:
        lines += [f"## {f.get('severity','?').upper()} {f.get('title','')}",
                  f"- CWE: {f.get('cwe','')} | confidence: {f.get('confidence',0)} | status: {f.get('status','')}",
                  f"- Location: `{f.get('path','')}:{f.get('start_line',0)}-{f.get('end_line',0)}`",
                  f"- Evidence: {f.get('evidence','')}",
                  f"- Fix: {f.get('fix_suggestion','')}", ""]
        collapsed = dupes.get(str(f.get("id", "")), [])
        if collapsed:
            locs = ", ".join(f"`{d.get('path','')}:{d.get('start_line',0)}`" for d in collapsed)
            lines += [f"  +{len(collapsed)} duplicate(s): {locs}", ""]
    if coverage:
        lines += ["## Coverage gaps", ""]
        lines += [f"- {note}" for note in coverage]
        lines.append("")
    out.write_text("\n".join(lines))


def write_html(findings: list[dict], out: Path) -> None:
    rows = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(str(f.get("severity", "medium")), 2), -(safe_float(f.get("confidence", 0)))),
    )
    trs = []
    dupes: dict[str, int] = {}
    for f in rows:
        if f.get("duplicate_of"):
            dupes[str(f["duplicate_of"])] = dupes.get(str(f["duplicate_of"]), 0) + 1
    for f in rows:
        sev = html.escape(str(f.get("severity", "")), quote=True)
        title = html.escape(str(f.get("title", "")), quote=True)
        n_dupe = dupes.get(str(f.get("id", "")), 0)
        if n_dupe and not f.get("duplicate_of"):
            title = f"{title} (+{n_dupe} duplicate{'s' if n_dupe != 1 else ''})"
        cwe = html.escape(str(f.get("cwe", "")), quote=True)
        conf = safe_float(f.get("confidence", 0) or 0)
        loc = html.escape(f"{f.get('path', '')}:{f.get('start_line', 0)}-{f.get('end_line', 0)}", quote=True)
        evidence = html.escape(str(f.get("evidence", "")), quote=True)
        fix = html.escape(str(f.get("fix_suggestion", "")), quote=True)
        status = html.escape(str(f.get("status", "")), quote=True)
        trs.append(
            "<tr><td>{sev}</td><td>{title}</td><td>{cwe}</td>"
            "<td>{conf:.2f}</td><td>{loc}</td><td>{status}</td>"
            "<td>{evidence}</td><td>{fix}</td></tr>".format(
                sev=sev, title=title, cwe=cwe, conf=conf,
                loc=loc, status=status, evidence=evidence, fix=fix,
            )
        )
    body = "\n".join(trs)
    doc = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<title>Vuln Harness Report</title>\n"
        "<style>"
        "body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #999;padding:4px 8px;text-align:left;vertical-align:top}"
        "th{background:#eee}"
        "</style>\n</head>\n<body>\n"
        "<h1>Vuln Harness Report</h1>\n"
        f"<p>Total findings: {len(rows)}</p>\n"
        "<table>\n<thead><tr>"
        "<th>Severity</th><th>Title</th><th>CWE</th><th>Confidence</th>"
        "<th>Location</th><th>Status</th><th>Evidence</th><th>Fix</th>"
        "</tr></thead>\n<tbody>\n"
        f"{body}\n"
        "</tbody>\n</table>\n</body>\n</html>\n"
    )
    out.write_text(doc, encoding="utf-8")


def write_junit(findings: list[dict], out: Path) -> None:
    failures = 0
    suite = ET.Element("testsuite", {
        "name": "vuln-harness",
        "tests": str(len(findings)),
        "errors": "0",
        "skipped": "0",
    })
    for f in findings:
        sev = str(f.get("severity", "medium"))
        title = str(f.get("title", "finding"))
        cwe = str(f.get("cwe") or "finding")
        path = str(f.get("path", ""))
        loc = f"{path}:{f.get('start_line', 0)}-{f.get('end_line', 0)}"
        name = f"{title} [{sev}] {loc}"
        case = ET.SubElement(suite, "testcase", {
            "classname": cwe,
            "name": name,
        })
        is_failure = SEVERITY_ORDER.get(sev, 2) <= SEVERITY_ORDER["high"] and str(f.get("status", "")) != "fp"
        if is_failure:
            failures += 1
            conf = safe_float(f.get("confidence", 0) or 0)
            msg = f"{title} ({cwe}) {sev} conf={conf} {loc}"
            fail = ET.SubElement(case, "failure", {"message": msg})
            evidence = str(f.get("evidence", "") or "")
            snippet = str(f.get("snippet", "") or "")
            fail.text = f"{evidence}\n{snippet}" if (evidence or snippet) else msg
    suite.set("failures", str(failures))
    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    out.write_bytes(b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suite, encoding="utf-8"))
