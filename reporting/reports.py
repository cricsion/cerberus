"""Minimal reporters: JSON + SARIF 2.1.0 + Markdown. No external deps."""
from __future__ import annotations

import html
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from harness.schemas import (SEVERITY_ORDER, group_duplicates, safe_float,
                             safe_int, sort_findings)

SEV_TO_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def write_json(findings: list[dict], out: Path) -> None:
    out.write_text(json.dumps(findings, indent=2), encoding="utf-8")


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

        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        poc_status = str(poc.get("status") or "").lower()
        msg_prefix = "[POC PROVEN] " if poc_status == "proven" else ""
        msg_text = f"{msg_prefix}{f.get('title')} (conf {f.get('confidence', 0)})"

        res_item: dict = {
            "ruleId": rule_id,
            "level": SEV_TO_SARIF.get(f.get("severity", "medium"), "warning"),
            "message": {"text": msg_text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("path", "")},
                "region": {"startLine": max(1, safe_int(f.get("start_line", 1), 1)),
                           "endLine": max(1, safe_int(f.get("end_line", 1), 1)),
                           "snippet": {"text": f.get("snippet", "")}}}}],
        }

        props: dict = {}
        if poc_status:
            props["pocStatus"] = poc_status
            props["reproduced"] = (poc_status == "proven")
            if poc.get("command"):
                props["pocCommand"] = poc["command"]
            receipt = poc.get("receipt") if isinstance(poc.get("receipt"), dict) else {}
            if receipt:
                props["pocReceipt"] = {
                    "runs": receipt.get("runs"),
                    "successes": receipt.get("successes"),
                    "controlStatus": receipt.get("control_status"),
                    "stampedBy": receipt.get("stamped_by"),
                }
        if f.get("patch"):
            props["patch"] = f["patch"]
        if f.get("patch_summary"):
            props["patchSummary"] = f["patch_summary"]
        if props:
            res_item["properties"] = props

        results.append(res_item)
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "cerberus", "rules": rules}}, "results": results}]}
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def write_markdown(findings: list[dict], out: Path) -> None:
    rows = sort_findings(findings)
    dupes = group_duplicates(rows)
    primaries = [f for f in rows if not f.get("duplicate_of")]
    proven_count = sum(1 for f in rows if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "proven")
    attempted_count = sum(1 for f in rows if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "attempted")

    poc_summary = ""
    if proven_count or attempted_count:
        poc_summary = f" | Dynamic PoCs: {proven_count} proven, {attempted_count} attempted"

    lines = ["# Cerberus Report", "", f"Total findings: {len(rows)}",
             f"Primaries: {len(primaries)} (+{len(rows) - len(primaries)} duplicates){poc_summary}", ""]
    for f in primaries:
        lines += [f"## {f.get('severity','?').upper()} {_md_safe(f.get('title',''))}",
                  f"- CWE: {f.get('cwe','')} | confidence: {f.get('confidence',0)} | status: {f.get('status','')}",
                  f"- Location: `{_md_safe(f.get('path',''))}:{f.get('start_line',0)}-{f.get('end_line',0)}`"]

        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        poc_status = str(poc.get("status") or "").lower()
        if poc_status:
            receipt = poc.get("receipt") if isinstance(poc.get("receipt"), dict) else {}
            if poc_status == "proven":
                runs = receipt.get("runs", 3)
                succ = receipt.get("successes", runs)
                lines.append(f"- Dynamic PoC: **PROVEN** ({succ}/{runs} exploit runs succeeded, control passed)")
            else:
                lines.append(f"- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)")
            if poc.get("command"):
                lines.append(f"  - Repro Command: `{_md_safe(poc['command'])}`")
            if poc.get("control") and poc.get("command"):
                lines.append(f"  - Control Command: `{_md_safe(poc['command'])} {poc.get('control')}`")
            if receipt.get("timestamp"):
                stamper = receipt.get("stamped_by", "cerberus")
                lines.append(f"  - Receipt: Stamped by {stamper} at `{receipt.get('timestamp')}`")
            script = str(poc.get("script") or "").strip()
            if script:
                fn = poc.get("filename", "test_repro.py")
                ext = fn.split(".")[-1] if "." in fn else "python"
                lines += [f"  - Repro Script (`{fn}`):", f"```{ext}", script, "```"]

        lines.append(f"- Evidence: {_md_safe(f.get('evidence',''))}")
        summary = str(f.get("patch_summary") or "").strip()
        patch_val = str(f.get("patch") or "").strip()
        if summary or patch_val:
            lines.append("- Patch:")
            if summary:
                lines.append(f"  - **Summary**: {_md_safe(summary)}")
            if patch_val:
                lines += ["  - **Diff**:", "```diff", patch_val, "```"]
        lines.append("")
        collapsed = dupes.get(str(f.get("id", "")), [])
        if collapsed:
            locs = ", ".join(f"`{_md_safe(d.get('path',''))}:{d.get('start_line',0)}`" for d in collapsed)
            lines += [f"  +{len(collapsed)} duplicate(s): {locs}", ""]
    out.write_text("\n".join(lines), encoding="utf-8")


def write_html(findings: list[dict], out: Path) -> None:
    rows = sort_findings(findings)
    trs = []
    dupes: dict[str, int] = {k: len(v) for k, v in group_duplicates(rows).items()}
    proven_count = sum(1 for f in rows if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "proven")
    attempted_count = sum(1 for f in rows if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "attempted")

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
        summary = html.escape(str(f.get("patch_summary", "")).strip(), quote=True)
        patch_val = str(f.get("patch", "")).strip()
        patch_parts = []
        if summary:
            patch_parts.append(f"<div>{summary}</div>")
        if patch_val:
            patch_escaped = html.escape(patch_val, quote=True)
            patch_parts.append(f"<details><summary>Diff</summary><pre class=\"diff\">{patch_escaped}</pre></details>")
        patch_cell = "".join(patch_parts) if patch_parts else "-"
        status = html.escape(str(f.get("status", "")), quote=True)
        if f.get("duplicate_of"):
            status = f"(duplicate of {html.escape(str(f['duplicate_of']), quote=True)})"

        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        poc_status = str(poc.get("status") or "").lower()
        if poc_status == "proven":
            poc_cell = '<span class="badge badge-proven">Proven</span>'
        elif poc_status == "attempted":
            poc_cell = '<span class="badge badge-attempted">Attempted</span>'
        else:
            poc_cell = '<span class="badge badge-none">-</span>'

        if poc.get("command") or poc.get("script"):
            details = []
            if poc.get("command"):
                cmd_escaped = html.escape(str(poc["command"]), quote=True)
                details.append(f"<div><strong>Command:</strong> <code>{cmd_escaped}</code></div>")
            if poc.get("script"):
                script_escaped = html.escape(str(poc["script"]).strip(), quote=True)
                fn = html.escape(str(poc.get("filename") or "test_repro.py"), quote=True)
                details.append(f"<details><summary>Script ({fn})</summary><pre>{script_escaped}</pre></details>")
            poc_cell = f"{poc_cell}<div class=\"poc-detail\">{''.join(details)}</div>"

        trs.append(
            "<tr><td>{sev}</td><td>{title}</td><td>{cwe}</td>"
            "<td>{conf:.2f}</td><td>{loc}</td><td>{status}</td><td>{poc}</td>"
            "<td>{evidence}</td><td>{patch}</td></tr>".format(
                sev=sev, title=title, cwe=cwe, conf=conf,
                loc=loc, status=status, poc=poc_cell, evidence=evidence, patch=patch_cell,
            )
        )
    body = "\n".join(trs)

    poc_summary = ""
    if proven_count or attempted_count:
        poc_summary = f" · <strong>PoCs:</strong> {proven_count} proven, {attempted_count} attempted"

    doc = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<title>Cerberus Report</title>\n"
        "<style>"
        "body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #999;padding:4px 8px;text-align:left;vertical-align:top}"
        "th{background:#eee}"
        ".badge{padding:2px 6px;border-radius:4px;font-size:0.8em;font-weight:bold;text-transform:uppercase}"
        ".badge-proven{background:#d4edda;color:#155724;border:1px solid #c3e6cb}"
        ".badge-attempted{background:#fff3cd;color:#856404;border:1px solid #ffeeba}"
        ".badge-none{background:#e2e3e5;color:#383d41;border:1px solid #d6d8db}"
        ".poc-detail{margin-top:4px;font-size:0.85em}"
        "pre{background:#f8f9fa;padding:6px;border:1px solid #ddd;border-radius:4px;overflow-x:auto;max-height:200px}"
        "pre.diff{background:#1e1e1e;color:#d4d4d4;border:1px solid #333}"
        "code{background:#f1f1f1;padding:1px 4px;border-radius:3px;font-family:monospace}"
        "</style>\n</head>\n<body>\n"
        "<h1>Cerberus Report</h1>\n"
        f"<p>Total findings: {len(rows)}{poc_summary}</p>\n"
        "<table>\n<thead><tr>"
        "<th>Severity</th><th>Title</th><th>CWE</th><th>Confidence</th>"
        "<th>Location</th><th>Status</th><th>PoC</th><th>Evidence</th><th>Patch</th>"
        "</tr></thead>\n<tbody>\n"
        f"{body}\n"
        "</tbody>\n</table>\n</body>\n</html>\n"
    )
    out.write_text(doc, encoding="utf-8")


def _md_safe(value: object) -> str:
    """Neutralize markdown structure in an untrusted report field."""
    parts = str(value if value is not None else "").replace("`", "'").splitlines()
    return " ".join(p.lstrip("#>|").lstrip() for p in parts)


def write_junit(findings: list[dict], out: Path) -> None:
    failures = 0
    suite = ET.Element("testsuite", {
        "name": "cerberus",
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
        # failure-counting gate deliberately treats junk severity as >=medium;
        # this is NOT schemas.UNKNOWN_SEVERITY_RANK (the sort rank) on purpose.
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
