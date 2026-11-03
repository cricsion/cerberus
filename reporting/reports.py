"""Minimal reporters: JSON + SARIF 2.1.0 + Markdown. No external deps."""
from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from cerberus.schemas import (
    SEVERITY_ORDER,
    STATUS_TITLES,
    group_duplicates,
    reportable_findings,
    safe_float,
    safe_int,
    sort_findings,
)

SEV_TO_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def write_json(findings: list[dict], out: Path) -> None:
    out.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def write_sarif(findings: list[dict], out: Path) -> None:
    rows = [f for f in sort_findings(findings) if not f.get("duplicate_of")]
    rules = []
    seen: dict[str, dict] = {}
    results = []
    for f in rows:
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

        if str(f.get("status", "")).lower() == "fp":
            res_item["suppressions"] = [{
                "kind": "external",
                "status": "accepted",
                "justification": "Marked false positive during cerberus triage; see triage.log",
            }]

        results.append(res_item)
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "cerberus", "rules": rules}}, "results": results}]}
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


# --- shared rendering helpers -------------------------------------------------

# Validator/pipeline tags appended into `evidence` via `_append_note` (" | ").
_EVIDENCE_TAG = re.compile(r"^ *(validator|consensus|alt|refute|fallback): ")
_LANG_BY_EXT = {"py": "python", "js": "javascript", "mjs": "javascript", "cjs": "javascript",
                "ts": "typescript", "go": "go", "rb": "ruby", "java": "java", "php": "php",
                "cs": "csharp", "sh": "bash", "html": "html", "cshtml": "cshtml"}
_PLACEHOLDER_PATCH_SUMMARIES = {"fix", "fix summary", "n/a", "none", "tbd", "todo", ""}
_THREAD_ORDER = ("critical", "high", "medium", "low", "info")


def _evidence_parts(evidence: object) -> tuple[str, dict[str, list[str]]]:
    """Split the pipe-joined evidence stream into (base, {tag: [chunks]})."""
    base: list[str] = []
    tags: dict[str, list[str]] = {}
    for chunk in str(evidence or "").split(" | "):
        m = _EVIDENCE_TAG.match(chunk)
        if m is not None:
            tags.setdefault(m.group(1), []).append(chunk.split(":", 1)[1].strip())
        elif chunk.strip():
            base.append(chunk.strip())
    return " | ".join(base), tags


def _real_diff(f: dict) -> str:
    """A patch is only a diff when it spans lines; single-word LLM junk like
    ``fix`` is not rendered."""
    text = str(f.get("patch") or "").strip()
    return text if "\n" in text else ""


def _summary(f: dict) -> str:
    text = str(f.get("patch_summary") or "").strip()
    return "" if text.lower() in _PLACEHOLDER_PATCH_SUMMARIES else text


def _snippet(f: dict) -> str:
    return str(f.get("snippet") or f.get("hunter_snippet") or "").strip()


def _code_safe(text: str) -> str:
    """Keep a fenced block from being broken by fence markers inside data."""
    return str(text or "").replace("```", "`\u200b``")


def _lang_for(path: str) -> str:
    ext = str(path or "").rsplit(".", 1)[-1].lower()
    return _LANG_BY_EXT.get(ext, ext[:10])


def _poc_counts(findings) -> tuple[int, int]:
    rows = list(findings or [])
    proven = sum(1 for f in rows
                 if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "proven")
    attempted = sum(1 for f in rows
                    if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "attempted")
    return proven, attempted


def _counts(findings) -> dict:
    """Header numbers, computed off the full triage record."""
    rows = list(findings or [])
    primaries = [f for f in rows if not f.get("duplicate_of")]
    fps = [f for f in primaries if f.get("status") == "fp"]
    reportable = reportable_findings(rows)
    by_sev: dict[str, int] = {}
    tier: dict[str, int] = {s: 0 for s, _ in STATUS_TITLES}
    for f in reportable:
        sev = str(f.get("severity", "info")).lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        status = str(f.get("status", "")).lower()
        tier[status if status in tier else "needs-review"] += 1
    proven, attempted = _poc_counts(rows)
    return {
        "total": len(reportable),
        "by_sev": by_sev,
        "tier": tier,
        "fps": len(fps),
        "dupes": len(rows) - len(primaries),
        "proven": proven,
        "attempted": attempted,
    }


def _sev_brief(by_sev: dict[str, int]) -> str:
    parts = [f"{by_sev[s]} {s}" for s in _THREAD_ORDER if by_sev.get(s)]
    return ", ".join(parts) if parts else "0 findings"


def _poc_brief(proven: int, attempted: int) -> str:
    if not proven and not attempted:
        return ""
    return f"Dynamic PoCs: {proven} proven, {attempted} attempted"


def write_markdown(findings: list[dict], out: Path) -> None:
    """Human report: confirmed tier first, then needs-review, by severity and
    confidence. FPs and duplicates are dropped; proven PoC payloads and
    receipts render in full."""
    rows = reportable_findings(findings)
    dupes = group_duplicates(list(findings or []))
    c = _counts(findings)

    lines = ["# Cerberus Report", "",
             f"**Findings:** {c['total']} actionable — {_sev_brief(c['by_sev'])}",
             "- Order: " + " → ".join(s for s, _ in STATUS_TITLES)
             + ", then severity, then confidence"]
    omitted = []
    if c["fps"]:
        omitted.append(f"{c['fps']} false positive{'s' if c['fps'] != 1 else ''}")
    if c["dupes"]:
        omitted.append(f"{c['dupes']} duplicate{'s' if c['dupes'] != 1 else ''}")
    if omitted:
        lines.append(f"- Omitted: {' and '.join(omitted)} — full triage record in `findings.json`")
    poc_brief = _poc_brief(c["proven"], c["attempted"])
    if poc_brief:
        lines.append(f"- {poc_brief}")
    lines.append("")

    for tier, tier_title in STATUS_TITLES:
        tier_rows = ([f for f in rows if str(f.get("status", "")).lower() == "confirmed"]
                     if tier == "confirmed" else
                     [f for f in rows if str(f.get("status", "")).lower() != "confirmed"])
        if not tier_rows:
            continue
        lines += [f"## {tier_title} ({len(tier_rows)})", ""]
        for f in tier_rows:
            lines += [f"### {str(f.get('severity', '?')).upper()} {_md_safe(f.get('title', ''))}",
                      f"- CWE: {f.get('cwe', '')} | confidence: {f.get('confidence', 0)}",
                      f"- Location: `{_md_safe(f.get('path', ''))}:{safe_int(f.get('start_line', 0), 0)}-"
                      f"{safe_int(f.get('end_line', 0), 0)}`"]

            snippet = _snippet(f)
            if snippet:
                lines += [f"- Vulnerable code (`{_md_safe(f.get('path', ''))}`):",
                          f"```{_lang_for(f.get('path', ''))}", _code_safe(snippet), "```"]

            base, tags = _evidence_parts(f.get("evidence"))
            lines.append(f"- Evidence: {_md_safe(base)}")
            if "validator" in tags:
                lines.append(f"  - Validation: {_md_safe(' | '.join(tags['validator']))}")
            if "alt" in tags:
                lines.append(f"  - Alternatives considered: {_md_safe(' | '.join(tags['alt']))}")
            if "consensus" in tags:
                lines.append(f"  - Consensus: {_md_safe(' | '.join(tags['consensus']))}")
            if "refute" in tags:
                lines.append(f"  - Refutation: {_md_safe(' | '.join(tags['refute']))}")

            poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
            poc_status = str(poc.get("status") or "").lower()
            receipt = poc.get("receipt") if isinstance(poc.get("receipt"), dict) else {}
            if poc_status == "blocked":
                blocker = str(poc.get("blocker") or "PoC generation did not produce a repro")
                lines.append(f"- Dynamic PoC: **BLOCKED** ({_md_safe(blocker)})")
            elif poc_status:
                if poc_status == "proven":
                    runs = receipt.get("runs", 3)
                    succ = receipt.get("successes", runs)
                    lines.append(f"- Dynamic PoC: **PROVEN** ({succ}/{runs} exploit runs "
                                 "succeeded, control passed)")
                else:
                    lines.append("- Dynamic PoC: **ATTEMPTED** (in-container execution "
                                 "did not fully confirm)")
                if poc.get("command"):
                    lines.append(f"  - Repro Command: `{_md_safe(poc['command'])}`")
                path_ref = str(poc.get("host_path") or poc.get("script_path") or "").strip()
                if path_ref:
                    lines.append(f"  - Script file: `{_md_safe(path_ref)}`")
                if poc.get("control") and poc.get("command"):
                    lines.append(f"  - Control Command: `{_md_safe(poc['command'])} "
                                 f"{poc.get('control')}`")
                receipt_outputs = receipt.get("outputs") or []
                if receipt_outputs:
                    lines += ["  - Observed output (stamped receipt):",
                              "    ```", _code_safe(str(receipt_outputs[0])[:1200]), "    ```"]
                if receipt.get("timestamp"):
                    stamper = receipt.get("stamped_by", "cerberus")
                    lines.append(f"  - Receipt: Stamped by {stamper} at `{receipt.get('timestamp')}`")
                script = str(poc.get("script") or "").strip()
                if script:
                    fn = poc.get("filename", "test_repro.py")
                    ext = fn.split(".")[-1] if "." in fn else "python"
                    lines += [f"  - Repro Script (`{fn}`):",
                              f"```{ext}", _code_safe(script), "```"]

            summary = _summary(f)
            diff = _real_diff(f)
            if summary or diff:
                lines.append("- Patch:")
                if summary:
                    lines.append(f"  - **Summary**: {_md_safe(summary)}")
                if diff:
                    lines += ["  - **Diff**:", "```diff", _code_safe(diff), "```"]

            collapsed = dupes.get(str(f.get("id", "")), [])
            if collapsed:
                locs = ", ".join(f"`{_md_safe(d.get('path', ''))}:{safe_int(d.get('start_line', 0), 0)}`"
                                 for d in collapsed)
                lines.append(f"  - +{len(collapsed)} duplicate(s): {locs}")
            lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")


_LIST_JS = """
document.addEventListener('DOMContentLoaded', function () {
  var main = document.getElementById('findings');
  var cards = Array.prototype.slice.call(main.querySelectorAll('details.finding'));
  var filter = document.getElementById('sev-filter');
  filter.addEventListener('change', function () {
    var v = filter.value;
    cards.forEach(function (c) { c.style.display = (!v || c.dataset.sev === v) ? '' : 'none'; });
  });
});
"""

_BADGE_CSS = (
    ".badge{padding:2px 8px;border-radius:999px;font-size:.72em;font-weight:700;"
    "text-transform:uppercase;flex:none}"
    ".badge-proven{background:#dcfce7;color:#166534}"
    ".badge-attempted{background:#fef9c3;color:#854d0e}"
    ".badge-blocked{background:#f8d7da;color:#721c24}"
    ".badge-none{background:#e2e3e5;color:#383d41}"
)

_FINDINGS_CSS = (
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
    "margin:0 auto;max-width:1100px;padding:1.5em;color:#1a1f24;background:#f5f6f8}"
    "h1{font-size:1.5em;margin:.2em 0 .4em}"
    ".controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:8px 0 14px;"
    "font-size:.9em;color:#475569}"
    ".controls select{margin-left:4px}"
    ".controls button{cursor:pointer;border:1px solid #cbd5e1;background:#fff;"
    "border-radius:6px;padding:3px 10px}"
    "details.finding{background:#fff;border:1px solid #d9dee3;border-radius:10px;"
    "margin:0 0 10px;box-shadow:0 1px 2px rgba(15,23,42,.05)}"
    "details.finding>summary{padding:10px 14px;cursor:pointer;display:flex;"
    "align-items:center;gap:10px;list-style:none;flex-wrap:wrap}"
    "details.finding>summary::-webkit-details-marker{display:none}"
    "details.finding>summary:hover{background:#f8fafc;border-radius:10px}"
    "details.finding[open]>summary{border-bottom:1px solid #e4e8ec;"
    "background:#f8fafc;border-radius:10px 10px 0 0}"
    ".sev{font-weight:700;font-size:.72em;letter-spacing:.05em;text-transform:uppercase;"
    "padding:3px 9px;border-radius:999px;flex:none}"
    ".sev-critical{background:#7a1024;color:#fff}.sev-high{background:#c2410c;color:#fff}"
    ".sev-medium{background:#b45309;color:#fff}.sev-low{background:#0e7490;color:#fff}"
    ".sev-info{background:#64748b;color:#fff}"
    ".title{font-weight:600;flex:1;min-width:200px}"
    ".title .rtag{font-size:.78em;color:#475569;text-transform:uppercase;"
    "letter-spacing:.05em;padding:2px 7px;border-radius:6px;background:#e2e8f0;"
    "font-weight:600;white-space:nowrap}"
    ".fmeta{color:#64748b;font-size:.82em;font-family:ui-monospace,monospace}"
    ".body{padding:14px 18px 18px}"
    ".body h3{font-size:.78em;text-transform:uppercase;letter-spacing:.08em;"
    "color:#64748b;margin:16px 0 6px}"
    ".body h3:first-child{margin-top:0}"
    "pre{background:#0f172a;color:#e2e8f0;padding:10px 12px;border-radius:8px;"
    "overflow-x:auto;max-height:420px;font-size:.85em;line-height:1.5;"
    "font-family:ui-monospace,monospace}"
    "details.finding details{margin:6px 0}"
    "details.finding details>summary{cursor:pointer;color:#2563eb;"
    "font-size:.9em;padding:2px 0}"
    ".meta-line{color:#475569;font-size:.88em;margin:3px 0}"
    ".kv{font-family:ui-monospace,monospace;font-size:.88em;margin:3px 0}"
    "code{background:#eef1f5;padding:1px 5px;border-radius:4px;"
    "font-family:ui-monospace,monospace;font-size:.92em}"
    ".dupe-line{color:#64748b;font-size:.85em;margin-top:12px}"
)


def write_html(findings: list[dict], out: Path) -> None:
    """Self-contained HTML report as an expandable findings list.

    Same ``reportable_findings`` set and order as the Markdown report; each
    finding is a collapsible card — severity, title, status and PoC badge on
    the summary row; vulnerable code, evidence, the full PoC (script, stamped
    output, commands) and the patch inside nested collapsibles.
    """
    rows = reportable_findings(findings)
    dupes: dict[str, list[dict]] = group_duplicates(list(findings or []))

    _SEV_CLASS = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
                  "low": "sev-low", "info": "sev-info"}
    _SEV_RANK = {s: i for i, s in enumerate(_THREAD_ORDER)}

    cards = []
    for f in rows:
        sev = str(f.get("severity", ""))
        sev_esc = html.escape(sev, quote=True)
        title = html.escape(str(f.get("title", "")), quote=True)
        n_dupe = len(dupes.get(str(f.get("id", "")), []))
        conf = safe_float(f.get("confidence", 0) or 0)
        cwe = html.escape(str(f.get("cwe", "")), quote=True)
        loc = html.escape(f"{f.get('path', '')}:{safe_int(f.get('start_line', 0), 0)}"
                          f"-{safe_int(f.get('end_line', 0), 0)}", quote=True)
        status = html.escape(str(f.get("status", "")), quote=True)
        if n_dupe:
            title = (f"{title} <span class='rtag'>+{n_dupe} "
                     f"duplicate{'s' if n_dupe != 1 else ''}</span>")

        # -- PoC block ----------------------------------------------------------
        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        poc_status = str(poc.get("status") or "").lower()
        receipt = poc.get("receipt") if isinstance(poc.get("receipt"), dict) else {}
        if poc_status == "proven":
            poc_badge = '<span class="badge badge-proven">Proven</span>'
        elif poc_status == "attempted":
            poc_badge = '<span class="badge badge-attempted">Attempted</span>'
        elif poc_status == "blocked":
            poc_badge = '<span class="badge badge-blocked">Blocked</span>'
        else:
            poc_badge = '<span class="badge badge-none">-</span>'

        poc_parts = []
        poc_head = ""
        if poc_status == "blocked":
            blocker = html.escape(str(poc.get("blocker")
                                      or "PoC generation did not produce a repro"), quote=True)
            poc_head = f"<p class=\"meta-line\"><strong>Dynamic PoC blocked.</strong> {blocker}</p>"
        elif poc_status:
            runs = receipt.get("runs", 3)
            succ = receipt.get("successes", runs)
            head = (f"Dynamic PoC — {succ}/{runs} exploit runs succeeded, control passed"
                    if poc_status == "proven" else
                    "Dynamic PoC — attempted; in-container execution did not fully confirm")
            poc_head = f"<p class=\"meta-line\"><strong>{head}</strong></p>"
            if poc.get("command"):
                poc_parts.append(
                    f"<div class=\"kv\"><strong>Repro:</strong> "
                    f"<code>{html.escape(str(poc['command']), quote=True)}</code></div>")
            path_ref = str(poc.get("host_path") or poc.get("script_path") or "").strip()
            if path_ref:
                poc_parts.append(
                    f"<div class=\"kv\"><strong>Script file:</strong> "
                    f"<code>{html.escape(path_ref, quote=True)}</code></div>")
            if poc.get("control") and poc.get("command"):
                poc_parts.append(
                    f"<div class=\"kv\"><strong>Control:</strong> "
                    f"<code>{html.escape(str(poc['command']) + ' ' + str(poc.get('control')), quote=True)}</code></div>")
            receipt_outputs = receipt.get("outputs") or []
            if receipt_outputs:
                out_escaped = html.escape(str(receipt_outputs[0])[:1200], quote=True)
                poc_parts.append("<details><summary>Observed output (stamped receipt)"
                                 f"</summary><pre class=\"diff\">{out_escaped}</pre></details>")
            script = str(poc.get("script") or "").strip()
            if script:
                script_escaped = html.escape(script, quote=True)
                fn = html.escape(str(poc.get("filename") or "test_repro.py"), quote=True)
                poc_parts.append(f"<details><summary>Full script — {fn}"
                                 f"</summary><pre>{script_escaped}</pre></details>")
            if receipt.get("timestamp"):
                stamper = html.escape(str(receipt.get("stamped_by") or "cerberus"), quote=True)
                tstamp = html.escape(str(receipt.get("timestamp")), quote=True)
                poc_parts.append(f"<p class=\"meta-line\">Receipt: stamped by {stamper} "
                                 f"at {tstamp}</p>")
        poc_section = poc_head + "".join(poc_parts) if (poc_head or poc_parts) else \
            "<p class=\"meta-line\">No dynamic proof attempted for this finding.</p>"

        # -- Evidence block -----------------------------------------------------
        base, tags = _evidence_parts(f.get("evidence"))
        ev_parts = []
        if base:
            ev_parts.append(f"<p>{html.escape(base, quote=True)}</p>")
        for tag_key, tag_label in (("validator", "Validation"), ("alt", "Alternatives considered"),
                                   ("consensus", "Consensus"), ("refute", "Refutation")):
            tag_chunks = tags.get(tag_key)
            if tag_chunks:
                ev_parts.append(f"<p class=\"meta-line\"><strong>{tag_label}:</strong> "
                                f"{html.escape(' | '.join(tag_chunks), quote=True)}</p>")
        evidence_section = "".join(ev_parts) or "<p class=\"meta-line\">—</p>"

        # -- Code snippet -------------------------------------------------------
        snippet = _snippet(f)
        snippet_section = (f"<pre>{html.escape(snippet, quote=True)}</pre>" if snippet
                           else "<p class=\"meta-line\">No vulnerable-code snippet recorded.</p>")

        # -- Patch block --------------------------------------------------------
        summary = _summary(f)
        patch_val = _real_diff(f)
        patch_parts = []
        if summary:
            patch_parts.append(f"<p>{html.escape(summary, quote=True)}</p>")
        if patch_val:
            patch_escaped = html.escape(patch_val, quote=True)
            patch_parts.append("<details><summary>Diff</summary>"
                               f"<pre class=\"diff\">{patch_escaped}</pre></details>")
        patch_section = "".join(patch_parts) if patch_parts else \
            "<p class=\"meta-line\">No patch proposed.</p>"

        dupe_line = ""
        if n_dupe:
            locs = ", ".join(
                "<code>" + html.escape(str(d.get("path", "")), quote=True)
                + ":" + str(safe_int(d.get("start_line", 0), 0)) + "</code>"
                for d in dupes[str(f.get("id", ""))])
            dupe_line = f"<p class=\"dupe-line\">Duplicates collapsed here: {locs}</p>"

        cards.append(
            f"<details class=\"finding\" data-sev=\"{sev_esc}\" "
            f"data-sevrank=\"{_SEV_RANK.get(sev, 9)}\" data-conf=\"{conf:.2f}\" "
            f"data-status=\"{status}\">\n"
            f"<summary><span class=\"sev {_SEV_CLASS.get(sev, 'sev-info')}\">{sev_esc}</span>"
            f"<span class=\"title\">{title}</span>"
            f"<span class=\"fmeta\">{cwe} &middot; {loc} &middot; conf {conf:.2f} &middot; {status}</span>"
            f"{poc_badge}</summary>\n"
            "<div class=\"body\">"
            "<h3>Vulnerable code</h3>" + snippet_section +
            "<h3>Evidence</h3>" + evidence_section +
            "<h3>Dynamic PoC</h3>" + poc_badge + poc_section +
            "<h3>Proposed patch</h3>" + patch_section +
            dupe_line +
            "</div>\n</details>"
        )
    body = "\n".join(cards)

    filter_opts = "".join(f"<option value=\"{s}\">{s}</option>" for s in _THREAD_ORDER)
    doc = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<title>Cerberus Report</title>\n"
        f"<style>{_FINDINGS_CSS}{_BADGE_CSS}</style>\n</head>\n<body>\n"
        "<h1>Cerberus Report</h1>\n"
        "<div class=\"controls\">"
        "<label>Filter severity<select id=\"sev-filter\">"
        f"<option value=\"\">all</option>{filter_opts}</select></label>"
        "</div>\n"
        "<main id=\"findings\">\n"
        f"{body}\n"
        "</main>\n"
        f"<script>{_LIST_JS}</script>\n"
        "</body>\n</html>\n"
    )
    out.write_text(doc, encoding="utf-8")


def _md_safe(value: object) -> str:
    """Neutralize markdown structure in an untrusted report field."""
    parts = str(value if value is not None else "").replace("`", "'").splitlines()
    return " ".join(p.lstrip("#>|").lstrip() for p in parts)


def write_junit(findings: list[dict], out: Path) -> None:
    rows = reportable_findings(findings)
    failures = 0
    suite = ET.Element("testsuite", {
        "name": "cerberus",
        "tests": str(len(rows)),
        "errors": "0",
        "skipped": "0",
    })
    for f in rows:
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
