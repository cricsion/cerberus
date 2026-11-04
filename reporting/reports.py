"""Report writers: JSON, SARIF 2.1.0, Markdown, self-contained HTML, and JUnit XML. No external deps."""
from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
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

_DEFAULT_CVSS_BY_SEV = {
    "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high": (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low": (3.1, "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
    "info": (0.0, "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}


def _cvss_score_and_vector(f: dict) -> tuple[float, str]:
    sev = str(f.get("severity") or "medium").lower()
    default_score, default_vec = _DEFAULT_CVSS_BY_SEV.get(
        sev, (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    )
    raw_score = f.get("cvss")
    score = safe_float(raw_score, default_score) if raw_score is not None else default_score
    vec = str(f.get("cvss_vector") or f.get("vector_string") or default_vec)
    return score, vec


def _cwe_num(cwe_val: object) -> str:
    m = re.search(r"(\d+)", str(cwe_val or ""))
    return m.group(1) if m else ""


def _parse_step_loc(
    step: str, default_path: str, default_line: int
) -> tuple[str, int, str]:
    """Parse 'path/file.ext:123 - message' or 'path/file.ext:123' into (path, line, msg)."""
    m = re.match(r"^([^:\s]+):(\d+)(?:-(\d+))?(?:\s*[-:]?\s*(.*))?$", step)
    if m:
        file_path = m.group(1)
        line_no = int(m.group(2))
        msg = (m.group(4) or step).strip()
        return file_path, line_no, msg
    return default_path, default_line, step


_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?", re.MULTILINE
)


def _parse_diff_to_replacements(diff_text: str) -> list[dict]:
    """Parse a unified diff into SARIF replacement entries.

    ``deletedRegion`` covers exactly the ``-`` (deleted) lines; context lines
    are NOT deleted (SARIF 2.1.0 §3.57.3). Consecutive ``-`` lines form one
    deletion run; queued ``+`` lines attach to the run they follow, so the
    common ``-a / +b`` hunk is one deletion-plus-insertion replacement. A
    segment with only ``+`` lines becomes a zero-length region — an insertion
    point at the line it precedes, encoded per §3.30.2 as
    ``{"startLine": N, "startColumn": 1, "endColumn": 1}``. All regions use
    pre-change (original file) coordinates and are disjoint.

    Diffs without any ``@@`` hunk header cannot be placed, so NO replacement
    is emitted; the raw patch text is still stored separately in the result's
    ``properties.patch``.
    """
    hunks = list(_HUNK_RE.finditer(diff_text))
    replacements: list[dict] = []
    for i, match in enumerate(hunks):
        old_start = int(match.group(1))
        old_count = int(match.group(2)) if match.group(2) is not None else 1
        body_end = hunks[i + 1].start() if i + 1 < len(hunks) else len(diff_text)
        body = diff_text[match.end():body_end]

        old_next = max(1, old_start if old_count > 0 else old_start + 1)

        del_start: int | None = None
        del_end = 0
        pending: list[str] = []

        for raw_line in body.splitlines():
            line = raw_line.rstrip("\r")
            if line.startswith("\\"):
                continue
            if line.startswith(("--- ", "+++ ")):
                continue
            if line.startswith("+"):
                pending.append(line[1:])
                continue
            if pending:
                if del_start is None:
                    replacements.append({
                        "deletedRegion": {
                            "startLine": old_next, "startColumn": 1, "endColumn": 1,
                        },
                        "insertedContent": {"text": "\n".join(pending)},
                    })
                else:
                    replacements.append({
                        "deletedRegion": {"startLine": del_start, "endLine": del_end},
                        "insertedContent": {"text": "\n".join(pending)},
                    })
                    del_start = None
                pending = []
            if line.startswith("-"):
                if del_start is None:
                    del_start = old_next
                del_end = old_next
                old_next += 1
            else:
                old_next += 1

        if del_start is not None:
            repl: dict = {"deletedRegion": {"startLine": del_start, "endLine": del_end}}
            if pending:
                repl["insertedContent"] = {"text": "\n".join(pending)}
            replacements.append(repl)
        elif pending:
            replacements.append({
                "deletedRegion": {
                    "startLine": old_next, "startColumn": 1, "endColumn": 1,
                },
                "insertedContent": {"text": "\n".join(pending)},
            })
    return replacements


def write_json(findings: list[dict], out: Path) -> None:
    enriched = []
    for idx, f in enumerate(findings, 1):
        item = dict(f)
        if not item.get("id"):
            item["id"] = f"cb-{idx:03d}"
        score, vec = _cvss_score_and_vector(item)
        if item.get("cvss") is None:
            item["cvss"] = score
        if not item.get("cvss_vector"):
            item["cvss_vector"] = vec
        enriched.append(item)
    out.write_text(json.dumps(enriched, indent=2), encoding="utf-8")


def write_sarif(findings: list[dict], out: Path) -> None:
    rows = [f for f in sort_findings(findings) if not f.get("duplicate_of")]
    rules = []
    seen: dict[str, dict] = {}
    results = []
    for f in rows:
        rule_id = f.get("cwe") or f.get("title", "finding")
        score, cvss_vec = _cvss_score_and_vector(f)
        cwe_num = _cwe_num(f.get("cwe") or "")
        if rule_id not in seen:
            rule_entry: dict = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.get("title", rule_id)},
                "properties": {
                    "security-severity": f"{score:.1f}",
                },
            }
            if cwe_num:
                help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                rule_entry["helpUri"] = help_uri
                rule_entry["help"] = {
                    "text": f"More information: {help_uri}",
                    "markdown": f"[MITRE CWE-{cwe_num}]({help_uri})",
                }
            seen[rule_id] = rule_entry
            rules.append(seen[rule_id])

        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        poc_status = _poc_status(f)
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

        props: dict = {
            "security-severity": f"{score:.1f}",
            "cvssVector": cvss_vec,
        }
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
        res_item["properties"] = props

        taint = f.get("taint") if isinstance(f.get("taint"), dict) else {}
        t_source = str(taint.get("source") or "").strip()
        t_sink = str(taint.get("sink") or "").strip()
        t_path = taint.get("path") or []
        if t_source or t_sink or t_path:
            thread_locs = []
            f_path = str(f.get("path") or "")
            f_start = max(1, safe_int(f.get("start_line", 1), 1))
            f_end = max(1, safe_int(f.get("end_line", 1), 1))

            def _make_tfl(u: str, line_no: int, msg: str) -> dict:
                return {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": u},
                            "region": {"startLine": max(1, line_no)},
                        },
                        "message": {"text": msg},
                    }
                }

            if t_source:
                thread_locs.append(_make_tfl(f_path, f_start, f"Source: {t_source}"))
            for step in t_path:
                step_str = str(step).strip()
                if step_str:
                    sp, sl, sm = _parse_step_loc(step_str, f_path, f_start)
                    thread_locs.append(_make_tfl(sp, sl, sm or step_str))
            if t_sink:
                thread_locs.append(_make_tfl(f_path, f_end, f"Sink: {t_sink}"))

            if thread_locs:
                res_item["codeFlows"] = [
                    {
                        "message": {"text": "Taint tracking data-flow path"},
                        "threadFlows": [{"locations": thread_locs}],
                    }
                ]

        # Native SARIF fixes
        patch_val = _real_diff(f)
        if patch_val:
            replacements = _parse_diff_to_replacements(patch_val)
            if replacements:
                res_item["fixes"] = [
                    {
                        "description": {"text": _summary(f) or "Apply proposed patch"},
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": str(f.get("path") or "")},
                                "replacements": replacements,
                            }
                        ],
                    }
                ]

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
_EVIDENCE_TAG = re.compile(r"^ *(validator|consensus|alt|refute|fallback|triage): ")
_INTERNAL_NOISE_RE = re.compile(
    r"(omitted from batch reply|triage:\s*|consensus:\s*|validator round failed)",
    re.IGNORECASE,
)
_LANG_BY_EXT = {"py": "python", "js": "javascript", "mjs": "javascript", "cjs": "javascript",
                "ts": "typescript", "go": "go", "rb": "ruby", "java": "java", "php": "php",
                "cs": "csharp", "sh": "bash", "html": "html", "cshtml": "cshtml"}
_PLACEHOLDER_PATCH_SUMMARIES = {"fix", "fix summary", "n/a", "none", "tbd", "todo", ""}
_THREAD_ORDER = ("critical", "high", "medium", "low", "info")


def _evidence_parts(evidence: object) -> tuple[str, dict[str, list[str]], list[str]]:
    """Split the pipe-joined evidence stream into (base, {tag: [chunks]}, audit_trail)."""
    base: list[str] = []
    tags: dict[str, list[str]] = {}
    audit: list[str] = []
    for chunk in str(evidence or "").split(" | "):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = _EVIDENCE_TAG.match(chunk)
        if m is not None:
            tag_name = m.group(1)
            val = chunk.split(":", 1)[1].strip()
            if tag_name in ("consensus", "validator", "fallback", "triage"):
                audit.append(chunk)
            tags.setdefault(tag_name, []).append(val)
        elif _INTERNAL_NOISE_RE.search(chunk):
            audit.append(chunk)
        else:
            base.append(chunk)
    return " | ".join(base), tags, audit


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
    ext = str(path or "").rsplit(".", 1)[-1].lower().split()
    ext = ext[0] if ext else ""
    return _LANG_BY_EXT.get(ext, ext[:10])


_POC_STATUSES = frozenset({"proven", "attempted", "blocked", "planned"})


def _poc_status(f: dict) -> str:
    """Whitelisted PoC status from a finding's poc dict.

    ``Finding.poc`` is a ``PocItem | dict`` union, so hunter-supplied dicts
    bypass the ``PocItem.status`` Literal validation upstream; collapsing
    anything outside ``_POC_STATUSES`` to "" keeps both the rendered badge
    and the HTML ``data-poc`` attribute injection-free.
    """
    poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
    status = str(poc.get("status") or "").strip().lower()
    return status if status in _POC_STATUSES else ""


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


def _format_diff_html(diff_text: str) -> str:
    """Highlight unified diff lines (+ green, - red, @@ cyan) with HTML escaping."""
    if not diff_text:
        return ""
    formatted_lines = []
    for line in diff_text.splitlines():
        escaped = html.escape(line, quote=True)
        if line.startswith("+++ ") or line.startswith("--- "):
            formatted_lines.append(f'<span class="diff-file">{escaped}</span>')
        elif line.startswith("+"):
            formatted_lines.append(f'<span class="diff-add">{escaped}</span>')
        elif line.startswith("-"):
            formatted_lines.append(f'<span class="diff-del">{escaped}</span>')
        elif line.startswith("@@"):
            formatted_lines.append(f'<span class="diff-hunk">{escaped}</span>')
        else:
            formatted_lines.append(escaped)
    return "\n".join(formatted_lines)


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

    # Executive Summary Matrix
    matrix_rows = [
        "| Severity | Count | Proven PoCs | Patched |",
        "| :--- | :---: | :---: | :---: |",
    ]
    tot_count = 0
    tot_proven = 0
    tot_patched = 0
    for sev in _THREAD_ORDER:
        sev_findings = [f for f in rows if str(f.get("severity", "")).lower() == sev]
        count = len(sev_findings)
        if count == 0 and sev not in ("critical", "high", "medium"):
            continue
        tot_count += count
        proven_cnt = sum(1 for f in sev_findings
                         if isinstance(f.get("poc"), dict) and f["poc"].get("status") == "proven")
        tot_proven += proven_cnt
        patch_cnt = sum(1 for f in sev_findings if _real_diff(f) or _summary(f))
        tot_patched += patch_cnt
        pct = f" ({round(proven_cnt / count * 100)}%)" if count > 0 else ""
        matrix_rows.append(f"| {sev.upper()} | {count} | {proven_cnt} / {count}{pct} | {patch_cnt} |")
    tot_pct = f" ({round(tot_proven / tot_count * 100)}%)" if tot_count > 0 else ""
    matrix_rows.append(f"| **TOTAL** | **{tot_count}** | **{tot_proven} / {tot_count}{tot_pct}** | **{tot_patched}** |")
    lines += matrix_rows
    lines.append("")

    # Table of Contents
    lines += ["## Table of Contents", ""]
    f_num = 0
    for tier, tier_title in STATUS_TITLES:
        tier_rows = ([f for f in rows if str(f.get("status", "")).lower() == "confirmed"]
                     if tier == "confirmed" else
                     [f for f in rows if str(f.get("status", "")).lower() != "confirmed"])
        if not tier_rows:
            continue
        tier_anchor = tier_title.lower().replace(" ", "-")
        lines.append(f"- [{tier_title} ({len(tier_rows)})](#{tier_anchor})")
        for f in tier_rows:
            f_num += 1
            f_title = _md_safe(f.get("title", ""))
            f_sev = str(f.get("severity", "?")).upper()
            f_loc = f"{_md_safe(f.get('path', ''))}:{safe_int(f.get('start_line', 0), 0)}"
            link_text = _md_link_text(f"{f_sev}: {f_title} (`{f_loc}`)")
            lines.append(f"  - [{link_text}](#finding-{f_num})")
    lines.append("")

    f_num = 0
    for tier, tier_title in STATUS_TITLES:
        tier_rows = ([f for f in rows if str(f.get("status", "")).lower() == "confirmed"]
                     if tier == "confirmed" else
                     [f for f in rows if str(f.get("status", "")).lower() != "confirmed"])
        if not tier_rows:
            continue
        tier_anchor = tier_title.lower().replace(" ", "-")
        lines += [
            f"<a id=\"{tier_anchor}\"></a>",
            f"## {tier_title} ({len(tier_rows)})",
            "",
        ]
        for f in tier_rows:
            f_num += 1
            score, cvss_vec = _cvss_score_and_vector(f)
            lines += [
                f"<a id=\"finding-{f_num}\"></a>",
                f"### {str(f.get('severity', '?')).upper()} {_md_safe(f.get('title', ''))}",
                f"- CVSS: **{score:.1f}** (`{_md_safe(cvss_vec)}`) | CWE: {_md_safe(f.get('cwe', ''))} | confidence: {f.get('confidence', 0)}",
                f"- Location: `{_md_safe(f.get('path', ''))}:{safe_int(f.get('start_line', 0), 0)}-"
                f"{safe_int(f.get('end_line', 0), 0)}`"
            ]

            snippet = _snippet(f)
            if snippet:
                lines += [f"- Vulnerable code (`{_md_safe(f.get('path', ''))}`):",
                          f"```{_lang_for(f.get('path', ''))}", _code_safe(snippet), "```"]

            # Taint data-flow
            taint = f.get("taint") if isinstance(f.get("taint"), dict) else {}
            t_source = str(taint.get("source") or "").strip()
            t_sink = str(taint.get("sink") or "").strip()
            t_path = taint.get("path") or []
            if t_source or t_sink or t_path:
                lines.append("- Taint Flow:")
                if t_source:
                    lines.append(f"  - **Source**: `{_md_safe(t_source)}`")
                if t_path:
                    lines.append("  - **Path**:")
                    for p_step in t_path:
                        lines.append(f"    - `{_md_safe(p_step)}`")
                if t_sink:
                    lines.append(f"  - **Sink**: `{_md_safe(t_sink)}`")

            base, tags, audit = _evidence_parts(f.get("evidence"))
            if base:
                lines.append(f"- Evidence: {_md_safe(base)}")
            if "validator" in tags:
                lines.append(f"  - Validation: {_md_safe(' | '.join(tags['validator']))}")
            if "alt" in tags:
                lines.append(f"  - Alternatives considered: {_md_safe(' | '.join(tags['alt']))}")
            if "consensus" in tags:
                lines.append(f"  - Consensus: {_md_safe(' | '.join(tags['consensus']))}")
            if "refute" in tags:
                lines.append(f"  - Refutation: {_md_safe(' | '.join(tags['refute']))}")
            if audit:
                lines.append(f"  - Audit Trail: {_md_safe(' | '.join(audit))}")

            poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
            poc_status = _poc_status(f)
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
                                 f"{_md_safe(poc.get('control'))}`")
                receipt_outputs = receipt.get("outputs") or []
                if receipt_outputs:
                    lines += ["  - Observed output (stamped receipt):",
                              "    ```", _code_safe(str(receipt_outputs[0])[:1200]), "    ```"]
                if receipt.get("timestamp"):
                    stamper = _md_safe(receipt.get("stamped_by", "cerberus"))
                    lines.append(f"  - Receipt: Stamped by {stamper} "
                                 f"at `{_md_safe(receipt.get('timestamp'))}`")
                script = str(poc.get("script") or "").strip()
                if script:
                    fn = str(poc.get("filename") or "test_repro.py")
                    lines += [f"  - Repro Script (`{_md_safe(fn)}`):",
                              f"```{_lang_for(fn)}", _code_safe(script), "```"]

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
  var sevFilter = document.getElementById('sev-filter');
  var searchBox = document.getElementById('search-box');
  var pocFilter = document.getElementById('poc-filter');

  function update() {
    var sev = (sevFilter ? sevFilter.value : '').toLowerCase();
    var q = (searchBox ? searchBox.value : '').toLowerCase().trim();
    var pocOnly = pocFilter ? pocFilter.checked : false;

    cards.forEach(function (c) {
      var cardSev = (c.dataset.sev || '').toLowerCase();
      var cardPoc = (c.dataset.poc || '').toLowerCase();
      var cardText = (c.textContent || '').toLowerCase();

      var matchSev = !sev || cardSev === sev;
      var matchPoc = !pocOnly || cardPoc === 'proven';
      var matchQ = !q || cardText.indexOf(q) !== -1;

      c.style.display = (matchSev && matchPoc && matchQ) ? '' : 'none';
    });
  }

  if (sevFilter) sevFilter.addEventListener('change', update);
  if (searchBox) searchBox.addEventListener('input', update);
  if (pocFilter) pocFilter.addEventListener('change', update);
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
    ".kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:14px 0 18px}"
    ".kpi-card{background:#fff;border:1px solid #d9dee3;border-radius:10px;padding:12px 14px;box-shadow:0 1px 2px rgba(15,23,42,.05);text-align:center}"
    ".kpi-val{font-size:1.6em;font-weight:700;color:#0f172a;line-height:1.2}"
    ".kpi-lbl{font-size:.78em;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}"
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
    ".diff-add{color:#4ade80;background:rgba(34,197,94,.12);display:block;margin:0 -12px;padding:0 12px}"
    ".diff-del{color:#f87171;background:rgba(239,68,68,.12);display:block;margin:0 -12px;padding:0 12px}"
    ".diff-hunk{color:#38bdf8;font-weight:600;display:block;margin:4px -12px;padding:2px 12px;background:rgba(56,189,248,.1)}"
    ".diff-file{color:#94a3b8;font-weight:600;display:block}"
    ".taint-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;margin:8px 0}"
    ".taint-steps{margin:6px 0;padding-left:22px;font-size:.88em}"
    ".taint-steps li{margin:3px 0}"
    ".audit-trail{margin-top:8px;font-size:.85em}"
    ".audit-trail summary{color:#64748b;cursor:pointer}"
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
    c = _counts(findings)

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
        score, _ = _cvss_score_and_vector(f)
        if n_dupe:
            title = (f"{title} <span class='rtag'>+{n_dupe} "
                     f"duplicate{'s' if n_dupe != 1 else ''}</span>")

        # -- PoC block ----------------------------------------------------------
        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        poc_status = _poc_status(f)
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

        # -- Taint Data-Flow block ----------------------------------------------
        taint = f.get("taint") if isinstance(f.get("taint"), dict) else {}
        t_source = str(taint.get("source") or "").strip()
        t_sink = str(taint.get("sink") or "").strip()
        t_path = taint.get("path") or []
        taint_section = ""
        if t_source or t_sink or t_path:
            t_parts = ["<div class=\"taint-box\">"]
            if t_source:
                t_parts.append(f"<div class=\"kv\"><strong>Source:</strong> <code>{html.escape(t_source, quote=True)}</code></div>")
            if t_path:
                t_parts.append("<ol class=\"taint-steps\">")
                for step in t_path:
                    t_parts.append(f"<li><code>{html.escape(str(step), quote=True)}</code></li>")
                t_parts.append("</ol>")
            if t_sink:
                t_parts.append(f"<div class=\"kv\"><strong>Sink:</strong> <code>{html.escape(t_sink, quote=True)}</code></div>")
            t_parts.append("</div>")
            taint_section = "<h3>Taint Data-Flow</h3>" + "".join(t_parts)

        # -- Evidence block -----------------------------------------------------
        base, tags, audit = _evidence_parts(f.get("evidence"))
        ev_parts = []
        if base:
            ev_parts.append(f"<p>{html.escape(base, quote=True)}</p>")
        for tag_key, tag_label in (("validator", "Validation"), ("alt", "Alternatives considered"),
                                   ("consensus", "Consensus"), ("refute", "Refutation")):
            tag_chunks = tags.get(tag_key)
            if tag_chunks:
                ev_parts.append(f"<p class=\"meta-line\"><strong>{tag_label}:</strong> "
                                f"{html.escape(' | '.join(tag_chunks), quote=True)}</p>")
        if audit:
            audit_escaped = "<br>".join(html.escape(a, quote=True) for a in audit)
            ev_parts.append(f"<details class=\"audit-trail\"><summary>Audit Trail / Engine Notes ({len(audit)})</summary>"
                            f"<div class=\"kv\">{audit_escaped}</div></details>")
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
            patch_formatted = _format_diff_html(patch_val)
            patch_parts.append("<details><summary>Diff</summary>"
                               f"<pre class=\"diff\">{patch_formatted}</pre></details>")
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
            f"data-status=\"{status}\" data-poc=\"{poc_status}\" data-cvss=\"{score:.1f}\">\n"
            f"<summary><span class=\"sev {_SEV_CLASS.get(sev, 'sev-info')}\">{sev_esc}</span>"
            f"<span class=\"title\">{title}</span>"
            f"<span class=\"fmeta\">{cwe} &middot; {loc} &middot; CVSS {score:.1f} &middot; conf {conf:.2f} &middot; {status}</span>"
            f"{poc_badge}</summary>\n"
            "<div class=\"body\">"
            "<h3>Vulnerable code</h3>" + snippet_section +
            taint_section +
            "<h3>Evidence</h3>" + evidence_section +
            "<h3>Dynamic PoC</h3>" + poc_badge + poc_section +
            "<h3>Proposed patch</h3>" + patch_section +
            dupe_line +
            "</div>\n</details>"
        )
    body = "\n".join(cards)

    # KPI Header Cards
    total_act = c["total"]
    crit_cnt = c["by_sev"].get("critical", 0)
    high_cnt = c["by_sev"].get("high", 0)
    proven_cnt = _poc_counts(rows)[0]
    poc_pct = f"{round(proven_cnt / total_act * 100)}%" if total_act > 0 else "0%"
    patched_cnt = sum(1 for f in rows if _real_diff(f) or _summary(f))

    kpi_grid = (
        "<div class=\"kpi-grid\">\n"
        f"  <div class=\"kpi-card\"><div class=\"kpi-val\">{total_act}</div><div class=\"kpi-lbl\">Actionable Findings</div></div>\n"
        f"  <div class=\"kpi-card\"><div class=\"kpi-val sev-critical\" style=\"display:inline-block;padding:2px 8px;border-radius:6px\">{crit_cnt}</div><div class=\"kpi-lbl\">Critical</div></div>\n"
        f"  <div class=\"kpi-card\"><div class=\"kpi-val sev-high\" style=\"display:inline-block;padding:2px 8px;border-radius:6px\">{high_cnt}</div><div class=\"kpi-lbl\">High</div></div>\n"
        f"  <div class=\"kpi-card\"><div class=\"kpi-val\">{proven_cnt} <span style=\"font-size:.6em;color:#16a34a\">({poc_pct})</span></div><div class=\"kpi-lbl\">Proven PoCs</div></div>\n"
        f"  <div class=\"kpi-card\"><div class=\"kpi-val\">{patched_cnt}</div><div class=\"kpi-lbl\">Patched</div></div>\n"
        "</div>\n"
    )

    filter_opts = "".join(f"<option value=\"{s}\">{s}</option>" for s in _THREAD_ORDER)
    doc = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<title>Cerberus Report</title>\n"
        f"<style>{_FINDINGS_CSS}{_BADGE_CSS}</style>\n</head>\n<body>\n"
        "<h1>Cerberus Report</h1>\n"
        f"{kpi_grid}"
        "<div class=\"controls\">"
        "<label>Filter severity<select id=\"sev-filter\">"
        f"<option value=\"\">all</option>{filter_opts}</select></label>"
        "<input type=\"search\" id=\"search-box\" placeholder=\"Search path, CWE, title...\" style=\"padding:4px 8px;border:1px solid #cbd5e1;border-radius:6px;font-size:.9em;flex:1;max-width:320px;\">"
        "<label style=\"display:flex;align-items:center;gap:4px;cursor:pointer;\">"
        "<input type=\"checkbox\" id=\"poc-filter\"> Proven PoCs only</label>"
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


def _md_link_text(value: object) -> str:
    """Escape a string for safe use inside a markdown ``[link text]`` slot.

    ``_md_safe`` alone does not touch brackets, so a title like
    ``evil](https://attacker.example) [x`` would render as a live external
    link inside the TOC; escaping brackets (and backslashes) keeps the text
    inert.
    """
    return (str(value if value is not None else "")
            .replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]"))


def write_junit(findings: list[dict], out: Path) -> None:
    rows = reportable_findings(findings)
    failures = 0
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    suite = ET.Element("testsuite", {
        "name": "cerberus",
        "tests": str(len(rows)),
        "errors": "0",
        "skipped": "0",
        "timestamp": now_iso,
        "time": "0.000",
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
        props = ET.SubElement(case, "properties")
        poc_status = _poc_status(f) or "none"
        score, _ = _cvss_score_and_vector(f)
        conf = safe_float(f.get("confidence", 0) or 0)
        has_patch = "true" if (_real_diff(f) or _summary(f)) else "false"
        ET.SubElement(props, "property", {"name": "poc_status", "value": poc_status})
        ET.SubElement(props, "property", {"name": "cvss", "value": f"{score:.1f}"})
        ET.SubElement(props, "property", {"name": "confidence", "value": f"{conf:.2f}"})
        ET.SubElement(props, "property", {"name": "has_patch", "value": has_patch})

        # failure-counting gate deliberately treats junk severity as >=medium;
        # this is NOT schemas.UNKNOWN_SEVERITY_RANK (the sort rank) on purpose.
        is_failure = SEVERITY_ORDER.get(sev, 2) <= SEVERITY_ORDER["high"] and str(f.get("status", "")) != "fp"
        if is_failure:
            failures += 1
            msg = f"{title} ({cwe}) {sev} conf={conf} {loc}"
            fail = ET.SubElement(case, "failure", {"message": msg})
            base, _, _ = _evidence_parts(f.get("evidence"))
            snippet = str(f.get("snippet", "") or "")
            fail.text = f"{base}\n{snippet}" if (base or snippet) else msg
    suite.set("failures", str(failures))
    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    out.write_bytes(b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suite, encoding="utf-8"))
