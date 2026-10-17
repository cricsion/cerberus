"""--vulns evidence files: JSON/CSV/markdown/id-list parsers, normalized rows."""
from __future__ import annotations

import logging as _logging
import re as _re
from pathlib import Path

from .render import _mask_fences

_logger = _logging.getLogger(__name__)


# --vulns input: past vulnerabilities as threat evidence; formats are
# auto-detected. Caps keep a hostile or accidental 10MB dump out of the prompt.
VULNS_ROW_CAP = 200
VULNS_FIELD_CAP = 600
VULNS_BYTES_CAP = 2_000_000


def _vuln_row(vid: object, title: object = "", component: object = "",
              description: object = "") -> dict:
    """Normalize one past-vulnerability row with per-field caps."""
    def _c(v: object) -> str:
        return " ".join(str(v or "").split())[:VULNS_FIELD_CAP]
    return {"id": _c(vid), "title": _c(title), "component": _c(component),
            "description": _c(description)}


def _vulns_from_json(text: str) -> list[dict]:
    import json as _json
    data = _json.loads(text)
    if not isinstance(data, list):
        return []
    rows = []
    for item in data[:VULNS_ROW_CAP]:
        if not isinstance(item, dict):
            continue
        rows.append(_vuln_row(
            item.get("id") or item.get("cve") or item.get("cve_id") or "",
            item.get("title") or item.get("name") or item.get("summary") or "",
            item.get("component") or item.get("file") or item.get("module") or "",
            item.get("description") or item.get("details") or ""))
    return [r for r in rows if r["id"]]


def _vulns_from_csv(text: str) -> list[dict]:
    import csv as _csv
    import io as _io
    reader = _csv.DictReader(_io.StringIO(text))
    rows = []
    for item in reader:
        if len(rows) >= VULNS_ROW_CAP:
            break
        low = {str(k or "").strip().lower(): v for k, v in item.items()}
        rows.append(_vuln_row(
            low.get("id") or low.get("cve") or low.get("cve_id") or "",
            low.get("title") or low.get("name") or low.get("summary") or "",
            low.get("component") or low.get("file") or low.get("module") or "",
            low.get("description") or low.get("details") or ""))
    return [r for r in rows if r["id"]]


def _vulns_from_markdown(text: str) -> list[dict]:
    """Sections by heading: the heading is the title (and id when it carries one),
    the body is the description.
    """
    import re as _re
    rows: list[dict] = []
    text = _mask_fences(text)  # a `## ` line inside a fence is not a finding
    parts = _re.split(r"^(#{1,4})\s+(.+)$", text, flags=_re.MULTILINE)
    # parts = [pre, hashes, title, body, hashes, title, body, ...]
    for i in range(1, len(parts) - 2, 3):
        title = parts[i + 1].strip()
        body = parts[i + 2].strip()
        if not title:
            continue
        if len(parts[i]) == 1 and not rows:
            continue  # the document title, not a finding
        m = _re.search(r"\b((?:CVE|GHSA|OSV|SNYK)-[\w.-]+)\b", title + " " + body)
        rows.append(_vuln_row(m.group(1) if m else f"md-{len(rows) + 1}",
                              title, "", body))
        if len(rows) >= VULNS_ROW_CAP:
            break
    return rows


def parse_vulns_file(path: str) -> list[dict]:
    """Parse a past-vulnerabilities file into normalized rows
    [{"id","title","component","description"}]. Formats auto-detected: JSON
    array, CSV, markdown report, or id list. Returns [] for a missing, empty, or
    unparseable file; never raises.
    """
    try:
        p = Path(path)
        # Guard non-regular files: a FIFO or device node would block (or exhaust
        # memory) on read and hang the whole scan.
        if not p.is_file():
            return []
        if p.stat().st_size > VULNS_BYTES_CAP:
            return []
        text = p.read_text(encoding="utf-8-sig", errors="replace")
    except (OSError, ValueError, TypeError):
        return []
    if not text.strip():
        return []
    try:
        stripped = text.lstrip()
        if stripped.startswith("["):
            return _vulns_from_json(stripped)
        lines = [ln for ln in text.splitlines() if ln.strip()]
        first = lines[0] if lines else ""
        n_headings = sum(1 for ln in lines if ln.lstrip().startswith("#"))
        # Markdown needs the extension or >=2 headings: a lone '#' comment line
        # in an id list is not a report.
        if (path.lower().endswith((".md", ".markdown")) or n_headings >= 2):
            return _vulns_from_markdown(text)
        if "," in first and ("id" in first.lower() or "cve" in first.lower()):
            return _vulns_from_csv(text)
        rows = []
        for line in text.splitlines():
            token = line.strip().lstrip("-*• \t")
            # id-list rows look like identifiers (CVE-2026-29022, GHSA-...,
            # commit-ish tokens); prose lines do not.
            if (_re.fullmatch(r"[A-Za-z][A-Za-z0-9_:.-]{3,79}", token or "")
                    and any(ch.isdigit() for ch in token)):
                rows.append(_vuln_row(token))
            if len(rows) >= VULNS_ROW_CAP:
                break
        return rows
    except Exception as e:
        _logger.debug("vulns parse failed for %s: %s", path, e)
        return []
