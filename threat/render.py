from __future__ import annotations

import re as _re

from .util import _SURFACE_FAMILY


# Headings are a machine contract: quality gates, verify, and the findings loop parse them by name.
SECTIONS = (
    "1. System context",
    "2. Assets",
    "3. Entry points & trust boundaries",
    "4. Threats",
    "5. Deprioritized",
    "6. Open questions",
    "7. Provenance",
    "8. Recommended mitigations",
)


# Parked threats stay in scope: hunters once read the deprioritized list as an exclusion filter.
_SCOPE_SEMANTICS_RE = _re.compile(
    r"prioriti|never excludes|not an exclusion|never grounds to skip|"
    r"absence .{0,40}not|not a scope",
    _re.IGNORECASE,
)


# Closed enums (schema.md). Rows outside these are flagged by threat_quality.
ACTORS = ("remote_unauth", "remote_auth", "adjacent_network", "local_user",
          "local_admin", "supply_chain", "insider")
IMPACTS = ("low", "medium", "high", "critical", "existential")
LIKELIHOODS = ("very_rare", "rare", "possible", "likely", "almost_certain")
STATUSES = ("unmitigated", "partially_mitigated", "mitigated", "risk_accepted")
THREAT_COLUMNS = ("id", "threat", "actor", "surface", "asset", "impact",
                  "likelihood", "status", "controls", "evidence")


OBSERVED_HEADING = "## Observed findings"
PROPOSALS_HEADING = "## Scope proposals"
FPS_HEADING = "## Known false positives"
# Incremental-update protocol: scans may ONLY replace these machine-owned sections.
MACHINE_SECTIONS = ("Observed findings", "Scope proposals", "Known false positives")


NON_EXCLUSION_NOTE = (
    "A threat model prioritizes, it never excludes: a parked row is not a "
    "scope decision, and absence from section 4 is never grounds to skip a "
    "class.")


# Caps on LLM-authored cells and rows: the document embeds into every hunter/validator/triage prompt.
CELL_CAP = 800
ROW_CAPS = {"entry_points": 40, "threats": 60, "assets": 30,
            "deprioritized": 30, "open_questions": 30, "mitigations": 30}


def _table_rows(section_text: str) -> list[dict]:
    rows: list[dict] = []
    header: list[str] = []
    for line in str(section_text or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or not any(cells):
            continue
        if not header:
            header = [c.lower().replace(" ", "_") for c in cells]
            continue
        if set("".join(cells)) <= {"-", ":", " "}:
            continue  # separator row
        row = {header[i]: cells[i] if i < len(cells) else ""
               for i in range(len(header))}
        rows.append(row)
    return rows


def _parse_threats(md: str) -> list[dict]:
    return _table_rows(_section(md or "", "4. Threats"))


def _parse_entry_points(md: str) -> list[dict]:
    return _table_rows(_section(md or "", "3. Entry points & trust boundaries"))


def _row_enum_gaps(row: dict) -> list[str]:
    bad = []
    for col, allowed in (("actor", ACTORS), ("impact", IMPACTS),
                         ("likelihood", LIKELIHOODS), ("status", STATUSES)):
        v = str(row.get(col, "") or "").strip().lower()
        if v not in allowed:
            bad.append(f"{col}={v or '<empty>'}")
    return bad


def _coverage_gaps(md: str) -> list[str]:
    eps = _parse_entry_points(md)
    threats = _parse_threats(md)
    if not eps:
        return []
    if not threats:
        return [f"entry point '{e.get('entry_point', '?')}' has no threat row"
                for e in eps]
    dep_rows = _table_rows(_section(md or "", "5. Deprioritized"))
    per_row = ([str(t.get("surface", "")).lower() for t in threats] +
               [str(t.get("threat", "")).lower() for t in threats] +
               [str(p.get("threat", "")).lower() for p in dep_rows])

    def _covered(name: str) -> bool:
        m = _re.search(r"`([^`\n]{1,120})`", name or "")
        key = m.group(1).strip().lower() if m else \
            " ".join((name or "").lower().split()[:3])
        for row_text in per_row:
            if key and key in row_text:
                return True
        for prefix, words in _SURFACE_FAMILY.items():
            if (name or "").startswith(prefix):
                if any(w in row_text for row_text in per_row for w in words):
                    return True
        return False

    return [f"entry point '{ep.get('entry_point', '?')}' has no threat row"
            for ep in eps if not _covered(str(ep.get("entry_point", "")))]


def render_md(sections: dict[str, str], repo: str = "") -> str:
    lines = [f"# Threat Model: {repo or 'repo'}", ""]
    for name in SECTIONS:
        body = (sections.get(name) or "").strip()
        lines += [f"## {name}", "", body or "_unknown — owner to confirm_", ""]
    return "\n".join(lines).rstrip() + "\n"


def _clean_llm_text(text: object) -> str:
    out = []
    for ln in str(text or "").split("\n"):
        if _re.match(r"\s{0,3}#{1,6}\s", ln):
            continue
        out.append(ln)
    return "\n".join(out).strip()


def _cell(text: object) -> str:
    return _clean_llm_text(_md_escape_cell(text))[:CELL_CAP].strip()


def _md_escape_cell(text: object) -> str:
    return str(text or "").replace("|", "/").replace("\n", " ").strip()


def _backticked_paths(text: str) -> list[str]:
    import re as _re

    code_exts = (
        ".py", ".ts", ".js", ".jsx", ".tsx", ".go", ".rs", ".java", ".c", ".cpp",
        ".h", ".hpp", ".cs", ".php", ".rb", ".swift", ".kt", ".scala", ".sh",
        ".bash", ".zsh", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
        ".conf", ".sql", ".html", ".htm", ".j2", ".jinja", ".jinja2", ".tpl",
        ".md", ".txt", ".dockerfile", ".env", ".lock", ".xml", ".css", ".scss"
    )
    known_filenames = {
        "dockerfile", "makefile", "procfile", "gemfile", "package.json",
        "pyproject.toml", "cargo.toml", "go.mod", "go.sum", "requirements.txt"
    }

    out = []
    for m in _re.finditer(r"`([^`\n]{1,160})`", text or ""):
        cand = m.group(1).strip().split(":", 1)[0].strip()
        if not cand or "(" in cand or ")" in cand:
            continue
        if cand.startswith(("/", "http://", "https://", "-", "--", "~")):
            continue
        if " " in cand or cand.startswith(("application/", "text/", "image/", "multipart/")):
            continue
        cand_lower = cand.lower()
        base_name = cand_lower.split("/")[-1]
        if any(base_name.endswith(ext) for ext in code_exts) or base_name in known_filenames:
            out.append(cand)
        elif "/" in cand and "." in base_name:
            out.append(cand)
        elif "/" in cand and (cand.endswith("/") or not ("." in cand)):
            out.append(cand)
    return out


def _mask_fences(text: str) -> str:
    out = list(text)
    in_fence = False
    for m in _re.finditer(r"^\s*(```|~~~)", text or "", flags=_re.MULTILINE):
        if not in_fence:
            in_fence = True
            start = m.end()
        else:
            for i in range(start, m.start()):
                if out[i] != "\n":
                    out[i] = " "
            in_fence = False
    return "".join(out)


def _replace_section(base: str, name: str, section_text: str) -> str:
    base = (base or "").rstrip()
    masked = _mask_fences(base)
    pat = rf"(?:^|\n)(##\s+{_re.escape(name)}\s*(?:\n|\Z).*?)(?=\n##\s+|\Z)"
    m = _re.search(pat, masked, flags=_re.DOTALL)
    if m:
        start = m.start(1)
        end = m.end(1)
        # offsets match in masked and real text (blanking preserves length)
        replacement = section_text.strip()
        prefix = base[:start].rstrip()
        suffix = base[end:].lstrip("\n")
        if replacement:
            parts = [p for p in (prefix, replacement, suffix) if p]
            base = "\n\n".join(parts)
        else:
            parts = [p for p in (prefix, suffix) if p]
            base = "\n\n".join(parts)
    elif section_text.strip():
        base = (base + "\n\n" + section_text.strip()).strip()
    return (base.rstrip() + "\n") if base.strip() else ""


def _section(text: str, name: str) -> str:
    pat = rf"(?:^|\n)##\s+{_re.escape(name)}\b[^\n]*(?:\n|\Z)(.*?)(?=\n##\s+|\Z)"
    m = _re.search(pat, text or "", flags=_re.DOTALL)
    return m.group(1) if m else ""


def validate_threat_md(md: str) -> list[str]:
    failures: list[str] = []
    text = md or ""
    if not text.strip():
        return ["empty document"]
    for name in SECTIONS:
        if f"## {name}" not in text:
            failures.append(f"missing section '{name}'")
        # A duplicate heading would shadow the code-rendered section.
        if len(_re.findall(rf"^##\s+{_re.escape(name)}\s*$", text,
                           flags=_re.MULTILINE)) > 1:
            failures.append(f"section '{name}' heading appears more than once")
    return failures
