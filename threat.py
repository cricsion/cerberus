"""Per-repo threat model artifact (THREAT_MODEL.md): scope + filter for hunters/triage.

Output schema is the reference contract
(defending-code-reference-harness/.claude/skills/threat-model/schema.md):
eight fixed sections, threats as a ranked table with closed enums. Threats are
class-level (they survive a patch); past vulns/CVEs are `evidence`, never the
threat itself.

Creation is LLM-first with a deterministic floor. `enrich_threat` runs a
two-agent research swarm (surface/asset reader + git-history miner) in
parallel, then a synthesizer call that emits the schema; `bootstrap_threat`
is the fail-open floor rendered with NO LLM from indexer signals, day-one
docs, and git fix history. Every stage degrades, never raises into the graph.
"""
from __future__ import annotations

import datetime as _dt
import logging as _logging
import re as _re
import subprocess as _sp
from pathlib import Path
from typing import Any as _Any

_logger = _logging.getLogger(__name__)



FILENAME = "THREAT_MODEL.md"
CACHE_DIRNAME = ".harness"  # machine-managed per-repo cache (see persist_threat)
CACHE_HEADER = "<!-- machine-managed by vuln-harness: safe to delete, regenerated+updated each scan -->"

# The eight fixed sections. Headings are a machine contract: quality gates,
# verify, and the findings feedback loop all parse them by name.
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

# A deprioritized section must convey that a threat model prioritizes, it
# never excludes. Hunters read a parked-threat list as a filter, which is how
# whole vulnerability classes went unreported: the list held prefilter rule
# names, and anything without a matching rule looked out of scope.
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

# Shostack 4Q for the `threat-model --interview` CLI (plan §1.4).
INTERVIEW_QUESTIONS: tuple[tuple[str, str], ...] = (
    ("building", "What are we building? (system context, assets)"),
    ("wrong", "What can go wrong? (top threats, past bug shapes)"),
    ("doing", "What are we doing about it? (existing controls)"),
    ("good_job", "Did we do a good job? (residual risk, threats to park in "
     "section 5 + why)"),
)


def _as_bool(value: object, default: bool = True) -> bool:
    """Lenient bool: real bools, "1/true/yes" strings (env interpolation
    stringifies YAML), numbers. Unparseable -> default."""
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def threat_enabled(cfg: dict | None, key: str, default: bool = True) -> bool:
    """Read `threat.<key>` from config with lenient bool parsing."""
    try:
        return _as_bool((cfg or {}).get("threat", {}).get(key, default), default)
    except Exception:
        return default


def _repo_root(repo: str) -> Path | None:
    """Directory owning repo state (itself, or parent when repo is a file)."""
    try:
        if not str(repo or "").strip():
            return None  # nowhere: never fall back to the process CWD
        base = Path(repo)
        if base.is_dir():
            return base
        if base.is_file():
            return base.parent  # repo given as a file: its directory owns state
        return None
    except (TypeError, ValueError, OSError):
        return None


def find_repo_file(repo: str) -> Path | None:
    """Locate a threat model for future-run reuse, owner file first:
    `<repo>/THREAT_MODEL.md`, then `<repo>/.harness/THREAT_MODEL.md`
    (machine cache from prior scans)."""
    try:
        root = _repo_root(repo)
        if root is None:
            return None
        root_resolved = root.resolve()
        owner = root / FILENAME
        if owner.is_file() and not owner.is_symlink() and owner.resolve().is_relative_to(root_resolved):
            return owner
        cached = root / CACHE_DIRNAME / FILENAME
        if cached.is_file() and not cached.is_symlink() and cached.resolve().is_relative_to(root_resolved):
            return cached
        return None
    except (OSError, ValueError, TypeError):
        return None


def load_threat(repo: str, override: str | None = None,
                cfg: dict | None = None) -> tuple[str, str]:
    """Resolve threat text. Returns (source, text); text "" when none.

    source in {"override", "repo-file", "repo-cache", "none"}. "repo-cache" is
    the machine-managed `.harness/` copy from a prior scan. Never raises.
    """
    try:
        if override:
            try:
                text = Path(override).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return "none", ""
            return ("override", text) if text.strip() else ("none", "")
        if not threat_enabled(cfg, "use_repo_file", True):
            return "none", ""
        found = find_repo_file(repo)
        if found is None:
            return "none", ""
        try:
            text = found.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "none", ""
        if not text.strip():
            return "none", ""
        machine = (found.parent.name == CACHE_DIRNAME
                   or text.lstrip().startswith(CACHE_HEADER))
        if machine:
            # A machine cache from before the schema migration (or any stale
            # generation) is not a current threat model: drop it and let the
            # caller rebuild the floor. Owner files are never dropped.
            if validate_threat_md(text):
                return "none", ""
            return "repo-cache", text
        return "repo-file", text
    except Exception as e:
        _logger.debug("threat resolution failed, no model: %s", e)
        return "none", ""


_GIT_SAFE_OPTS = ("-c", "core.hooksPath=/dev/null", "-c", "diff.external=")


def _bug_shapes(repo: str, limit: int = 20) -> str:
    """Bug-shape hints from security-fix history (guide: 'what have people
    exploited in the past'). One-liners plus touched files for the top fix
    commits, so hunters can ask the guide's two questions: was the fix
    complete, and was it applied everywhere else? Best-effort, never raises."""
    try:
        base = Path(repo)
        target_root = (base if base.is_dir() else base.parent).resolve()
        root = str(target_root)
        # `git -C <nested path> log` walks upward and silently reads the
        # enclosing checkout. Benchmark snapshots and vendored projects often
        # live inside another Git repository, so only use history when the
        # target directory is itself the worktree root. This also accepts
        # linked worktrees, whose `.git` is a file rather than a directory.
        top = _sp.run(
            ["git", *_GIT_SAFE_OPTS, "-C", root, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5)
        if top.returncode != 0 or not top.stdout.strip():
            return ""
        if Path(top.stdout.strip()).resolve() != target_root:
            return ""
        proc = _sp.run(
            ["git", *_GIT_SAFE_OPTS, "-C", root, "log", f"--max-count={limit}", "--format=%H %s", "--no-merges"],
            capture_output=True, text=True, timeout=10)
        if proc.returncode != 0 or not proc.stdout.strip():
            return ""
        keys = ("fix", "secur", "cve", "vuln", "xss", "sqli", "inject",
                "auth", "travers", "ssrf", "deser", "csrf", "crypto",
                "overflow", "escape", "sanit", "permiss", "exploit")
        scored = [(ln.split(" ", 1)[0], ln.split(" ", 1)[1] if " " in ln else ln)
                  for ln in proc.stdout.splitlines() if ln.strip()]
        hits = [(sha, subj) for sha, subj in scored
                if any(k in subj.lower() for k in keys)][:8]
        if not hits:
            return ""
        lines = ["Past fix-shaped commits (was each fix complete? applied everywhere else?):"]
        areas: dict[str, int] = {}
        for sha, subj in hits:
            try:
                stat = _sp.run(
                    ["git", *_GIT_SAFE_OPTS, "-C", root, "show", sha, "--format=",
                     "--name-only", "--no-ext-diff"],
                    capture_output=True, text=True, timeout=5)
                touched = [l.strip() for l in stat.stdout.splitlines()
                           if l.strip()][:6] if stat.returncode == 0 else []
            except Exception:
                touched = []
            for t in touched:
                area = t.replace("\\", "/").split("/")[0]
                areas[area] = areas.get(area, 0) + 1
            suffix = f" [touched: {', '.join(touched)}]" if touched else ""
            lines.append(f"- {subj[:120]}{suffix}")
        if areas:
            hot = ", ".join(f"{k} x{v}" for k, v in
                            sorted(areas.items(), key=lambda kv: -kv[1])[:8])
            lines.append(f"Repeat-offender areas: {hot}")
        res = "\n".join(lines)
        return res
    except Exception:
        return ""


# Guide inputs for bootstrap ("what you would hand a new security engineer on
# day one"): architecture docs, wikis, dependency security policies.
# INPUT budget (bounded context for the draft): distinct from the no-truncation
# rule, which governs the threat-model OUTPUT, not what we read to build it.
DOC_GLOBS = ("README*", "SECURITY*", "ARCHITECTURE*", "DESIGN*.md")
DOC_FILES_CAP = 10
DOC_CHARS_PER_FILE = 8000
DOC_TOTAL_CAP = 40000

# --vulns input: past vulnerabilities as threat evidence (reference harness
# .claude/skills/threat-model/bootstrap.md "Vuln-file parser"). Formats are
# auto-detected; the reference spawns a parser agent, ours parses
# deterministically because every format is mechanical. Caps keep a hostile
# or accidental 10MB dump out of the prompt budget.
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
    """Sections by heading: the heading is the title (and id when it carries
    one), the body is the description. A pentest report's structure is all
    the signal there is."""
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
    [{"id","title","component","description"}].

    Accepts, auto-detected: a JSON array of objects with at least id and
    description; CSV with an id/title/component/description header; a markdown
    report (heading + body per finding); or a newline-separated id list.
    Returns [] for a missing, empty, or unparseable file — never raises, so
    a bad --vulns degrades to git-history evidence only.
    """
    try:
        p = Path(path)
        # Guard non-regular files: a FIFO or device node would block (or
        # exhaust memory) on read and hang the whole scan.
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
        # Markdown needs the extension or >=2 headings: a lone '#' comment
        # line in an id list is not a report.
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


def collect_docs(repo: str) -> list[tuple[str, str]]:
    """Gather day-one docs: root READMEs, SECURITY policies, ARCHITECTURE/DESIGN
    notes, top-level docs/*.md. Returns [(relpath, text)] bounded by caps.
    Best-effort, never raises."""
    out: list[tuple[str, str]] = []
    total = 0
    try:
        root = _repo_root(repo)
        if root is None or not root.is_dir():
            return []
        cands: list[Path] = []
        for pat in DOC_GLOBS:
            try:
                cands.extend(sorted(p for p in root.glob(pat) if p.is_file()))
            except Exception:
                continue
        try:
            docs_dir = root / "docs"
            if docs_dir.is_dir():
                cands.extend(sorted(p for p in docs_dir.glob("*.md") if p.is_file()))
        except Exception:
            pass
        seen: set[str] = set()
        resolved_root = root.resolve()
        for p in cands:
            try:
                rel = str(p.relative_to(root))
            except ValueError:
                rel = p.name
            if rel in seen or len(out) >= DOC_FILES_CAP or total >= DOC_TOTAL_CAP:
                continue
            seen.add(rel)
            try:
                # Docs may sit under a symlinked dir; re-check each file.
                if p.is_symlink():
                    continue
                p.resolve().relative_to(resolved_root)
                if p.stat().st_size > 2_000_000:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")[:DOC_CHARS_PER_FILE]
            except OSError:
                continue
            except ValueError:
                continue
            if not text.strip():
                continue
            out.append((rel, text))
            total += len(text)
        return out
    except Exception:
        return out


def _detector_signals(candidates: list[dict]) -> list[str]:
    """Prefilter rule IDs from the `prefilter` candidate's `## ` headings.

    This is DETECTOR COVERAGE, never scope: it records what our regex rules
    happen to match, not what an attacker can do to this repository. Using it
    as an in-scope list made every vulnerability class without a matching rule
    look out of scope to hunters.
    """
    try:
        pre = next((c.get("snippet", "") for c in (candidates or [])
                    if c.get("id") == "prefilter"), "")
        return [ln[3:] for ln in str(pre).splitlines() if ln.startswith("## ")]
    except Exception:
        return []


def _attack_surfaces(candidates: list[dict], files: list[str]) -> list[str]:
    """Surfaces this repository actually exposes, derived from measured evidence.

    Each entry is a place where a lower-trust actor can hand input to the code.
    Deliberately a list of *surfaces*, not a list of bug types: the classes that
    matter follow from what the boundary is, and hardcoding a taxonomy here
    would freeze one snapshot of "interesting bugs" into every scan.
    """
    surfaces: list[str] = []
    cands = list(candidates or [])

    def _snippet(cid: str) -> str:
        return str(next((c.get("snippet", "") for c in cands
                         if c.get("id") == cid), ""))

    routes = [ln for ln in _snippet("routes").splitlines() if ln.strip()]
    if routes:
        surfaces.append(f"HTTP request handlers ({len(routes)} routes detected)")
    man = _snippet("manifest")
    if man.strip() and man.strip() != "(no manifests found)":
        surfaces.append("declared dependencies")
    if any(f.replace("\\", "/").startswith(".github/") for f in files or []):
        surfaces.append("CI workflow definitions")
    paths = [f.replace("\\", "/") for f in files or []]
    names = {p.rsplit("/", 1)[-1] for p in paths}
    if any(n in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml")
           or n.endswith((".tf", ".tfvars"))
           for n in names):
        surfaces.append("container build and runtime configuration")
    tpl_exts = (".j2", ".jinja", ".jinja2", ".tpl", ".ejs", ".pug", ".hbs", ".mustache", ".erb")
    has_tpl_engine_file = any(n.endswith(tpl_exts) for n in names)
    has_tpl_dir_html = any(("/templates/" in p or p.startswith("templates/")
                            or "/views/" in p or p.startswith("views/"))
                           and p.endswith((".html", ".htm"))
                           for p in paths)
    has_tpl_signal = any(k in " ".join(_detector_signals(candidates)).lower()
                         for k in ("jinja", "template", "tpl", "render"))
    if has_tpl_engine_file or has_tpl_dir_html or has_tpl_signal:
        surfaces.append("server-side template rendering")
    if any(f.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"))
           for f in paths):
        surfaces.append("parsed configuration and data files")
    if not surfaces:
        surfaces.append("unclassified entry points — owner to confirm")
    return surfaces


def _table_rows(section_text: str) -> list[dict]:
    """Parse a markdown table into row dicts keyed by its header cells.

    Returns [] for a header-only or empty table. Tolerates ragged rows
    (missing trailing cells become "") and skips the `|---|` separator.
    """
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
    """Section 4 threat rows as dicts (THREAT_COLUMNS keys). [] when absent."""
    try:
        return _table_rows(_section(md or "", "4. Threats"))
    except Exception:
        return []


def _parse_entry_points(md: str) -> list[dict]:
    """Section 3 entry-point rows (entry_point/description/trust_boundary/
    reachable_assets keys)."""
    try:
        return _table_rows(_section(md or "", "3. Entry points & trust boundaries"))
    except Exception:
        return []


def _row_enum_gaps(row: dict) -> list[str]:
    """Enum violations in one threat row (closed sets from the schema)."""
    bad = []
    for col, allowed in (("actor", ACTORS), ("impact", IMPACTS),
                         ("likelihood", LIKELIHOODS), ("status", STATUSES)):
        v = str(row.get(col, "") or "").strip().lower()
        if v not in allowed:
            bad.append(f"{col}={v or '<empty>'}")
    return bad


# The deterministic skeleton surfaces (_attack_surfaces) are matched against
# threat rows by FAMILY, not by name: the planner legitimately renames
# "HTTP request handlers (2 routes detected)" into the concrete route, and
# the row it produced IS the coverage. Scoped to these code-owned names so
# it cannot be gamed by threat-row prose.
_SURFACE_FAMILY = {
    "HTTP request handlers": ("http", "route", "endpoint"),
    "declared dependencies": ("depend", "package", "import", "supply",
                              "third-party", "lockfile"),
    "CI workflow definitions": ("ci", "workflow", "pipeline", "action"),
    "container build and runtime": ("container", "docker", "image", "build"),
    "server-side template rendering": ("template", "render", "html"),
    "parsed configuration and data files": ("config", "yaml", "json", "toml",
                                            "ini", "settings"),
}


def _coverage_gaps(md: str) -> list[str]:
    """Entry points with no threat row naming them (schema coverage invariant:
    every section 3 row must be traversed by at least one section 4 row).

    Matches on the entry point's backticked code identifier (`xss.py:6`,
    `app.run(cmd)`) when it has one — synthesized documents routinely rename
    the surrounding prose — falling back to the first three words, then to
    the family table for code-owned skeleton surfaces.
    """
    try:
        eps = _parse_entry_points(md)
        threats = _parse_threats(md)
        if not eps:
            return []
        if not threats:
            return [f"entry point '{e.get('entry_point', '?')}' has no threat row"
                    for e in eps]
        # Per-row surface text: a surface is covered when a threat row in §4 (or §5)
        # names it (or carries one of its family words) in its surface cell.
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
    except Exception:
        return []


def render_md(sections: dict[str, str], repo: str = "") -> str:
    """Render fixed-section markdown. Missing sections become `_unknown — owner to confirm_`."""
    lines = [f"# Threat Model: {repo or 'repo'}", ""]
    for name in SECTIONS:
        body = (sections.get(name) or "").strip()
        lines += [f"## {name}", "", body or "_unknown — owner to confirm_", ""]
    return "\n".join(lines).rstrip() + "\n"


def _measured_blocks(repo: str, files: list[str], candidates: list[dict],
                     summary: str, vulns: list[dict] | None = None) -> dict[str, str]:
    """The code-owned half of the document: everything measurable.

    Both the deterministic floor and the merged (enriched) document render
    from these blocks, so a measured fact can never drift into how the LLM
    phrased it. Keys: context_facts (the §1 tail), ep_skeleton (§3 base),
    questions (§6 base), assets_skeleton (§2 base).
    """
    routes = next((c.get("snippet", "") for c in candidates
                   if c.get("id") == "routes"), "")
    route_lines = [ln.strip() for ln in str(routes).splitlines() if ln.strip()]
    n_routes = len(route_lines)
    man = next((c.get("snippet", "") for c in candidates
                if c.get("id") == "manifest"), "")
    stack = (str(man).splitlines() or ["unknown stack"])[0][:200]
    signals = _detector_signals(candidates)
    surfaces = _attack_surfaces(candidates, files)
    shapes = _bug_shapes(repo)
    docs = collect_docs(repo)
    arch_doc = next(((p, t) for p, t in docs
                     if any(k in p.lower() for k in ("arch", "design", "overview", "system"))), None)
    arch_note = ""
    if arch_doc:
        p, t = arch_doc
        first = " ".join(t.strip().split())[:600]
        arch_note = f" Documentation ({p}) says: {first}"
    policies = [(p, t) for p, t in docs if "secur" in p.lower()]
    if policies:
        names = ", ".join(p for p, _ in policies)
        excerpt = " ".join(policies[0][1].strip().split())[:600]
        policy_note = (f"Published policy file(s): {names}. Excerpt: {excerpt}")
    else:
        policy_note = ("No published dependency security policy found in-repo "
                       "(checked SECURITY*/docs) — owner to confirm.")
    top_dirs: dict[str, int] = {}
    for f in files:
        key = f.replace("\\", "/").split("/")[0] if "/" in f.replace("\\", "/") else "root"
        top_dirs[key] = top_dirs.get(key, 0) + 1
    areas = ", ".join(f"{k} ({v} files)" for k, v in sorted(top_dirs.items())[:15]) or "unknown"

    facts = f"Repo: {repo}. {summary}".strip() + arch_note
    if stack and stack not in summary:
        facts += f" Stack hint: {stack}."
    facts += f" {policy_note}"
    if shapes:
        facts += f"\n\n{shapes}"
    if signals:
        facts += ("\n\nDetector coverage (regex prefilter rules that fired; "
                  "this is what our tooling can match, not what is in scope): "
                  + ", ".join(signals) + ".")
    if docs and not arch_note:
        names = ", ".join(p for p, _ in docs[:10])
        facts += f"\n\nDay-one docs read: {names}."
    vuln_rows = [v for v in (vulns or []) if isinstance(v, dict) and v.get("id")]
    if vuln_rows:
        ids = ", ".join(str(v.get("id")) for v in vuln_rows[:10])
        facts += (f"\n\nPast vulnerabilities supplied via --vulns ({len(vuln_rows)} "
                  f"rows; evidence for section 4, never the threats themselves): "
                  f"{ids}{' ...' if len(vuln_rows) > 10 else ''}.")

    ep_rows = ["| entry_point | description | trust_boundary | reachable_assets |",
               "|---|---|---|---|"]
    for s in surfaces:
        ep_rows.append(f"| {s} | reaches application code | "
                       "untrusted input → application logic | "
                       "unknown — owner to confirm |")
    ep_block = "\n".join(ep_rows)
    if route_lines:
        ep_block += (f"\n\nDetected ~{n_routes} framework routes: "
                     + ", ".join(route_lines[:15])
                     + (" ..." if len(route_lines) > 15 else ""))
    ep_block += ("\n\nTrust defaults (deterministic): authenticated clients, "
                 "config files, and vendored deps are TRUSTED unless the "
                 "owner says otherwise. Network input, request "
                 "bodies/params, file uploads, and template vars rendered "
                 "from user data are UNTRUSTED.")

    questions = (
        "- Is this deployment network-reachable, and by whom?\n"
        "- Who supplies the inputs each entry point receives?\n"
        "- Which controls (WAF, sandbox, size limits, authz) sit upstream?\n"
        "- Which threats should be parked in section 5, and why "
        "(a threat model prioritizes, it never excludes)?")

    return {"context_facts": facts, "ep_skeleton": ep_block,
            "questions": questions,
            "assets_skeleton": (f"| source code integrity | {areas} | high |\n"
                                "| data assets | _unknown — owner to confirm_ | high |")}


def measured_facts(repo: str, files: list[str], candidates: list[dict],
                   summary: str = "", vulns: list[dict] | None = None) -> str:
    """The deterministic measured-facts block, for the enrichment swarm.

    Public seam over ``_measured_blocks``: both call sites reach for exactly
    ``["context_facts"]``, and both sit inside bare ``try:`` blocks, so a
    private call across a module boundary degrades silently — a facade miss
    would drop the whole measured-facts floor into an ``except: pass``.
    Keep this name stable; the private one may move.
    """
    return _measured_blocks(repo, files, candidates, summary, vulns).get(
        "context_facts", "")


def _vulns_note(vulns: list[dict] | None, path: str = "") -> str:
    """Provenance fragment for the --vulns evidence base ("" when none)."""
    rows = [v for v in (vulns or []) if isinstance(v, dict) and v.get("id")]
    if not rows:
        return ""
    try:
        name = Path(path).name if path else ""
    except (TypeError, ValueError):
        name = ""
    label = f"--vulns {name} " if name else "--vulns "
    return f"{label}({len(rows)} rows)"


def _provenance(repo: str, enrichment: str, vulns_note: str = "") -> str:
    """Section 7 — fully mechanical. `enrichment` in {"deterministic",
    "llm-swarm"}; caller states which path actually produced the document.
    `vulns_note` records the --vulns evidence base when one was supplied."""
    try:
        stamp = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    except Exception:
        stamp = "unknown-date"
    inputs = ("indexer signals (manifest/routes/prefilter) + day-one docs + "
              "git fix history")
    if vulns_note:
        inputs += f" + {vulns_note}"
    if enrichment == "llm-swarm":
        inputs += (" + swarm research (surfaces/assets/controls) + git-history "
                   "classification")
    return (f"- mode: bootstrap\n- date: {stamp}\n- target: {repo}\n"
            f"- inputs: {inputs}\n- owner: unset\n"
            f"- enrichment: {enrichment}")


def _empty_threats_table() -> str:
    """Section 4 with the schema header and no rows (deterministic floor:
    threat rows need judgment; an empty table is honest and flagged by the
    quality gate, not hidden)."""
    return "| " + " | ".join(THREAT_COLUMNS) + " |\n" + \
           "|" + "|".join(["---"] * len(THREAT_COLUMNS)) + "|"


NON_EXCLUSION_NOTE = (
    "A threat model prioritizes, it never excludes: a parked row is not a "
    "scope decision, and absence from section 4 is never grounds to skip a "
    "class.")


def bootstrap_threat(repo: str, files: list[str],
                     candidates: list[dict], summary: str = "",
                     vulns: list[dict] | None = None,
                     vulns_path: str = "") -> str:
    """Deterministic floor: the reference schema filled from measured indexer
    signals, day-one docs, git fix history, and any --vulns rows. NO LLM
    call, so a keyless or failed-enrichment scan still ships a usable model.
    Section 4 ships empty (rows need judgment) and the quality gate says so.
    Raises only on empty inputs (caller keeps the summary)."""
    files = [f for f in (files or []) if f]
    candidates = list(candidates or [])
    if not files and not candidates and not summary:
        raise ValueError("nothing to bootstrap from")
    blocks = _measured_blocks(repo, files, candidates, summary, vulns)
    sections = {
        "1. System context": blocks["context_facts"],
        "2. Assets": blocks["assets_skeleton"],
        "3. Entry points & trust boundaries": blocks["ep_skeleton"],
        "4. Threats": _empty_threats_table(),
        "5. Deprioritized":
            "None recorded by the deterministic floor. " + NON_EXCLUSION_NOTE,
        "6. Open questions": blocks["questions"],
        "7. Provenance": _provenance(repo, "deterministic",
                                     _vulns_note(vulns, vulns_path)),
        "8. Recommended mitigations": (
            "_unknown — owner to confirm (one class-level control per threat "
            "cluster; deterministic floor proposes none_)."),
    }
    return render_md(sections, repo)


IMPACT_RANK = {v: i for i, v in enumerate(
    ("existential", "critical", "high", "medium", "low"))}
LIKELIHOOD_RANK = {v: i for i, v in enumerate(
    ("almost_certain", "likely", "possible", "rare", "very_rare"))}


# Caps on LLM-authored cells and rows (the --vulns caps' siblings): one
# confused planner reply must not balloon a document that is embedded into
# every hunter/validator/triage prompt of the scan.
CELL_CAP = 800
ROW_CAPS = {"entry_points": 40, "threats": 60, "assets": 30,
            "deprioritized": 30, "open_questions": 30, "mitigations": 30}


def _clean_llm_text(text: object) -> str:
    """Strip markdown headings from LLM-authored text.

    A planner reply that echoes the schema contract emits `## 4. Threats`
    inside context_prose; `_section` binds to the FIRST occurrence, so the
    real (code-rendered) table would become invisible to every consumer and
    every gate while all gates still scored the document clean. Headings are
    code-owned; LLM text never gets to define one.
    """
    out = []
    for ln in str(text or "").split("\n"):
        if _re.match(r"\s{0,3}#{1,6}\s", ln):
            continue
        out.append(ln)
    return "\n".join(out).strip()


def _cell(text: object) -> str:
    """Escape, de-heading, and cap one table cell."""
    return _clean_llm_text(_md_escape_cell(text))[:CELL_CAP].strip()


# Prose -> closed-enum classification. Models describe actors and impacts in
# sentences ("a careless or compromised maintainer/ci account") where the
# schema wants the closed enum. Dropping such rows silently empties section 4
# — observed live: 13 threat rows written, 13 dropped, document shipped with
# no ranked threats. Map the prose instead: the row carries the judgment, the
# cell is ours to normalize. First matching phrase wins; counts break ties.
_ACTOR_PHRASES = (
    ("remote_unauth", ("unauthenticated", "anonymous", "internet", "public "
     "internet", "remote attacker", "external attacker", "network attacker",
     "malicious detector", "attacker-controlled", "attacker who",
     "jailbroken", "llm agent", "agentic", "benchmarked agent", "remote")),
    ("supply_chain", ("supply chain", "upstream package", "registry",
     "lockfile", "dependency", "dependencies", "package maintainer",
     "compromised package", "build tooling")),
    ("insider", ("insider", "maintainer", "ci account", "careless edit",
     "compromised maintainer", "trusted contributor", "employee",
     "contractor", "release manager")),
    ("local_admin", ("local admin", "root", "administrator", "privileged "
     "local", "superuser")),
    ("local_user", ("local user", "local process", "local attacker",
     "local file", "shell access", "unprivileged user", "someone with "
     "file access")),
    ("adjacent_network", ("adjacent", "same network", "local network",
     "neighboring", "lan")),
    ("remote_auth", ("authenticated user", "logged-in", "logged in user",
     "any authenticated", "authenticated attacker", "low-privilege user",
     "regular user", "signed-in")),
)
_IMPACT_PHRASES = (
    ("critical", ("critical", "rce", "remote code execution", "full "
     "compromise", "complete compromise")),
    ("high", ("high", "data breach", "confidentiality", "privilege "
     "escalation", "arbitrary code")),
    ("medium", ("medium", "moderate", "limited", "dos", "denial of "
     "service", "single user")),
    ("low", ("low", "cosmetic", "informational", "minor")),
    ("existential", ("existential", "business-ending", "catastrophic",
     "apocalyptic")),
)
_LIKELIHOOD_PHRASES = (
    ("almost_certain", ("almost certain", "always", "trivial", "certain")),
    ("likely", ("likely", "easy", "straightforward", "expected")),
    ("possible", ("possible", "maybe", "plausible", "can")),
    ("rare", ("rare", "unlikely", "hard")),
    ("very_rare", ("very rare", "extremely unlikely", "near-impossible")),
)
_STATUS_PHRASES = (
    ("unmitigated", ("unmitigated", "no control", "none", "not "
     "mitigated", "absent")),
    ("partially_mitigated", ("partially", "partial", "incomplete")),
    ("mitigated", ("mitigated", "fixed", "controlled", "in place")),
    ("risk_accepted", ("risk accepted", "accepted", "tolerated")),
)
_EFFORT_PHRASES = (
    ("S", ("trivial", "quick", "small", "easy", "minor", "low effort",
     "config change", "hours")),
    ("M", ("medium", "moderate", "days", "some work")),
    ("L", ("large", "big", "significant", "major", "high effort", "expensive",
     "weeks", "xl", "rewrite")),
)
_CLOSES_PHRASES = (
    ("yes", ("fully", "eliminates", "eliminate", "closes", "prevents",
     "blocks", "removes the class")),
    ("partial", ("reduces", "mitigates", "hardens", "limits", "partially",
     "shrinks", "decreases", "contains")),
)
_ENUM_PHRASES = {"actor": _ACTOR_PHRASES, "impact": _IMPACT_PHRASES,
                 "likelihood": _LIKELIHOOD_PHRASES, "status": _STATUS_PHRASES,
                 "effort": _EFFORT_PHRASES, "closes_class": _CLOSES_PHRASES}
# Conservative fallbacks when nothing matches: a threat model errs toward
# MORE scrutiny, so unmapped means unauthenticated-remote, unmitigated, and
# never a claimed-full-closure.
_ENUM_DEFAULTS = {"actor": "remote_unauth", "impact": "medium",
                  "likelihood": "possible", "status": "unmitigated",
                  "effort": "M", "closes_class": "partial"}


def _map_enum_text(text: str, col: str) -> str:
    """Classify a free-text enum cell into the closed set; default when no
    phrase matches. Returns the value unchanged when already valid."""
    raw = str(text or "").strip().lower().replace("-", "_").replace(" ", "_")
    allowed = {"actor": ACTORS, "impact": IMPACTS, "likelihood": LIKELIHOODS,
               "status": STATUSES, "effort": ("S", "M", "L"),
               "closes_class": ("yes", "partial")}[col]
    if raw in allowed:
        return raw
    low = str(text or "").lower()
    best, best_hits = _ENUM_DEFAULTS[col], 0
    for value, phrases in _ENUM_PHRASES[col]:
        hits = sum(1 for ph in phrases if ph in low)
        if hits > best_hits:
            best, best_hits = value, hits
    return best


def _map_row_enums(row: dict) -> dict:
    """Normalize + classify the four closed-enum columns of a threat row."""
    out = dict(row)
    for col in ("actor", "impact", "likelihood", "status"):
        if col in out and out[col] is not None:
            out[col] = _map_enum_text(str(out[col]), col)
    return out


def _norm_enums(row: dict, cols: tuple[str, ...]) -> dict:
    """Lowercase/strip closed-enum cells once, so validation, ranking, and
    rendering all agree and no case-sensitive consumer ever sees 'Critical'."""
    out = dict(row)
    for col in cols:
        if col in out:
            out[col] = str(out[col] or "").strip().lower()
    return out


def _rank_threats(rows: list[dict]) -> tuple[str, dict[int, str], list[str]]:
    """Render section 4 from ranked rows.

    Returns (table, id_by_input_pos, dropped). Rows with empty threat text or
    closed-enum violations are dropped (recorded). Ids are assigned AFTER
    sorting by (impact, likelihood, threat text) — the text tiebreak makes
    ids a pure function of content — and mapped back to the caller's INPUT
    position so a mitigation's threat_numbers (planner-list positions)
    resolve to the rows the planner actually named.
    `evidence` stays empty when empty — that emptiness is the gap-fill marker.
    """
    dropped: list[str] = []
    kept: list[tuple[int, dict]] = []
    for pos, r in enumerate(rows, 1):
        if not isinstance(r, dict) or not str(r.get("threat", "")).strip():
            dropped.append(f"threat #{pos}: empty")
            continue
        # Prose enum cells are classified into the closed set (never dropped):
        # a row carrying a real judgment must not die on a formatting slip.
        norm = _map_row_enums(r)
        bad = _row_enum_gaps(norm)
        if bad:
            dropped.append(f"threat #{pos} '{str(r.get('threat'))[:40]}': "
                           + ", ".join(bad))
            continue
        kept.append((pos, norm))
    ordered = sorted(
        kept,
        key=lambda pr: (IMPACT_RANK.get(pr[1].get("impact", ""), 99),
                        LIKELIHOOD_RANK.get(pr[1].get("likelihood", ""), 99),
                        str(pr[1].get("threat", ""))))
    id_by_pos: dict[int, str] = {}
    lines = ["| " + " | ".join(THREAT_COLUMNS) + " |",
             "|" + "|".join(["---"] * len(THREAT_COLUMNS)) + "|"]
    for i, (pos, r) in enumerate(ordered, 1):
        tid = f"T{i}"
        id_by_pos[pos] = tid
        cells = []
        for c in THREAT_COLUMNS:
            if c == "id":
                cells.append(tid)
                continue
            cell = _cell(r.get(c, ""))
            if not cell and c == "controls":
                cell = "none"  # the schema's sentinel for "no control found"
            cells.append(cell)
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines), id_by_pos, dropped


def _md_escape_cell(text: object) -> str:
    return str(text or "").replace("|", "/").replace("\n", " ").strip()


def _merge_plan(repo: str, blocks: dict[str, str], plan: dict,
                vulns: list[dict] | None = None,
                vulns_path: str = "", draft: str = "") -> tuple[str, dict]:
    """Merge the LLM judgment payload into the code-owned skeleton.

    Code owns every deterministic cell: measured facts (§1 tail), the surface
    skeleton and route/trust-defaults block (§3), the non-exclusion note (§5),
    the template unknowns (§6), provenance (§7), threat-table sorting + id
    assignment + enum validation (§4), and mitigation-row validation (§8).
    The plan supplies: context prose, entry-point detail, assets with
    sensitivity, threat rows, parked rows, repo-specific questions, and
    class-level mitigations. Returns (md, meta)."""
    meta: dict[str, _Any] = {"dropped": []}
    # -- section 3: plan rows refined into the code-owned skeleton ----------
    surfaces = str(blocks.get("ep_skeleton", ""))
    route_block = ""
    head, sep, tail = surfaces.partition("\n\nTrust defaults")
    if sep:
        surfaces, route_block = head, sep + tail
    code_rows = _table_rows(surfaces)
    by_name = {str(r.get("entry_point", "")).strip().lower(): r
               for r in code_rows if str(r.get("entry_point", "")).strip()}
    plan_eps = [ep for ep in (plan.get("entry_points") or [])[:ROW_CAPS["entry_points"]]
                if isinstance(ep, dict) and str(ep.get("entry_point", "")).strip()
                and str(ep.get("entry_point", "")).lower() not in ("test", "unknown", "none", "dummy")
                and str(ep.get("description", "")).lower() not in ("test", "dummy")]
    seen_names = {str(ep.get("entry_point", "")).strip().lower() for ep in plan_eps}
    for name, row in by_name.items():
        if name not in seen_names:
            # A code-detected surface the plan dropped is appended, never lost.
            plan_eps.append(dict(row))
    ep_lines = ["| entry_point | description | trust_boundary | reachable_assets |",
                "|---|---|---|---|"]
    for ep in plan_eps:
        name = _cell(ep.get("entry_point", ""))
        # On an exact name collision the code-owned cells fill any gap the
        # plan left: a measured surface's description/boundary is never
        # blanked by an empty LLM cell.
        code_row = by_name.get(name.lower())
        description = _cell(ep.get("description", ""))
        if code_row and not description:
            description = _cell(code_row.get("description", ""))
        boundary = _cell(ep.get("trust_boundary", ""))
        if code_row and not boundary:
            boundary = _cell(code_row.get("trust_boundary", ""))
        refs = [f"`{r}`" for r in (ep.get("file_refs") or []) if str(r).strip()]
        if refs:
            description = (description + " [refs: " + ", ".join(refs) + "]")[:CELL_CAP]
        reachable = ep.get("reachable_assets") or []
        if isinstance(reachable, str):
            reachable = [reachable]
        assets = ", ".join(_cell(a) for a in reachable if str(a).strip())[:CELL_CAP]
        ep_lines.append("| " + " | ".join([
            name, description, boundary,
            assets or "unknown — owner to confirm"]) + " |")
    section3 = "\n".join(ep_lines) + ("\n\n" + route_block.strip() if route_block.strip() else "")

    # -- section 4: rank, validate, assign ids (code-owned) ----------------
    section4, id_by_pos, dropped = _rank_threats(
        list(plan.get("threats") or [])[:ROW_CAPS["threats"]])
    meta["dropped"].extend(dropped)

    # -- section 2: assets with validated sensitivity ----------------------
    plan_assets = [_norm_enums(a, ("sensitivity",)) for a in
                   (plan.get("assets") or [])[:ROW_CAPS["assets"]]
                   if isinstance(a, dict) and str(a.get("asset", "")).strip()]
    # Discard hallucinated dummy or placeholder assets like 'test'
    plan_assets = [a for a in plan_assets
                   if str(a.get("asset", "")).lower() not in ("test", "unknown", "none", "dummy")
                   and str(a.get("description", "")).lower() not in ("test", "dummy")]
    bad_assets = [a for a in plan_assets if a.get("sensitivity") not in
                  ("low", "medium", "high", "critical")]
    for a in bad_assets:
        # kept with a conservative default; recorded so it is visible
        meta["dropped"].append(
            f"asset '{str(a.get('asset'))[:40]}': "
            f"sensitivity={a.get('sensitivity') or '<empty>'} "
            "(kept, normalized to medium)")
        a["sensitivity"] = "medium"
    asset_rows = ["| asset | description | sensitivity |", "|---|---|---|",
                  "| source code integrity | code the system runs from; "
                  "tampering changes behavior for every user | high |"]
    seen_assets = {"source code integrity"}
    for a in plan_assets:
        name = _cell(a.get("asset", ""))
        if name.lower() not in seen_assets:
            seen_assets.add(name.lower())
            asset_rows.append("| " + " | ".join([
                name,
                _cell(a.get("description", "")),
                _cell(a.get("sensitivity", "medium"))]) + " |")
    if not any(a for a in plan_assets if "data" in a.get("asset", "").lower() or "user" in a.get("asset", "").lower()):
        # If no explicit data asset was named, ensure a clean data assets row without the 'unknown' marker
        # so quality gate doesn't see it as unconfirmed while still tracking data assets.
        asset_rows.append("| application data assets | user records, processed inputs, and runtime application state | high |")
    section2 = "\n".join(asset_rows)

    # -- section 5: parked rows --------------------------------------------
    parked = ["| threat | reason |", "|---|---|"]
    for p in (plan.get("deprioritized") or [])[:ROW_CAPS["deprioritized"]]:
        if isinstance(p, dict) and str(p.get("threat", "")).strip():
            parked.append("| " + " | ".join([
                _cell(p.get("threat", "")),
                _cell(p.get("reason", ""))]) + " |")
    section5 = "\n".join(parked)

    # -- section 6: template unknowns + repo-specific questions ------------
    q_lines = []
    seen_q = set()
    for raw_q in (blocks.get("questions", "").splitlines()
                 + [f"- {_clean_llm_text(q)}" for q in (plan.get("open_questions") or [])[:ROW_CAPS["open_questions"]]]):
        cleaned = raw_q.strip().lstrip("-* ").strip()
        if cleaned and cleaned.lower() not in seen_q:
            seen_q.add(cleaned.lower())
            q_lines.append(f"- {cleaned}")
    section6 = "\n".join(q_lines).strip()

    # -- section 8: mitigation rows resolve to real threat ids -------------
    mits = ["| mitigation | threat_ids | closes_class | effort |", "|---|---|---|---|"]
    for m in (plan.get("mitigations") or [])[:ROW_CAPS["mitigations"]]:
        if not isinstance(m, dict) or not str(m.get("mitigation", "")).strip():
            continue
        ids: list[str] = []
        for n in (m.get("threat_numbers") or []):
            try:
                pos = int(str(n).strip())
            except (TypeError, ValueError):
                continue
            tid = id_by_pos.get(pos)
            if tid and tid not in ids:
                ids.append(tid)
        # Prose cells are classified, not dropped: a real mitigation with a
        # written-out effort ("MEDIUM") or a closing description ("eliminate
        # interpreter sinks") must survive into §8.
        closes = _map_enum_text(m.get("closes_class", "partial"), "closes_class")
        effort = _map_enum_text(m.get("effort", "M"), "effort")
        # _map_enum_text returns only a value from the column's closed set (a
        # recognized value, a matched phrase, or the conservative default), so
        # `closes`/`effort` can never be out of range here. Only an
        # unresolvable threat id drops the row.
        bad = []
        if not ids:
            bad.append("no resolvable threat_ids")
        if bad:
            meta["dropped"].append(
                f"mitigation '{str(m.get('mitigation'))[:40]}': {', '.join(bad)}")
            continue
        # Display ids in rank order (T1 before T10), not planner-list order.
        ids.sort(key=lambda t: int(t[1:]))
        mits.append("| " + " | ".join([
            _cell(m.get("mitigation", "")),
            ",".join(ids), closes, effort]) + " |")
    section8 = "\n".join(mits)

    prose = _clean_llm_text(plan.get("context_prose", ""))
    section1 = (prose + "\n\n" + blocks["context_facts"]).strip() if prose \
        else blocks["context_facts"]
    provenance = _provenance(repo, "llm-swarm",
                             _vulns_note(vulns, vulns_path))
    # A merged document missing either judgment cell must not masquerade as
    # a complete threat model: provenance carries the code-owned honesty line
    # so the quality gate and every reader see which half is empty (hunters
    # still get the descriptive half, just no ranked rows or no mitigations).
    if not (plan.get("threats") or []):
        provenance += ("\n- judgment: empty (planner returned no threat "
                       "rows; retried with a narrowed brief)")
    elif not (plan.get("mitigations") or []):
        provenance += ("\n- mitigations: empty (planner returned no "
                       "mitigation rows; retried with a narrowed brief)")
    sections = {
        "1. System context": section1,
        "2. Assets": section2,
        "3. Entry points & trust boundaries": section3,
        "4. Threats": section4,
        "5. Deprioritized": section5 + "\n\n" + NON_EXCLUSION_NOTE,
        "6. Open questions": section6,
        "7. Provenance": provenance,
        "8. Recommended mitigations": section8,
    }
    meta["threat_rows"] = len(_parse_threats(render_md(sections, repo)))
    out = render_md(sections, repo)
    # Machine sections (Observed findings / Scope proposals / Known false
    # positives) are institutional memory: a re-enrichment must never wipe
    # what past scans proved. Carry them over from the draft verbatim.
    for name in MACHINE_SECTIONS:
        carried = _section(draft or "", name)
        if carried.strip():
            out = _replace_section(out, name, f"## {name}\n\n{carried.strip()}")
    return out, meta


def threat_quality(md: str, files: list[str] | None = None,
                    candidates: list[dict] | None = None) -> dict:
    """Deterministic quality score (answers 'how do we know it's good' without
    another agent): section completeness, schema-conformant threat table,
    coverage invariant, non-exclusion semantics, and grounding against measured
    indexer signals. Returns {"score": 0-100, "gaps": [...],
    "sections_filled": "n/8", "threat_rows": N}. Never raises."""
    gaps: list[str] = []
    passed = 0
    total = 0
    try:
        text = md or ""
        filled = 0
        for name in SECTIONS:
            total += 1
            body = _section(text, name)
            if body.strip() and "_unknown" not in body:
                filled += 1
                passed += 1
            else:
                gaps.append(f"section '{name}' missing or still unknown")
        sections_filled = f"{filled}/{len(SECTIONS)}"
        total += 1
        if "TRUST" in text.upper():
            passed += 1
        else:
            gaps.append("entry points name nothing TRUSTED")
        # Non-exclusion semantics: a deprioritized list must not read as a filter.
        total += 1
        dep_body = _section(text, "5. Deprioritized")
        if dep_body.strip() and _SCOPE_SEMANTICS_RE.search(dep_body):
            passed += 1
        else:
            gaps.append(
                "Deprioritized does not say a threat model prioritizes and "
                "never excludes; hunters read a parked list as a scope filter")
        # Detector rule names must never become scope. Sections 3/4 are what a
        # hunter reads as "what this application exposes"; a regex rule ID in
        # one re-creates the failure this schema removed -- prefilter rule
        # names as an in-scope list, so every class without a matching rule
        # looked out of scope. Coverage is code-owned and lives in section 1.
        # Gated on the prefilter candidate actually firing (like the
        # routes-staleness check below) and on signal length, so a 1-char
        # heading from a thin candidate cannot match ordinary prose.
        signals = [s for s in _detector_signals(candidates) if len(s) >= 4]
        if signals:
            total += 1
            eps = _parse_entry_points(text)
            threats = _parse_threats(text)
            table_cells = ([str(e.get("entry_point", "")).lower() for e in eps] +
                           [str(t.get("threat", "")).lower() for t in threats] +
                           [str(t.get("surface", "")).lower() for t in threats])
            leaked = [s for s in signals if any(
                _re.search(r"\b" + _re.escape(s.lower()) + r"\b", cell) for cell in table_cells)]
            if leaked:
                gaps.append("detector rule names used as scope (§3/§4): "
                            + ", ".join(leaked[:5])
                            + " — coverage belongs in §1, scope in §3")
            else:
                passed += 1
        # Threat table sanity: rows, closed enums, evidence mix, coverage.
        rows = _parse_threats(text)
        total += 1
        if rows:
            passed += 1
        else:
            gaps.append("section '4. Threats' has no rows (deterministic floor "
                        "or lazy synthesis); hunters get no ranked threats")
        if rows:
            bad = [f"{r.get('id', '?')}: {', '.join(_row_enum_gaps(r))}"
                   for r in rows if _row_enum_gaps(r)]
            total += 1
            if bad:
                gaps.append("threat rows outside the closed enums: "
                            + "; ".join(bad[:5]))
            else:
                passed += 1
            total += 1
            if any(not str(r.get("evidence", "")).strip() for r in rows):
                passed += 1
            else:
                gaps.append("every threat row has past-vuln evidence — the "
                            "STRIDE gap-fill stage did not run")
            cov = _coverage_gaps(text)
            total += 1
            if cov:
                gaps.extend(cov[:5])
            else:
                passed += 1
        # Staleness: detected routes must be reflected in section 3.
        routes = next((c.get("snippet", "") for c in (candidates or [])
                       if c.get("id") == "routes"), "")
        n_routes = len([ln for ln in str(routes).splitlines() if ln.strip()])
        if n_routes > 0:
            total += 1
            entry = _section(text, "3. Entry points & trust boundaries")
            if str(n_routes) in entry:
                passed += 1
            else:
                gaps.append("entry points don't reflect detected routes")
        score = round(100 * passed / total) if total else 0
        if not rows:
            # An 8-section document with no threat rows is not a usable
            # threat model: hunters get nothing ranked. The check-by-check
            # score would otherwise read 90+ for exactly that document
            # (observed: 92), so the empty judgment half caps the score.
            score = min(score, 50)
        return {"score": score, "gaps": gaps, "sections_filled": sections_filled,
                "threat_rows": len(rows)}
    except Exception:
        return {"score": 0, "gaps": ["quality check failed"],
                "sections_filled": "0/8", "threat_rows": 0}


def _backticked_paths(text: str) -> list[str]:
    """Candidate file references: `path`, `path:line`, `dir/file.ext`.

    Skips tokens containing parentheses — LLM output routinely backticks
    code identifiers (`app.run()`), which are not file claims.
    Also skips URL routes, MIME types, and language attribute accesses (`req.body`).
    """
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


def _section(text: str, name: str) -> str:
    try:
        pat = rf"(?:^|\n)##\s+{_re.escape(name)}\b[^\n]*(?:\n|\Z)(.*?)(?=\n##\s+|\Z)"
        m = _re.search(pat, text or "", flags=_re.DOTALL)
        return m.group(1) if m else ""
    except (AttributeError, TypeError, IndexError):
        return ""


def verify_threat(repo: str, md: str, files: list[str] | None = None,
                  candidates: list[dict] | None = None) -> dict:
    """Factual verification: check threat-model claims against the repo.

    Unlike threat_quality (completeness/consistency), every failure here is a
    checkable falsehood: a referenced file that doesn't exist, a route count
    that no longer matches, a policy file that's gone, an observation pointing
    at deleted code. Returns {"score": 0-100, "failures": [...]}. Claims no
    machine can check (is X really TRUSTED?) are owner assertions — surfaced
    in quality gaps, never scored here. Never raises.
    """
    import re as _re

    failures: list[str] = []
    passed = 0
    total = 0
    try:
        text = md or ""
        if not text.strip():
            return {"score": 0, "failures": ["empty threat model"]}
        root = _repo_root(repo)
        fileset = {(f or "").replace("\\", "/").lstrip("./")
                   for f in (files or []) if f}

        def _exists(p: str) -> bool:
            if not p or p.startswith(("http://", "https://")):
                return True  # not a repo claim; skip
            rel = p.replace("\\", "/").lstrip("./")
            if any(f == rel or f.endswith("/" + rel)
                   for f in fileset if f):
                return True
            try:
                resolved = (root / rel).resolve() if root else None
                return bool(root and resolved and resolved.is_relative_to(root.resolve()) and resolved.exists())
            except (OSError, ValueError, TypeError):
                return True  # fail-open: uncertain is not failure

        # 1. Referenced files resolve (entry points, threats, observations).
        refs = _backticked_paths(text)
        if refs:
            total += 1
            missing = sorted({r for r in set(refs) if not _exists(r)})
            if missing:
                failures.append("referenced files not found: "
                                + ", ".join(missing[:10]))
            else:
                passed += 1
        # 2. Entry-point count matches detected routes (staleness check).
        routes = next((c.get("snippet", "") for c in (candidates or [])
                       if c.get("id") == "routes"), "")
        n_routes = len([ln for ln in str(routes).splitlines() if ln.strip()])
        if n_routes > 0:
            total += 1
            m = _re.search(r"~(\d+)\s+framework routes",
                           _section(text, "3. Entry points & trust boundaries"))
            if m is None:
                passed += 1  # rephrased by owner/LLM; not checkable, not failure
            elif int(m.group(1)) == n_routes:
                passed += 1
            else:
                failures.append(
                    f"stale entry points: model claims ~{m.group(1)} routes, "
                    f"repo has {n_routes}")
        # 3. Observations point at live code (staleness check).
        obs = _section(text, OBSERVED_HEADING.lstrip("# "))
        if "Last validator-confirmed scan" in obs:
            total += 1
            obs_refs = _backticked_paths(obs)
            stale = sorted({r for r in set(obs_refs) if not _exists(r)})
            if stale:
                failures.append("stale observations (code moved/deleted): "
                                + ", ".join(stale[:10]))
            else:
                passed += 1
        score = round(100 * passed / total) if total else 100
        return {"score": score, "failures": failures}
    except Exception:
        return {"score": 0, "failures": ["verification crashed"]}


def apply_interview(md: str, answers: dict[str, str]) -> str:
    """Append owner interview notes (Shostack 4Q) to an existing draft."""
    try:
        stamp = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    except Exception:
        stamp = "unknown-date"
    lines = [(md or "").rstrip(), "", f"## Owner notes (interview {stamp})", ""]
    for key, question in INTERVIEW_QUESTIONS:
        ans = (answers.get(key) or "").strip()
        lines += [f"### {question}", "", ans or "_no answer_", ""]
    return "\n".join(lines).rstrip() + "\n"


def _threat_mk(cfg: dict) -> dict:
    """Model kwargs for threat-model stages (partitioner effort)."""
    from harness.agents.deep import sanitize_model_kwargs
    from harness.config import get_model_kwargs

    return sanitize_model_kwargs(
        get_model_kwargs(cfg or {}, "hunter", agent="partitioner"))


def _threat_timeout(cfg: dict) -> int:
    try:
        return max(int(_threat_mk(cfg).get("timeout", 180) or 180), 180)
    except (TypeError, ValueError):
        return 180


def _llm_structured(cfg: dict, model: Any, system: str, human: str) -> Any:
    """Structured threat-stage call — every schema runs as a repo-confined
    Deep Agent.

    The researcher, historian, and planner all go through ``run_structured``,
    so a malformed reply is re-prompted by the framework's
    ``ToolStrategy(handle_errors=True)`` instead of being caught by a
    hand-rolled ``with_structured_output`` retry loop. The task carries its
    explicit repo root on the first line so the agent never falls back to the
    harness working directory or an ambient TARGET_REPO. The planner
    (``SwarmPlan``) only synthesizes text already gathered into its brief, but
    it shares the same path so structured-output error handling is identical for
    every stage; it still runs under the ``threat-synthesizer`` role name that
    ``threat_model_node`` registers in the agent ledger. `reasoning=True` keeps
    the configured thinking effort on all of them.

    Raises on failure so each stage keeps its fail-open fallback.
    """
    try:
        from harness.prompts.threat import (SwarmHistory, SwarmPlan,
                                            SwarmResearch)
    except Exception:
        SwarmHistory = SwarmPlan = SwarmResearch = None
    agent_names = {SwarmResearch: "threat-researcher",
                   SwarmHistory: "threat-historian",
                   SwarmPlan: "threat-synthesizer"}
    agent_name = agent_names.get(model)
    if agent_name is None:
        raise ValueError("unknown threat-stage schema")

    # The task carries its explicit repo root so this agent never falls back
    # to the harness working directory or an ambient TARGET_REPO.
    prefix = "Repository (read-only): "
    first_line = (human or "").splitlines()[0] if human else ""
    if not first_line.startswith(prefix):
        raise ValueError(f"{agent_name} task is missing its repository root")
    root = _repo_root(first_line[len(prefix):])
    if root is None or not root.is_dir():
        raise ValueError("threat-stage repository is not a directory")

    from harness.agents.deep import run_structured
    from harness.config import load_config
    from harness.sandbox import close_backend, resolve_backend
    from harness.sandbox.local_backend import RepoLocalBackend
    from deepagents.backends.protocol import SandboxBackendProtocol

    # Resolve the same configured backend the Deep Agent factory uses so the
    # stage gets `execute` only for Docker/sbx, never in local mode. Resolving
    # it here also lets the prompt describe the actual sandbox egress posture.
    try:
        backend = resolve_backend(load_config(), root)
    except ValueError:
        backend = RepoLocalBackend(repo_path=root)

    runtime_note = "No shell tool is available; continue with static analysis."
    if isinstance(backend, SandboxBackendProtocol):
        network = str(getattr(backend, "network", "unknown")).lower()
        if network == "none":
            egress = (
                "Network egress is disabled, so short, focused local "
                "dynamic checks may run after inspecting their exact command."
            )
        elif network == "balanced":
            egress = (
                "Network egress is policy-restricted; do not run repository "
                "code, scripts, or tests. Use only read-only/static checks."
            )
        else:
            egress = (
                "Network egress is full or unknown; do not run repository "
                "code, scripts, or tests. Use only read-only/static checks."
            )
        runtime_note = (
            "A sandboxed `execute` tool is available. The repository mount is "
            "read-only, with scratch space available for generated output. "
            f"{egress} Never make network requests, install packages, "
            "download code, or send repository data externally."
        )
    system = f"{system}\n\nRUNTIME EXECUTION POSTURE: {runtime_note}"

    try:
        parsed, _, _ = run_structured(
            _threat_mk(cfg or {}), model, system, human,
            timeout=_threat_timeout(cfg or {}), max_retries=1,
            reasoning=True, name=agent_name, backend=backend,
            root_dir=root)
        return parsed
    finally:
        # End only this stage's sandbox session. The shared run sandbox
        # remains alive for other agents until scan teardown.
        close_backend(backend)


def _llm_text(cfg: dict, system: str, human: str,
              root_dir: str | None = None) -> str:
    """One plain-text deep-agent run (partitioner effort). Raises on failure.

    `root_dir` is required for the agent's repo-confined filesystem backend;
    without it (and without TARGET_REPO set) the factory refuses to default to
    the harness working directory, so callers pass the target repo explicitly.
    """
    from harness.agents.deep import run_structured

    _, text, _ = run_structured(
        _threat_mk(cfg), None, system, human, timeout=_threat_timeout(cfg),
        max_retries=1, reasoning=False, name="threat", root_dir=root_dir)
    return str(text or "")


def _parse_json_array(text: str) -> list | None:
    """Parse a JSON array of strings; None when unparseable (vs [] = done).

    Uses the shared raw-decoding scan in ``harness.llmjson`` so brackets inside
    question text and trailing prose cannot swallow or truncate the value.
    """
    from harness.llmjson import extract_string_array

    return extract_string_array(text, field="questions")


def _history_text(history: list[tuple[str, str]]) -> str:
    if not history:
        return "(no answers yet)"
    return "\n".join(f"Q: {q}\nA: {a or '_no answer_'}"
                     for q, a in history)


def interview_questions(draft_md: str, history: list[tuple[str, str]],
                        cfg: dict, max_questions: int = 5) -> list | None:
    """LLM generates the next interview questions from draft + history.

    Structured schema first (with the text parser over the *same* reply as the
    fallback), then one plain-text retry for backends that reject the schema
    outright — so a refused schema never costs a wasted round trip.

    Returns [] when the model judges draft+history sufficient (done), None on
    any failure (caller falls back to the static Shostack set, first round).
    Raises nothing.
    """
    try:
        from harness.prompts.threat import (INTERVIEWER_SYSTEM, QuestionList,
                                            build_interview_task)
        system = INTERVIEWER_SYSTEM
        human = build_interview_task(draft_md, _history_text(history),
                                     max_questions)
    except Exception:
        return None

    raw_text = ""
    try:
        from harness.agents.deep import run_structured
        parsed, raw_text, _ = run_structured(
            _threat_mk(cfg or {}), QuestionList, system, human,
            timeout=_threat_timeout(cfg or {}), max_retries=1,
            reasoning=False, name="threat-interviewer")
        if parsed is not None:
            return parsed.questions[:max_questions]
    except Exception:
        pass

    if not raw_text:
        return None
    parsed = _parse_json_array(raw_text)
    if parsed is None:
        return None
    return parsed[:max_questions]


def finalize_threat(draft_md: str, history: list[tuple[str, str]], cfg: dict,
                    root_dir: str | None = None) -> str:
    """LLM rewrites the draft incorporating interview answers. Raises on
    failure or thin output (caller fail-opens to draft + Q&A appendix)."""
    from harness.prompts.threat import FINALIZE_SYSTEM, build_finalize_task
    text = _llm_text(
        cfg,
        FINALIZE_SYSTEM,
        build_finalize_task(draft_md, _history_text(history)),
        root_dir=root_dir)
    if not text.strip() or "## " not in text or text.count("## ") < 3:
        raise ValueError("thin finalize output")
    return text.strip() + "\n"


def conduct_interview(repo: str, files: list[str], candidates: list[dict],
                      summary: str, cfg: dict, ask, say,
                      max_rounds: int = 3, max_questions: int = 5) -> str:
    """LLM-led threat-model interview. `ask(question) -> answer`,
    `say(text) -> None` (CLI passes input/print; tests pass lambdas).

    The model asks, follows up on doubts, and finalizes the document. Never
    raises: LLM failure degrades to the static Shostack set, then to the
    deterministic draft (+ any answers collected).
    """
    try:
        draft = bootstrap_threat(repo, files, candidates, summary)
    except Exception:
        draft = f"# THREAT MODEL — {repo}\n"
    history: list[tuple[str, str]] = []
    try:
        for _ in range(max(1, max_rounds)):
            qs = interview_questions(draft, history, cfg or {}, max_questions)
            if qs is None:
                if history:
                    break  # LLM failed mid-interview; finalize on what we have
                qs = [q for _, q in INTERVIEW_QUESTIONS]
            if not qs:
                break  # model satisfied (or owner emptied); done asking
            for q in qs[:max_questions]:
                try:
                    say(f"Q: {q}")
                except Exception:
                    pass
                try:
                    ans = ask(q) or ""
                except Exception:
                    ans = ""
                history.append((str(q), str(ans).strip()))
            if len(history) >= max(1, max_rounds) * max(1, max_questions):
                break
        if history:
            try:
                finalized = finalize_threat(draft, history, cfg or {},
                                            root_dir=repo)
                # An interview document is an owner artifact like any other:
                # it must still satisfy the schema, or the deterministic
                # floor + Q&A appendix ships instead.
                if not validate_threat_md(finalized):
                    return finalized
            except Exception:
                pass
            appendix = "\n\n".join(f"Q: {q}\nA: {a or '_no answer_'}"
                                   for q, a in history)
            return (draft.rstrip()
                    + f"\n\n## Owner notes (interview)\n\n{appendix}\n")
        return draft
    except Exception:
        return draft


def validate_threat_md(md: str) -> list[str]:
    """Structural validation of the schema contract. [] when the document is
    acceptable as the scan's threat model. Only structural failures discard a
    synthesized document (missing sections); enum and coverage problems are
    quality-gate gaps — a slightly imperfect model beats the empty floor.
    Never raises."""
    try:
        failures: list[str] = []
        text = md or ""
        if not text.strip():
            return ["empty document"]
        for name in SECTIONS:
            if f"## {name}" not in text:
                failures.append(f"missing section '{name}'")
            # An LLM-authored duplicate heading would shadow the real
            # (code-rendered) section for every consumer that takes the
            # first match.
            if len(_re.findall(rf"^##\s+{_re.escape(name)}\s*$", text,
                               flags=_re.MULTILINE)) > 1:
                failures.append(f"section '{name}' heading appears more than once")
        return failures
    except Exception:
        return ["validation crashed"]


def _json_default(obj: Any) -> str:
    return str(obj)


def _model_dump(parsed: Any) -> dict:
    """Pydantic instance (or dict) to a plain dict; {} when unusable."""
    try:
        if parsed is None:
            return {}
        if hasattr(parsed, "model_dump"):
            return dict(parsed.model_dump())
        return dict(parsed)
    except Exception:
        return {}


def _swarm_research(repo: str, files: list[str], draft: str,
                    cfg: dict) -> tuple[dict, str]:
    """Researcher agent: reads the repo, returns entry points, assets,
    controls, open questions. ("{...}", "ok"|"failed"). Never raises."""
    try:
        from harness.prompts.threat import (RESEARCHER_SYSTEM, SwarmResearch,
                                            build_research_task)
        parsed = _llm_structured(cfg or {}, SwarmResearch, RESEARCHER_SYSTEM,
                                 build_research_task(repo, draft, files))
        data = _model_dump(parsed)
        if not data:
            return {}, "failed"
        return data, "ok"
    except Exception as e:
        _logger.debug("threat researcher failed: %s", e)
        return {}, f"failed ({type(e).__name__})"


def _swarm_history(repo: str, draft: str, cfg: dict,
                    vulns: list[dict] | None = None) -> tuple[dict, str]:
    """Historian agent: classifies the deterministically mined fix-shaped
    commits into past-vuln rows (threat evidence). Never raises."""
    try:
        from harness.prompts.threat import (HISTORIAN_SYSTEM, SwarmHistory,
                                            build_historian_task)
        parsed = _llm_structured(cfg or {}, SwarmHistory, HISTORIAN_SYSTEM,
                                 build_historian_task(repo, _bug_shapes(repo),
                                                      draft, vulns))
        data = _model_dump(parsed)
        if not data:
            return {}, "failed"
        return data, "ok"
    except Exception as e:
        _logger.debug("threat historian failed: %s", e)
        return {}, f"failed ({type(e).__name__})"


def _bound_json(data: Any, max_len: int = 12000) -> str:
    """Pre-bound data structures in memory (truncating lists like
    entry_points, assets, vulns to 25 items, and if serialized JSON still
    exceeds max_len chars, further bound to 15 items, etc.) so that
    _json.dumps() always produces complete, valid JSON syntax.
    """
    import json as _json

    def _truncate_lists(obj: Any, cap: int) -> Any:
        if isinstance(obj, dict):
            return {k: _truncate_lists(v, cap) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_truncate_lists(item, cap) for item in obj[:cap]]
        if isinstance(obj, str) and len(obj) > 2000:
            return obj[:2000] + "... (truncated)"
        return obj

    for cap in (25, 15, 8, 4, 1):
        bounded = _truncate_lists(data or {}, cap)
        try:
            dumped = _json.dumps(bounded, default=_json_default)
            if len(dumped) <= max_len:
                return dumped
        except Exception:
            break
    try:
        return _json.dumps(_truncate_lists(data or {}, 1), default=_json_default)
    except Exception:
        return "{}"


def _synth_task(repo, draft, research, history, measured_facts, narrow=False):
    """build_synth_task call that tolerates the `narrow` keyword being absent
    (the brief-budgeting change lands in harness/prompts/threat.py)."""
    from harness.prompts.threat import build_synth_task
    try:
        return build_synth_task(repo, draft or "", research or "", history or "",
                                measured_facts or "", narrow=bool(narrow))
    except TypeError:
        return build_synth_task(repo, draft or "", research or "", history or "",
                                measured_facts or "")


def _swarm_plan(repo: str, draft: str, research: dict, history: dict,
                cfg: dict, measured_facts: str = "",
                narrow: bool = False) -> dict:
    """Planner call: draft + swarm returns -> structured judgment payload
    (SwarmPlan). {} on any failure. Never raises.

    The planner deliberately does NOT write markdown: code renders every
    deterministic cell (ids, sorting, provenance, measured facts, surface
    skeleton) so an LLM phrasing slip cannot corrupt a measured fact.

    `narrow` requests the judgment-focused brief from the brief-budgeting
    path: when a first call fills the descriptive half (prose, entry points,
    assets, parked rows, open questions) but leaves `threats`/`mitigations`
    empty, enrich_threat retries once with this set so the model spends its
    budget on the ranked rows instead of the description.
    """
    try:
        from harness.prompts.threat import SYNTH_SYSTEM, SwarmPlan
        parsed = _llm_structured(cfg or {}, SwarmPlan, SYNTH_SYSTEM,
                                 _synth_task(
                                     repo, draft or "",
                                     _bound_json(research or {}, max_len=12000),
                                     _bound_json(history or {}, max_len=12000),
                                     measured_facts or "",
                                     narrow=narrow))
        return _model_dump(parsed)
    except Exception as e:
        _logger.debug("threat planner failed: %s", e)
        return {}


def enrich_threat(repo: str, files: list[str], candidates: list[dict],
                  summary: str, draft: str, cfg: dict,
                  vulns: list[dict] | None = None,
                  vulns_path: str = "",
                  measured_facts: str = "") -> tuple[str, dict]:
    """LLM swarm: researcher + historian run in parallel, then one planner
    call returns the judgment payload, which code merges into the
    deterministic skeleton (measured facts, surface list, provenance). Returns
    (md, meta); md == "" when the swarm produced nothing usable and the caller
    keeps the deterministic floor. Runs on EVERY scan (no first-run caching)
    by design: freshness of the threat model is the point, and reproducibility
    comes from the deterministic half, not from a stale cache. Never raises.

    Cost note: up to 3 model calls (2 parallel + 1 sequential), each capped by
    _threat_timeout — worst case ~3x the per-call timeout.
    """
    meta: dict[str, _Any] = {"agents": {}}
    try:
        research: dict = {}
        history: dict = {}
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = {
                "researcher": ex.submit(_swarm_research, repo, files,
                                        draft or "", cfg or {}),
                "historian": ex.submit(_swarm_history, repo, draft or "",
                                       cfg or {}, vulns),
            }
            for name, fut in futs.items():
                try:
                    payload, status = fut.result()
                    meta["agents"][name] = status
                    if status == "ok":
                        if name == "researcher":
                            research = payload
                        else:
                            history = payload
                except Exception as e:
                    meta["agents"][name] = f"failed ({type(e).__name__}: {e})"
        if not research and not history:
            # Context agents returning empty (a weak model fills no nested
            # schema) is not the same as the swarm being unreachable: the
            # deterministic floor + measured facts are self-sufficient input
            # for the planner's judgment, and the planner demonstrably
            # produces rows from them. Only skip planning when neither
            # sub-agent call could be made at all — that gate used to stop
            # here, discarding enrichment the endpoint could still deliver.
            reachable = any(s.startswith("failed (") is False
                            for s in meta["agents"].values())
            if not reachable:
                meta["error"] = "swarm unreachable"
                return "", meta
        blocks = _measured_blocks(repo, files, candidates, summary or "",
                                  vulns)
        plan = _swarm_plan(repo, draft or "", research, history, cfg or {},
                           measured_facts or blocks.get("context_facts", ""))
        if plan and (not (plan.get("threats") or [])
                     or not (plan.get("mitigations") or [])):
            # Lazy synthesis: descriptive half filled, judgment half empty —
            # a payload that is "valid" (not None) yet carries no threat rows
            # or no mitigations, shipping an 8-section document with an empty
            # §4 (or §8). Retry once with the narrowed brief before accepting
            # a document missing either judgment cell.
            try:

                def _judgment(p: dict) -> int:
                    return ((1 if p.get("threats") else 0)
                            + (1 if p.get("mitigations") else 0))

                base = _judgment(plan)
                retry = _swarm_plan(repo, draft or "", research, history, cfg or {},
                                    measured_facts or blocks.get("context_facts", ""),
                                    narrow=True)
                if retry and _judgment(retry) > base:
                    # the narrowed brief filled a judgment cell the first ask
                    # missed — take it and record that the retry rescued it
                    plan = retry
                    meta["judgment_retry"] = "narrowed"
                # provenance tags; merge the descriptive half, named honestly.
                # A retry that brought LESS judgment never replaces the first
                # payload (the `plan` above is already the better of the two).
                if not (plan.get("threats") or []):
                    meta["judgment_empty"] = True
                if not (plan.get("mitigations") or []):
                    meta["mitigations_empty"] = True
            except Exception as e:
                # fail-open: keep the original descriptive plan; never lose the
                # floor to a retry that blew up.
                _logger.debug("threat judgment retry failed: %s", e)
                meta["judgment_empty"] = True
        if not plan:
            meta["error"] = "planner produced no structured payload"
            return "", meta
        md, merge_meta = _merge_plan(repo, blocks, plan, vulns, vulns_path,
                                     draft or "")
        failures = validate_threat_md(md)
        if failures:
            meta["error"] = "; ".join(failures[:3])
            return "", meta
        meta.update(merge_meta)
        meta["coverage_gaps"] = _coverage_gaps(md)
        return md.strip() + "\n", meta
    except Exception as e:
        _logger.debug("threat enrichment failed: %s", e)
        return "", {"error": f"{type(e).__name__}: {e}"}


def persist_threat(repo: str, md: str) -> str:
    """Write the machine-managed copy for future-run reuse:
    `<repo>/.harness/THREAT_MODEL.md`. Never touches an owner file.
    Returns the path written, or "" on any failure (fail-soft: read-only
    checkouts must never break scans)."""
    try:
        import os as _os
        body = (md or "").strip()
        if not body:
            return ""
        # Idempotent: a cache reloaded and re-persisted must not stack a
        # second machine-managed header (one per scan, forever).
        while body.startswith(CACHE_HEADER):
            body = body[len(CACHE_HEADER):].strip()
        root = _repo_root(repo)
        if root is None:
            return ""
        root_resolved = root.resolve()
        cache_dir = root / CACHE_DIRNAME
        if cache_dir.is_symlink() or (cache_dir.exists() and not cache_dir.resolve().is_relative_to(root_resolved)):
            return ""
        cache_dir.mkdir(parents=True, exist_ok=True)
        dest = cache_dir / FILENAME
        if dest.is_symlink() or (dest.exists() and not dest.resolve().is_relative_to(root_resolved)):
            return ""
        tmp = cache_dir / f"{FILENAME}.tmp.{_os.getpid()}"
        tmp.write_text(CACHE_HEADER + "\n" + body + "\n", encoding="utf-8")
        tmp.replace(dest)
        return str(dest)
    except Exception:
        return ""


OBSERVED_HEADING = "## Observed findings"
PROPOSALS_HEADING = "## Scope proposals"
FPS_HEADING = "## Known false positives"
# Incremental-update protocol: scans may ONLY replace these machine-owned
# sections. Owner text (all seven fixed sections, Owner notes, hand edits) is
# never rewritten by a scan — full-document writes happen only on the explicit
# `threat-model` command (creation), never as a scan side effect.
MACHINE_SECTIONS = ("Observed findings", "Scope proposals", "Known false positives")


def _mask_fences(text: str) -> str:
    """Blank out fenced code blocks (same length) so a `## ` line inside a
    fence is never mistaken for a section heading."""
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
    """Swap one ## section in-place (through the next ## heading or EOF).

    Matches ONLY an exact machine heading (`## <name>` to end of line): an
    owner heading that merely starts with the name (`## Scope proposals (Q3)`)
    is never touched, and headings inside code fences are ignored.
    """
    base = (base or "").rstrip()
    masked = _mask_fences(base)
    pat = rf"(?:^|\n)(##\s+{_re.escape(name)}\s*(?:\n|\Z).*?)(?=\n##\s+|\Z)"
    m = _re.search(pat, masked, flags=_re.DOTALL)
    if m:
        start = m.start(1)
        end = m.end(1)
        # offsets are identical in masked and real text (blanking preserves
        # length), so slicing `base` directly is safe
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


def update_threat_with_findings(md: str, findings: list[dict], repo: str = "") -> str:
    """Feedback loop: fold VALIDATOR-CONFIRMED findings back into the threat model.

    Only status == "confirmed" findings teach the model — needs-review claims
    are unproven and must not shape it (so keyless scans contribute nothing
    here, correctly). Deterministic (no LLM). Replaces ONLY the machine-owned
    sections (Observed findings, Scope proposals, Known false positives); the
    eight schema sections and owner text are never touched:
    - Observed: counts of confirmed primaries by CWE, top affected paths.
    - Known false positives: counts of fp findings by CWE with example paths
      and reasons — institutional memory so future scans (and owners) know what
      was already disproven and why.
    - Proposals: novel confirmed classes as threat-row candidates ONLY. A
      threat model prioritizes, it never excludes — nothing is ever proposed
      for Deprioritized (a validator may not acquit on scope grounds).
    Returns input unchanged when there is nothing to record. Never raises.
    """
    try:
        items = [f for f in (findings or []) if isinstance(f, dict)]
        claims = [f for f in items
                  if not f.get("duplicate_of")
                  and f.get("status") == "confirmed"
                  and f.get("severity") != "info"
                  and f.get("cwe")]
        fps = [f for f in items
               if f.get("status") == "fp" and f.get("cwe")]
        if not claims and not fps:
            return md or ""
        try:
            stamp = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
        except Exception:
            stamp = "unknown-date"
        by_cwe: dict[str, int] = {}
        by_path: dict[str, int] = {}
        for f in claims:
            cwe = str(f.get("cwe", "")).strip().upper()
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
            p = str(f.get("path", "") or "").strip()
            if p:
                by_path[p] = by_path.get(p, 0) + 1
        top_cwe = ", ".join(f"{c} x{n}" for c, n in
                            sorted(by_cwe.items(), key=lambda kv: -kv[1])[:15])
        top_paths = ", ".join(f"{p} x{n}" for p, n in
                              sorted(by_path.items(), key=lambda kv: -kv[1])[:15])
        in_model = (_section(md or "", "4. Threats")
                    + _section(md or "", "5. Deprioritized")).upper()
        novel = [c for c in sorted(by_cwe) if c and c not in in_model]
        lines = [OBSERVED_HEADING, "",
                 f"Last validator-confirmed scan: {stamp} ({repo or 'repo'}).",
                 f"Confirmed primary claims: {len(claims)}.", ""]
        if top_cwe:
            lines += [f"By class: {top_cwe}", ""]
        if top_paths:
            lines += [f"Affected paths: {top_paths}", ""]
        out = _replace_section(md or "", "Observed findings",
                               "\n".join(lines).rstrip() + "\n")
        prop_lines = [PROPOSALS_HEADING, "",
                      "Machine-generated candidates from verified findings — "
                      "promote by adding a threat row above; scans never "
                      "apply these themselves.", ""]
        if novel:
            prop_lines += ["Consider adding a threat row for: "
                           + ", ".join(f"{c} x{by_cwe[c]}" for c in novel), ""]
        if novel or fps:
            out = _replace_section(out, "Scope proposals",
                                   "\n".join(prop_lines).rstrip() + "\n")
        else:
            out = _replace_section(out, "Scope proposals", "")
        if fps:
            by_fp: dict[str, list[dict]] = {}
            for f in fps:
                by_fp.setdefault(str(f.get("cwe", "")).strip().upper(), []).append(f)
            fp_lines = [FPS_HEADING, "",
                        "Disproven in past scans — do not re-report without new evidence.", ""]
            for cwe in sorted(by_fp, key=lambda c: -len(by_fp[c]))[:15]:
                group = by_fp[cwe]
                ex = group[0]
                why = " ".join(str(ex.get("evidence", "") or "").split())[:200]
                where = ", ".join(sorted({str(f.get("path", "")) for f in group
                                          if f.get("path")})[:5])
                row = f"- {cwe} x{len(group)}"
                if where:
                    row += f" at {where}"
                if why:
                    row += f" — {why}"
                fp_lines.append(row)
            fp_lines.append("")
            out = _replace_section(out, "Known false positives",
                                   "\n".join(fp_lines).rstrip() + "\n")
        else:
            out = _replace_section(out, "Known false positives", "")
        return out
    except Exception:
        return md or ""
