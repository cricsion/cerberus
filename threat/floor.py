from __future__ import annotations

import logging as _logging
import subprocess as _sp
from pathlib import Path

from .render import (NON_EXCLUSION_NOTE, THREAT_COLUMNS, render_md,
                     validate_threat_md)
from .util import (CACHE_DIRNAME, CACHE_HEADER, _GIT_SAFE_OPTS,
                   _attack_surfaces, _detector_signals, _now_iso, _repo_root,
                   find_repo_file, threat_enabled)

_logger = _logging.getLogger(__name__)


def load_threat(repo: str, override: str | None = None,
                cfg: dict | None = None) -> tuple[str, str]:
    if override:
        try:
            text = Path(override).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "none", ""
        return ("override", text) if text.strip() else ("none", "")
    if not threat_enabled(cfg, "use_repo_file"):
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
        # Machine-format copy = stale prior scan, dropped so the floor rebuilds; owner files are never dropped.
        if validate_threat_md(text):
            return "none", ""
        return "repo-cache", text
    return "repo-file", text


def _bug_shapes(repo: str, limit: int = 20) -> str:
    try:
        base = Path(repo)
        target_root = (base if base.is_dir() else base.parent).resolve()
        root = str(target_root)
        # `git -C <nested path>` walks upward to an enclosing checkout; require the target dir to BE the root.
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
    except (OSError, _sp.SubprocessError):
        return ""


# Day-one doc inputs (arch/security docs read for bootstrap); INPUT budget only — the no-truncation rule governs the OUTPUT.
DOC_GLOBS = ("README*", "SECURITY*", "ARCHITECTURE*", "DESIGN*.md")
DOC_FILES_CAP = 10
DOC_CHARS_PER_FILE = 8000
DOC_TOTAL_CAP = 40000


def collect_docs(repo: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    total = 0
    root = _repo_root(repo)
    if root is None or not root.is_dir():
        return []
    cands: list[Path] = []
    for pat in DOC_GLOBS:
        try:
            cands.extend(sorted(p for p in root.glob(pat) if p.is_file()))
        except OSError:
            continue
    try:
        docs_dir = root / "docs"
        if docs_dir.is_dir():
            cands.extend(sorted(p for p in docs_dir.glob("*.md") if p.is_file()))
    except OSError:
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


_SURFACE_METADATA = {
    "http": {
        "desc": "Web and REST API endpoints processing external client HTTP requests",
        "boundary": "untrusted network / client → application logic",
        "assets": "application data, session state, process integrity",
    },
    "template": {
        "desc": "Template engine evaluating dynamic views with server and user variables",
        "boundary": "untrusted template variables → template engine runtime",
        "assets": "server process integrity, application data",
    },
    "depend": {
        "desc": "Third-party libraries and runtime packages declared in project manifests",
        "boundary": "untrusted package registries / upstream supply chain → runtime process",
        "assets": "host process integrity, source code integrity",
    },
    "ci": {
        "desc": "Automation pipelines (.github/workflows) triggered on pull requests and commits",
        "boundary": "untrusted pull requests / external action runners → CI runner environment",
        "assets": "source code integrity, CI secrets & deployment credentials",
    },
    "container": {
        "desc": "Dockerfile, container images, and runtime deployment manifests",
        "boundary": "untrusted base images / container host runtime → container namespace",
        "assets": "container isolation, host process integrity",
    },
    "config": {
        "desc": "Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime",
        "boundary": "untrusted configuration files → configuration parser",
        "assets": "application configuration state, runtime logic",
    },
}


def _surface_row_spec(surface_name: str, n_routes: int = 0) -> tuple[str, str, str]:
    """Return (description, trust_boundary, reachable_assets) tailored to surface."""
    s_lower = surface_name.lower()
    for key, spec in _SURFACE_METADATA.items():
        if key in s_lower:
            desc = spec["desc"]
            if "route" in s_lower and n_routes:
                desc = f"Web and REST API endpoints (~{n_routes} routes detected) processing external requests"
            return desc, spec["boundary"], spec["assets"]
    return ("Application input interface reaching internal logic",
            "untrusted input → application logic",
            "application data and system state, process integrity")


def _format_detected_routes(route_lines: list[str], max_display: int = 15) -> str:
    n_routes = len(route_lines)
    if not n_routes:
        return ""

    seen_endpoints: set[str] = set()
    formatted_items: list[str] = []

    for line in route_lines:
        line = line.strip()
        if not line:
            continue
        cleaned = line
        file_ref = ""
        if ": [route] " in cleaned:
            parts = cleaned.split(": [route] ", 1)
            file_ref = parts[0].strip()
            cleaned = parts[1].strip()
        elif ":" in cleaned and any(cleaned.split(":", 1)[0].endswith(ext)
                                    for ext in (".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".cs")):
            parts = cleaned.split(":", 2)
            if len(parts) >= 2:
                file_ref = f"{parts[0]}:{parts[1]}"
                cleaned = parts[2].strip() if len(parts) > 2 else ""

        handler = ""
        if "->" in cleaned:
            c_parts = cleaned.split("->", 1)
            cleaned = c_parts[0].strip()
            handler = c_parts[1].strip()

        endpoint = cleaned.strip()
        if not endpoint:
            continue

        key = endpoint.lower()
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)

        ref_str = f" (`{file_ref}`)" if file_ref else (f" (`{handler}`)" if handler else "")
        formatted_items.append(f"- `{endpoint}`{ref_str}")
        if len(formatted_items) >= max_display:
            break

    header = f"### Key Detected Endpoints\n*Detected ~{n_routes} framework routes:*"
    if formatted_items:
        body = "\n".join(formatted_items)
        remaining = n_routes - len(formatted_items)
        if remaining > 0:
            body += f"\n- *(and ~{remaining} additional route handlers)*"
        return f"{header}\n\n{body}"
    return f"{header}\n\n- *(route definitions detected across repository)*"


def _measured_blocks(repo: str, files: list[str], candidates: list[dict],
                     summary: str, vulns: list[dict] | None = None) -> dict[str, str]:
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
        desc, boundary, assets = _surface_row_spec(s, n_routes)
        ep_rows.append(f"| {s} | {desc} | {boundary} | {assets} |")
    ep_block = "\n".join(ep_rows)
    if route_lines:
        ep_block += f"\n\n{_format_detected_routes(route_lines)}"
    ep_block += (
        "\n\n### Trust Boundaries & Assumptions\n\n"
        "Trust defaults (deterministic):\n"
        "- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.\n"
        "- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface."
    )

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
    return _measured_blocks(repo, files, candidates, summary, vulns).get(
        "context_facts", "")


def _vulns_note(vulns: list[dict] | None, path: str = "") -> str:
    rows = [v for v in (vulns or []) if isinstance(v, dict) and v.get("id")]
    if not rows:
        return ""
    name = Path(path).name if path else ""
    label = f"--vulns {name} " if name else "--vulns "
    return f"{label}({len(rows)} rows)"


def _provenance(repo: str, enrichment: str, vulns_note: str = "") -> str:
    stamp = _now_iso()
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
    return "| " + " | ".join(THREAT_COLUMNS) + " |\n" + \
           "|" + "|".join(["---"] * len(THREAT_COLUMNS)) + "|"


def bootstrap_threat(repo: str, files: list[str],
                     candidates: list[dict], summary: str = "",
                     vulns: list[dict] | None = None,
                     vulns_path: str = "") -> str:
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
