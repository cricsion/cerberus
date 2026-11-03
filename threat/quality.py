from __future__ import annotations

import re as _re

from .render import (
    _SCOPE_SEMANTICS_RE,
    ACTORS,
    IMPACTS,
    LIKELIHOODS,
    OBSERVED_HEADING,
    SECTIONS,
    STATUSES,
    THREAT_COLUMNS,
    _backticked_paths,
    _cell,
    _coverage_gaps,
    _parse_entry_points,
    _parse_threats,
    _row_enum_gaps,
    _section,
)
from .util import _detector_signals, _repo_root, _signal_text

IMPACT_RANK = {v: i for i, v in enumerate(
    ("existential", "critical", "high", "medium", "low"))}
LIKELIHOOD_RANK = {v: i for i, v in enumerate(
    ("almost_certain", "likely", "possible", "rare", "very_rare"))}


# Models emit enums as prose and unmapped rows used to drop silently, so the phrases are mapped instead. First match wins; counts break ties.
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
# Conservative fallbacks: unmapped -> remote_unauth/unmitigated, never a claimed-full-closure (err toward MORE scrutiny).
_ENUM_DEFAULTS = {"actor": "remote_unauth", "impact": "medium",
                  "likelihood": "possible", "status": "unmitigated",
                  "effort": "M", "closes_class": "partial"}


def _map_enum_text(text: str, col: str) -> str:
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
    out = dict(row)
    for col in ("actor", "impact", "likelihood", "status"):
        if col in out and out[col] is not None:
            out[col] = _map_enum_text(str(out[col]), col)
    return out


def _norm_enums(row: dict, cols: tuple[str, ...]) -> dict:
    out = dict(row)
    for col in cols:
        if col in out:
            out[col] = str(out[col] or "").strip().lower()
    return out


def _rank_threats(rows: list[dict]) -> tuple[str, dict[int, str], list[str]]:
    dropped: list[str] = []
    kept: list[tuple[int, dict]] = []
    for pos, r in enumerate(rows, 1):
        if not isinstance(r, dict) or not str(r.get("threat", "")).strip():
            dropped.append(f"threat #{pos}: empty")
            continue
        # Prose enum cells are classified into the closed set, never dropped: a real judgment must not die on a formatting slip.
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


def threat_quality(md: str, files: list[str] | None = None,
                   signals: list[dict] | None = None) -> dict:
    gaps: list[str] = []
    passed = 0
    total = 0
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
    # Detector rule names must never become scope: a rule ID in §3/§4 reads as an in-scope list; coverage is code-owned.
    detector_rules = [s for s in _detector_signals(signals) if len(s) >= 4]
    if detector_rules:
        total += 1
        eps = _parse_entry_points(text)
        threats = _parse_threats(text)
        table_cells = ([str(e.get("entry_point", "")).lower() for e in eps] +
                       [str(t.get("threat", "")).lower() for t in threats] +
                       [str(t.get("surface", "")).lower() for t in threats])
        leaked = [s for s in detector_rules if any(
            _re.search(r"\b" + _re.escape(s.lower()) + r"\b", cell) for cell in table_cells)]
        if leaked:
            gaps.append("detector rule names used as scope (§3/§4): "
                        + ", ".join(leaked[:5])
                        + " — coverage belongs in §1, scope in §3")
        else:
            passed += 1
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
    routes_text = _signal_text(signals, "routes")
    n_routes = len([ln for ln in str(routes_text).splitlines() if ln.strip()])
    if n_routes > 0:
        total += 1
        entry = _section(text, "3. Entry points & trust boundaries")
        if str(n_routes) in entry:
            passed += 1
        else:
            gaps.append("entry points don't reflect detected routes")
    score = round(100 * passed / total) if total else 0
    if not rows:
        # No ranked threat rows is unusable, so the check-by-check score is capped.
        score = min(score, 50)
    return {"score": score, "gaps": gaps, "sections_filled": sections_filled,
            "threat_rows": len(rows)}


def verify_threat(repo: str, md: str, files: list[str] | None = None,
                  signals: list[dict] | None = None) -> dict:
    import re as _re

    failures: list[str] = []
    passed = 0
    total = 0
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

    refs = _backticked_paths(text)
    if refs:
        total += 1
        missing = sorted({r for r in set(refs) if not _exists(r)})
        if missing:
            failures.append("referenced files not found: "
                            + ", ".join(missing[:10]))
        else:
            passed += 1
    routes_text = _signal_text(signals, "routes")
    n_routes = len([ln for ln in str(routes_text).splitlines() if ln.strip()])
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
