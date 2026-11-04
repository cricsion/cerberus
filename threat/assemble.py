"""Hybrid assembly: merge the LLM judgment payload into the code-owned skeleton."""
from __future__ import annotations

from typing import Any as _Any

from .floor import _provenance, _vulns_note
from .quality import _map_enum_text, _norm_enums, _rank_threats
from .render import (
    CELL_CAP,
    MACHINE_SECTIONS,
    NON_EXCLUSION_NOTE,
    ROW_CAPS,
    _cell,
    _clean_llm_text,
    _parse_threats,
    _replace_section,
    _section,
    _table_rows,
    render_md,
)


def _merge_plan(repo: str, blocks: dict[str, str], plan: dict,
                vulns: list[dict] | None = None,
                vulns_path: str = "", draft: str = "") -> tuple[str, dict]:
    """Merge the LLM judgment payload into the code-owned skeleton: (md, meta).
    The plan leads the narrative (§1 context_prose, §3 plan entry points first);
    code-generated rows fill in / corroborate §1 facts and §3 surface rows, and
    code owns §4 sorting/ids/enums, §5 non-exclusion note, §6 template unknowns,
    §7 provenance, §8 mitigation validation. The plan supplies the judgment only.
    """
    meta: dict[str, _Any] = {"dropped": []}
    # -- section 3: plan rows + code skeleton --------------------------------
    surfaces = str(blocks.get("ep_skeleton", ""))
    route_block = ""
    for sep_marker in ("\n\n### Key Detected Endpoints", "\n\n### Trust Boundaries",
                       "\n\nDetected ~", "\n\nTrust defaults"):
        if sep_marker in surfaces:
            head, sep, tail = surfaces.partition(sep_marker)
            surfaces, route_block = head, sep + tail
            break
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
            plan_eps.append(dict(row))
    ep_lines = ["| entry_point | description | trust_boundary | reachable_assets |",
                "|---|---|---|---|"]
    for ep in plan_eps:
        name = _cell(ep.get("entry_point", ""))
        # On an exact name collision, code-owned cells fill any gap the plan
        # left: a measured description/boundary is never blanked by an empty cell.
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
        fallback_assets = (code_row.get("reachable_assets") if code_row else "") or "application data and system state"
        ep_lines.append("| " + " | ".join([
            name, description, boundary,
            assets or fallback_assets]) + " |")
    section3 = "\n".join(ep_lines) + ("\n\n" + route_block.strip() if route_block.strip() else "")

    # -- section 4: rank, validate, assign ids (code-owned) ----------------
    section4, id_by_pos, dropped = _rank_threats(
        list(plan.get("threats") or [])[:ROW_CAPS["threats"]])
    meta["dropped"].extend(dropped)

    # -- section 2: assets with validated sensitivity ----------------------
    plan_assets = [_norm_enums(a, ("sensitivity",)) for a in
                   (plan.get("assets") or [])[:ROW_CAPS["assets"]]
                   if isinstance(a, dict) and str(a.get("asset", "")).strip()]
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
        # No explicit data asset named: add a clean row (no '_unknown' marker)
        # so the quality gate does not read it as unconfirmed.
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
        # Prose cells are classified, not dropped: a written-out effort ("MEDIUM")
        # or closing description must still survive into §8.
        closes = _map_enum_text(m.get("closes_class", "partial"), "closes_class")
        effort = _map_enum_text(m.get("effort", "M"), "effort")
        # _map_enum_text only ever returns a closed-set value or the default, so
        # `closes`/`effort` cannot be out of range; only a missing id drops.
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
    # §7 provenance carries the honesty line when a judgment cell is empty, so a
    # half-filled document never masquerades as a complete threat model.
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
    # Carried from the draft verbatim: a re-enrichment must never wipe the
    # machine-owned sections a past scan proved.
    for name in MACHINE_SECTIONS:
        carried = _section(draft or "", name)
        if carried.strip():
            out = _replace_section(out, name, f"## {name}\n\n{carried.strip()}")
    return out, meta
