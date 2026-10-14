"""Deterministic partitioning: which files each hunter sees.

The algorithm, in stages:
   0. vendor isolation (node_modules/dist/minified -> one budget-exempt unit),
   1. small-repo collapse (a repo that fits the budget is ONE unit),
   2. graph signals (partitioning.graph: graphify communities),
   3. grouping (graphify communities, else top-level directories),
   4. size balancing (the per-agent byte budget; partition_target),
   5. normalization (merge same-named, tiny units, cap at MAX_UNITS, then
      re-enforce the byte budget so no merge/cap leaves a blob behind).

Policy knobs live in partitioning.config; the Deep-Agent proposer and its
invariant enforcement live in partitioning.llm.

Primary source: Graphify communities (Leiden clustering over the AST graph) —
real subsystems, not directory accidents. Fallback: top-level directory
grouping. By default, tiny CODE units never land in misc: they merge into their
most-coupled in-budget neighbour (file-coupling edges) or stay singletons; only
untyped non-code leftovers absorb into misc. Unowned support groups remain
explicit. Set PARTITION_MISC_CODE_MERGE=0 for the
legacy policy. Huge unit lists cap at MAX_UNITS, and the byte budget is
re-enforced afterwards, so neither step can re-form an over-budget blob.

Units are [{name, files, reason}] (plus budget_exempt on the vendor unit).
Hunters run all vulnerability classes inside ONE unit (full coherent context);
validators later partition by class.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path, PurePosixPath

from harness.partitioning.config import (NON_CODE_EXTS, NON_CODE_NAMES,
                                         VENDOR_DIR_SEGMENTS,
                                         VENDOR_FILE_SUFFIXES,
                                         VENDOR_UNIT_NAME, max_units,
                                         min_files, misc_code_merge_enabled,
                                         single_unit_max_files,
                                         single_unit_enabled, vendor_unit_enabled)
from harness.partitioning.graph import (file_communities, load_partition_graph,
                                        support_file_kind)

_NON_CODE_EXTS_LOWER = frozenset(e.lower() for e in NON_CODE_EXTS)
_NON_CODE_NAMES_LOWER = frozenset(n.lower() for n in NON_CODE_NAMES)
_SUPPORT_GROUP_MAX_FILES = 50


# --- P0.1 vendor isolation ---------------------------------------------------


_VENDOR_FILE_SUFFIXES = VENDOR_FILE_SUFFIXES + ("-bundle.js", "-min.js",
                                                "-pack.js", "standalone.js",
                                                ".vendor.js")
_MINIFIED_MIN_BYTES = 65_536
_MINIFIED_LINE_CHARS = 500


def _is_minified(path: Path) -> bool:
    """A large single-line/low-newline file: a bundled artifact (swagger-ui,
    redoc, angular, AdminLTE), not source. Never raises."""
    try:
        if not path.is_file() or path.stat().st_size < _MINIFIED_MIN_BYTES:
            return False
        with path.open("rb") as fh:
            head = fh.read(8192)
    except OSError:
        return False
    if not head:
        return False
    if b"\n" not in head:
        return True
    return max(len(line) for line in head.split(b"\n")) > _MINIFIED_LINE_CHARS


def _is_vendor_file(f: str, repo: str | None = None) -> bool:
    """True when any path segment is a vendor directory, the file name is a
    minified/bundled artifact, or the content is a minified bundle. Never
    raises on a malformed path."""
    path = str(f or "").replace("\\", "/")
    if not path:
        return False
    for seg in path.split("/"):
        if seg.lower() in VENDOR_DIR_SEGMENTS:
            return True
    name = path.rsplit("/", 1)[-1].lower()
    if any(name.endswith(s) for s in _VENDOR_FILE_SUFFIXES):
        return True
    if repo and _is_path(f):
        try:
            p = Path(f) if Path(f).is_absolute() else Path(repo) / f
            if _is_minified(p):
                return True
        except (OSError, ValueError):
            pass
    return False


def _is_path(f: object) -> bool:
    """A usable relative path: a non-empty string (fail-soft filter for the
    junk a malformed caller can pass)."""
    return isinstance(f, str) and bool(f)


def isolate_vendor(files: list[str],
                   repo: str | None = None) -> tuple[list[str], list[str]]:
    """(app_files, vendor_files), both sorted: third-party dependencies never
    get their own structural treatment, they get one budget-exempt unit."""
    app: list[str] = []
    vendor: list[str] = []
    for f in files or []:
        if not _is_path(f):
            continue
        (vendor if _is_vendor_file(f, repo) else app).append(f)
    return sorted(app), sorted(vendor)


def _vendor_unit(vendor_files: list[str], taken: set[str]) -> dict:
    """The vendor unit: budget-exempt (node_modules is nobody's byte budget)
    and collision-safe named ("vendor", else "vendor-2", ...)."""
    name = VENDOR_UNIT_NAME
    i = 2
    while name in (taken or set()):
        name = f"{VENDOR_UNIT_NAME}-{i}"
        i += 1
    return {"name": name, "files": sorted(set(vendor_files)),
            "reason": "vendor-deps", "budget_exempt": True}


# --- P0.2 small-repo single unit ---------------------------------------------


def _dominant_top_dir(files: list[str], weight_of: dict[str, int]) -> str:
    """Top-level directory holding the most bytes (sorted tie-break); "app"
    when every file is top-level or the winner carries no name at all."""
    total: dict[str, int] = defaultdict(int)
    for f in files:
        parts = [p for p in str(f).replace("\\", "/").split("/") if p and p != "."]
        top = parts[0] if len(parts) > 1 else ""
        try:
            total[top] += int(weight_of.get(f, 0) or 0)
        except (TypeError, ValueError):
            pass
    if not total:
        return "app"
    best = sorted(total.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return best or "app"


def small_repo_unit(app_files: list[str],
                    weight_of: dict[str, int] | None = None,
                    target: int = 0,
                    repo: str = ".") -> dict | None:
    """One unit for a repo that fits BOTH the file count and the byte budget
    (P0.2); None when the rule is off or the repo does not qualify."""
    if single_unit_max_files() <= 0:
        return None
    fs = sorted({f for f in (app_files or []) if _is_path(f)})
    if not fs or len(fs) > single_unit_max_files():
        return None
    w = weight_of if weight_of is not None else _file_weights(repo, fs)
    t = target if target > 0 else partition_target(w)
    try:
        total = sum(int(w.get(f, 0) or 0) for f in fs)
    except (TypeError, ValueError):
        total = 0
    if total > t:
        return None
    return {"name": _dominant_top_dir(fs, w), "files": fs,
            "reason": "small-repo-single-unit"}


# --- P1.3 misc policy helpers -------------------------------------------------


def _is_non_code(f: str) -> bool:
    """Docs/config/manifest/assets by extension, exact file name, or support kind.
    Everything else counts as code (and never merges into misc)."""
    name = str(f or "").replace("\\", "/").rsplit("/", 1)[-1]
    if name.lower() in _NON_CODE_NAMES_LOWER:
        return True
    if PurePosixPath(name).suffix.lower() in _NON_CODE_EXTS_LOWER:
        return True
    return support_file_kind(f) in {"docs", "asset", "config"}


def _support_reason_kind(reason: object) -> str | None:
    for part in str(reason or "").split("+"):
        if part.startswith("unowned-support:"):
            return part.partition(":")[2] or "other"
    return None


def _unit_bytes(u: dict, weight_of: dict[str, int] | None) -> int:
    if not weight_of:
        return 0
    try:
        return sum(int(weight_of.get(f, 0) or 0) for f in (u.get("files") or []))
    except (TypeError, ValueError):
        return 0


def _edge_index(edges: dict | None) -> dict[str, dict[str, int]]:
    """file -> {neighbour: weight}, both directions ((a,b) means a needs b).
    Malformed entries are skipped, never raised."""
    idx: dict[str, dict[str, int]] = {}
    if not edges or not hasattr(edges, "items"):
        return idx
    try:
        items = list(edges.items())
    except Exception:
        return idx
    for key, w in items:
        try:
            a, b = key
        except (TypeError, ValueError):
            continue
        if not a or not b or a == b:
            continue
        try:
            w = int(w)
        except (TypeError, ValueError):
            continue
        idx.setdefault(a, {})
        idx.setdefault(b, {})
        idx[a][b] = idx[a].get(b, 0) + w
        idx[b][a] = idx[b].get(a, 0) + w
    return idx


def _cross_weight(a: list[str], b: list[str],
                  idx: dict[str, dict[str, int]]) -> int:
    """Total coupling between two file sets: sum over all cross pairs."""
    if not idx or not a or not b:
        return 0
    sb = set(b)
    total = 0
    for f in a:
        for other, w in (idx.get(f) or {}).items():
            if other in sb:
                total += w
    return total


def _fresh_unit_name(files: list[str], n: int) -> str:
    """Name for a unit that must not be called "misc": its first file's top
    directory, else that file's basename stem, else unit-<n>."""
    fs = sorted(f for f in (files or []) if f)
    if not fs:
        return f"unit-{n}"
    parts = fs[0].replace("\\", "/").split("/")
    if len(parts) > 1 and parts[0]:
        return parts[0][:60]
    stem = PurePosixPath(fs[0]).stem
    return stem[:60] or f"unit-{n}"


def _keep_tiny_singleton(u: dict, n: int) -> dict:
    """A tiny CODE unit kept on its own. A stray code unit named "misc" is
    renamed from its first file, so code is never labelled as docs."""
    name = u.get("name")
    if name == "misc":
        name = _fresh_unit_name(u.get("files") or [], n)
    return {"name": name,
            "files": sorted(f for f in (u.get("files") or []) if f),
            "reason": u.get("reason", "")}


def _merge_tiny_legacy(units: list[dict],
                       _min: int) -> tuple[list[dict], dict | None]:
    """Legacy policy: tiny units fold into misc except explicit support groups."""
    misc = next((u for u in units if u["name"] == "misc"), None)
    big = [u for u in units
           if (len(u["files"]) >= _min or u["name"] == "misc"
               or _support_reason_kind(u.get("reason")) is not None)]
    for u in units:
        if (len(u["files"]) < _min and u["name"] != "misc"
                and _support_reason_kind(u.get("reason")) is None):
            if misc is None:
                misc = {"name": "misc", "files": [], "reason": "merged-tiny-units"}
                big.append(misc)
            misc["files"] = sorted(set(misc["files"]) | set(u["files"]))
    return big, misc


def _merge_tiny_policy(units: list[dict], _min: int, edges: dict | None,
                       weight_of: dict[str, int] | None,
                       target: int) -> tuple[list[dict], dict | None]:
    """P1.3 policy (PARTITION_MISC_CODE_MERGE): unowned support groups remain
    explicit; other non-code leftovers fold into misc. Tiny CODE units never
    do. Each tiny code unit
    merges into the kept unit it is most coupled to (most cross-pair edge
    weight; ties: larger unit bytes, then unit name) when that still fits the
    byte budget — otherwise it stays a singleton of its own."""
    kept: list[dict] = []
    misc: dict | None = None
    tiny_code: list[dict] = []
    for u in units:
        fs = [f for f in (u.get("files") or []) if f]
        if _support_reason_kind(u.get("reason")) is not None:
            kept.append(_keep_tiny_singleton(u, len(kept) + 1))
            continue
        non_code = all(_is_non_code(f) for f in fs)
        if u.get("name") == "misc" and (len(fs) >= _min or non_code):
            # An existing misc is the catch-all whenever it can hold a unit; a
            # stray tiny CODE unit named misc falls through to tiny_code below
            # and gets renamed (code is never labelled as docs).
            misc = u
            kept.append(u)
        elif len(fs) >= _min:
            kept.append(u)
        elif non_code:
            if misc is not None:
                misc["files"] = sorted(set(misc["files"]) | set(fs))
            else:
                misc = {"name": "misc", "files": sorted(fs),
                        "reason": "merged-tiny-units"}
                kept.append(misc)
        else:
            tiny_code.append(u)
    idx = _edge_index(edges) if edges else {}
    for n, u in enumerate(sorted(tiny_code, key=lambda x: str(x.get("name"))), 1):
        fs = [f for f in (u.get("files") or []) if f]
        ub = _unit_bytes({"files": fs}, weight_of)
        cands: list[tuple] = []
        for v in kept:
            if (v is u or v.get("budget_exempt") or v["name"] == "misc"
                    or _support_reason_kind(v.get("reason")) is not None):
                continue
            w = _cross_weight(fs, [f for f in (v.get("files") or []) if f], idx)
            if w <= 0:
                continue
            vb = _unit_bytes(v, weight_of)
            if target > 0 and vb + ub > target:
                continue
            cands.append((-w, -vb, str(v.get("name")), v))
        if not cands:
            kept.append(_keep_tiny_singleton(u, n))
            continue
        cands.sort(key=lambda c: c[:3])
        pick = cands[0][3]
        pick["files"] = sorted(set(pick["files"]) | set(fs))
        prev = pick.get("reason", "")
        if u.get("reason") and u.get("reason") not in prev:
            pick["reason"] = f"{prev}+{u['reason']}" if prev else u["reason"]
    return kept, misc


def _fold_to_cap(units: list[dict], max_units: int,
                 weight_of: dict[str, int], target: int,
                 edges: dict | None = None) -> list[dict]:
    """Re-apply MAX_UNITS after size-splitting WITHOUT breaking the budget.

    Whole units merge, smallest first, into the neighbor with highest edge
    coupling that still fits under target (falling back to the lightest unit).
    A merge that would blow the target is skipped, so at worst the unit count
    stays above the cap — an over-budget blob is never re-created just to
    satisfy a soft cap. Unit dicts are copied before mutation: the caller may
    reject this fold and reuse its own list, which must not carry the folded
    files (aliasing would duplicate them)."""
    out = [dict(u, files=list(u.get("files") or [])) for u in units]
    idx = _edge_index(edges) if edges else {}
    for _ in range(len(out) + 1):
        if len(out) <= max_units:
            break
        out.sort(key=lambda u: (_unit_bytes(u, weight_of),
                                -len(u.get("files") or []), str(u.get("name"))))
        i = 0
        while i < len(out) and out[i].get("budget_exempt"):
            i += 1
        if i >= len(out):
            break
        small = out[i]
        sb = _unit_bytes(small, weight_of)
        sfiles = [f for f in (small.get("files") or []) if f]
        small_kind = _support_reason_kind(small.get("reason"))
        fits = [j for j, v in enumerate(out)
                if j != i and not v.get("budget_exempt")
                and _unit_bytes(v, weight_of) + sb <= target
                and _support_reason_kind(v.get("reason")) == small_kind
                and (small_kind is None
                     or len(v.get("files") or []) + len(sfiles)
                     <= _SUPPORT_GROUP_MAX_FILES)]
        if not fits:
            break
        # Prefer highest cross-coupling weight first, then lightest byte weight
        best = min(fits, key=lambda j: (
            -_cross_weight(sfiles, out[j].get("files") or [], idx),
            _unit_bytes(out[j], weight_of),
            str(out[j].get("name"))))
        tgt = out[best]
        tgt["files"] = sorted(set(tgt["files"]) | set(sfiles))
        prev = tgt.get("reason", "")
        if small.get("reason") and small.get("reason") not in prev:
            tgt["reason"] = f"{prev}+{small['reason']}" if prev else small["reason"]
        out.pop(i)
    return out


def _attach_linked_support(files: list[str], units: list[dict],
                           edges: dict | None,
                           weight_of: dict[str, int] | None,
                           target: int) -> list[str]:
    """Attach linked templates/configs to the strongest owning community.

    Direct renderer/config references establish ownership first. Template
    includes/inheritance and config-to-config imports then carry that ownership
    through support-file chains. Files without a strong path to code stay
    unowned for the explicit support fallback.
    """
    if not edges or not units:
        return files
    records: list[tuple] = []
    for f in sorted(files):
        kind = support_file_kind(f)
        if kind not in {"template", "config"}:
            continue
        candidates = []
        for unit in units:
            members = [member for member in unit.get("files", []) if member]
            member_set = set(members)
            weights = []
            for other in member_set:
                try:
                    weight = max(int(edges.get((f, other), 0) or 0),
                                 int(edges.get((other, f), 0) or 0))
                except (TypeError, ValueError):
                    continue
                # Bidirectional same-directory soft edges are weight 1 each;
                # use only direct graph/render/config evidence for ownership.
                if weight >= 2:
                    weights.append(weight)
            if not weights:
                continue
            score = sum(weights)
            size = _unit_bytes(unit, weight_of)
            candidates.append((-max(weights), -score, size,
                               str(unit.get("name", "")), unit))
        if candidates:
            candidates.sort(key=lambda item: item[:4])
            records.append((-candidates[0][0], -candidates[0][1], f,
                            kind, candidates))
    records.sort(key=lambda item: (-item[0], -item[1], item[2]))
    attached: set[str] = set()
    for _, _, f, kind, candidates in records:
        fsize = int((weight_of or {}).get(f, 0) or 0)
        for _, _, _, _, unit in candidates:
            current = _unit_bytes(unit, weight_of)
            if target > 0 and current + fsize > target:
                continue
            unit["files"] = sorted(set(unit.get("files") or []) | {f})
            prev = unit.get("reason", "")
            reason = f"linked-support:{kind}"
            if reason not in prev:
                unit["reason"] = f"{prev}+{reason}" if prev else reason
            attached.add(f)
            break
    # Propagate ownership through template inheritance/includes and config
    # imports. Process paths in sorted order and repeat until no more files
    # join, so the result is independent of input ordering.
    remaining = set(files) - attached
    while remaining:
        progress = False
        for f in sorted(remaining):
            kind = support_file_kind(f)
            if kind not in {"template", "config"}:
                continue
            fsize = int((weight_of or {}).get(f, 0) or 0)
            candidates = []
            for unit in units:
                members = [member for member in unit.get("files", [])
                           if support_file_kind(member) == kind]
                weights = []
                for other in members:
                    try:
                        weight = max(int(edges.get((f, other), 0) or 0),
                                     int(edges.get((other, f), 0) or 0))
                    except (TypeError, ValueError):
                        continue
                    if weight >= 2:
                        weights.append(weight)
                if not weights:
                    continue
                size = _unit_bytes(unit, weight_of)
                if target > 0 and size + fsize > target:
                    continue
                candidates.append((-max(weights), -sum(weights), size,
                                   str(unit.get("name", "")), unit))
            if not candidates:
                continue
            candidates.sort(key=lambda item: item[:4])
            unit = candidates[0][4]
            unit["files"] = sorted(set(unit.get("files") or []) | {f})
            prev = unit.get("reason", "")
            reason = f"linked-support:{kind}"
            if reason not in prev:
                unit["reason"] = f"{prev}+{reason}" if prev else reason
            remaining.remove(f)
            attached.add(f)
            progress = True
        if not progress:
            break
    return [f for f in files if f not in attached]


def _support_group_units(groups: dict[tuple[str, str], list[str]],
                         prefix: str, weight_of: dict[str, int] | None,
                         target: int) -> list[dict]:
    """Small, explicit chunks for support files with no owning code unit."""
    units: list[dict] = []
    root = f"{prefix}/" if prefix else ""
    # Group support files by *kind* globally rather than by directory, so a
    # repository never becomes a spray of single-file support buckets per
    # parent path. Each kind forms at most a handful of byte-bounded chunks.
    by_kind: dict[str, list[str]] = defaultdict(list)
    for (kind, _parent), members in (groups or {}).items():
        by_kind[kind].extend(members or [])
    for kind in sorted(by_kind):
        members = sorted(set(by_kind[kind]))
        chunks: list[list[str]] = []
        current: list[str] = []
        current_bytes = 0
        for f in members:
            size = int((weight_of or {}).get(f, 0) or 0)
            if current and (len(current) >= _SUPPORT_GROUP_MAX_FILES
                            or (target > 0 and current_bytes + size > target)):
                chunks.append(current)
                current, current_bytes = [], 0
            current.append(f)
            current_bytes += size
        if current:
            chunks.append(current)
        base = f"{root}support-{kind}"
        for index, chunk in enumerate(chunks, 1):
            name = base if len(chunks) == 1 else f"{base}/part-{index}"
            units.append({"name": name, "files": chunk,
                          "reason": f"unowned-support:{kind}"})
    return units


def _units_from_graphify(repo: str, files: list[str],
                          weight_of: dict[str, int] | None = None,
                          target: int = 0,
                          edges: dict | None = None) -> list[dict] | None:
    file_community = file_communities(load_partition_graph(repo))
    if not file_community:
        return None
    # Suffix index (O(files), not O(files x communities)): the graph records
    # repo-relative paths while the file list may carry a prefix, so a file
    # matches through an exact key, a key that suffixes the file, or a file
    # that suffixes a key. First match wins, deterministic by construction.
    exact: dict[str, int] = {}
    key_suffix: dict[str, int] = {}
    for key, comm in file_community.items():
        exact.setdefault(key, comm)
        parts = key.split("/")
        for i in range(1, len(parts)):
            key_suffix.setdefault("/".join(parts[i:]), comm)

    def _match(f: str) -> int | None:
        if f in exact:
            return exact[f]
        parts = f.split("/")
        for i in range(1, len(parts)):
            if (s := "/".join(parts[i:])) in exact:
                return exact[s]
        return key_suffix.get(f)

    by_comm: dict[int, list[str]] = defaultdict(list)
    unmapped: list[str] = []
    support_files: list[str] = []
    for f in files:
        if support_file_kind(f) in {"template", "config"}:
            support_files.append(f)
            continue
        hit = _match(f)
        if hit is None:
            unmapped.append(f)
        else:
            by_comm[hit].append(f)
    units = [{"name": f"community-{c}", "files": sorted(fs),
              "reason": "graphify-leiden-community"}
             for c, fs in sorted(by_comm.items())]
    unowned_support = _attach_linked_support(support_files, units, edges,
                                             weight_of, target)
    unmapped.extend(unowned_support)
    # Linked templates/configs join their owning community. Remaining support
    # files become small typed groups; other unmapped files use directory fallback.
    if unmapped:
        units.extend(_raw_units_from_dirs(repo, unmapped, prefix="unmapped",
                                          weight_of=weight_of, target=target))
    return _normalize_units(units, weight_of, target, edges=edges)


def _raw_units_from_dirs(repo: str, files: list[str], prefix: str = "",
                           weight_of: dict[str, int] | None = None,
                           target: int = 0) -> list[dict]:
    """Raw directory and support-group units without normalization."""
    groups: dict[str, list[str]] = defaultdict(list)
    support_groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for f in files:
        parts = [p for p in str(f).replace("\\", "/").split("/") if p and p != "."]
        kind = support_file_kind(f) if prefix else None
        if kind:
            parent = str(PurePosixPath(str(f).replace("\\", "/")).parent)
            support_groups[(kind, parent)].append(f)
            continue
        key = parts[0] if len(parts) > 1 else "root"
        # Strip repo-prefix noise: a lone dir equal to repo basename merges to root.
        groups[key].append(f)
    try:
        base = Path(repo).name.lower()
        if base in groups and len(groups) > 1 and len(groups[base]) <= min_files():
            groups["root"].extend(groups.pop(base))
    except Exception:
        pass
    units = [{"name": f"{prefix}/{k}" if prefix else k, "files": sorted(v),
               "reason": "top-level-directory"}
             for k, v in sorted(groups.items())]
    units.extend(_support_group_units(support_groups, prefix, weight_of, target))
    return units


def _units_from_dirs(repo: str, files: list[str], prefix: str = "",
                      weight_of: dict[str, int] | None = None,
                      target: int = 0,
                      edges: dict | None = None) -> list[dict]:
    units = _raw_units_from_dirs(repo, files, prefix=prefix, weight_of=weight_of, target=target)
    return _normalize_units(units, weight_of, target, edges=edges)


def _file_weights(repo: str, files: list[str]) -> dict[str, int]:
    """Byte sizes for budget weighting. stat-only; unstattable = 0 (fail-soft:
    an unreadable file never breaks partitioning, it just weighs nothing)."""
    out: dict[str, int] = {}
    base = Path(repo or ".").resolve()
    for f in files:
        try:
            p = (Path(f) if Path(f).is_absolute() else base / f).resolve()
            if not p.is_relative_to(base):
                out[f] = 0
            else:
                out[f] = max(0, p.stat().st_size)
        except (OSError, ValueError):
            out[f] = 0
    return out


def partition_target(weight_of: dict[str, int]) -> int:
    """Per-unit ceiling in BYTES.

    = max(loc_budget x bytes_per_loc, ceil(code_total_bytes / MAX_UNITS))

    The LOC budget (default 10k) governs repos that fit in MAX_UNITS units;
    for bigger repos MAX_UNITS raises the ceiling so a large repo can spread
    across the configured unit count instead of collapsing into one blob.
    Binary assets (.png, .pdf, .mp4, etc.) are excluded from total_bytes so
    non-code blobs do not inflate the audit target for actual source code.
    """
    try:
        from harness.config import load_config
        cfg = load_config()
    except Exception:
        cfg = {}
    try:
        _part = (cfg or {}).get("partition") or {}
        loc = int(_part.get("loc_budget", 10000) or 0)
        bpl = float(_part.get("bytes_per_loc", 40) or 40)
    except (TypeError, ValueError):
        loc, bpl = 10000, 40.0
    nominal = int(loc * bpl) if loc > 0 and bpl > 0 else 0
    # Exclude non-code assets from the total byte calculation
    total = sum(v for f, v in weight_of.items() if support_file_kind(f) != "asset")
    cap = max_units()  # MAX_UNITS (env), <= 0 meaning unlimited
    derived = -(-total // cap) if total > 0 else 0  # ceil division
    return max(nominal, derived)


def _split_over_budget(files: list[str], weight_of: dict[str, int],
                        target: int,
                        edges: dict | None = None) -> list[list[str]]:
    """Deterministic, locality- and coupling-preserving split of one oversized unit.

    When graph edges exist among these files, parts are seeded by the highest-degree
    files and greedily expanded by cross-coupling up to the byte budget target.
    Files without edge coupling fall back to directory locality grouping.
    Everything sorts deterministically by degree, weight, and path (lexical tie-breaking).
    The ceiling `target` is strictly enforced so verify_partition never fails.
    """
    if not files:
        return []
    if target <= 0:
        return [sorted(files)]

    idx = _edge_index(edges) if edges else {}
    file_set = set(files)
    # Check if there is meaningful internal edge coupling among the files
    has_internal_edges = False
    if idx:
        for f in file_set:
            if any(nbr in file_set for nbr in idx.get(f, {})):
                has_internal_edges = True
                break

    if has_internal_edges:
        # Edge-aware greedy clustering
        unassigned = set(files)
        parts: list[list[str]] = []
        weights: list[int] = []

        while unassigned:
            # Seed selection: pick the unassigned file with highest internal degree,
            # then largest byte size, then lexical path.
            def seed_key(f: str):
                deg = sum(w for nbr, w in idx.get(f, {}).items() if nbr in unassigned)
                return (-deg, -weight_of.get(f, 0), f)

            seed = min(unassigned, key=seed_key)
            unassigned.remove(seed)
            chunk = [seed]
            cw = weight_of.get(seed, 0)

            # Greedily pull in highest cross-coupled unassigned files that fit
            while unassigned:
                chunk_set = set(chunk)
                candidates = []
                for f in unassigned:
                    fw = weight_of.get(f, 0)
                    if cw + fw > target and chunk:
                        continue
                    cross = sum(idx.get(f, {}).get(cf, 0) for cf in chunk_set)
                    if cross > 0:
                        candidates.append((-cross, -fw, f))

                if not candidates:
                    break
                candidates.sort()
                best_f = candidates[0][2]
                unassigned.remove(best_f)
                chunk.append(best_f)
                cw += weight_of.get(best_f, 0)

            parts.append(sorted(chunk))
            weights.append(cw)

        # Try to merge tiny tail parts into previous parts if they have coupling and fit under 1.25x target
        if len(parts) > 1:
            max_ceiling = int(target * 1.25)
            # Sort parts: largest first, so smaller remainder parts merge into core parts
            sorted_indices = sorted(range(len(parts)), key=lambda i: (-weights[i], parts[i][0]))
            compacted_parts: list[list[str]] = []
            compacted_weights: list[int] = []
            for i in sorted_indices:
                p, pw = parts[i], weights[i]
                best_idx = -1
                best_score = (0, -1)
                for ci, (cp, cpw) in enumerate(zip(compacted_parts, compacted_weights)):
                    if cpw + pw <= max_ceiling:
                        cross = _cross_weight(p, cp, idx)
                        if cross > 0:
                            score = (cross, -cpw)
                            if score > best_score:
                                best_score = score
                                best_idx = ci
                if best_idx >= 0:
                    compacted_parts[best_idx].extend(p)
                    compacted_parts[best_idx].sort()
                    compacted_weights[best_idx] += pw
                else:
                    compacted_parts.append(p)
                    compacted_weights.append(pw)
            parts = compacted_parts

        return [p for p in parts if p]

    # Fallback to directory locality when no internal edges exist
    groups: dict[str, list[str]] = defaultdict(list)
    for f in files:
        norm_f = str(f).replace("\\", "/")
        groups[str(PurePosixPath(norm_f).parent)].append(f)
    ordered = sorted(groups.items(),
                     key=lambda kv: (-sum(weight_of.get(f, 0) for f in kv[1]),
                                     kv[0]))
    parts: list[list[str]] = []
    weights: list[int] = []
    for gname, gfiles in ordered:
        gfiles = sorted(gfiles)
        gw = sum(weight_of.get(f, 0) for f in gfiles)
        if gw > target:
            # A directory that alone exceeds the budget: locality is already
            # as good as it will get, so chunk in path order rather than
            # emitting one part that still blows the ceiling.
            chunk: list[str] = []
            cw = 0
            for f in gfiles:
                fw = weight_of.get(f, 0)
                if chunk and cw + fw > target:
                    parts.append(chunk)
                    weights.append(cw)
                    chunk, cw = [], 0
                chunk.append(f)
                cw += fw
            if chunk:
                parts.append(chunk)
                weights.append(cw)
            continue
        # Best-fit: the lightest part that still fits (first on ties).
        best = -1
        for i, w in enumerate(weights):
            if w + gw <= target and (best < 0 or w < weights[best]):
                best = i
        if best < 0:
            parts.append(list(gfiles))
            weights.append(gw)
        else:
            parts[best].extend(gfiles)
            weights[best] += gw
    return [p for p in parts if p]


def _balance_units(units: list[dict], weight_of: dict[str, int],
                        target: int,
                        skip_exempt: bool = False,
                        edges: dict | None = None) -> list[dict]:
    """Split any unit over 1.25x byte target. No-op when target <= 0.

    The LLM planner output is not size-constrained; this is the stage that
    makes the budget an invariant regardless of who proposed the units.
    Units within 1.25x target are preserved to maintain feature cohesion.
    skip_exempt leaves budget_exempt units (vendor) untouched.
    """
    if target <= 0:
        return units
    max_ceiling = int(target * 1.25)
    out: list[dict] = []
    for u in units:
        files = [f for f in (u.get("files") or []) if f]
        if not files:
            continue
        if skip_exempt and u.get("budget_exempt"):
            out.append(u)
            continue
        if sum(weight_of.get(f, 0) for f in files) <= max_ceiling:
            out.append(u)
            continue
        parts = _split_over_budget(files, weight_of, target, edges=edges)
        if len(parts) <= 1:
            out.append(u)  # a single oversized file cannot be split further
            continue
        reason = u.get("reason", "")
        for i, pf in enumerate(parts, start=1):
            out.append({"name": f"{u['name']}-part{i}", "files": sorted(pf),
                         "reason": f"{reason}+size-split" if reason else "size-split"})
    return out


def verify_partition(units: list[dict], all_files: list[str],
                       weight_of: dict[str, int] | None = None,
                       target: int = 0) -> dict:
    """Coverage + ceiling invariants. Asserts; returns run stats."""
    names = [u.get("name") for u in units if u.get("name")]
    name_counts: dict[str, int] = defaultdict(int)
    for n in names:
        name_counts[n] += 1
    dupe_names = sorted(n for n, c in name_counts.items() if c > 1)
    assert not dupe_names, f"duplicate unit names: {dupe_names[:10]}"

    seen = [f for u in units for f in (u.get("files") or [])]
    counts: dict[str, int] = defaultdict(int)
    for f in seen:
        counts[f] += 1
    dupes = sorted(f for f, n in counts.items() if n > 1)
    missing = sorted({f for f in all_files if f} - set(seen))
    assert not dupes, f"files assigned to multiple units: {dupes[:10]}"
    assert not missing, f"files in no unit: {missing[:10]}"
    if weight_of and target > 0:
        # A lone oversized file is unsplittable by the balancer's own rule
        # ("cannot be split further"), so a one-file unit over target is not
        # a violation. budget_exempt units (vendor) are out of budget scope.
        max_ceiling = int(target * 1.25)
        over = [str(u.get("name")) for u in units
                if not u.get("budget_exempt")
                and len(u.get("files") or []) > 1
                and sum(weight_of.get(f, 0) for f in (u.get("files") or [])) > max_ceiling]
        assert not over, f"units over the {max_ceiling}-byte budget (1.25x target): {over}"
    return {"units": len(units), "files": len(seen),
            "max_unit_bytes": max((sum(weight_of.get(f, 0) for f in (u.get("files") or []))
                                   for u in units), default=0) if weight_of else 0}




def _rebalance_units(units: list[dict], weight_of: dict[str, int] | None,
                      target: int) -> list[dict]:
    """Last-mile rebalance: merge support micro-units and split giant leftovers.

    Conservative - only merges units with <= 3 files or < 5% of the byte
    budget into a neighbour that can absorb them without crossing 1.25x
    target; leaves semantic code units alone. Splits any remaining unit
    above 1.25x target into byte-bounded chunks. Only runs with weights so
    direct unit tests keep their structural behavior.
    """
    out = [dict(u) for u in units if u.get("files")]
    if not weight_of or target <= 0 or not out:
        return out
    max_ceiling = int(target * 1.25)
    # Only scattershot support shards are candidates for merging. Code
    # singletons and the canonical `misc` bucket deliberately stay alone.
    def _is_mergeable_micro(u: dict) -> bool:
        name = str(u.get("name", "")).lower()
        return ("support" in name or "unmapped" in name or "part-" in name)
    micro_idx = [i for i, u in enumerate(out)
                 if (not u.get("budget_exempt")
                     and (len(u["files"]) <= 3
                          or _unit_bytes(u, weight_of) < max(1, int(target * 0.05)))
                     and _is_mergeable_micro(u))]
    # drop micro units into the best (smallest full) neighbour
    for i in sorted(micro_idx, reverse=True):
        tiny = out.pop(i)
        tiny_bytes = _unit_bytes(tiny, weight_of)
        # prefer a neighbour that stays under 1.25x target; if none fits, keep tiny unit as its own unit
        candidates = [u for u in out if not u.get("budget_exempt")]
        absorbed = None
        for u in candidates:
            if (_unit_bytes(u, weight_of) + tiny_bytes <= max_ceiling):
                absorbed = u
                break
        if absorbed is None:
            out.append(tiny)
            continue
        absorbed["files"] = sorted(set(absorbed.get("files", [])) | set(tiny["files"]))
        if tiny.get("reason") and tiny.get("reason") not in (absorbed.get("reason") or ""):
            absorbed["reason"] = (absorbed.get("reason") or "") + "+merged-tiny"
    # split oversized non-exempt units (incl. any catch-all misc)
    rebuilt: list[dict] = []
    for u in out:
        bytes_u = _unit_bytes(u, weight_of)
        name_l = str(u.get("name", "")).lower()
        supportish = ("support" in name_l or "unmapped" in name_l or "misc" in name_l)
        if (u.get("budget_exempt") or bytes_u <= max_ceiling or not supportish):
            rebuilt.append(u)
            continue
        chunk: list[str] = []
        cur = 0
        part = 1
        for f in sorted(u["files"]):
            size = int(weight_of.get(f, 0) or 0)
            if chunk and cur + size > target:
                name = u["name"] if part == 1 else f"{u['name']}-part-{part}"
                rebuilt.append({"name": name, "files": sorted(chunk),
                                "reason": (u.get("reason", "") + "+size-split").strip("+"),
                                **({"budget_exempt": True} if u.get("budget_exempt") else {})})
                chunk, cur, part = [], 0, part + 1
            chunk.append(f)
            cur += size
        if chunk:
            name = u["name"] if part == 1 else f"{u['name']}-part-{part}"
            rebuilt.append({"name": name, "files": sorted(chunk),
                            "reason": (u.get("reason", "") + "+size-split").strip("+"),
                            **({"budget_exempt": True} if u.get("budget_exempt") else {})})
    return rebuilt


def _normalize_units(units: list[dict], weight_of: dict[str, int] | None = None,
                      target: int = 0, edges: dict | None = None) -> list[dict]:
    """Merge, cap, and guarantee UNIQUE names (one hunter label each).

    MIN_FILES/MIN_FILES env-overridable (0/1 disables tiny-merge, keeping
    singletons separate). MAX_UNITS env-overridable (0=unlimited).

    With PARTITION_MISC_CODE_MERGE on, tiny CODE units never land in misc
    (they merge into their most-coupled in-budget neighbour per the `edges`
    coupling, or stay singletons); only untyped non-code leftovers absorb into misc.
    Either way the byte budget is re-enforced after the merge/cap steps, so
    re-merging cannot re-form an over-budget blob. budget_exempt units are
    never split or folded away.
    """
    cap = max_units()  # MAX_UNITS (env), <= 0 meaning unlimited
    # Re-read MIN_FILES live so tests/env can disable tiny-merge without reimport.
    _min = min_files()
    if _min < 0:
        _min = 0
    # 1. Combine same-named units (inner + outer misc must fuse, never coexist).
    merged: dict[str, dict] = {}
    for u in units:
        if not u.get("files"):
            continue
        if u["name"] in merged:
            merged[u["name"]]["files"] = sorted(
                set(merged[u["name"]]["files"]) | set(u["files"]))
            prev = merged[u["name"]].get("reason", "")
            if u.get("reason") and u.get("reason") not in prev:
                merged[u["name"]]["reason"] = f"{prev}+{u['reason']}"
            if u.get("budget_exempt"):
                merged[u["name"]]["budget_exempt"] = True
        else:
            entry = {"name": u["name"],
                     "files": sorted(set(u["files"])),
                     "reason": u.get("reason", "")}
            if u.get("budget_exempt"):
                entry["budget_exempt"] = True
            merged[u["name"]] = entry
    units = list(merged.values())
    # 1b. Size balancing: split units over the per-agent byte budget so no
    # hunter inherits an unbounded unit. Skipped when no weights are supplied
    # (direct unit tests keep the pure structural behavior).
    if weight_of is not None and target > 0:
        units = _balance_units(units, weight_of, target, edges=edges)
    # 2. Merge tiny units: legacy (everything into misc) or the P1.3 code
    # policy (only non-code into misc, tiny code couples or stays singleton).
    if misc_code_merge_enabled():
        big, misc = _merge_tiny_policy(units, _min, edges, weight_of, target)
    else:
        big, misc = _merge_tiny_legacy(units, _min)
    # 3. Cap: fold overflow by support category, keeping unrelated support
    # classes out of the application-code catch-all.
    if len(big) > cap:
        big.sort(key=lambda u: (-len(u["files"]), str(u.get("name", ""))))
        keep_len = min(cap, len(big) - 1)

        def _explicit_support_groups(folded_units: list[dict]) -> list[dict]:
            grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
            for unit in folded_units:
                kind = _support_reason_kind(unit.get("reason"))
                if not kind:
                    continue
                for f in unit.get("files") or []:
                    parent = str(PurePosixPath(
                        str(f).replace("\\", "/")).parent)
                    grouped[(kind, parent)].append(f)
            return _support_group_units(grouped, "support-cap", weight_of,
                                        target)

        while keep_len > 0:
            keep, fold = big[:keep_len], big[keep_len:]
            support_units = _explicit_support_groups(fold)
            needs_misc = (any(_support_reason_kind(u.get("reason")) is None
                              for u in fold)
                          and not any(u.get("name") == "misc" for u in keep))
            extra = len(support_units) + int(needs_misc)
            if keep_len + extra <= cap:
                break
            if keep_len <= 1:
                break
            keep_len = max(1, keep_len - (keep_len + extra - cap))
        keep, fold = big[:keep_len], big[keep_len:]
        folded_other: list[str] = []
        for u in fold:
            kind = _support_reason_kind(u.get("reason"))
            if kind:
                continue
            else:
                folded_other.extend(u["files"])
        keep.extend(_explicit_support_groups(fold))
        if folded_other:
            misc = next((u for u in keep if u.get("name") == "misc"), None)
            if misc is None:
                misc = {"name": "misc", "files": [],
                        "reason": "folded-over-cap"}
                keep.append(misc)
            misc["files"] = sorted(set(misc["files"]) | set(folded_other))
        big = keep
    # 3b. Re-enforce the byte budget AFTER merge/cap: misc absorbs tiny and
    # folded units alike, so both steps can outgrow the target. Split the
    # offenders (never the budget_exempt ones). When the split would exceed
    # MAX_UNITS, the fold that re-forms the over-budget blob is refused: the
    # byte budget is the asserted invariant, the cap is a soft bound.
    if weight_of and target > 0:
        for _ in range(2):
            split = _balance_units(big, weight_of, target, skip_exempt=True, edges=edges)
            if len(split) <= cap:
                big = split
                break
            folded = _fold_to_cap(split, cap, weight_of, target, edges=edges)

            def _over(u: dict) -> bool:
                return not u.get("budget_exempt") and len(u.get("files") or []) > 1 and sum(weight_of.get(f, 0) for f in u["files"]) > target

            big = split if any(_over(u) for u in folded) else folded
    # 3c. Rebalance micro/giant units from stage 2.
    if weight_of and target > 0:
        big = _rebalance_units(big, weight_of, target)
    # 4. Defensive: unique names guaranteed even if logic above regresses.
    taken: set[str] = set()
    for u in big:
        name = u["name"]
        if name in taken:
            base = name
            i = 2
            while f"{base}-{i}" in taken:
                i += 1
            u["name"] = f"{base}-{i}"
        taken.add(u["name"])
    return [u for u in big if u.get("files")]


def _load_partition_edges(repo: str, files: list[str]) -> dict:
    """File-coupling edges for the misc policy.

    graph.file_edges / graph.augment_edges are imported lazily (they may not
    exist yet): an ImportError, a missing graph, or a malformed repo all mean
    "no edge signal", which degrades the policy to "tiny code units stay
    singletons". Never raises.
    """
    try:
        from harness.partitioning.config import framework_edges_enabled
        from harness.partitioning.graph import (augment_edges, file_edges,
                                                load_partition_graph)
        edges = file_edges(load_partition_graph(repo), files)
        if framework_edges_enabled():
            edges = augment_edges(repo, files, edges)
        return dict(edges or {})
    except Exception:
        return {}


def partition_units(repo: str, files: list[str],
                    candidates: list[dict] | None = None) -> list[dict]:
    """Logical units for per-unit hunting. Never returns [].

    Both the unit source (graphify communities, else directories) and the
    size balancer run here, so units are structurally coherent AND bounded by
    the per-agent byte budget (see partition_target). Vendor files split off
    first into one budget-exempt unit; a repo small enough to fit the budget
    collapses into a single unit instead of being scattered.
    """
    files = [f for f in (files or []) if f]
    if not files:
        return []
    app_files, vendor_files = files, []
    if vendor_unit_enabled():
        app_files, vendor_files = isolate_vendor(files, repo)

    def _finish(units: list[dict]) -> list[dict]:
        # Appended AFTER normalization: the vendor unit bypasses tiny-merge
        # and the MAX_UNITS cap, and is named collision-safely.
        if vendor_files:
            units.append(_vendor_unit(vendor_files, {u["name"] for u in units}))
        return units

    if not app_files:  # all-vendor repo: just the vendor unit
        return _finish([])
    weight_of = _file_weights(repo, app_files)
    target = partition_target(weight_of)
    # P0.2 small-repo single unit (file count AND byte budget must both fit).
    if single_unit_enabled():
        single = small_repo_unit(app_files, weight_of, target)
        if single is not None:
            return _finish([single])
    edges = _load_partition_edges(repo, app_files)
    units = _units_from_graphify(repo, app_files, weight_of, target, edges=edges)
    if not units:
        support_files = [
            f for f in app_files
            if support_file_kind(f) in {"template", "config"}]
        if support_files:
            support_set = set(support_files)
            units = _units_from_dirs(
                repo, [f for f in app_files if f not in support_set],
                weight_of=weight_of, target=target, edges=edges)
            unowned = _attach_linked_support(support_files, units, edges,
                                             weight_of, target)
            groups: dict[tuple[str, str], list[str]] = defaultdict(list)
            for f in unowned:
                kind = support_file_kind(f)
                if kind:
                    parent = str(PurePosixPath(f.replace("\\", "/")).parent)
                    groups[(kind, parent)].append(f)
            units.extend(_support_group_units(groups, "unmapped", weight_of,
                                             target))
            units = _normalize_units(units, weight_of, target, edges=edges)
        else:
            units = _units_from_dirs(repo, app_files, weight_of=weight_of,
                                     target=target, edges=edges)
    if not units:
        units = _normalize_units(
            [{"name": "all", "files": sorted(set(app_files)),
              "reason": "fallback-single-unit"}], weight_of, target, edges=edges)
    return _finish(units)
