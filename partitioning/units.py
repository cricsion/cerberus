"""Deterministic partitioning: which files each hunter sees: vendor isolation ->
small-repo collapse -> dir grouping -> byte budget -> normalization.
Units are [{name, files, reason}] (+ budget_exempt on the vendor unit)."""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path, PurePosixPath

from cerberus.config import effective_config
from cerberus.partitioning.config import (
    NON_CODE_EXTS,
    NON_CODE_NAMES,
    PARTITION_MODES,
    VENDOR_DIR_SEGMENTS,
    VENDOR_FILE_SUFFIXES,
    VENDOR_UNIT_NAME,
)
from cerberus.partitioning.graph import support_file_kind

_logger = logging.getLogger(__name__)

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
    """A large single-line/low-newline file (a bundled artifact, not source). Never raises."""
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
    """True for a usable relative path (fail-soft filter for malformed caller input)."""
    return isinstance(f, str) and bool(f)


def isolate_vendor(files: list[str],
                   repo: str | None = None) -> tuple[list[str], list[str]]:
    """(app_files, vendor_files), both sorted; vendor gets one budget-exempt unit."""
    app: list[str] = []
    vendor: list[str] = []
    for f in files or []:
        if not _is_path(f):
            continue
        (vendor if _is_vendor_file(f, repo) else app).append(f)
    return sorted(app), sorted(vendor)


def _vendor_unit(vendor_files: list[str], taken: set[str]) -> dict:
    name = VENDOR_UNIT_NAME
    i = 2
    while name in (taken or set()):
        name = f"{VENDOR_UNIT_NAME}-{i}"
        i += 1
    return {"name": name, "files": sorted(set(vendor_files)),
            "reason": "vendor-deps", "budget_exempt": True}


# --- P0.2 small-repo single unit ---------------------------------------------


def _dominant_top_dir(files: list[str], weight_of: dict[str, int]) -> str:
    """Top-level directory holding the most bytes; tie-breaks by file count,
    then the reverse-alphabetical top name; "app" fallback."""
    total: dict[str, int] = defaultdict(int)
    counts: dict[str, int] = defaultdict(int)
    for f in files:
        parts = [p for p in str(f).replace("\\", "/").split("/") if p and p != "."]
        top = parts[0] if len(parts) > 1 else ""
        total[top] += int(weight_of.get(f, 0) or 0)
        counts[top] += 1
    if not total:
        return "app"
    top_bytes = max(total.values())
    tie = {k: counts[k] for k, b in total.items() if b == top_bytes}
    max_files = max(tie.values())
    best = max(k for k, c in tie.items() if c == max_files)
    return best or "app"


def small_repo_unit(app_files: list[str],
                    weight_of: dict[str, int] | None = None,
                    target: int = 0,
                    repo: str = ".",
                    cfg: dict | None = None) -> dict | None:
    """One unit when the repo fits both the file count and byte budget; None otherwise."""
    max_files = effective_config(cfg)["partition"]["single_unit_max_files"]
    if max_files <= 0:
        return None
    fs = sorted({f for f in (app_files or []) if _is_path(f)})
    if not fs or len(fs) > max_files:
        return None
    w = weight_of if weight_of is not None else _file_weights(repo, fs)
    t = target if target > 0 else partition_target(w, cfg)
    total = sum(int(w.get(f, 0) or 0) for f in fs)
    if total <= 0:
        return None  # no measured bytes: cannot certify the budget, decline
    if total > t:
        return None
    return {"name": _dominant_top_dir(fs, w), "files": fs,
            "reason": "small-repo-single-unit"}


# --- P1.3 misc policy helpers -------------------------------------------------


def _is_non_code(f: str) -> bool:
    """Docs/config/manifest/assets by extension, name, or support kind; else code."""
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
    return sum(int(weight_of.get(f, 0) or 0) for f in (u.get("files") or []))


def _edge_index(edges: dict | None) -> dict[str, dict[str, int]]:
    """file -> {neighbour: weight}, both directions; malformed entries skipped."""
    idx: dict[str, dict[str, int]] = {}
    if not edges or not hasattr(edges, "items"):
        return idx
    for key, w in edges.items():
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
    """Non-"misc" name for a unit: first file's top dir, else stem, else unit-<n>."""
    fs = sorted(f for f in (files or []) if f)
    if not fs:
        return f"unit-{n}"
    parts = fs[0].replace("\\", "/").split("/")
    if len(parts) > 1 and parts[0]:
        return parts[0][:60]
    stem = PurePosixPath(fs[0]).stem
    return stem[:60] or f"unit-{n}"


def _keep_tiny_singleton(u: dict, n: int) -> dict:
    """A tiny code unit kept alone, renamed so code is never labelled "misc"."""
    name = u.get("name")
    if name == "misc":
        name = _fresh_unit_name(u.get("files") or [], n)
    return {"name": name,
            "files": sorted(f for f in (u.get("files") or []) if f),
            "reason": u.get("reason", "")}


def _merge_tiny_legacy(units: list[dict]) -> tuple[list[dict], dict | None]:
    """Legacy policy: singleton units fold into misc except explicit support groups."""
    misc = next((u for u in units if u["name"] == "misc"), None)
    big = [u for u in units
           if (len(u["files"]) >= 2 or u["name"] == "misc"
               or _support_reason_kind(u.get("reason")) is not None)]
    for u in units:
        if (len(u["files"]) < 2 and u["name"] != "misc"
                and _support_reason_kind(u.get("reason")) is None):
            if misc is None:
                misc = {"name": "misc", "files": [], "reason": "merged-tiny-units"}
                big.append(misc)
            misc["files"] = sorted(set(misc["files"]) | set(u["files"]))
    return big, misc


def _merge_tiny_policy(units: list[dict], _min: int, edges: dict | None,
                       weight_of: dict[str, int] | None,
                       target: int) -> tuple[list[dict], dict | None]:
    """P1.3 policy (PARTITION_MISC_CODE_MERGE): support groups stay explicit, non-code
    folds into misc; tiny CODE units merge into their most-coupled in-budget unit."""
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
            # A misc that can hold this unit is the catch-all; a tiny CODE unit
            # named misc falls through to tiny_code and gets renamed.
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
    """Re-apply MAX_UNITS after size-splitting: merge smallest-first into the
    most-coupled neighbor that still fits; over-cap beats an over-budget blob.
    Unit dicts are copied (no aliasing)."""
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



def _support_group_units(groups: dict[tuple[str, str], list[str]],
                         prefix: str, weight_of: dict[str, int] | None,
                         target: int) -> list[dict]:
    """Small, explicit chunks for support files with no owning code unit."""
    units: list[dict] = []
    root = f"{prefix}/" if prefix else ""
    # Group by kind globally, not per directory: a repo must not become a spray
    # of single-file support buckets per parent path.
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


def _raw_units_from_dirs(repo: str, files: list[str], prefix: str = "",
                           weight_of: dict[str, int] | None = None,
                           target: int = 0,
                           cfg: dict | None = None) -> list[dict]:
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
    base = Path(repo).name.lower()
    min_files = effective_config(cfg)["partition"]["min_files"]
    if base in groups and len(groups) > 1 and len(groups[base]) <= min_files:
        groups["root"].extend(groups.pop(base))
    units = [{"name": f"{prefix}/{k}" if prefix else k, "files": sorted(v),
               "reason": "top-level-directory"}
             for k, v in sorted(groups.items())]
    units.extend(_support_group_units(support_groups, prefix, weight_of, target))
    return units


def _units_from_dirs(repo: str, files: list[str], prefix: str = "",
                      weight_of: dict[str, int] | None = None,
                      target: int = 0,
                      edges: dict | None = None,
                      cfg: dict | None = None) -> list[dict]:
    units = _raw_units_from_dirs(repo, files, prefix=prefix,
                                 weight_of=weight_of, target=target, cfg=cfg)
    return _normalize_units(units, weight_of, target, edges=edges, cfg=cfg)


def _file_weights(repo: str, files: list[str]) -> dict[str, int]:
    """Byte sizes for budget weighting; stat-only, unstattable = 0.

    Invariant relied on downstream: every value is a non-negative int, so
    byte-summing helpers coerce with ``int(x or 0)`` without a guard."""
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


def partition_target(weight_of: dict[str, int], cfg: dict | None = None) -> int:
    """Per-unit byte ceiling: max(loc_budget x bytes_per_loc, code_bytes / MAX_UNITS);
    binary assets excluded."""
    part = effective_config(cfg)["partition"]
    loc = int(part["loc_budget"])
    bpl = float(part["bytes_per_loc"])
    nominal = int(loc * bpl) if loc > 0 and bpl > 0 else 0
    total = sum(v for f, v in weight_of.items() if support_file_kind(f) != "asset")
    cap = int(part["max_units"])  # normalized: 0 becomes the unlimited sentinel
    derived = -(-total // cap) if (total > 0 and cap > 0) else 0  # ceil division
    return max(nominal, derived)


def _split_over_budget(files: list[str], weight_of: dict[str, int],
                        target: int,
                        edges: dict | None = None) -> list[list[str]]:
    """Deterministic split of an oversized unit: seeds on the highest-degree file,
    grows greedily by coupling up to `target` (strict); unconnected files fall
    back to directory locality."""
    if not files:
        return []
    if target <= 0:
        return [sorted(files)]

    idx = _edge_index(edges) if edges else {}
    file_set = set(files)
    has_internal_edges = False
    if idx:
        for f in file_set:
            if any(nbr in file_set for nbr in idx.get(f, {})):
                has_internal_edges = True
                break

    if has_internal_edges:
        unassigned = set(files)
        parts: list[list[str]] = []
        weights: list[int] = []

        while unassigned:
            # Seed: highest internal degree, then largest bytes, then lexical path.
            def seed_key(f: str):
                deg = sum(w for nbr, w in idx.get(f, {}).items() if nbr in unassigned)
                return (-deg, -weight_of.get(f, 0), f)

            seed = min(unassigned, key=seed_key)
            unassigned.remove(seed)
            chunk = [seed]
            cw = weight_of.get(seed, 0)

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

        # Merge tail parts into coupled parts that stay under 1.25x target.
        if len(parts) > 1:
            max_ceiling = int(target * 1.25)
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

        # Best-fit compact remaining small parts under the target budget
        if len(parts) > 1:
            final_parts: list[list[str]] = []
            final_weights: list[int] = []
            for p in parts:
                pw = sum(weight_of.get(f, 0) for f in p)
                best_idx = -1
                for fi, (_fp, fpw) in enumerate(zip(final_parts, final_weights)):
                    if fpw + pw <= target:
                        best_idx = fi
                        break
                if best_idx >= 0:
                    final_parts[best_idx].extend(p)
                    final_parts[best_idx].sort()
                    final_weights[best_idx] += pw
                else:
                    final_parts.append(p)
                    final_weights.append(pw)
            parts = final_parts

        return [p for p in parts if p]

    groups: dict[str, list[str]] = defaultdict(list)
    for f in files:
        norm_f = str(f).replace("\\", "/")
        groups[str(PurePosixPath(norm_f).parent)].append(f)
    ordered = sorted(groups.items(),
                     key=lambda kv: (-sum(weight_of.get(f, 0) for f in kv[1]),
                                     kv[0]))
    parts: list[list[str]] = []
    weights: list[int] = []
    for _gname, gfiles in ordered:
        gfiles = sorted(gfiles)
        gw = sum(weight_of.get(f, 0) for f in gfiles)
        if gw > target:
            # A lone over-budget directory: chunk in path order (locality is maxed).
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
    """Split any unit over 1.25x byte target (no-op when target <= 0); skip_exempt leaves
    budget_exempt units (vendor) untouched."""
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
        # A one-file unit over target is not a violation (unsplittable), and
        # budget_exempt (vendor) units are out of budget scope.
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
    """Last-mile rebalance: merge support micro-units (<= 3 files or < 5% of budget) into
    a neighbor under 1.25x target, split giant leftovers. Runs only with weights."""
    out = [dict(u) for u in units if u.get("files")]
    if not weight_of or target <= 0 or not out:
        return out
    max_ceiling = int(target * 1.25)
    # Only scattershot support shards merge; code singletons and `misc` stay alone.
    def _is_mergeable_micro(u: dict) -> bool:
        name = str(u.get("name", "")).lower()
        return ("support" in name or "unmapped" in name or "part-" in name)
    micro_idx = [i for i, u in enumerate(out)
                 if (not u.get("budget_exempt")
                     and (len(u["files"]) <= 3
                          or _unit_bytes(u, weight_of) < max(1, int(target * 0.05)))
                     and _is_mergeable_micro(u))]
    for i in sorted(micro_idx, reverse=True):
        tiny = out.pop(i)
        tiny_bytes = _unit_bytes(tiny, weight_of)
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
                      target: int = 0, edges: dict | None = None,
                      cfg: dict | None = None) -> list[dict]:
    """Merge tiny units, cap at MAX_UNITS, re-enforce the budget, unique names."""
    part = effective_config(cfg)["partition"]
    cap = int(part["max_units"])
    _min = max(0, int(part["min_files"]))
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
    # 1b. Split units over the byte budget; skipped when no weights are given
    # (pure structural normalization).
    if weight_of is not None and target > 0:
        units = _balance_units(units, weight_of, target, edges=edges)
    # 2. Merge tiny units: with misc_code_merge, only non-code units fold into
    # misc; otherwise every
    # singleton folds into misc.
    if part["misc_code_merge"]:
        big, misc = _merge_tiny_policy(units, _min, edges, weight_of, target)
    else:
        big, misc = _merge_tiny_legacy(units)
    # 3. Cap: fold overflow by support category, never into the code catch-all.
    if cap > 0 and len(big) > cap:
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
    # 3b. Merge/cap can outgrow the target, so re-enforce the byte budget after
    # them; when a split would exceed MAX_UNITS the budget wins (cap is soft).
    if weight_of and target > 0:
        for _ in range(2):
            split = _balance_units(big, weight_of, target, skip_exempt=True, edges=edges)
            if len(split) <= cap:
                big = split
                break
            folded = _fold_to_cap(split, cap, weight_of, target, edges=edges)

            def _over(u: dict) -> bool:
                return not u.get("budget_exempt") and len(u.get("files") or []) > 1 and sum(weight_of.get(f, 0) for f in u["files"]) > target

            if len(folded) <= cap:
                big = folded
                break
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


def _load_partition_edges(repo: str, files: list[str],
                          cfg: dict | None = None) -> dict:
    """File-coupling edges from source-level framework/same-dir analysis."""
    from cerberus.partitioning.graph import augment_edges

    enabled = effective_config(cfg)["partition"]["framework_edges"]
    edges = augment_edges(repo, files, {}) if enabled else {}
    return dict(edges or {})


def partition_units(repo: str, files: list[str],
                    cfg: dict | None = None) -> list[dict]:
    """Logical units for per-unit hunting: vendor splits off into one budget-exempt
    unit; a repo that fits the budget collapses to a single unit."""
    files = [f for f in (files or []) if f]
    if not files:
        return []
    part = effective_config(cfg)["partition"]
    app_files, vendor_files = files, []
    if part["vendor_unit"]:
        app_files, vendor_files = isolate_vendor(files, repo)

    def _finish(units: list[dict]) -> list[dict]:
        # Appended after normalization: vendor bypasses tiny-merge and the cap.
        if vendor_files:
            units.append(_vendor_unit(vendor_files, {u["name"] for u in units}))
        return units

    if not app_files:  # all-vendor repo: just the vendor unit
        return _finish([])
    weight_of = _file_weights(repo, app_files)
    target = partition_target(weight_of, cfg)
    # P0.2 small-repo single unit (file count AND byte budget must both fit).
    single = small_repo_unit(app_files, weight_of, target, cfg=cfg)
    if single is not None:
        return _finish([single])
    from cerberus.partitioning import codegraph as _cg
    mode = str(effective_config(cfg)["codegraph"]["partition"]["mode"]).strip().lower()
    if mode not in PARTITION_MODES:
        mode = "primary"
    if mode == "primary" and _cg.index_available(repo):
        max_uf = int(effective_config(cfg)["partition"].get("max_module_files", 100))
        edges = _load_partition_edges(repo, app_files, cfg)
        raw_units = _cg.partition_codegraph_native(app_files, max_unit_files=max_uf,
                                                   edges=edges, weights=weight_of,
                                                   target=target)
        units = (_normalize_units(raw_units, weight_of, target, edges=edges, cfg=cfg)
                 if raw_units else [])
    else:
        edges = _load_partition_edges(repo, app_files, cfg)
        units = None
    if not units:
        if edges is None:
            edges = _load_partition_edges(repo, app_files, cfg)
        units = _units_from_dirs(repo, app_files, weight_of=weight_of,
                                 target=target, edges=edges, cfg=cfg)
    if not units:
        units = _normalize_units(
            [{"name": "all", "files": sorted(set(app_files)),
              "reason": "single-unit"}], weight_of, target, edges=edges,
            cfg=cfg)
    return _finish(units)
