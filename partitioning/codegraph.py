"""Architectural module partitioning for CodeGraph-indexed targets.

Groups inventory files into hunter units by architectural depth: depth-1
directories become units, single-child wrapper directories collapse into their
child (``frontend/src`` rather than ``frontend``), and an oversized module is
split one level deeper.
"""
from __future__ import annotations


def index_available(root: str = ".") -> bool:
    """True when a readable CodeGraph index exists for ``root`` (never raises)."""
    try:
        from pathlib import Path
        return (Path(root) / ".codegraph").is_dir()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CodeGraph Native Module Partitioning
# ---------------------------------------------------------------------------

def pass_through_dirs(paths: list[str]) -> set[str]:
    """Identify single-child wrapper directories (e.g. frontend/src) that should collapse."""
    from collections import defaultdict

    children: dict[str, set[str]] = defaultdict(set)
    holds_files: set[str] = set()
    for raw in paths:
        parts = [p for p in raw.replace("\\", "/").split("/") if p]
        d = ""
        for i in range(len(parts) - 1):
            kids = children[d]
            kids.add(parts[i])
            d = f"{d}/{parts[i]}" if d else parts[i]
        holds_files.add(d)
    out: set[str] = set()
    for d, kids in children.items():
        if d != "" and len(kids) == 1 and d not in holds_files:
            out.add(d)
    return out


def _effective_dir_levels(file_path: str, pass_through: set[str] | None = None) -> list[str]:
    parts = [p for p in file_path.replace("\\", "/").split("/") if p]
    if not parts or len(parts) == 1:
        return []
    dirs = parts[:-1]
    levels: list[str] = []
    i = 0
    while i < len(dirs):
        seg = dirs[i]
        curr = "/".join(dirs[:i + 1])
        i += 1
        while pass_through and curr in pass_through and i < len(dirs):
            seg = f"{seg}/{dirs[i]}"
            curr = "/".join(dirs[:i + 1])
            i += 1
        levels.append(seg)
    return levels


def _fuse_coupled_modules(units: list[dict], edges: dict | None,
                          weights: dict[str, int] | None,
                          target: int = 0) -> list[dict]:
    """Capacitated Architectural Affinity Clustering (CAAC).
    Agglomeratively fuses modules using a multi-factor affinity score:
      1. CodeGraph static call/import coupling (W_graph: 1000x)
      2. Directory hierarchy proximity / LCA depth (W_tree: 25x)
      3. File extension / role similarity (W_role: 2x)
      4. Entrypoint / root attachment preference (W_root: 10x)
    Merged units are strictly bounded by the nominal budget (target), with
    a 25% tolerance buffer (1.25x target) reserved for strongly-coupled modules.
    """
    if not weights or target <= 0 or len(units) <= 1:
        return units
    from pathlib import PurePosixPath
    from cerberus.partitioning.units import _edge_index, _cross_weight, _dominant_top_dir

    idx = _edge_index(edges) if edges else {}
    current = [dict(u, files=list(u.get("files") or [])) for u in units]
    max_ceiling = int(target * 1.25)

    def lca_depth(p1: str, p2: str) -> int:
        pts1 = PurePosixPath(p1).parts
        pts2 = PurePosixPath(p2).parts
        d = 0
        for a, b in zip(pts1, pts2):
            if a == b:
                d += 1
            else:
                break
        return d

    def affinity(u1: dict, u2: dict, gw: int) -> float:
        f1, f2 = u1["files"], u2["files"]
        score = gw * 1000.0
        max_lca = max((lca_depth(a, b) for a in f1[:6] for b in f2[:6]), default=0)
        score += max_lca * 25.0
        ext1 = set(PurePosixPath(f).suffix for f in f1 if PurePosixPath(f).suffix)
        ext2 = set(PurePosixPath(f).suffix for f in f2 if PurePosixPath(f).suffix)
        shared_ext = len(ext1 & ext2)
        score += shared_ext * 2.0
        n1, n2 = str(u1.get("name", "")), str(u2.get("name", ""))
        if "(root)" in n1 or "(root)" in n2:
            score += 10.0
        score += 1.0
        return score

    changed = True
    while changed:
        changed = False
        best_pair = None
        best_score = -1.0
        for i in range(len(current)):
            u1 = current[i]
            if u1.get("budget_exempt") or str(u1.get("name", "")).startswith("vendor"):
                continue
            w1 = sum(weights.get(f, 0) for f in u1.get("files", []))
            for j in range(i + 1, len(current)):
                u2 = current[j]
                if u2.get("budget_exempt") or str(u2.get("name", "")).startswith("vendor"):
                    continue
                w2 = sum(weights.get(f, 0) for f in u2.get("files", []))
                f1, f2 = u1.get("files", []), u2.get("files", [])
                gw = _cross_weight(f1, f2, idx) if idx else 0
                allowed_budget = max_ceiling if gw > 0 else target
                if w1 + w2 > allowed_budget:
                    continue
                score = affinity(u1, u2, gw)
                if score > best_score:
                    best_score = score
                    best_pair = (i, j)

        if best_pair is not None:
            i, j = best_pair
            u1, u2 = current[i], current[j]
            merged_files = sorted(set(u1.get("files", [])) | set(u2.get("files", [])))
            u1["files"] = merged_files
            name1 = str(u1.get("name", "")).split("+")[0]
            name2 = str(u2.get("name", "")).split("+")[0]
            if name1 == name2:
                u1["name"] = name1
            elif len(name1) + len(name2) < 25:
                u1["name"] = f"{name1}+{name2}"
            else:
                u1["name"] = _dominant_top_dir(merged_files, weights)
            current.pop(j)
            changed = True

    return current


def partition_codegraph_native(files: list[str], max_unit_files: int = 100,
                               edges: dict | None = None,
                               weights: dict[str, int] | None = None,
                               target: int = 0) -> list[dict]:
    """CodeGraph Native module partitioning based on architectural depth + pass-through collapsing + CAAC clustering."""
    from collections import defaultdict

    pt = pass_through_dirs(files)
    depth1_map: dict[str, list[str]] = defaultdict(list)
    file_levels: dict[str, list[str]] = {}
    for f in files:
        levels = _effective_dir_levels(f, pt)
        file_levels[f] = levels
        d1 = levels[0] if levels else "(root)"
        depth1_map[d1].append(f)

    final_units: dict[str, list[str]] = defaultdict(list)
    for mod_name, mod_files in depth1_map.items():
        if len(mod_files) > max_unit_files and mod_name != "(root)":
            d2_map: dict[str, list[str]] = defaultdict(list)
            for f in mod_files:
                levels = file_levels[f]
                d2 = f"{levels[0]}/{levels[1]}" if len(levels) >= 2 else f"{levels[0]}/(root files)"
                d2_map[d2].append(f)
            for sub_name, sub_files in d2_map.items():
                final_units[sub_name].extend(sub_files)
        else:
            final_units[mod_name].extend(mod_files)

    units: list[dict] = []
    for uname, ufiles in sorted(final_units.items()):
        units.append({
            "name": uname,
            "files": sorted(ufiles),
            "reason": "codegraph-native-module",
        })

    if weights and target > 0:
        units = _fuse_coupled_modules(units, edges, weights, target)

    return units


__all__ = [
    "index_available", "pass_through_dirs", "partition_codegraph_native",
]
