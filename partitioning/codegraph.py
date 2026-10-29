"""CodeGraph Native module partitioning.

Groups inventory files into hunter units by architectural depth: depth-1
directories become units, single-child wrapper directories collapse into their
child (``frontend/src`` rather than ``frontend``), and an oversized module is
split one level deeper.

"""
from __future__ import annotations


def index_available(root: str = ".") -> bool:
    """True when a readable CodeGraph index exists for ``root`` (never raises)."""
    from harness.codegraph import _db

    return _db.connect(root) is not None


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


def partition_codegraph_native(files: list[str], max_unit_files: int = 50) -> list[dict]:
    """CodeGraph Native module partitioning based on architectural depth + pass-through collapsing."""
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
    return units


__all__ = [
    "index_available", "pass_through_dirs", "partition_codegraph_native",
]
