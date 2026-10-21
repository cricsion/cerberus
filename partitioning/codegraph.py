"""CodeGraph-index-backed file coupling + deterministic community detection.

P2.5 replacement substrate for the graphify ``graph.json`` path (plan §6.2
F1-F3). Three mechanisms, each bounded:

- **SQL file coupling** (F2 substrate). Reads ``<root>/.codegraph/codegraph.db``
  read-only through ``harness.codegraph._db`` (containment + mtime cache + the
  fail-open contract), keeps only inter-file edges whose ``kind`` is in the D7
  weight map (plan §5: weight 2 = def-use / type relations, weight 1 =
  call-like; ``contains`` is intra-file and excluded), and drops "heel" edges
  whose ``metadata.confidence`` is below CodeGraph's ``UNCERTAIN_BELOW``. Every
  file with at least one surviving edge becomes a graph node, so only true
  orphans (zero edges) fall through to the ``unmapped-*`` dirs units — the
  edge-connected attachment of F2.
- **Louvain** (``networkx.community.louvain_communities``, ``seed=0``).
- **Deterministic oversized-community split** (F3). The split trigger and the
  cohesion second pass are ported byte-for-byte from graphify
  (``graphify/cluster.py:179-182``, ``:373-380``, ``:410-425``); the re-split
  resolution bump (2.0) and the depth cap (<= 2) are NEW additions, not a port
  (the audit correction recorded in §6.2 F3). Community IDs are remapped by
  smallest member file — OUR rule, not graphify's size-desc/greedy-overlap
  remap — so ``community-N`` is run-stable under networkx.

Failure contract (D6): an absent or unreadable index degrades to ``{}`` /
``None`` exactly like ``load_partition_graph``'s graph-absent semantics; the
units layer then rescues to the dirs path (F1). Nothing here raises for a
missing index, and nothing here writes the target repo.
"""
from __future__ import annotations

import json
import logging
import sqlite3

from harness.config import get_default_config

_logger = logging.getLogger(__name__)

# --- D7 weight map (plan §5) -------------------------------------------------
# weight 2 = def-use / type relations; weight 1 = call-like. ``contains`` is
# intra-file and never couples two files, so it is absent on purpose.
_RELATION_WEIGHT: dict[str, int] = {
    "imports": 2,
    "references": 2,
    "exports": 2,
    "extends": 2,
    "implements": 2,
    "decorates": 2,
    "calls": 1,
    "instantiates": 1,
    "navigates": 1,
}

# CodeGraph's UNCERTAIN_BELOW: below it an edge is a name-only guess, not a call.
# The value is the harness/config/default.yaml default; the partitioner can override it
# per scan via codegraph.partition.uncertain_below.
UNCERTAIN_BELOW = float(get_default_config("codegraph.partition.uncertain_below"))

# --- F3 split constants (ported from graphify/cluster.py:179-182) ------------
_MAX_COMMUNITY_FRACTION = 0.25   # split communities larger than 25% of the graph
_MIN_SPLIT_SIZE = 10             # ...but only if they have at least this many nodes
_COHESION_SPLIT_THRESHOLD = 0.05  # re-split communities with cohesion below this
_COHESION_SPLIT_MIN_SIZE = 50     # ...and at least this many members

# --- NEW (not a port, §6.2 F3): re-split resolution bump + depth cap ----------
_SPLIT_RESOLUTION = 2.0
_MAX_SPLIT_DEPTH = 2

# Fixed Louvain seed: the determinism recipe (plan §6.2).
LOUVAIN_SEED = 0

_EDGE_SQL_TEMPLATE = (
    "SELECT e.kind AS kind, e.metadata AS metadata, "
    "sn.file_path AS source_file, tn.file_path AS target_file "
    "FROM edges e "
    "JOIN nodes sn ON sn.id = e.source "
    "JOIN nodes tn ON tn.id = e.target "
    "WHERE e.kind IN ({placeholders})"
)


# ---------------------------------------------------------------------------
# coupling
# ---------------------------------------------------------------------------

def index_available(root: str = ".") -> bool:
    """True when a readable CodeGraph index exists for ``root`` (never raises)."""
    from harness.codegraph import _db

    return _db.connect(root) is not None


def _file_matcher(files: list[str]):
    """Map an index ``file_path`` onto the inventory file it belongs to.

    Mirrors ``units._units_from_graphify``'s matching (exact key, then a suffix
    of the index key, then a suffix of an inventory key), so a file list that
    carries a repo prefix still matches the index's repo-relative paths and vice
    versa. Returns the first (lexicographically smallest) match.
    """
    inventory = set(files)
    # inventory-suffix -> inventory file (handles a prefixed inventory).
    inv_suffix: dict[str, str] = {}
    for f in sorted(inventory):
        parts = f.split("/")
        for i in range(1, len(parts)):
            inv_suffix.setdefault("/".join(parts[i:]), f)

    def match(path: str) -> str | None:
        if path in inventory:
            return path
        parts = path.split("/")
        for i in range(1, len(parts)):
            candidate = "/".join(parts[i:])
            if candidate in inventory:
                return candidate
        return inv_suffix.get(path)

    return match


def _edge_weight(kind: object) -> int:
    return _RELATION_WEIGHT.get(str(kind or "").lower(), 0)


def _confidence(metadata: object) -> float | None:
    """``metadata.confidence`` as a float, or None when absent/unparseable."""
    if metadata is None or metadata == "":
        return None
    if isinstance(metadata, (bytes, bytearray)):
        try:
            metadata = metadata.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - defensive decode, never fatal
            return None
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (ValueError, TypeError):
            return None
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("confidence")
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_file_edges(root: str, files: list[str], *,
                    uncertain_below: float | None = None
                    ) -> dict[tuple[str, str], int]:
    """Inter-file coupling edges over the CodeGraph index, D7-weighted.

    ``{(a, b): weight}`` with ``a < b`` (orientation-agnostic pairs — the
    partition graph is undirected), both endpoints canonicalised onto the
    inventory ``files`` list. Returns ``{}`` when the index is missing,
    unreadable, or contributes no surviving edge (the fail-open contract).
    """
    if not files:
        return {}
    from harness.codegraph import _db

    conn = _db.connect(root)
    if conn is None:
        return {}
    threshold = UNCERTAIN_BELOW if uncertain_below is None else float(uncertain_below)
    kinds = sorted(_RELATION_WEIGHT)
    sql = _EDGE_SQL_TEMPLATE.format(placeholders=",".join("?" * len(kinds)))
    try:
        rows = conn.execute(sql, tuple(kinds)).fetchall()
    except sqlite3.Error:
        return {}

    match = _file_matcher(files)
    out: dict[tuple[str, str], int] = {}
    for row in rows:
        try:
            kind = row["kind"]
            metadata = row["metadata"]
            sf = row["source_file"]
            tf = row["target_file"]
        except (IndexError, KeyError, TypeError):
            continue
        weight = _edge_weight(kind)
        if weight <= 0:
            continue
        confidence = _confidence(metadata)
        if confidence is not None and confidence < threshold:
            continue
        a = match(str(sf or ""))
        b = match(str(tf or ""))
        if not a or not b or a == b:
            continue
        key = (a, b) if a <= b else (b, a)
        out[key] = out.get(key, 0) + weight
    return out


# ---------------------------------------------------------------------------
# F3 — cohesion + oversized-community split
# ---------------------------------------------------------------------------

def cohesion_score(graph, members) -> float:
    """Ratio of actual intra-community edges to maximum possible (graphify port).

    Port of ``graphify/cluster.py:410-425``: unweighted, minus self-loops, over
    distinct node pairs; a <=1-member community scores 1.0 (never split).
    """
    import networkx as nx

    nodes = list(members)
    n = len(nodes)
    if n <= 1:
        return 1.0
    sub = graph.subgraph(nodes)
    actual = sub.number_of_edges() - nx.number_of_selfloops(sub)
    possible = n * (n - 1) / 2
    return actual / possible if possible > 0 else 0.0


def _split_triggered(graph, members, max_size: int) -> bool:
    if len(members) > max_size:
        return True
    return (len(members) >= _COHESION_SPLIT_MIN_SIZE
            and cohesion_score(graph, members) < _COHESION_SPLIT_THRESHOLD)


def split_oversized_communities(graph, communities, resolution: float = 1.0,
                                depth: int = 0) -> list[list[str]]:
    """Deterministically re-partition communities the F3 trigger fires on.

    The trigger (fraction > 25% with a 10-node floor, plus the >=50-member
    cohesion second pass) is graphify's, ported exactly. The re-split itself is
    OUR addition: Louvain at resolution ``_SPLIT_RESOLUTION`` (2.0), recursing
    up to ``_MAX_SPLIT_DEPTH``; a sub-split that makes no progress is kept
    whole, so the recursion always terminates.
    """
    import networkx as nx

    total = graph.number_of_nodes()
    max_size = max(_MIN_SPLIT_SIZE, int(total * _MAX_COMMUNITY_FRACTION))
    out: list[list[str]] = []
    for members in communities:
        nodes = sorted(members)
        if _split_triggered(graph, nodes, max_size) and depth < _MAX_SPLIT_DEPTH:
            sub = graph.subgraph(nodes)
            if sub.number_of_edges() == 0:
                out.append(nodes)
                continue
            sub_communities = nx.community.louvain_communities(
                sub, weight="weight", resolution=_SPLIT_RESOLUTION,
                seed=LOUVAIN_SEED)
            if len(sub_communities) <= 1:
                out.append(nodes)  # no progress: keep the community whole
                continue
            out.extend(split_oversized_communities(
                graph, [sorted(c) for c in sub_communities], resolution, depth + 1))
        else:
            out.append(nodes)
    return out


def remap_communities(communities) -> list[list[str]]:
    """Deterministically order communities by their smallest member file.

    OUR rule (§6.2 F3): ``community-N`` must be run-stable under networkx, and
    networkx's Louvain enumeration order is not. Sorting communities by their
    lexicographically smallest member makes the ``community-N`` label a pure
    function of the grouping.
    """
    return sorted((sorted(c) for c in communities),
                  key=lambda members: members[0] if members else "")


# ---------------------------------------------------------------------------
# Louvain over the coupling graph
# ---------------------------------------------------------------------------

def louvain_file_communities(root: str, files: list[str], *,
                             resolution: float | None = None,
                             uncertain_below: float | None = None,
                             split: bool = True
                             ) -> dict[str, int] | None:
    """``{inventory_file: community_id}`` from Louvain over SQL file coupling.

    Returns ``None`` when the index is missing/unreadable or yields no coupling
    at all — the units layer then rescues to the dirs path (F1). Community IDs
    are ``0..k-1`` in the remap order (smallest member file first), so the same
    grouping always yields the same ``community-N`` names.
    """
    import networkx as nx

    from harness.partitioning.config import partition_resolution, \
        partition_uncertain_below

    if resolution is None:
        resolution = partition_resolution()
    if uncertain_below is None:
        uncertain_below = partition_uncertain_below()

    edges = load_file_edges(root, files, uncertain_below=uncertain_below)
    if not edges:
        return None
    graph = nx.Graph()
    for (a, b), weight in sorted(edges.items()):
        graph.add_edge(a, b, weight=int(weight))
    if graph.number_of_nodes() == 0:
        return None
    communities = nx.community.louvain_communities(
        graph, weight="weight", resolution=float(resolution), seed=LOUVAIN_SEED)
    if split:
        communities = split_oversized_communities(graph, communities,
                                                  float(resolution))
    ordered = remap_communities(communities)
    out: dict[str, int] = {}
    for cid, members in enumerate(ordered):
        for member in members:
            out.setdefault(member, cid)
    return out


__all__ = [
    "UNCERTAIN_BELOW", "LOUVAIN_SEED",
    "index_available", "load_file_edges", "louvain_file_communities",
    "cohesion_score", "split_oversized_communities", "remap_communities",
]
