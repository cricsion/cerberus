"""The identical skeleton of the codegraph fixture seeders in one place.

Every ``_seed_rows`` in the codegraph suites does the same four things around
its domain-specific rows: write the fixture SOURCES to disk, mint a file
node + files row per source, record ``contains`` edges for identifiers, and
flush all collected rows into the mini index. This module holds exactly that
skeleton; the domain rows stay in the modules that define their fixture.
"""
from __future__ import annotations

import sqlite3

from test_codegraph_foundation import _EDGES_SQL, _NODES_SQL, NODE_COLUMNS, _node

_FILES_SQL = ("INSERT INTO files (path, content_hash, language, size, "
              "modified_at, indexed_at, node_count, errors, generated) "
              "VALUES (?,?,?,?,?,?,?,?,?)")
_REFS_SQL = ("INSERT INTO unresolved_refs (from_node_id, reference_name, "
             "reference_kind, line, col, candidates, file_path, language, "
             "status, name_tail) VALUES (?,?,?,?,?,?,?,?,?,?)")


class GraphSeed:
    """Collects nodes/edges/files/refs rows and flushes them to the index."""

    def __init__(self, root, db_path, sources, *, rel_paths=False):
        self.root = root
        self.db_path = db_path
        self.sources = sources
        self.rel_paths = rel_paths      # supply-style: node name = basename
        self.nodes: list[tuple] = []
        self.edges: list[tuple] = []
        self.files: list[tuple] = []
        self.refs: list[tuple] = []

    def write_sources(self) -> None:
        for rel, text in self.sources.items():
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)

    def file_node(self, name: str, text: str, language: str,
                  generated: int = 0) -> str:
        node_id = f"{name}:{name}"
        display = name.rsplit("/", 1)[-1] if self.rel_paths else name
        self.nodes.append(_node(node_id, "file", display, name, language, 1,
                                len(text.splitlines())))
        self.files.append((name, f"hash-{name}", language, len(text),
                           1_700_000_000_000, 1_700_000_000_000, 0, None,
                           generated))
        return node_id

    def contains(self, parent: str, child: str, line: int) -> None:
        self.edges.append((parent, child, "contains", None, line, 1, "static"))

    def flush(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.executemany(_NODES_SQL, self.nodes)
            conn.executemany(_EDGES_SQL, self.edges)
            conn.executemany(_FILES_SQL, self.files)
            conn.executemany(_REFS_SQL, self.refs)   # empty for most suites
            conn.commit()
        finally:
            conn.close()
