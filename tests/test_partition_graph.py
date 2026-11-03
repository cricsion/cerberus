"""Contract tests for cerberus.partitioning.graph edge functions.

Covers augment_edges (CodeGraph-indexed inter-file edges, same-dir proximity,
no-index operation, determinism).
"""
from __future__ import annotations

from cerberus.partitioning.graph import augment_edges

# --- augment_edges: CodeGraph index integration -----------------------------

def test_augment_reads_native_codegraph_edges(tmp_path, monkeypatch):
    """When CodeGraph native SDK reports file dependencies, augment_edges connects them."""
    from cerberus.codegraph import native
    sample_pairs = [
        {"source": "app/renderer.py", "target": "sub/suffix.html"},
        {"source": "app/renderer.py", "target": "sub/other.py"},
    ]
    monkeypatch.setattr(native, "file_dependency_pairs", lambda repo: sample_pairs)

    files = ["app/renderer.py", "sub/suffix.html", "sub/other.py"]
    out = augment_edges(str(tmp_path), files, {})
    assert out[("app/renderer.py", "sub/suffix.html")] >= 1
    assert out[("app/renderer.py", "sub/other.py")] >= 1



# --- augment_edges: no-graph operation and determinism ----------------------

def test_augment_works_without_index(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("def f():\n    return 1\n")
    (src / "b.py").write_text("def g():\n    return 2\n")
    files = ["src/a.py", "src/b.py"]
    assert not (tmp_path / ".codegraph").exists()
    out = augment_edges(str(tmp_path), files, {})
    assert out == {}


def test_augment_never_raises_on_unreadable_repo():
    seed = {("a.py", "b.py"): 5}
    out = augment_edges("\\no\\such\\repo", ["a.py", "b.py"], seed)
    assert out[("a.py", "b.py")] == 5


def test_augment_is_deterministic_and_never_downgrades(tmp_path):
    app = tmp_path / "app"
    views = app / "views"
    views.mkdir(parents=True)
    files = ["app/a.py", "app/b.py", "app/views/v.py"]
    first = augment_edges(str(tmp_path), files, {})
    second = augment_edges(str(tmp_path), files, {})
    assert first == second == {}

    seeded = {("app/a.py", "app/b.py"): 9}
    out = augment_edges(str(tmp_path), files, seeded)
    assert out[("app/a.py", "app/b.py")] == 9  # never reduced


def test_native_file_dependency_pairs_live_fixture():
    from cerberus.codegraph.native import file_dependency_pairs
    res = file_dependency_pairs("tests/fixtures/pygoat-sample")
    assert isinstance(res, list)
