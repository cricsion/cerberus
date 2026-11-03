"""Unit partition (logical units)."""
import pytest
from cerberus.partitioning import (
    _normalize_units,
    partition_target,
    partition_units,
    verify_partition,
)


def test_units_from_dirs(monkeypatch):
    # Isolate the directory + misc policy from the small-repo collapse rule.
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "0")
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    files = ["api/users.py", "api/orders.py", "web/app.py", "README.md"]
    units = partition_units("repo", files)
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert by_name["api"] == ["api/orders.py", "api/users.py"]
    # P1.3: code never lands in misc. "web" is a one-file CODE unit, so it
    # keeps its own name; the README (non-code) is what folds into misc.
    assert by_name["web"] == ["web/app.py"]
    assert by_name["misc"] == ["README.md"]
    assert sum(len(u["files"]) for u in units) == len(files)


def test_tiny_units_merge(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    units = _normalize_units([
        {"name": "a", "files": ["a.py", "b.py"], "reason": "t"},
        {"name": "b", "files": ["c.py"], "reason": "t"},
        {"name": "docs", "files": ["README.md"], "reason": "t"},
    ])
    # Tiny CODE unit keeps its singleton name (no edges => no neighbour);
    # the tiny non-code unit is what misc absorbs.
    assert {u["name"] for u in units} == {"a", "b", "misc"}
    assert sorted(next(u["files"] for u in units if u["name"] == "misc")) == ["README.md"]


def test_empty_files_no_units():
    assert partition_units("repo", []) == []


# --- size balancing (byte-weighted budget) ---------------------------------


def test_balance_splits_oversized_unit_under_budget():
    files = ["a/1.py", "a/2.py", "a/3.py", "b/1.py", "b/2.py", "b/3.py"]
    w = dict.fromkeys(files, 100)
    units = _normalize_units([{"name": "big", "files": files, "reason": "llm"}],
                             weight_of=w, target=250)
    assert len(units) >= 2
    assert all(sum(w[f] for f in u["files"]) <= 250 for u in units)
    assert sorted(f for u in units for f in u["files"]) == sorted(files)
    # Deterministic: same input, same output.
    assert units == _normalize_units(
        [{"name": "big", "files": files, "reason": "llm"}],
        weight_of=w, target=250)


def test_balance_keeps_directories_together():
    files = ["a/1.py", "a/2.py", "b/1.py", "b/2.py"]
    w = dict.fromkeys(files, 100)
    units = _normalize_units([{"name": "u", "files": files, "reason": "x"}],
                             weight_of=w, target=300)
    assert len(units) == 2
    for u in units:
        dirs = {str(f).rsplit("/", 1)[0] for f in u["files"]}
        assert len(dirs) == 1  # no directory is split across units


def test_balance_skipped_without_weights():
    units = _normalize_units([{"name": "u", "files": ["a.py", "b.py"]}])
    assert [u["name"] for u in units] == ["u"]


def test_verify_partition_invariants():
    ok = verify_partition([{"name": "a", "files": ["a.py", "b.py"]},
                           {"name": "b", "files": ["c.py"]}],
                          ["a.py", "b.py", "c.py"],
                          weight_of={"a.py": 10, "b.py": 10, "c.py": 10},
                          target=100)
    assert ok["units"] == 2 and ok["files"] == 3
    with pytest.raises(AssertionError):  # missing file
        verify_partition([{"name": "a", "files": ["a.py"]}], ["a.py", "b.py"])
    with pytest.raises(AssertionError):  # double assignment
        verify_partition([{"name": "a", "files": ["a.py", "a.py"]}], ["a.py"])
    with pytest.raises(AssertionError):  # over budget (multi-file unit)
        verify_partition([{"name": "a", "files": ["a.py", "b.py"]}],
                         ["a.py", "b.py"],
                         weight_of={"a.py": 300, "b.py": 300}, target=400)
    # A lone oversized file cannot be split further, so it is not a violation.
    verify_partition([{"name": "a", "files": ["big.py"]}], ["big.py"],
                     weight_of={"big.py": 500}, target=400)


def test_partition_target_raises_ceiling_over_max_units(monkeypatch):
    monkeypatch.setenv("PARTITION_LOC_BUDGET", "10000")
    monkeypatch.setenv("PARTITION_BYTES_PER_LOC", "40")
    monkeypatch.delenv("MAX_UNITS", raising=False)
    # The default cap is 20: 20 x 1MB files spread evenly at 1MB per unit.
    big = {f"f{i}.py": 1_000_000 for i in range(20)}
    assert partition_target(big) == 1_000_000
    # Small repo: nominal 10k-LOC budget applies.
    small = {f"f{i}.py": 10_000 for i in range(10)}
    assert partition_target(small) == 400_000


# --- budget invariant must hold AFTER merge/cap, not only after splitting ---


def test_cap_fold_does_not_reform_over_budget_blob(monkeypatch):
    """Over-cap units fold into misc; the fold must still respect the target."""
    monkeypatch.delenv("MIN_FILES", raising=False)
    monkeypatch.delenv("MAX_UNITS", raising=False)
    w = {f"d{i}/{n}.py": 40_000 for i in range(35) for n in "abcd"}
    units = _normalize_units(
        [{"name": f"u{i}", "files": [f"d{i}/{n}.py" for n in "abcd"], "reason": "d"}
         for i in range(35)],
        weight_of=w, target=400_000)
    assert all(sum(w[f] for f in u["files"]) <= 400_000 for u in units)
    assert sorted(f for u in units for f in u["files"]) == sorted(w)


def test_split_normalizes_backslash_paths():
    files = ["a\\b\\c.py", "a\\b\\d.py", "a\\b\\e.py"]
    w = dict.fromkeys(files, 300)
    units = _normalize_units([{"name": "u", "files": files, "reason": "x"}],
                             weight_of=w, target=700)
    assert all(sum(w[f] for f in u["files"]) <= 700 for u in units)
    assert sorted(f for u in units for f in u["files"]) == sorted(files)


def test_partitioner_coverage_enforcement():
    from cerberus.partitioning.llm import _enforce_coverage
    files = ["a.py", "b.py", "c.py"]
    # Unknown files dropped, orphans in own unit (locality preserved), no loss.
    # Note: with repo=None the weights are 0 (no on-disk files), so the
    # small-repo rule declines (total <= 0); ghost.py drops as unknown and
    # b.py/c.py reattach via the exact-parent orphan rule ("." parent).
    units = _enforce_coverage(
        [{"name": "auth", "files": ["a.py", "ghost.py"]}], files)
    assert sum(len(u["files"]) for u in units) == 3
    assert all(f in files for u in units for f in u["files"])
    assert "ghost.py" not in [f for u in units for f in u["files"]]
    assert any("a.py" in u["files"] for u in units)
    assert any("b.py" in u["files"] and "c.py" in u["files"] for u in units)
    # Default cap: 30 tiny units fold down to at most 20.
    many = [{"name": f"u{i}", "files": [f"f{i}.py"]} for i in range(30)]
    capped = _enforce_coverage(many, [f"f{i}.py" for i in range(30)])
    assert len(capped) <= 20
    assert sum(len(u["files"]) for u in capped) == 30
