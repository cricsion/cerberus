"""CodeGraph Native module partitioning + the served-partition guard.

The Louvain/shadow substrate (SQL file coupling, Louvain communities, the F3
cohesion split/remap) was retired at P4 along with the gate-runner scripts
that compared it. What remains pinned here:

- the native partitioning ``partition_units`` serves in
  ``codegraph.partition.mode: primary`` (pass-through collapsing, depth-1
  grouping, depth-2 split for oversized modules, full coverage);
- the index gate (``index_available``) never raises on an absent index;
- golden invariance: the served partition still reproduces the §6.3 golden
  baseline for the committed pygoat-sample fixture (skipped until the
  baseline is generated).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cerberus.partitioning import codegraph as cg
from cerberus.partitioning.units import partition_units, verify_partition

GOLDEN_DIR = Path(__file__).resolve().parent / "fixtures" / "partition-golden"
PYGOAT_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "pygoat-sample"


def test_codegraph_native_pass_through_and_depth():
    """Verify single-child directory collapsing and native module partitioning."""
    files = [
        "frontend/src/components/Button.tsx",
        "frontend/src/components/Modal.tsx",
        "frontend/src/utils/format.ts",
        "backend/api/users.py",
        "backend/api/auth.py",
        "backend/models/user.py",
        "root_config.json",
    ]
    pt = cg.pass_through_dirs(files)
    assert "frontend" in pt  # single child frontend -> src

    units = cg.partition_codegraph_native(files)
    unit_map = {u["name"]: u["files"] for u in units}
    all_files = [f for u in units for f in u["files"]]
    assert set(all_files) == set(files)
    assert "frontend/src" in unit_map
    assert "backend" in unit_map
    assert "(root)" in unit_map
    assert unit_map["(root)"] == ["root_config.json"]


def test_native_partitioning_covers_and_separates():
    """100% coverage with clean locality: siblings stay together, unrelated
    dirs stay apart (the coverage half of the retired Louvain parity gate)."""
    files = ["pass1/left/a.py", "pass1/left/b.py",
             "pass1/right/c.py", "pass1/right/d.py",
             "core/p.py", "core/q.py"]
    native_units = cg.partition_codegraph_native(files)
    native_by_file = {f: u["name"] for u in native_units for f in u["files"]}
    assert set(native_by_file) == set(files)
    assert native_by_file["pass1/left/a.py"] == native_by_file["pass1/left/b.py"]
    assert native_by_file["core/p.py"] == native_by_file["core/q.py"]
    assert native_by_file["pass1/left/a.py"] != native_by_file["core/p.py"]


def test_index_gate_absent_index_never_raises(tmp_path):
    """A repo without an index: the gate answered False, no exception —
    ``partition_units`` feeds that into the dirs fallback unchanged."""
    assert cg.index_available(str(tmp_path)) is False


def test_golden_invariance_served_units_unmoved():
    """The P4 retirement must not perturb the served partition:
    ``partition_units`` still reproduces the frozen §6.3 golden for the
    committed fixture. Skipped until the baseline is generated."""
    baseline_path = GOLDEN_DIR / "pygoat-sample" / "baseline.json"
    if not baseline_path.is_file():
        pytest.skip("partition-golden baseline not generated yet")
    baseline = json.loads(baseline_path.read_text())
    files = baseline["files"]
    units = partition_units(str(PYGOAT_FIXTURE), files)

    def _partition(us):
        return sorted(tuple(sorted(u["files"])) for u in us)

    assert _partition(units) == _partition(baseline["units"])
    assert verify_partition(units, files, baseline["weights"],
                            baseline["target"]) == baseline["verify"]


def test_shadow_mode_is_retired(monkeypatch):
    """The old shadow rollout no longer exists: a stale value is normalized to
    the documented default instead of silently behaving like off."""
    from cerberus.config import effective_config, reset_config
    from cerberus.partitioning.config import PARTITION_MODES

    assert PARTITION_MODES == ("off", "primary")
    monkeypatch.setenv("CODEGRAPH_PARTITION_MODE", "shadow")
    reset_config()
    assert effective_config({})["codegraph"]["partition"]["mode"] == "primary"
    cfg = effective_config(
        {"codegraph": {"partition": {"mode": "off"}}})
    assert cfg["codegraph"]["partition"]["mode"] == "off"
    cfg = effective_config(
        {"codegraph": {"partition": {"mode": "primary"}}})
    assert cfg["codegraph"]["partition"]["mode"] == "primary"
