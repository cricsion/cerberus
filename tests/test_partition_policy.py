"""Vendor isolation (P0.1), small-repo single unit (P0.2), misc policy (P1.3)."""
import pytest
from cerberus.partitioning import (
    _file_weights,
    _normalize_units,
    _units_from_dirs,
    partition_target,
    partition_units,
    verify_partition,
)
from cerberus.partitioning.llm import _enforce_coverage
from cerberus.partitioning.units import _load_partition_edges, _vendor_unit, isolate_vendor


def _write(repo, rel, text="x = 1\n"):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return rel


# --- P0.1 vendor isolation ----------------------------------------------------


def test_isolate_vendor_matches_dir_segments_and_file_suffixes():
    files = [
        "src/app.py",                      # app
        "docs/readme.md",                  # app
        "web/node_modules/lib/dep.js",     # vendor dir segment (mid-path)
        "web\\node_modules\\lib\\dep2.js",# vendor dir segment (win separators)
        "static/js/main.chunk.js",        # vendor name suffix
        "assets/dist/bundle.min.js",       # vendor dir + suffix
        "frontend/third_party/thing.py",   # vendor dir segment
        "app/__pycache__/x.pyc",           # vendor dir segment
        "bower.json",                      # app (not bower_components)
    ]
    app, vendor = isolate_vendor(files)
    assert app == ["bower.json", "docs/readme.md", "src/app.py"]
    assert vendor == sorted([
        "web/node_modules/lib/dep.js",
        "web\\node_modules\\lib\\dep2.js",
        "static/js/main.chunk.js",
        "assets/dist/bundle.min.js",
        "frontend/third_party/thing.py",
        "app/__pycache__/x.pyc",
    ])


def test_isolate_vendor_is_sorted_and_order_stable():
    files = ["src/a.py", "vendor/b.js", "node_modules/c.js", "lib/d.js"]
    app, vendor = isolate_vendor(files)
    assert app == ["lib/d.js", "src/a.py"]
    assert vendor == ["node_modules/c.js", "vendor/b.js"]
    assert isolate_vendor(list(reversed(files))) == (app, vendor)
    assert isolate_vendor([]) == ([], [])


def test_isolate_vendor_suffix_needs_the_file_name_not_the_dir():
    # A directory called "min.js" is not a vendor artifact; only names ending
    # with a vendor suffix are.
    app, vendor = isolate_vendor(["pkg.min.js/lib/x.py", "pkg/a.min.js"])
    assert app == ["pkg.min.js/lib/x.py"]
    assert vendor == ["pkg/a.min.js"]


def test_vendor_unit_helper_names_collision_safely():
    assert _vendor_unit(["a.js"], set())["name"] == "vendor"
    assert _vendor_unit(["a.js"], {"vendor"})["name"] == "vendor-2"
    assert _vendor_unit(["a.js"], {"vendor", "vendor-2"})["name"] == "vendor-3"
    assert _vendor_unit(["b.js", "a.js"], set())["files"] == ["a.js", "b.js"]
    assert _vendor_unit(["a.js"], set())["budget_exempt"] is True


def test_partition_units_appends_vendor_unit_last(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "0")
    files = [_write(tmp_path, "src/a.py"), _write(tmp_path, "src/b.py"),
             _write(tmp_path, "src/c.py"),
             _write(tmp_path, "web/node_modules/dep.js", "x" * 5000)]
    units = partition_units(str(tmp_path), files)
    assert [u["name"] for u in units] == ["src", "vendor"]
    vendor = units[-1]
    assert vendor["files"] == ["web/node_modules/dep.js"]
    assert vendor["reason"] == "vendor-deps"
    assert vendor["budget_exempt"] is True
    # The exempt unit passes verify_partition even under a tiny budget that
    # nothing else could satisfy either.
    w = _file_weights(str(tmp_path), files)
    verify_partition(units, files, weight_of=w, target=100)


def test_partition_units_vendor_unit_survives_the_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "0")
    monkeypatch.setenv("MAX_UNITS", "1")
    app = [_write(tmp_path, f"d{i}/f{n}.py") for i in range(2) for n in "ab"]
    files = app + [_write(tmp_path, "node_modules/dep.js")]
    units = partition_units(str(tmp_path), files)
    assert units[-1]["name"] == "vendor"
    assert sorted(f for u in units[:-1] for f in u["files"]) == sorted(app)


def test_all_vendor_repo_is_just_the_vendor_unit(monkeypatch):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    files = ["node_modules/a.js", "vendor/b/c.js", "dist/d.min.js"]
    units = partition_units("repo", files)
    assert [u["name"] for u in units] == ["vendor"]
    assert units[0]["files"] == sorted(files)
    assert units[0]["budget_exempt"] is True


def test_no_vendor_files_no_vendor_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "0")
    files = [_write(tmp_path, "a/1.py"), _write(tmp_path, "a/2.py")]
    units = partition_units(str(tmp_path), files)
    assert [u["name"] for u in units] == ["a"]


def test_vendor_unit_is_last_for_the_llm_path(monkeypatch, tmp_path):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "0")
    files = [_write(tmp_path, "api/a.py"), _write(tmp_path, "api/b.py"),
             _write(tmp_path, "web/node_modules/dep.js")]
    units = _enforce_coverage(
        [{"name": "api", "files": ["api/a.py", "api/b.py", "web/node_modules/dep.js"]}],
        files, str(tmp_path))
    assert units[-1]["name"] == "vendor"
    assert units[-1]["files"] == ["web/node_modules/dep.js"]
    assert units[-1]["budget_exempt"] is True
    assert sorted(f for u in units for f in u["files"]) == sorted(files)


def test_vendor_name_collision_renames_on_the_llm_path(monkeypatch, tmp_path):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "0")
    files = [_write(tmp_path, "src/a.py"), _write(tmp_path, "src/b.py"),
             _write(tmp_path, "node_modules/dep.js")]
    units = _enforce_coverage(
        [{"name": "vendor", "files": ["src/a.py", "src/b.py"]}],
        files, str(tmp_path))
    by_name = {u["name"]: u["files"] for u in units}
    assert set(by_name) == {"vendor", "vendor-2"}
    assert by_name["vendor"] == ["src/a.py", "src/b.py"]
    assert by_name["vendor-2"] == ["node_modules/dep.js"]


# --- P0.2 small-repo single unit ---------------------------------------------


def test_small_repo_becomes_one_unit_named_after_the_biggest_dir(tmp_path,
                                                                 monkeypatch):
    monkeypatch.setenv("PARTITION_SINGLE_UNIT", "1")
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "50")
    files = [_write(tmp_path, "src/a.py", "x" * 300),
             _write(tmp_path, "src/b.py", "x" * 300),
             _write(tmp_path, "docs/readme.md", "x" * 50)]
    units = partition_units(str(tmp_path), files)
    assert units == [{"name": "src", "files": sorted(files),
                      "reason": "small-repo-single-unit"}]


def test_small_repo_unit_names_app_when_all_files_are_top_level(tmp_path,
                                                               monkeypatch):
    monkeypatch.setenv("PARTITION_SINGLE_UNIT", "1")
    files = [_write(tmp_path, "main.py"), _write(tmp_path, "util.py")]
    units = partition_units(str(tmp_path), files)
    assert units[0]["name"] == "app"
    assert units[0]["reason"] == "small-repo-single-unit"


def test_small_repo_rule_off_by_file_count(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "2")
    files = [_write(tmp_path, f"a/f{n}.py") for n in "abc"]
    units = partition_units(str(tmp_path), files)
    # Directory grouping survives (no single-unit collapse, no misc blob).
    assert [u["name"] for u in units] == ["a"]
    assert [u["reason"] for u in units] == ["top-level-directory"]


def test_small_repo_rule_off_by_byte_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_LOC_BUDGET", "100")   # nominal target 4000B
    monkeypatch.setenv("PARTITION_BYTES_PER_LOC", "40")
    assert partition_target({"x": 1}) == 4000
    files = [_write(tmp_path, f"d{i}/{n}.py", "x" * 3000)
             for i in range(2) for n in "ab"]
    assert _file_weights(str(tmp_path), files)["d0/a.py"] == 3000
    units = partition_units(str(tmp_path), files)
    assert all(u.get("reason") != "small-repo-single-unit" for u in units)
    # 12k of app files cannot fit the 4k ceiling, so the units are split by
    # the byte budget rather than collapsed into one.
    assert any(len(u["files"]) < 4 for u in units)
    assert all(sum(_file_weights(str(tmp_path), u["files"]).values())
               <= 4000 for u in units)


def test_small_repo_collapse_applies_to_llm_units(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "10")
    files = [_write(tmp_path, "api/users.py"), _write(tmp_path, "api/orders.py"),
             _write(tmp_path, "web/app.py"), _write(tmp_path, "web/views.py")]
    units = _enforce_coverage(
        [{"name": "users", "files": ["api/users.py"]},
         {"name": "orders", "files": ["api/orders.py"]},
         {"name": "web", "files": ["web/app.py", "web/views.py"]}],
        files, str(tmp_path))
    # "web" holds the most files (and bytes), so the collapse keeps its name.
    assert units == [{"name": "web", "files": sorted(files),
                      "reason": "small-repo-single-unit"}]


# --- P1.3 misc policy --------------------------------------------------------


def test_misc_code_merge_prefers_the_most_coupled_neighbour(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    edges = {("solo/x.py", "alpha/core.py"): 3, ("solo/x.py", "beta/core.py"): 9}
    units = _normalize_units([
        {"name": "alpha", "files": ["alpha/core.py", "alpha/util.py"], "reason": "d"},
        {"name": "beta", "files": ["beta/core.py", "beta/util.py"], "reason": "d"},
        {"name": "solo", "files": ["solo/x.py"], "reason": "d"},
    ], edges=edges)
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert "misc" not in by_name
    assert by_name["beta"] == ["beta/core.py", "beta/util.py", "solo/x.py"]
    assert sorted(f for u in units for f in u["files"]) == [
        "alpha/core.py", "alpha/util.py", "beta/core.py", "beta/util.py",
        "solo/x.py"]


def test_misc_code_merge_tie_breaks_on_unit_bytes(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    w = {"x/t.py": 10, "big/a.py": 500, "big/b.py": 500,
         "small/a.py": 100, "small/b.py": 100}
    edges = {("x/t.py", "big/a.py"): 4, ("x/t.py", "small/a.py"): 4}
    units = _normalize_units([
        {"name": "big", "files": ["big/a.py", "big/b.py"], "reason": "d"},
        {"name": "small", "files": ["small/a.py", "small/b.py"], "reason": "d"},
        {"name": "x", "files": ["x/t.py"], "reason": "d"},
    ], weight_of=w, target=5000, edges=edges)
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert by_name["big"] == ["big/a.py", "big/b.py", "x/t.py"]


def test_misc_code_merge_tie_breaks_on_unit_name(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    w = {"x/t.py": 10, "beta/a.py": 200, "beta/b.py": 200,
         "alpha/a.py": 200, "alpha/b.py": 200}
    edges = {("x/t.py", "beta/a.py"): 4, ("x/t.py", "alpha/a.py"): 4}
    units = _normalize_units([
        {"name": "beta", "files": ["beta/a.py", "beta/b.py"], "reason": "d"},
        {"name": "alpha", "files": ["alpha/a.py", "alpha/b.py"], "reason": "d"},
        {"name": "x", "files": ["x/t.py"], "reason": "d"},
    ], weight_of=w, target=5000, edges=edges)
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert by_name["alpha"] == ["alpha/a.py", "alpha/b.py", "x/t.py"]


def test_misc_code_merge_keeps_singleton_when_no_neighbour_fits(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    w = {"x/t.py": 100, "alpha/a.py": 300, "alpha/b.py": 300,
         "beta/a.py": 300, "beta/b.py": 300}
    edges = {("x/t.py", "alpha/a.py"): 5}
    units = _normalize_units([
        {"name": "alpha", "files": ["alpha/a.py", "alpha/b.py"], "reason": "d"},
        {"name": "beta", "files": ["beta/a.py", "beta/b.py"], "reason": "d"},
        {"name": "x", "files": ["x/t.py"], "reason": "d"},
    ], weight_of=w, target=650, edges=edges)
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert by_name["x"] == ["x/t.py"]          # 600 + 100 > 650 => no merge
    assert by_name["alpha"] == ["alpha/a.py", "alpha/b.py"]
    assert "misc" not in by_name


def test_misc_code_merge_without_edges_keeps_code_singletons(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    units = _normalize_units([
        {"name": "core", "files": ["core/a.py", "core/b.py"], "reason": "d"},
        {"name": "lone", "files": ["lone/z.py"], "reason": "d"},
    ], edges=None)
    assert {u["name"] for u in units} == {"core", "lone"}


def test_non_code_still_lands_in_misc_even_with_coupling(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    edges = {("docs/readme.md", "core/a.py"): 50,
             ("Makefile", "core/b.py"): 50}
    units = _normalize_units([
        {"name": "core", "files": ["core/a.py", "core/b.py"], "reason": "d"},
        {"name": "docs", "files": ["docs/readme.md"], "reason": "d"},
        {"name": "cfg", "files": ["Makefile"], "reason": "d"},
    ], edges=edges)
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert by_name["core"] == ["core/a.py", "core/b.py"]
    assert by_name["misc"] == ["Makefile", "docs/readme.md"]


def test_mixed_extensions_make_a_unit_code_not_non_code(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    units = _normalize_units([
        {"name": "core", "files": ["core/a.py", "core/b.py"], "reason": "d"},
        {"name": "mixed", "files": ["mixed/z.py", "mixed/README.md"], "reason": "d"},
    ])
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert by_name["mixed"] == ["mixed/README.md", "mixed/z.py"]
    assert "misc" not in by_name


def test_tiny_code_unit_named_misc_is_renamed_from_its_first_file(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    units = _normalize_units([
        {"name": "core", "files": ["core/a.py", "core/b.py"], "reason": "d"},
        {"name": "misc", "files": ["feature/z.py"], "reason": "llm-partition"},
    ])
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert "misc" not in by_name
    assert by_name["feature"] == ["feature/z.py"]

    top_level = _normalize_units(
        [{"name": "misc", "files": ["z.py"], "reason": "t"}])
    assert [u["name"] for u in top_level] == ["z"]   # basename stem fallback


def test_malformed_edges_never_raise(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    units = _normalize_units([
        {"name": "core", "files": ["core/a.py", "core/b.py"], "reason": "d"},
        {"name": "lone", "files": ["lone/z.py"], "reason": "d"},
    ], edges={"garbage": 5, ("a", "b"): "not-an-int", ("x",): 1})
    assert {u["name"] for u in units} == {"core", "lone"}
    assert _load_partition_edges("no-such-repo-xyz", ["a.py"]) == {}


def test_grouping_helpers_work_without_edges(monkeypatch):
    """edges defaults to None: tiny code units stay singletons, never misc."""
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    units = _units_from_dirs("repo", ["a/1.py", "a/2.py", "b/3.py"])
    assert {u["name"] for u in units} == {"a", "b"}
    assert sorted(f for u in units for f in u["files"]) == [
        "a/1.py", "a/2.py", "b/3.py"]


def test_big_misc_unit_stays_the_catch_all(monkeypatch):
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    units = _normalize_units([
        {"name": "misc", "files": ["a.md", "b.md", "c.md"],
         "reason": "folded-over-cap"},
        {"name": "docs", "files": ["readme.rst"], "reason": "d"},
    ], edges={("readme.rst", "a.md"): 5})
    by_name = {u["name"]: sorted(u["files"]) for u in units}
    assert by_name["misc"] == ["a.md", "b.md", "c.md", "readme.rst"]


def test_post_merge_rebalance_fixes_over_budget_misc(monkeypatch):
    """Non-code leftovers still absorb into misc under the new policy, and the
    re-balance must not leave that blob over budget."""
    monkeypatch.delenv("MIN_FILES", raising=False)
    monkeypatch.delenv("MAX_UNITS", raising=False)
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    w = {f"p{i:03d}/m.md": 10_000 for i in range(100)}
    units = _normalize_units(
        [{"name": f"p{i:03d}", "files": [f], "reason": "d"}
         for i, f in enumerate(w)],
        weight_of=w, target=250_000)
    assert all(sum(w[f] for f in u["files"]) <= 250_000 for u in units)
    assert sorted(f for u in units for f in u["files"]) == sorted(w)
    assert len(units) >= 4  # 1,000,000 / 250,000


def test_legacy_misc_policy_unchanged_when_flag_off():
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "0")
    try:
        units = _normalize_units([
            {"name": "a", "files": ["a.py", "b.py"], "reason": "t"},
            {"name": "b", "files": ["c.py"], "reason": "t"},
        ])
        assert {u["name"] for u in units} == {"a", "misc"}
    finally:
        monkeypatch.undo()


# --- invariants --------------------------------------------------------------


def test_budget_exempt_unit_skips_the_budget_assertion(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    files = [_write(tmp_path, "src/a.py"),
             _write(tmp_path, "node_modules/dep.js", "x" * 5000)]
    w = _file_weights(str(tmp_path), files)
    units = partition_units(str(tmp_path), files)
    verify_partition(units, files, weight_of=w, target=10)  # vendor is exempt
    over = [{"name": "app", "files": ["a.py", "b.py"], "budget_exempt": False}]
    with pytest.raises(AssertionError):  # non-exempt multi-file over target
        verify_partition(over, ["a.py", "b.py"],
                         weight_of={"a.py": 300, "b.py": 300}, target=400)
    verify_partition([{**over[0], "budget_exempt": True}], ["a.py", "b.py"],
                     weight_of={"a.py": 300, "b.py": 300},
                     target=400)  # same unit exempt: no assertion


def test_partition_units_invariants_hold_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("PARTITION_VENDOR_UNIT", "1")
    monkeypatch.setenv("PARTITION_SINGLE_UNIT_MAX_FILES", "0")
    monkeypatch.setenv("PARTITION_MISC_CODE_MERGE", "1")
    files = [_write(tmp_path, f"d{i}/f{n}.py") for i in range(4) for n in "abcd"]
    files += [_write(tmp_path, "docs/readme.md"),
              _write(tmp_path, "vendor/lib/dep.js")]
    units = partition_units(str(tmp_path), files)
    w = _file_weights(str(tmp_path), files)
    stats = verify_partition(units, files, weight_of=w,
                             target=partition_target(w))
    assert stats["files"] == len(files)
    names = [u["name"] for u in units]
    assert len(names) == len(set(names))          # unique hunter labels
    assert names[-1] == "vendor"
    assert units[-1]["files"] == ["vendor/lib/dep.js"]
