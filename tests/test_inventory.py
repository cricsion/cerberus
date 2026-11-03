from pathlib import Path

from cerberus.pipeline import _inventory_files, _is_shebang_script

_PY_SHEBANG = "#!/usr/bin/env python3\nprint('hi')\n"
_NODE_SHEBANG = "#!/usr/bin/env node\nconsole.log('hi')\n"
_BASH_SHEBANG = "#!/bin/bash\necho hi\n"


def test_extensionless_shebang_scripts_included(tmp_path):
    (tmp_path / "www").write_text(_PY_SHEBANG)
    (tmp_path / "manage").write_text(_NODE_SHEBANG)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "start").write_text(_BASH_SHEBANG)
    files = _inventory_files(tmp_path)
    assert sorted(files) == ["bin/start", "manage", "www"]


def test_extensionless_data_file_excluded(tmp_path):
    (tmp_path / "LICENSE").write_text("plain text blob with no shebang\nline two\n")
    (tmp_path / "data").write_text("some\tstuff\nnot code\n")
    (tmp_path / "app.py").write_text("print('x')\n")
    assert _inventory_files(tmp_path) == ["app.py"]


def test_symlinked_extensionless_script_excluded(tmp_path):
    (tmp_path / "bin").mkdir()
    real = tmp_path / "bin" / "www"
    real.write_text(_PY_SHEBANG)
    link = tmp_path / "www"
    link.symlink_to(real, target_is_directory=False)
    files = _inventory_files(tmp_path)
    assert files == ["bin/www"]
    assert "www" not in files


def test_large_extensionless_file_excluded(tmp_path):
    (tmp_path / "blob").write_text("#!" + "x" * 300_000)
    (tmp_path / "app.py").write_text("pass\n")
    assert _inventory_files(tmp_path) == ["app.py"]


def test_normal_extensions_unchanged(tmp_path):
    (tmp_path / "a.py").write_text("pass\n")
    (tmp_path / "b.js").write_text("let a = 1\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "notes.txt").write_text("ignored\n")
    (tmp_path / "readme").write_text("no shebang, no extension\n")
    assert _inventory_files(tmp_path) == ["Dockerfile", "a.py", "b.js"]


def test_base_is_file_returns_that_file(tmp_path):
    target = tmp_path / "solo.py"
    target.write_text("pass\n")
    assert _inventory_files(target) == [str(target)]


def test_missing_base_returns_empty(tmp_path):
    assert _inventory_files(tmp_path / "nope") == []


def test_inventory_deterministic(tmp_path):
    """The inventory is sorted, so identical repos give identical lists."""
    (tmp_path / "www").write_text(_PY_SHEBANG)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "start").write_text(_BASH_SHEBANG)
    (tmp_path / "app.py").write_text("pass\n")
    expected = ["app.py", "bin/start", "www"]
    assert _inventory_files(tmp_path) == expected
    assert _inventory_files(tmp_path) == expected  # stable across calls


def test_is_shebang_script_binary_returns_false(tmp_path):
    blob = tmp_path / "firmware"
    blob.write_bytes(b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 8)
    assert _is_shebang_script(blob) is False


def test_is_shebang_script_unreadable_returns_false(tmp_path):
    assert _is_shebang_script(tmp_path) is False
    assert _is_shebang_script(tmp_path / "missing") is False


def test_is_shebang_script_ignores_suffixed_and_unknown(tmp_path):
    script = tmp_path / "app.py"
    script.write_text(_PY_SHEBANG)
    assert _is_shebang_script(script) is False
    weird = tmp_path / "tool"
    weird.write_text("#!/usr/bin/awk -f\nprint('hi')\n")
    assert _is_shebang_script(weird) is False
    for name, text in (("p", _PY_SHEBANG), ("n", _NODE_SHEBANG), ("b", _BASH_SHEBANG)):
        p = tmp_path / name
        p.write_text(text)
        assert _is_shebang_script(p) is True


def test_is_shebang_script_no_shebang_first_line(tmp_path):
    p = tmp_path / "conf"
    p.write_text("# python config\nkey = value\n")
    assert _is_shebang_script(p) is False


def test_indexer_node_includes_extensionless_entrypoint(tmp_path):
    (tmp_path / "views.py").write_text("pass\n")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "www").write_text(_PY_SHEBANG)
    from cerberus.pipeline import indexer_node

    state = indexer_node({"repo": str(tmp_path)})
    assert "bin/www" in state["files"]
    assert "views.py" in state["files"]


def test_is_shebang_script_large_is_false(tmp_path):
    big = tmp_path / "big"
    big.write_text(_PY_SHEBANG + "y" * 300_000)
    assert _is_shebang_script(big) is False
    assert Path(big).is_file()


def test_inventory_skips_generated_and_dependency_dirs(tmp_path):
    for name in (".codegraph", "tmp", "node_modules", "vendor", "dist",
                 "build", ".next", "site-packages", ".worktrees"):
        nested = tmp_path / name / "nested"
        nested.mkdir(parents=True)
        (nested / "noise.py").write_text("pass\n")
    (tmp_path / "app.py").write_text("pass\n")
    assert _inventory_files(tmp_path) == ["app.py"]


def test_inventory_keeps_unmarked_target_and_skips_build_target(tmp_path):
    # A Python app's target/ is first-party source. Cargo/Maven target/ is not.
    (tmp_path / "target" / "project").mkdir(parents=True)
    (tmp_path / "target" / "project" / "app.py").write_text("pass\n")
    (tmp_path / "target" / "runserver.py").write_text("pass\n")

    (tmp_path / "rust").mkdir()
    (tmp_path / "rust" / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    (tmp_path / "rust" / "target" / "debug").mkdir(parents=True)
    (tmp_path / "rust" / "target" / "debug" / "gen.py").write_text("pass\n")

    (tmp_path / "maven").mkdir()
    (tmp_path / "maven" / "pom.xml").write_text("<project/>\n")
    (tmp_path / "maven" / "target" / "classes").mkdir(parents=True)
    (tmp_path / "maven" / "target" / "classes" / "Gen.java").write_text("class Gen {}\n")

    assert _inventory_files(tmp_path) == [
        "target/project/app.py", "target/runserver.py"]


def test_inventory_skips_venv_env_but_keeps_config_env(tmp_path):
    (tmp_path / "env" / "bin").mkdir(parents=True)
    (tmp_path / "env" / "bin" / "activate").write_text("#!/bin/sh\n")
    (tmp_path / "env" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (tmp_path / "env" / "lib" / "python3.12" / "site-packages" / "dep.py").write_text("pass\n")

    (tmp_path / "config" / "env").mkdir(parents=True)
    (tmp_path / "config" / "env" / "all.js").write_text("module.exports = {}\n")
    (tmp_path / "config" / "env" / "development.js").write_text("module.exports = {}\n")
    (tmp_path / "app.py").write_text("pass\n")

    assert _inventory_files(tmp_path) == [
        "app.py", "config/env/all.js", "config/env/development.js"]


def test_inventory_gates_env_suffix_and_skips_venv_suffix(tmp_path):
    (tmp_path / "config_env").mkdir()
    (tmp_path / "config_env" / "app.js").write_text("module.exports = {}\n")

    (tmp_path / "my_env").mkdir()
    (tmp_path / "my_env" / "pyvenv.cfg").write_text("home = /x\n")
    (tmp_path / "my_env" / "app.py").write_text("pass\n")

    (tmp_path / "my_venv").mkdir()
    (tmp_path / "my_venv" / "app.py").write_text("pass\n")

    (tmp_path / "pkg.egg-info").mkdir()
    (tmp_path / "pkg.egg-info" / "info.py").write_text("pass\n")

    (tmp_path / "app.py").write_text("pass\n")
    assert _inventory_files(tmp_path) == ["app.py", "config_env/app.js"]


def test_inventory_keeps_out_and_coverage(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "a.js").write_text("let a = 1\n")
    (tmp_path / "coverage").mkdir()
    (tmp_path / "coverage" / "b.js").write_text("let b = 1\n")
    (tmp_path / "app.py").write_text("pass\n")
    assert _inventory_files(tmp_path) == [
        "app.py", "coverage/b.js", "out/a.js"]


def test_grep_files_uses_inventory_skip_policy(tmp_path, monkeypatch):
    from cerberus.tools.code import grep_files

    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    (tmp_path / "target" / "project").mkdir(parents=True)
    (tmp_path / "target" / "project" / "visible.py").write_text("NEEDLE = 1\n")

    (tmp_path / "rust").mkdir()
    (tmp_path / "rust" / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    (tmp_path / "rust" / "target" / "debug").mkdir(parents=True)
    (tmp_path / "rust" / "target" / "debug" / "hidden.py").write_text("NEEDLE = 2\n")

    output = grep_files("NEEDLE", include="*.py")
    assert "target/project/visible.py" in output
    assert "rust/target/debug/hidden.py" not in output
