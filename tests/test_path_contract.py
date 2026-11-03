"""Path contract: one canonical root, three input spellings, relative output."""
from __future__ import annotations

import pytest
from cerberus.paths import canonical_repo, resolve_tool_path, to_repo_relative
from cerberus.sandbox.local_backend import RepoLocalBackend
from cerberus.tools.code import _safe_path


@pytest.fixture()
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\n")
    return root


def test_canonical_repo_is_absolute(repo):
    assert canonical_repo(repo) == repo.resolve()
    assert canonical_repo(str(repo)) == repo.resolve()


def test_relative_host_absolute_and_virtual_forms(repo):
    expected = (repo / "src" / "a.py").resolve()
    assert resolve_tool_path("src/a.py", repo) == expected
    assert resolve_tool_path(str(expected), repo) == expected
    assert resolve_tool_path("/src/a.py", repo) == expected


def test_nonexistent_child_is_allowed_for_writes(repo):
    expected = (repo / "src" / "new.py").resolve()
    assert resolve_tool_path("src/new.py", repo) == expected


def test_escape_forms_are_denied(repo):
    assert resolve_tool_path("../outside.py", repo) is None
    assert resolve_tool_path(str(repo.parent / "outside.py"), repo) is None
    assert resolve_tool_path("/definitely-not-in-this-repo", repo) is None


def test_virtual_path_requires_a_repo_local_target(repo):
    (repo / "etc").mkdir()
    (repo / "etc" / "passwd").write_text("repo-local\n")
    assert resolve_tool_path("/etc/passwd", repo) == (repo / "etc" / "passwd").resolve()
    assert resolve_tool_path("/etc/hosts", repo) is None


def test_symlink_escape_is_denied(repo):
    outside = repo.parent / "secret.txt"
    outside.write_text("secret\n")
    link = repo / "link.txt"
    link.symlink_to(outside)
    assert resolve_tool_path("link.txt", repo) is None
    assert resolve_tool_path(str(link), repo) is None


def test_to_repo_relative_normalizes_contained_forms(repo):
    expected = "src/a.py"
    assert to_repo_relative("src/a.py", repo) == expected
    assert to_repo_relative("./src/a.py", repo) == expected
    assert to_repo_relative(str(repo / "src" / "a.py"), repo) == expected
    assert to_repo_relative("/src/a.py", repo) == expected
    assert to_repo_relative(".", repo) == "."


def test_repo_name_prefix_prefers_the_literal_existing_path(tmp_path):
    root = tmp_path / "cyber"
    (root / "cyber").mkdir(parents=True)
    (root / "inner.py").write_text("root\n")
    (root / "other.py").write_text("other\n")
    (root / "cyber" / "inner.py").write_text("nested\n")
    # Both files exist; the literal nested path must win over prefix stripping.
    assert to_repo_relative("cyber/inner.py", root) == "cyber/inner.py"
    # Prefix stripping still handles the model-habit form when the literal
    # nested path does not exist.
    assert to_repo_relative("cyber/other.py", root) == "other.py"


def test_backend_accepts_host_absolute_and_preserves_shadowing(repo):
    target = repo / "src" / "a.py"
    backend = RepoLocalBackend(repo_path=repo)
    res = backend.read(str(target))
    assert res.error is None
    assert "x = 1" in (res.file_data or {}).get("content", "")

    (repo / "etc").mkdir()
    (repo / "etc" / "passwd").write_text("repo-local\n")
    shadow = backend.read("/etc/passwd")
    assert shadow.error is None
    assert "repo-local" in (shadow.file_data or {}).get("content", "")


def test_safe_path_accepts_host_absolute_under_target_repo(repo, monkeypatch):
    target = repo / "src" / "a.py"
    monkeypatch.setenv("TARGET_REPO", str(repo))
    assert _safe_path(str(target)) == target.resolve()
