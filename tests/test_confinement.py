"""Agent containment: nothing leaves the target repo directory.

Covers the three enforcement points:
1. sast.py tools refuse out-of-repo targets and scrub secrets from children.
2. RepoLocalBackend confines reads and has no shell; mutations are functional
   but any path resolving outside the repo is re-pointed inside it.
3. Agents built on it expose no execute tool and require an explicit repo.
"""

import pytest
from cerberus.sandbox.local_backend import RepoLocalBackend
from cerberus.scan_manifest import close_scan, record_scan_manifest
from cerberus.tools import sast as S


def _call(tool, **kwargs):
    fn = tool.func if hasattr(tool, "func") else tool
    return fn(**kwargs)


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    root = tmp_path / "target"
    (root / "sub").mkdir(parents=True)
    (root / "app.py").write_text("x = 1\n")
    (root / "sub" / "b.py").write_text("y = 2\n")
    monkeypatch.setenv("TARGET_REPO", str(root))
    return root


@pytest.fixture()
def backend(repo):
    return RepoLocalBackend(repo_path=repo)


# --- sast.py tools ----------------------------------------------------

ESCAPES = [
    "/etc/hosts",
    "/etc/passwd",
    "../../../etc/hosts",
    "/tmp",
]


@pytest.mark.parametrize("path", ESCAPES)
def test_sast_tools_refuse_escapes(repo, path):
    for tool in (S.secrets_scan, S.sca_scan, S.iac_check):
        out = _call(tool, target=path)
        assert isinstance(out, str) and out.startswith("ERROR:"), (
            f"{tool} accepted escape {path!r}")


def test_sast_symlink_escape_refused(repo):
    outside = repo.parent / "secret.txt"
    outside.write_text("password = 'hunter2'\n")
    link = repo / "innocent.py"
    try:
        link.symlink_to(outside)
        out = _call(S.iac_check, target="innocent.py")
        assert out.startswith("ERROR:"), f"symlink escape accepted: {out[:100]}"
    finally:
        if link.is_symlink() or link.exists():
            link.unlink()
        outside.unlink()


def test_sast_children_do_not_inherit_secrets(repo, monkeypatch):
    monkeypatch.setenv("API_KEY", "sk-test-should-not-leak")
    out = S._run(["env"], max_bytes=0)
    leaked = [l for l in out["stdout"].splitlines()
              if l.startswith("API_KEY=")]
    assert leaked == []
    assert any(l.startswith("PATH=") for l in out["stdout"].splitlines())


def test_template_candidates_refuse_escapes(repo):
    assert S.template_reflect_candidates("/etc") == []


# --- backend ----------------------------------------------------------

@pytest.mark.parametrize("path", ESCAPES)
def test_backend_read_refuses_escapes(backend, repo, path):
    """Virtual-mode reads of an absolute path map INTO the repo; the host
    file at that path is never read, and a traversal resolving outside
    returns a structured not-found."""
    res = backend.read(path)
    if path.startswith("/"):
        # /etc/passwd -> repo/etc/passwd: absent inside the repo, so an
        # error is returned and host content never appears.
        assert res.error, f"read of {path} unexpectedly succeeded"
        content = (res.file_data or {}).get("content", "") if isinstance(
            res.file_data, dict) else ""
        assert "root:" not in content and "127.0.0.1" not in content
    else:
        # A traversal escape resolves outside the repo: structured not-found.
        assert res.error and "not found" in res.error


def test_backend_symlink_escape_refused(backend, repo):
    outside = repo.parent / "secret.txt"
    outside.write_text("top secret\n")
    link = repo / "evil.py"
    try:
        link.symlink_to(outside)
        res = backend.read("evil.py")
        assert res.error and "not found" in res.error
    finally:
        if link.is_symlink() or link.exists():
            link.unlink()
        outside.unlink()


def test_backend_legit_reads_work(backend):
    res = backend.read("app.py")
    assert res.error is None
    assert "x = 1" in (res.file_data["content"] if isinstance(res.file_data, dict) else "")


def test_backend_has_no_shell(backend):
    assert not hasattr(backend, "execute")
    assert not hasattr(backend, "aexecute")


@pytest.mark.parametrize("method", ["write", "edit", "delete"])
def test_backend_mutation_works_and_stays_confined(backend, repo, method):
    # Mutations are functional by design; nothing resolves OUTSIDE the repo.
    if method == "write":
        res = backend.write("app.py", "z = 9\n")
        assert (repo / "app.py").read_text() == "z = 9\n"
    elif method == "edit":
        res = backend.edit("app.py", "x = 1", "x = 41")
        assert "x = 41" in (repo / "app.py").read_text()
    else:
        res = backend.delete("app.py")
        assert not (repo / "app.py").exists()
    assert res.error is None
    outside = repo.parent / "app.py"
    assert not outside.exists()  # never written through the boundary


def test_manifest_digests_content_not_size(repo):
    from cerberus.scan_manifest import _digest_repo
    (repo / "app.py").write_text("x = 1\n")
    before = _digest_repo(repo)["manifest_hash"]
    (repo / "app.py").write_text("x = 2\n")          # SAME size, different content
    assert _digest_repo(repo)["manifest_hash"] != before


def test_manifest_records_no_credential_fields(repo):
    """The credential-file bookkeeping subsystem was removed outright."""
    (repo / ".env").write_text("API_KEY=x\n")
    record = record_scan_manifest(repo)
    assert "credential_files" not in record
    assert "credential_files_error" not in record


def test_docker_settings_do_not_mask_credentials(repo):
    from cerberus.sandbox import _docker_settings
    settings = _docker_settings({"sandbox": {}}, repo)
    assert "mask_paths" not in settings


def test_backend_rejects_non_directory(tmp_path):
    with pytest.raises(ValueError, match="not a directory"):
        RepoLocalBackend(repo_path=tmp_path / "missing")


# --- agent composition -------------------------------------------------

def test_agent_has_no_execute_tool(repo, monkeypatch):
    # Two independent layers: the backend type never materializes `execute`
    # (only a SandboxBackendProtocol does), and the per-agent fs allowlist
    # (`_fs_tools`) omits it for a non-sandbox backend.
    import itertools

    from cerberus.agents.deep import SHELL_TOOL, _fs_tools, build_deep_agent
    from cerberus.sandbox.local_backend import RepoLocalBackend
    from deepagents.backends.protocol import SandboxBackendProtocol
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

    local_backend = RepoLocalBackend(repo_path=repo)
    assert SHELL_TOOL not in _fs_tools(local_backend)
    assert not isinstance(local_backend, SandboxBackendProtocol)

    # The agent still builds (profile registration no longer crashes on
    # models without a name).
    monkeypatch.delenv("TARGET_REPO", raising=False)
    llm = GenericFakeChatModel(messages=itertools.repeat("ok"))
    agent = build_deep_agent(llm, system_prompt="x", tools=[], name="t",
                             root_dir=repo)
    assert agent is not None


def test_agent_requires_explicit_repo(monkeypatch):
    from cerberus.agents.deep import build_deep_agent

    monkeypatch.delenv("TARGET_REPO", raising=False)
    with pytest.raises(ValueError, match="root_dir or TARGET_REPO"):
        build_deep_agent(object(), system_prompt="x", tools=[])


def test_agent_falls_back_to_target_repo(repo, monkeypatch):
    import itertools

    from cerberus.agents.deep import build_deep_agent
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

    llm = GenericFakeChatModel(messages=itertools.repeat("ok"))
    # No root_dir: TARGET_REPO (set by the repo fixture) is used, not CWD.
    agent = build_deep_agent(llm, system_prompt="x", tools=[], name="t")
    assert agent is not None


# --- manifest ----------------------------------------------------------

def test_manifest_detects_mid_scan_edits(repo):
    record_scan_manifest(repo)
    (repo / "app.py").write_text("x = 1  # edited mid-scan\n")
    record = close_scan(repo)
    assert record["tree_changed_during_scan"] is True
    assert record["manifest_files"] == 2


def test_manifest_clean_when_untouched(repo):
    record_scan_manifest(repo)
    record = close_scan(repo)
    assert record["tree_changed_during_scan"] is False


def test_manifest_ignores_generated_scan_dirs(repo):
    """The index/tmp writes during a scan are not target-source changes."""
    record_scan_manifest(repo)
    (repo / ".codegraph").mkdir()
    (repo / ".codegraph" / "codegraph.db").write_bytes(b"index")
    (repo / "tmp").mkdir()
    (repo / "tmp" / "scratch.py").write_text("x = 1\n")
    record = close_scan(repo)
    assert record["tree_changed_during_scan"] is False
    assert record["manifest_files"] == 2


def test_close_scan_never_raises(tmp_path):
    assert close_scan(tmp_path / "missing")["manifest_files"] == 0


def test_backend_read_shadowed_virtual_path_returns_repo_file(repo):
    """A repo that CONTAINS etc/passwd shadows the host path: the repo file
    wins, host content never appears."""
    (repo / "etc").mkdir()
    (repo / "etc" / "passwd").write_text("repo-local passwd")
    backend = RepoLocalBackend(repo_path=repo)
    res = backend.read("/etc/passwd")
    assert res.error is None
    content = res.file_data["content"] if isinstance(res.file_data, dict) else ""
    assert "repo-local passwd" in content
    assert "root:" not in content
