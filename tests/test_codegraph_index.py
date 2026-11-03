"""P1 gate tests for ``cerberus.codegraph._index`` (index lifecycle).

Two layers:

- **Offline gate/containment/protocol tests** drive the module against a fake
  ``subprocess`` seam and canned ``status -j`` payloads, so the walk-up
  rejections, the init-first rule, the sync-only-on-own-index rule, fail-open,
  and the per-call env flags are all pinned without any CLI on the host.
- **Live tests** (``skipif`` no CLI) build a real index with codegraph 1.6.2 in
  ``tmp_path`` and assert the same contracts against the real thing: a fresh
  root is initialized first, the second run is a gated skip, and a nested
  target gets its OWN index instead of the ancestor's. Nothing here reads or
  writes ``tests/fixtures`` or any original repo: the live fixture is a
  two-file repo authored in ``tmp_path``.

Payload shapes below are quoted from live 1.6.2 output (see the module
docstring for the full shape and the gate predicate).
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cerberus.codegraph import _index
from codegraph_support import live_cli

CLI = "/opt/fake/bin/codegraph"

_DB_REL = ".codegraph/codegraph.db"


# ---------------------------------------------------------------------------
# fixtures + fakes
# ---------------------------------------------------------------------------

@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A target root with an index-shaped ``.codegraph`` (no CLI involved)."""
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    return tmp_path


def _seed_index(root: Path) -> Path:
    db = root / _DB_REL
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_bytes(b"SQLite format 3\x00")
    return db


def _payload(root: Path, *, state="complete", pending_refs=0, reindex=False,
             changes=(0, 0, 0), project=None, index_dir=None, extra=True,
             initialized=True) -> dict:
    """A ``status -j`` payload in the live 1.6.2 shape (nesting included)."""
    payload = {
        "initialized": initialized,
        "version": "1.6.2",
        "projectPath": str(project if project is not None else root),
        "indexPath": str(index_dir if index_dir is not None
                          else root / ".codegraph"),
        "fileCount": 2,
        "nodeCount": 7,
        "edgeCount": 6,
        "languages": ["python"],
        "pendingChanges": {"added": changes[0], "modified": changes[1],
                           "removed": changes[2]},
    }
    if extra:
        payload["index"] = {
            "builtWithVersion": "1.6.2",
            "builtWithExtractionVersion": 27,
            "currentExtractionVersion": 27,
            "reindexRecommended": reindex,
            "state": state,
            "pendingRefs": pending_refs,
        }
    return payload


class _Recorder:
    """Records every CLI call; answers ``status -j`` from a script.

    ``statuses`` is the queue of payloads returned by successive ``status``
    calls (the last one repeats). ``on_init`` mimics the real ``init``: it
    creates ``<root>/.codegraph/codegraph.db``, because the gate asserts the
    DB exists where ``_db.resolve_db_path`` says.
    """

    def __init__(self, root: Path, statuses: list[dict | str], *,
                 status_rc: int = 0, builds: str = "ok"):
        self.root = root
        self.statuses = list(statuses) or [{}]
        self.status_rc = status_rc
        self.builds = builds
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []

    def run(self, cmd, **kwargs) -> SimpleNamespace:
        self.calls.append(list(cmd))
        self.envs.append(dict(kwargs.get("env") or {}))
        sub = cmd[1]
        if sub in ("init", "index", "sync"):
            if self.builds == "ok":
                _seed_index(self.root)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if sub == "status":
            n = sum(1 for c in self.calls if c[1] == "status")
            item = self.statuses[min(n - 1, len(self.statuses) - 1)]
            out = item if isinstance(item, str) else json.dumps(item)
            return SimpleNamespace(returncode=self.status_rc, stdout=out, stderr="")
        raise AssertionError(f"unexpected CLI subcommand: {cmd}")

    @property
    def subs(self) -> list[str]:
        return [c[1] for c in self.calls]


def _install(monkeypatch, rec: _Recorder, *, cli: str | None = CLI):
    monkeypatch.setattr(_index, "subprocess", SimpleNamespace(run=rec.run))
    monkeypatch.setattr(_index, "_cli_path", lambda: cli)
    return rec


# ---------------------------------------------------------------------------
# gate parsing
# ---------------------------------------------------------------------------

def test_valid_payload_gates_ready(repo, monkeypatch):
    db = _seed_index(repo)
    rec = _install(monkeypatch, _Recorder(repo, [_payload(repo)]))
    assert _index.index_needed(str(repo)) is False
    assert _index.index_status(str(repo))["index"]["state"] == "complete"
    assert [c[1] for c in rec.calls] == ["status"] * len(rec.calls)
    assert str(db) == _index.index_build(str(repo))
    # Fresh ⇒ only status READS happened: no init/index/sync write.
    assert set(rec.subs) == {"status"}


@pytest.mark.parametrize("payload", [
    "{not json at all",                       # malformed
    json.dumps([1, 2, 3]),                    # not an object
    "",                                       # empty stdout
    json.dumps({"initialized": False}),       # missing `index` block entirely
    json.dumps({"index": {"state": "complete"}}),        # missing pendingRefs
    json.dumps({"index": {"state": "complete", "pendingRefs": 0}}),  # no flag
    json.dumps(_payload(Path("/tmp/x"), state="building")),
    json.dumps(_payload(Path("/tmp/x"), pending_refs=3)),
    json.dumps(_payload(Path("/tmp/x"), reindex=True)),
    json.dumps(_payload(Path("/tmp/x"), changes=(1, 0, 0))),
    json.dumps({**_payload(Path("/tmp/x")), "index": {"state": "complete",
                                                     "pendingRefs": "0",
                                                     "reindexRecommended": False}}),
    json.dumps({**_payload(Path("/tmp/x")), "pendingChanges": {"added": 0}}),
], ids=["malformed", "not-object", "empty", "no-index-block", "no-pendingRefs",
        "no-reindex-flag", "state-building", "pendingRefs", "reindex-recommended",
        "pending-changes", "pendingRefs-type", "changes-incomplete"])
def test_not_ready_payloads_are_never_ready(repo, monkeypatch, payload):
    _seed_index(repo)
    _install(monkeypatch, _Recorder(repo, [payload]))
    assert _index.index_needed(str(repo)) is True
    assert _index.index_status(str(repo)) == {}


def test_missing_codegraph_dir_is_not_ready(repo, monkeypatch):
    # Payload says complete, but `<root>/.codegraph` (and the DB) do not exist:
    # the gate asserts the files where _db.resolve_db_path joins.
    _install(monkeypatch, _Recorder(repo, [_payload(repo)]))
    assert _index.index_needed(str(repo)) is True
    assert _index.index_status(str(repo))["index"]["state"] == "complete"


def test_db_absent_below_codegraph_is_not_ready(repo, monkeypatch):
    (repo / ".codegraph").mkdir()
    _install(monkeypatch, _Recorder(repo, [_payload(repo)]))
    assert _index.index_needed(str(repo)) is True


# ---------------------------------------------------------------------------
# containment gates
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("override", [
    pytest.param({"project": "ancestor", "index_dir": "ancestor"}, id="ancestor-indexpath"),
    pytest.param({"project": "ancestor"}, id="mismatched-projectpath"),
    pytest.param({"index_dir": "ancestor"}, id="wrong-indexpath-right-project"),
])
def test_status_rejects_an_index_that_is_not_this_root(repo, monkeypatch, caplog, override):
    # The live walk-up: `status -j <root>/pkg` answers for <root>. Both halves of
    # the containment predicate (projectPath and indexPath) must name this root.
    _seed_index(repo)
    ancestor = repo.parent
    kwargs = {key: ancestor if value == "ancestor" else ancestor / ".codegraph"
              for key, value in override.items()}
    _install(monkeypatch, _Recorder(repo, [_payload(repo, **kwargs)]))
    with caplog.at_level("WARNING"):
        assert _index.index_status(str(repo)) == {}
    assert "refusing an index that is not this root's" in caplog.text
    assert str(ancestor) in caplog.text




def test_status_accepts_symlinked_equivalent_path(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    _seed_index(real)
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    _install(monkeypatch, _Recorder(real, [_payload(real)]))
    # Requested via the symlink, answered by the CLI with the resolved path.
    payload = _index.index_status(str(link))
    assert payload and payload["projectPath"] == str(real)


# ---------------------------------------------------------------------------
# build ordering + fail-open
# ---------------------------------------------------------------------------

def test_init_and_sync_run_when_not_fresh(repo, monkeypatch):
    # A non-fresh root runs `init -y <root>` then `sync -q <root>`.
    rec = _install(monkeypatch, _Recorder(repo, [_payload(repo, extra=False),
                                                _payload(repo)]))
    assert _index.index_build(str(repo)) == str(repo / _DB_REL)
    assert rec.subs == ["status", "init", "sync", "status"]
    assert rec.calls[1] == [CLI, "init", "-y", str(repo)]
    assert rec.calls[2] == [CLI, "sync", "-q", str(repo)]


@pytest.mark.parametrize("payload", [
    "{not json at all", json.dumps({"initialized": False}),
])
def test_init_runs_when_status_is_unusable(repo, monkeypatch, payload):
    rec = _install(monkeypatch, _Recorder(repo, [payload, _payload(repo)]))
    assert _index.index_build(str(repo)) == str(repo / _DB_REL)
    assert rec.subs == ["status", "init", "sync", "status"]


def test_sync_when_own_db_exists_and_gate_stale(repo, monkeypatch):
    db = _seed_index(repo)
    rec = _install(monkeypatch, _Recorder(repo, [
        _payload(repo, changes=(0, 1, 0)), _payload(repo)]))
    assert _index.index_build(str(repo)) == str(db)
    assert rec.subs == ["status", "init", "sync", "status"]
    assert rec.calls[1] == [CLI, "init", "-y", str(repo)]
    assert rec.calls[2] == [CLI, "sync", "-q", str(repo)]


def test_build_returns_empty_when_gate_never_passes(repo, monkeypatch):
    stalled = _payload(repo, state="building")
    rec = _install(monkeypatch, _Recorder(repo, [_payload(repo, extra=False),
                                                 stalled]))
    assert _index.index_build(str(repo)) == ""
    assert rec.subs == ["status", "init", "sync", "status"]


@pytest.mark.parametrize("exc", [OSError("no such binary"),
                                 __import__("subprocess").TimeoutExpired("cg", 5)])
def test_fail_open_on_subprocess_failure(repo, monkeypatch, exc):
    monkeypatch.setattr(_index, "_cli_path", lambda: CLI)

    def boom(cmd, **kwargs):
        raise exc

    monkeypatch.setattr(_index, "subprocess", SimpleNamespace(run=boom))
    assert _index.index_build(str(repo)) == ""
    assert _index.index_status(str(repo)) == {}
    assert _index.index_needed(str(repo)) is True
    assert "unavailable" in _index.index_summary(str(repo))


def test_no_cli_is_fail_open(repo, monkeypatch):
    _seed_index(repo)
    _install(monkeypatch, _Recorder(repo, [_payload(repo)]), cli=None)
    assert _index.index_status(str(repo)) == {}
    assert _index.index_needed(str(repo)) is True
    assert _index.index_build(str(repo)) == ""


def test_non_directory_root_never_builds(tmp_path, monkeypatch):
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    target = tmp_path / "app.py"
    target.write_text("x = 1\n")
    rec = _install(monkeypatch, _Recorder(tmp_path, [_payload(tmp_path)]))
    assert _index.index_build(str(target)) == ""
    # Not even a status read: a file path cannot be a repo root here.
    assert rec.calls == []


def test_unaddressable_root_is_fail_open(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    inside = tmp_path / "inside"
    inside.mkdir()
    monkeypatch.setenv("TARGET_REPO", str(inside))
    _install(monkeypatch, _Recorder(inside, [_payload(inside)]))
    # root escapes TARGET_REPO ⇒ _db.resolve_db_path raises ValueError.
    assert _index.index_status(str(outside)) == {}
    assert _index.index_needed(str(outside)) is True
    assert _index.index_build(str(outside)) == ""


# ---------------------------------------------------------------------------
# D9 / hygiene: the env of EVERY CLI call
# ---------------------------------------------------------------------------

def test_every_cli_call_carries_the_scan_env_flags(repo, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-do-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    rec = _install(monkeypatch, _Recorder(repo, [
        _payload(repo, changes=(1, 0, 0)), _payload(repo, changes=(1, 0, 0)),
        _payload(repo)]))
    assert _index.index_build(str(repo)) == str(repo / _DB_REL)
    assert rec.subs == ["status", "init", "sync", "status"]
    assert rec.envs, "no CLI call captured"
    for env in rec.envs:
        for key, value in _index.SCAN_ENV.items():
            assert env.get(key) == value, (key, env.get(key))
        assert "OPENAI_API_KEY" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env


def test_scan_env_flags_are_the_d9_set():
    # D9's named invariants, in one place: every flag is truthy, and the four
    # named keys are present (a daemon would outlive the scan; telemetry and
    # update-check would phone home from a security tool).  The failure message
    # names the missing key.
    for key, value in _index.SCAN_ENV.items():
        assert value, key
    for key in ("PYTHONDONTWRITEBYTECODE", "CODEGRAPH_NO_DAEMON",
                "CODEGRAPH_NO_UPDATE_CHECK", "DO_NOT_TRACK"):
        assert key in _index.SCAN_ENV, key
        assert _index.SCAN_ENV[key], key


def test_cli_is_always_invoked_with_the_explicit_root(repo, monkeypatch):
    # Every subcommand is root-pinned by argument (never by cwd).
    rec = _install(monkeypatch, _Recorder(repo, [_payload(repo, extra=False),
                                                 _payload(repo)]))
    _index.index_build(str(repo))
    assert rec.calls
    for call in rec.calls:
        assert call[0] == CLI
        assert call[-1] == str(repo)


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

def test_summary_reports_counts_and_gate(repo, monkeypatch):
    _seed_index(repo)
    _install(monkeypatch, _Recorder(repo, [_payload(repo)]))
    text = _index.index_summary(str(repo))
    assert "7 nodes" in text and "6 edges" in text and "2 files" in text
    assert "state complete" in text
    assert "pendingRefs 0" in text
    assert "gate ready" in text
    assert "languages python" in text


def test_summary_not_ready_is_explicit(repo, monkeypatch):
    _seed_index(repo)
    _install(monkeypatch, _Recorder(repo, [_payload(repo, reindex=True)]))
    assert "gate not ready" in _index.index_summary(str(repo))


def test_summary_empty_payload_is_short_and_safe(repo, monkeypatch):
    _install(monkeypatch, _Recorder(repo, ["{oops"]))
    text = _index.index_summary(str(repo))
    assert text == "codegraph index: unavailable for this root"
    assert len(text) < 200


def test_summary_is_bounded(repo, monkeypatch):
    _seed_index(repo)
    _install(monkeypatch, _Recorder(repo, [_payload(repo)]))
    assert len(_index.index_summary(str(repo))) <= 600


def test_documented_constants():
    assert _index.CLI_NAME == "codegraph"
    assert _index.DEFAULT_BUILD_TIMEOUT > 0
    assert _index.STATUS_TIMEOUT > 0


# ---------------------------------------------------------------------------
# live build (real codegraph CLI) — scratch tmp_path only
# ---------------------------------------------------------------------------

_TINY_REPO = {
    "pkg/app.py": "def hello(name):\n    return greet(name)\n",
    "pkg/util.py": "def greet(name):\n    return 'hi ' + name\n",
}


def _tiny_repo(root: Path) -> Path:
    for rel, body in _TINY_REPO.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def test_live_build_gates_and_skips_on_second_run(tmp_path, monkeypatch):
    cli = live_cli()
    monkeypatch.setenv("PATH", f"{Path(cli).parent}:{__import__('os').environ['PATH']}")
    target = _tiny_repo(tmp_path / "target")
    monkeypatch.setenv("TARGET_REPO", str(target))

    # Fresh root: the CLI's honest answer is initialized:false, not-ready.
    assert _index.index_needed(str(target)) is True
    assert _index.index_build(str(target)) == str(target / _DB_REL)
    assert (target / _DB_REL).is_file()
    assert (target / ".codegraph").is_dir()

    payload = _index.index_status(str(target))
    assert payload["projectPath"] == str(target)
    assert payload["indexPath"] == str(target / ".codegraph")
    assert payload["index"]["state"] == "complete"
    assert payload["index"]["pendingRefs"] == 0
    assert _index.index_needed(str(target)) is False
    assert "gate ready" in _index.index_summary(str(target))

    # Second run: gated skip — nothing rewrites the DB.
    before = (target / _DB_REL).stat().st_mtime_ns
    assert _index.index_build(str(target)) == str(target / _DB_REL)
    assert (target / _DB_REL).stat().st_mtime_ns == before


def test_live_incremental_change_is_detected_and_synced(tmp_path, monkeypatch):
    cli = live_cli()
    monkeypatch.setenv("PATH", f"{Path(cli).parent}:{__import__('os').environ['PATH']}")
    target = _tiny_repo(tmp_path / "target")
    monkeypatch.setenv("TARGET_REPO", str(target))
    assert _index.index_build(str(target))
    (target / "pkg" / "added.py").write_text("def added():\n    return 1\n")
    assert _index.index_needed(str(target)) is True
    assert _index.index_build(str(target)) == str(target / _DB_REL)
    assert _index.index_needed(str(target)) is False
    assert _index.index_status(str(target))["fileCount"] == 3


def test_live_nested_target_gets_its_own_index_not_the_ancestor(tmp_path, monkeypatch):
    cli = live_cli()
    monkeypatch.setenv("PATH", f"{Path(cli).parent}:{__import__('os').environ['PATH']}")
    ancestor = _tiny_repo(tmp_path / "ancestor")
    monkeypatch.setenv("TARGET_REPO", str(ancestor))
    assert _index.index_build(str(ancestor)) == str(ancestor / _DB_REL)
    ancestor_mtime = (ancestor / _DB_REL).stat().st_mtime_ns

    nested = ancestor / "pkg"
    # The trap, live: status for the nested target answers for the ancestor.
    assert _index.index_status(str(nested)) == {}
    assert _index.index_status(str(nested)) != _index.index_status(str(ancestor))

    # Build: init creates the nested root's OWN index; the ancestor is untouched.
    assert _index.index_build(str(nested)) == str(nested / _DB_REL)
    assert (nested / ".codegraph").is_dir()
    assert _index.index_status(str(nested))["projectPath"] == str(nested)
    assert (ancestor / _DB_REL).stat().st_mtime_ns == ancestor_mtime
    assert _index.index_needed(str(nested)) is False
