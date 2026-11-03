"""signals.run-id sanitization — the ..-escape regression (audit D3).

RUN_ID='..' once produced safe_rid '..' → .cerberus/../signals → signal files
written into <repo>/signals/, outside .cerberus/, with the returned
repo-relative path embedding the upward component for agents to reproduce.
"""
from __future__ import annotations

import os

from cerberus.signals import (
    DEFAULT_RUN_ID,
    RUN_ID_ENV,
    resolve_run_id,
    sanitize_run_id,
    signals_dir,
    write_signal,
)


def test_dot_runs_never_survive():
    for rid in ("..", "...", "....", ".hidden", "-top", "", "   "):
        got = sanitize_run_id(rid)
        assert got == "" or (not got.startswith((".", "-")) and ".." not in got), \
            f"RUN_ID {rid!r} -> {got!r}"


def test_env_dot_run_resolves_to_default_or_flat_name(monkeypatch):
    monkeypatch.setenv(RUN_ID_ENV, "..")
    assert resolve_run_id() in (DEFAULT_RUN_ID, "_", "-") or not resolve_run_id().startswith(".")
    assert ".." not in resolve_run_id()


def test_sane_ids_survive_intact():
    assert sanitize_run_id("scan-2026.11.04_a") == "scan-2026.11.04_a"
    assert sanitize_run_id("a/../b") == "a_.._b".replace("..", "_")          # '..' run flattened


def test_dot_run_env_cannot_escape_cerberus_dir(tmp_path, monkeypatch):
    """Filesystem proof: with RUN_ID='..' the signals dir stays under .cerberus/."""
    monkeypatch.setenv(RUN_ID_ENV, "..")
    repo = str(tmp_path)
    d = signals_dir(repo)
    assert (tmp_path / ".cerberus") in d.parents or d.parent == tmp_path / ".cerberus"
    assert ".cerberus" in d.parts and str(d).endswith("signals")
    assert ("signals" == d.parts[-1] and d.parts[-2][0] != ".") or d.parts[-2] != ".."
    rel = write_signal(repo, "secrets", '[{"Secret": "x"}]')
    assert not rel.startswith("..")
    assert (tmp_path / ".cerberus" / resolve_run_id() / "signals" / "secrets.json").is_file()
    # and nothing landed directly in the repo root
    assert not (tmp_path / "signals" / "secrets.json").exists()
