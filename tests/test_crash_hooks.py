"""Crash-path teardown: ONE SIGTERM handler reaps EVERY registered shutdown.

signal.signal() replaces the installed handler, so backends that each
installed "their own" handler meant the last import won and the other
backend's registries were never reaped on SIGTERM -- the path atexit covers
only when interpreter shutdown gets that far (it does not, if a non-daemon
thread is still alive: thread-join precedes atexit).

These tests pin the shared-handler contract without touching process state
a second time: registrations are spied, the live handler is invoked directly,
and the handler that existed before is restored afterwards.
"""
from __future__ import annotations

import signal

import pytest
from cerberus.sandbox import run_base


def test_one_handler_reaps_every_registration(monkeypatch):
    calls = []
    prev = signal.getsignal(signal.SIGTERM)
    # Keep the spies off the real atexit list (no unregister in 3.12): we are
    # testing the SIGTERM chaining, and process-exit noise would be false
    # signal about the real registries.
    monkeypatch.setattr(run_base.atexit, "register", lambda f: None)
    monkeypatch.setattr(run_base, "_CRASH_HANDLER_INSTALLED", False)
    monkeypatch.setattr(run_base, "_CRASH_SHUTDOWNS", [])
    try:
        run_base.install_crash_hooks(lambda: calls.append("first"))
        run_base.install_crash_hooks(lambda: calls.append("second"))
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        with pytest.raises(SystemExit) as exc:
            handler(signal.SIGTERM, None)
        # Both registrations reaped, in registration order.
        assert calls == ["first", "second"]
        # The documented exit status survives the chaining.
        assert exc.value.code == 128 + int(signal.SIGTERM)
    finally:
        # Never leave the test's handler installed for the rest of the run.
        try:
            signal.signal(signal.SIGTERM, prev)
        except (TypeError, ValueError, OSError):
            pass


def test_a_wedged_registry_does_not_strand_the_others(monkeypatch):
    calls = []

    def boom():
        calls.append("wedged")
        raise RuntimeError("registry teardown hung")

    prev = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(run_base.atexit, "register", lambda f: None)
    monkeypatch.setattr(run_base, "_CRASH_HANDLER_INSTALLED", False)
    monkeypatch.setattr(run_base, "_CRASH_SHUTDOWNS", [])
    try:
        run_base.install_crash_hooks(lambda: calls.append("before"))
        run_base.install_crash_hooks(boom)
        run_base.install_crash_hooks(lambda: calls.append("after"))
        handler = signal.getsignal(signal.SIGTERM)
        with pytest.raises(SystemExit):
            handler(signal.SIGTERM, None)
        assert calls == ["before", "wedged", "after"]
    finally:
        try:
            signal.signal(signal.SIGTERM, prev)
        except (TypeError, ValueError, OSError):
            pass


def test_worker_thread_registration_defers_the_shared_handler(monkeypatch):
    """A worker-thread importer cannot install a handler; its shutdown is
    still registered, and the later main-thread caller installs the shared
    handler that reaps it."""
    monkeypatch.setattr(run_base.atexit, "register", lambda f: None)
    monkeypatch.setattr(run_base, "_CRASH_HANDLER_INSTALLED", False)
    monkeypatch.setattr(run_base, "_CRASH_SHUTDOWNS", [])
    run_base.install_crash_hooks(lambda: None)
    assert run_base._CRASH_SHUTDOWNS  # registered regardless of signal()
    assert run_base._CRASH_HANDLER_INSTALLED  # main thread installs it
    assert callable(signal.getsignal(signal.SIGTERM))
