import io
import time
from argparse import Namespace

import cerberus.cli as cli
import cerberus.pipeline as pipeline
import pytest
from cerberus.progress import AgentEvent
from cerberus.reporting.ui import ScanReporter, build_reporter, duration_s, short_path
from cerberus.reporting.view import THEME
from rich.console import Console


def _reporter(*, tty=True, agent_log="normal", width=100):
    kwargs = {"force_terminal": True, "color_system": "standard", "width": width} if tty else {"width": width}
    err = Console(file=io.StringIO(), theme=THEME, **kwargs)
    out = Console(file=io.StringIO(), theme=THEME, **kwargs)
    return ScanReporter(agent_log=agent_log, err_console=err,
                        out_console=out)


def _event(agent_id, role, state, **kwargs):
    return AgentEvent(ts=time.time(), run_id="r", agent_id=agent_id,
                      role=role, state=state, **kwargs)


# -- parser / helpers --------------------------------------------------------


def test_parser_agent_log_choices():
    p = cli.build_parser()
    ns = p.parse_args(["scan", "r", "--agent-log", "quiet"])
    assert ns.agent_log == "quiet"
    assert ns.func is cli.cmd_scan


def test_parser_global_no_color_and_debug():
    p = cli.build_parser()
    ns = p.parse_args(["--no-color", "--debug", "scan", "r"])
    assert ns.no_color is True
    assert ns.debug is True


def test_cmd_scan_recovers_config_before_building_reporter(tmp_path, monkeypatch):
    import cerberus.config as config
    import cerberus.sandbox as sandbox
    import cerberus.scan_manifest as manifest

    def broken_loader(*_args, **_kwargs):
        raise OSError("config unavailable")

    monkeypatch.setattr(config, "load_config", broken_loader)
    monkeypatch.setattr(pipeline, "run_scan", lambda *_a, **_k:
                        (_ for _ in ()).throw(RuntimeError("stop after setup")))
    monkeypatch.setattr(manifest, "record_scan_manifest", lambda *_a: None)
    monkeypatch.setattr(manifest, "close_scan", lambda *_a: {})
    monkeypatch.setattr(sandbox, "shutdown_run_sandbox", lambda: None)
    args = Namespace(
        out=str(tmp_path / "out"), confirm_critical=False,
        repo=str(tmp_path), agent_log="quiet", no_color=True,
        threat_model=None, focus=None, votes=None, vulns=None,
        fail_on="high", min_confidence=0.0,
    )

    with pytest.raises(RuntimeError, match="stop after setup"):
        cli.cmd_scan(args)


@pytest.mark.parametrize("value,expected", [
    (0, "0s"), (-5, "0s"), (42, "42s"), (59, "59s"),
    (60, "1m00s"), (512, "8m32s"), (3600, "1h00m"), (3840, "1h04m"),
    ("bad", "0s"), (None, "0s"),
])
def test_duration_s(value, expected):
    assert duration_s(value) == expected


def test_short_path_keeps_tail():
    long_path = "/Users/critical/llms/cyber/Real-Vuln-Benchmark/realvuln-dvna"
    shortened = short_path(long_path)
    assert shortened.startswith("…/")
    assert shortened.endswith("realvuln-dvna")
    assert len(shortened) <= 40
    assert short_path("runs/latest") == "runs/latest"


# -- agent lines -------------------------------------------------------------


def test_agent_line_rich_hostile_name_is_literal_and_colored():
    reporter = _reporter()
    reporter.on_event(_event("hunter:api[/red]", "hunter", "running",
                             model="m"))
    reporter.on_event(_event("hunter:api[/red]", "hunter", "succeeded",
                             progress={"findings_produced": 4}, elapsed_s=91))
    output = reporter._err.file.getvalue()
    assert "hunter:api[/red]" in output  # markup lookalike rendered literally
    assert "▶" in output and "✓" in output
    assert "4 findings" in output
    assert "1m31s" in output
    assert "\x1b[" in output  # force_terminal proves the color path ran


def test_agent_line_plain_has_no_escapes():
    reporter = _reporter(tty=False)
    reporter.on_event(_event("hunter:api", "hunter", "running"))
    reporter.on_event(_event("hunter:api", "hunter", "succeeded",
                             progress={"findings_produced": 0}, elapsed_s=44))
    output = reporter._err.file.getvalue()
    assert "\x1b" not in output
    assert "▶" in output and "✓" in output  # no color, same layout/glyphs
    assert "0 findings" in output
    assert "44s" in output


def test_validator_units_collapse_to_failures_only():
    reporter = _reporter()
    for index in range(1, 10):
        reporter.on_event(_event(f"validator:u{index}", "validator", "running"))
        reporter.on_event(_event(f"validator:u{index}", "validator", "succeeded"))
    reporter.on_event(_event("validator:u7", "validator", "failed",
                             error="ProviderError", elapsed_s=3))
    lines = [ln for ln in reporter._err.file.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 1
    assert "validator:u7" in lines[0]
    assert "failed" in lines[0]
    assert "ProviderError" in lines[0]


def test_validator_pool_shows_launch_and_finish():
    reporter = _reporter()
    reporter.on_event(_event("validator", "validator", "running"))
    reporter.on_event(_event("validator", "validator", "succeeded",
                             elapsed_s=12))
    output = reporter._err.file.getvalue()
    assert "▶" in output and "✓" in output
    assert "validator" in output
    assert "12s" in output


# -- validator cell ids (validator:<unit>:cN:vM) & heartbeat ------------------


def _hb_reporter(width=100):
    err = Console(file=io.StringIO(), theme=THEME, force_terminal=True, width=width)
    out = Console(file=io.StringIO(), theme=THEME, force_terminal=True, width=width)
    return ScanReporter(err_console=err, out_console=out, heartbeat=True)


def test_validator_cell_ids_render_like_agent_lines():
    reporter = _reporter()
    reporter.on_event(_event("validator:auth:c1:v1", "validator", "running",
                             model="m"))
    reporter.on_event(_event("validator:auth:c1:v1", "validator", "succeeded",
                             message="2 verdicts", elapsed_s=64))
    output = reporter._err.file.getvalue()
    assert "validator:auth:c1:v1" in output  # real id, not pooled
    assert "▶" in output and "✓" in output
    assert "2 verdicts" in output
    assert "1m04s" in output


def test_validator_cell_failure_line_shows_error_and_elapsed():
    reporter = _reporter()
    reporter.on_event(_event("validator:api:c2:v3", "validator", "failed",
                             error="unparseable reply", elapsed_s=42))
    line = reporter._err.file.getvalue()
    assert "validator:api:c2:v3" in line
    assert "✗" in line and "unparseable reply" in line and "42s" in line


def test_heartbeat_tick_prints_longest_running_elapsed():
    reporter = _hb_reporter()
    now = time.time()
    with reporter._lock:
        reporter._starts["hunter:auth"] = now - 252
        reporter._starts["hunter:api"] = now - 30
    reporter.heartbeat_tick(now=now)
    output = reporter._err.file.getvalue()
    assert "▶" in output
    assert "running 2" in output
    assert "hunter:auth" in output  # longest-running agent named
    assert "4m12s" in output
    assert "30s" not in output  # only the longest agent appears


def test_heartbeat_tick_silent_when_nothing_running():
    reporter = _hb_reporter()
    reporter.on_event(_event("hunter:auth", "hunter", "running"))
    reporter.on_event(_event("hunter:auth", "hunter", "succeeded"))
    before = reporter._err.file.getvalue()  # the two agent lines themselves
    reporter.heartbeat_tick()
    assert reporter._err.file.getvalue() == before


def test_heartbeat_auto_disabled_off_tty():
    # pytest replaces sys.stderr (not a TTY): auto-gate keeps the thread off.
    reporter = _reporter()  # heartbeat=None → auto detection
    reporter.on_event(_event("hunter:auth", "hunter", "running"))
    assert reporter._hb_thread is None


def test_heartbeat_quiet_never_runs():
    err = Console(file=io.StringIO(), theme=THEME, force_terminal=True, width=100)
    reporter = ScanReporter(agent_log="quiet", err_console=err,
                            heartbeat=True)
    reporter.on_event(_event("hunter:auth", "hunter", "running"))
    assert reporter._starts == {}
    assert reporter._hb_thread is None


def test_close_stops_heartbeat_thread():
    reporter = _hb_reporter()
    reporter._hb_s = 0.05
    reporter.on_event(_event("hunter:auth", "hunter", "running"))
    thread = reporter._hb_thread
    assert thread is not None and thread.is_alive()
    reporter.close()
    assert reporter._hb_stop.is_set()
    thread.join(5.0)
    assert not thread.is_alive()


def test_heartbeat_off_tty_renders_without_escapes():
    # Single-path rendering: non-TTY console → styles stripped by rich,
    # unicode glyphs kept, zero escape bytes.
    err = Console(file=io.StringIO(), theme=THEME, width=100)
    out = Console(file=io.StringIO(), theme=THEME, width=100)
    reporter = ScanReporter(err_console=err, out_console=out, heartbeat=True)
    now = time.time()
    with reporter._lock:
        reporter._starts["val:c1:v1"] = now - 5
    reporter.heartbeat_tick(now=now)
    output = err.file.getvalue()
    assert "\x1b" not in output
    assert "▶" in output
    assert "running 1" in output and "val:c1:v1" in output and "5s" in output


def test_reporter_ctor_auto_heartbeat_on_tty_stderr(monkeypatch):
    # Regression: the heartbeat auto-gate must run AFTER the consoles exist.
    # Computing _hb_ready before _err was assigned crashed real interactive
    # scans with AttributeError (pytest's non-tty stderr masked it).
    import sys as _sys

    real = _sys.stderr

    class FakeTty:
        def isatty(self):
            return True

        def fileno(self):
            raise io.UnsupportedOperation("fileno")

        def __getattr__(self, name):  # delegate everything else
            return getattr(real, name)

    monkeypatch.setattr(_sys, "stderr", FakeTty())
    reporter = ScanReporter()  # heartbeat=None → auto-gate path
    assert reporter._err is not None
    assert reporter._hb_ready is True  # fake tty + rich console is_terminal
    reporter.on_event(_event("hunter:auth", "hunter", "running"))
    thread = reporter._hb_thread  # auto path MUST be able to arm safely
    reporter.close()
    assert reporter._hb_stop.is_set()
    if thread is not None:
        thread.join(5.0)
        assert not thread.is_alive()


def test_heartbeat_tick_silent_after_close():
    reporter = _hb_reporter()
    now = time.time()
    with reporter._lock:
        reporter._starts["hunter:auth"] = now - 10
    reporter.close()  # stops the loop AND clears tracked starts
    reporter.heartbeat_tick(now=now)
    assert reporter._err.file.getvalue() == ""


def test_per_cell_validator_transitions_match_cell_id(monkeypatch, capsys):
    import cerberus.agents.deep as deep

    calls = []

    class FakeRegistry:
        def transition(self, agent_id, state, **kwargs):
            calls.append((agent_id, str(getattr(state, "value", state)),
                          kwargs))

    def _fake_agent(*args, **kwargs):
        return object()

    def _fake_structured(mk, fmt, system, msg, **kwargs):
        verdict = {"id": "F1", "status": "confirmed", "confidence": 0.9,
                   "evidence": "x", "snippet": "s", "path": "p.py",
                   "start_line": 1}
        return {"verdicts": [verdict]}, "raw text"

    monkeypatch.setattr(deep, "build_deep_agent", _fake_agent)
    monkeypatch.setattr(deep, "make_llm", _fake_agent)
    monkeypatch.setattr(deep, "run_structured", _fake_structured)

    from cerberus.agents.validator import _validate_unit_batch

    item = {"id": "F1", "title": "t", "cwe": "CWE-89", "severity": "high",
            "confidence": 0.8, "path": "p.py", "start_line": 1,
            "snippet": "s", "evidence": "e"}
    out = _validate_unit_batch("auth", [item], {}, threat_md="", n_votes=1,
                               repo=None, cell_no=0,
                               agent_registry=FakeRegistry())
    ids = [c[0] for c in calls]
    states = [c[1] for c in calls]
    assert ids[0] == "validator:auth:c1:v1"
    assert states == ["running", "succeeded"]
    assert calls[1][2].get("message") == "1 verdicts"
    assert calls[1][2].get("unit") == "auth"
    assert out and out[0]["id"] == "F1"
    # Legacy stderr line survives byte-identically when no reporter is installed
    err = capsys.readouterr().err
    assert "[validator] unit 'auth' cell 1: 1 findings," in err
    assert "vote 1/1..." in err


def test_quiet_suppresses_agent_lines():
    reporter = _reporter(agent_log="quiet")
    reporter.on_event(_event("hunter:api", "hunter", "running"))
    reporter.on_event(_event("hunter:api", "hunter", "succeeded"))
    assert reporter._err.file.getvalue() == ""


def test_registry_findings_produced_reaches_agent_line():
    from cerberus.progress import AgentRegistry, AgentState

    reporter = _reporter()
    registry = AgentRegistry(run_id="r", sink=reporter)
    registry.create("hunter:u", "hunter", state=AgentState.queued)
    registry.transition("hunter:u", AgentState.running)
    registry.transition("hunter:u", AgentState.succeeded,
                        findings_produced=4)
    output = reporter._err.file.getvalue()
    assert "✓" in output
    assert "4 findings" in output


def test_queued_hunters_do_not_spam():
    reporter = _reporter()
    for index in range(6):
        reporter.on_event(_event(f"hunter:u{index}", "hunter", "queued"))
    assert reporter._err.file.getvalue() == ""


# -- stage lines / header ----------------------------------------------------


def test_stage_done_uses_buffered_detail_and_right_duration():
    reporter = _reporter()
    reporter.detail("hunters", "[hunters] unit: 4 findings in 12s")
    reporter.detail("hunters", "6 units · 14 findings")
    reporter.stage_done("hunters", 512)
    output = reporter._err.file.getvalue()
    assert "6 units · 14 findings" in output
    assert "8m32s" in output
    assert "✓" in output
    assert "unit: 4 findings" not in output  # latest detail wins


def test_stage_failure_routes_glyph_and_error():
    reporter = _reporter()
    reporter.stage_done("validator", 13, ok=False, error="ProviderError: boom")
    output = reporter._err.file.getvalue()
    assert "✗" in output
    assert "failed after 13s" in output
    assert "ProviderError: boom" in output


def test_stage_done_plain_no_escapes():
    reporter = _reporter(tty=False)
    reporter.detail("hunters", "6 units · 14 findings")
    reporter.stage_done("hunters", 512)
    output = reporter._err.file.getvalue()
    assert "\x1b" not in output
    assert "✓" in output
    assert "6 units · 14 findings" in output
    assert "8m32s" in output


def test_header_echoes_only_non_default_rows():
    plain = _reporter(tty=False)
    plain.header("repo", {})
    output = plain._err.file.getvalue()
    assert "repo" in output
    assert "models" in output
    assert "run" in output
    assert "sandbox" not in output
    assert "options" not in output

    echoed = _reporter(tty=False)
    echoed.header("repo", {"sandbox": {"backend": "docker"}},
                  fail_on="critical", focus="injection",
                  vulns="cve.txt", votes=3)
    output = echoed._err.file.getvalue()
    assert "sandbox" in output and "docker" in output
    assert "options" in output
    assert "focus injection" in output
    assert "vulns cve.txt" in output
    assert "votes 3" in output
    assert "gate critical" in output


def test_build_reporter_always_constructs():
    reporter = build_reporter(no_color=True, agent_log="quiet")
    assert isinstance(reporter, ScanReporter)


# -- receipt -----------------------------------------------------------------


FINDINGS = [
    {"severity": "critical", "cwe": "CWE-89", "path": "api/login.py",
     "start_line": 42, "title": "SQLi via sort param", "confidence": 0.9,
     "status": "confirmed"},
    {"severity": "high", "cwe": "CWE-79", "path": "web/x.py",
     "start_line": 7, "title": "XSS [evil]", "confidence": 0.8,
     "status": "confirmed"},
]


def test_receipt_pass_variant():
    reporter = _reporter()
    reporter.done(findings=FINDINGS, out="runs/dvna", fail_on="high",
                  min_confidence=0.6, gated=[], elapsed=512,
                  state={"tools_used": ["semgrep"], "threat_quality": {"score": 72},
                         "threat_model_source": "summary"})
    output = reporter._out.file.getvalue()
    assert "✓ PASS" in output
    assert "2 critical" not in output
    assert "1 critical" in output and "1 high" in output
    assert "72/100 · source=summary" in output
    assert "semgrep" in output
    assert "8m32s" in output
    assert "cerberus inspect runs/dvna" in output


def test_receipt_fail_variant_includes_gate_detail():
    reporter = _reporter()
    reporter.done(findings=FINDINGS, out="runs/dvna", fail_on="high",
                  min_confidence=0.6, gated=FINDINGS, elapsed=90)
    output = reporter._out.file.getvalue()
    assert "✗ FAIL" in output
    assert "(2 gated)" in output
    assert "CWE-89 api/login.py:42 SQLi via sort param" in output
    assert "CWE-79 web/x.py:7 XSS [evil]" in output


def test_receipt_zero_findings_and_plain_no_escapes():
    reporter = _reporter(tty=False)
    reporter.done(findings=[], out="runs/dvna", gated=[], elapsed=1)
    output = reporter._out.file.getvalue()
    assert "\x1b" not in output
    assert "✓ no findings" in output
    assert "PASS" in output


# -- pipeline hook -----------------------------------------------------------


def test_stage_detail_prints_when_no_progress(monkeypatch, capsys):
    monkeypatch.setattr(pipeline, "_PROGRESS", None)
    pipeline._stage_detail("hunters", "[hunters] u: 1 findings in 2s")
    assert "[hunters] u: 1 findings in 2s" in capsys.readouterr().err


def test_stage_detail_routes_to_progress(monkeypatch):
    seen = []

    class Sink:
        def detail(self, stage, text):
            seen.append((stage, text))

    monkeypatch.setattr(pipeline, "_PROGRESS", Sink())
    pipeline._stage_detail("hunters", "hello")
    assert seen == [("hunters", "hello")]


# -- main() crash UX ---------------------------------------------------------


def test_main_keyboard_interrupt_returns_130(monkeypatch, capsys):
    def boom(_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_status", boom)
    assert cli.main(["status", "runs/x"]) == 130
    err = capsys.readouterr().err
    assert "cancelled" in err
    assert "Traceback" not in err


def test_main_exception_is_one_line(monkeypatch, capsys):
    def boom(_args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli, "cmd_status", boom)
    assert cli.main(["status", "runs/x"]) == 1
    captured = capsys.readouterr()
    assert "error: RuntimeError: kaboom" in captured.err
    assert "cerberus inspect" in captured.err
    assert "Traceback" not in captured.err


def test_main_debug_prints_traceback(monkeypatch, capsys):
    def boom(_args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli, "cmd_status", boom)
    assert cli.main(["--debug", "status", "runs/x"]) == 1
    captured = capsys.readouterr()
    assert "error: RuntimeError: kaboom" in captured.err
    assert "Traceback" in (captured.out + captured.err)
