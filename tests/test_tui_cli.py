import io
import json

from cerberus.cli import build_parser
from cerberus.reporting.view import THEME, render_findings
from rich.console import Console


def test_new_subcommands_parse():
    p = build_parser()
    for argv in (
        ["runs", "--runs-dir", "runs"],
        ["findings", "runs/x", "--limit", "5"],
        ["status", "runs/x"],
        ["inspect", "runs/x"],
        ["cancel", "runs/x"],
    ):
        ns = p.parse_args(argv)
        assert ns.func is not None


def test_findings_filter_via_render():
    findings = [
        {"severity": "high", "cwe": "CWE-89", "path": "a.py", "start_line": 1,
         "confidence": 0.9, "status": "confirmed", "title": "sqli"},
        {"severity": "low", "cwe": "CWE-79", "path": "b.py", "start_line": 2,
         "confidence": 0.1, "status": "fp", "title": "xss"},
    ]
    console = Console(file=io.StringIO(), theme=THEME, width=120)
    render_findings(console, findings)
    out = console.file.getvalue()
    assert "CWE-89" in out
    assert "CWE-79" in out


def test_clean_untrusted_strips_terminal_controls():
    from cerberus.reporting.view import clean_untrusted

    assert clean_untrusted("a\x1b]0;pwned\x07b") == "ab"
    assert clean_untrusted("\x1b[31mred\x1b[0m") == "red"
    assert clean_untrusted("keep\ttext\nlines") == "keep\ttext\nlines"


def test_render_findings_strips_escapes():
    findings = [
        {"severity": "high", "cwe": "CWE-89[bold]",
         "path": "a\x1b]0;pwned\x07.py", "start_line": 1,
         "confidence": 0.9, "status": "confirmed",
         "title": "sqli[/red]"},
    ]
    console = Console(file=io.StringIO(), theme=THEME, width=120)
    render_findings(console, findings)
    out = console.file.getvalue()
    assert "\x1b" not in out
    assert "a.py:1" in out  # the path survives; only the escape sequence is gone
    assert "CWE-89[bold]" in out  # markup lookalikes render literally


def test_status_panel_escapes_agent_ids(tmp_path, capsys):
    import argparse

    from cerberus.cli import cmd_status

    run = tmp_path / "run"
    run.mkdir()
    (run / "agent_summary.json").write_text(json.dumps({
        "total": 1,
        "by_state": {"failed": 1},
        "by_role": {"hunter": 1},
        "failed": ["hunter[/red]"],
        "running": [],
    }), encoding="utf-8")
    assert cmd_status(argparse.Namespace(run=str(run))) == 0
    out = capsys.readouterr().out
    assert "hunter[/red]" in out
    assert "\x1b" not in out


def test_cmd_findings_tolerates_hostile_json_rows(tmp_path, capsys):
    """Audit regression: a findings.json containing a bare string row used to
    crash the --status pre-filter with AttributeError before sort_findings'
    dict check could save it. Boundary coercion (schemas.coerce_findings)
    makes the crash unreachable; scalar rows are dropped, dict rows render."""
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps([
        "evil string entry",
        {"severity": "high", "cwe": "CWE-89", "path": "a.py", "start_line": 1,
         "confidence": 0.9, "status": "confirmed", "title": "sqli"},
    ]), encoding="utf-8")

    p = build_parser()
    for argv in (
        ["findings", str(findings_path)],
        ["findings", str(findings_path), "--status", "confirmed"],
        ["findings", str(findings_path), "--severity", "high"],
        ["findings", str(findings_path), "--cwe", "CWE-89"],
    ):
        ns = p.parse_args(argv)
        ns.func(ns)          # must not raise
    out = capsys.readouterr().out
    assert "CWE-89" in out and "sqli" in out


def test_threat_model_record_signals_flag_parse():
    """W12 opt-in: --record-signals must parse gate cleanly (store_true,
    default False) so the read-only default of --verify is preserved."""
    p = build_parser()
    on = p.parse_args(["threat-model", "r", "--verify", "--record-signals"])
    assert getattr(on, "record_signals", False) is True
    off = p.parse_args(["threat-model", "r", "--verify"])
    assert getattr(off, "record_signals", False) is False


def test_cmd_threat_model_attaches_signal_paths(tmp_path, monkeypatch, capsys):
    """Audit E2 parity: `cerberus threat-model` (generated doc) now carries the
    same §7 signal-path block the scan-path persists — same attach helper, so
    the standalone artifact is the same shape."""
    import os
    monkeypatch.setenv("THREAT_LLM", "0")
    monkeypatch.delenv("API_KEY", raising=False)
    repo = "tests/fixtures/pygoat-sample"
    out = tmp_path / "TM.md"
    p = build_parser()
    ns = p.parse_args(["threat-model", repo, "--out", str(out)])
    rc = ns.func(ns)
    assert rc == 0
    md = out.read_text()
    assert "stored scan signals:" in md
    assert ".cerberus/" in md and "signals/" in md
    # the doc it reads is unchanged (attachment is idempotent by marker)
    assert md.count("stored scan signals:") == 1
