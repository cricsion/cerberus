"""CLI: scan <repo> -> findings.json + results.sarif + report.md + report.html + junit.xml"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness.schemas import safe_float


def prompt_confirm(payload: dict) -> bool:
    """Plain CLI prompt: show confirmed critical/high findings, ask on stdin.

    EOF (non-interactive run) counts as a decline, so criticals are held for
    review instead of being released unreviewed.
    """
    print("HUMAN REVIEW REQUIRED (confirmed critical/high):")
    try:
        print(json.dumps(payload, indent=2)[:3000])
    except (TypeError, ValueError):
        print(str(payload)[:3000])
    try:
        ans = input("Proceed with these as confirmed? [y/N] ").strip().lower()
    except EOFError:
        ans = "n"
    return ans in ("y", "yes")


def cmd_scan(args: argparse.Namespace) -> int:
    from harness.pipeline import SEVERITY_ORDER, run_scan
    from harness.reporting.reports import write_html, write_json, write_junit, write_markdown, write_sarif

    _ui = "auto"
    try:
        from harness.tui import RICH_AVAILABLE
    except Exception:
        RICH_AVAILABLE = False
    use_rich = False
    if _ui == "rich":
        use_rich = True
    elif _ui == "auto":
        import os as _os
        if sys.stdout.isatty() and not _os.environ.get("CI") and RICH_AVAILABLE:
            use_rich = True
    if use_rich and getattr(args, "confirm_critical", False):
        print("warning: --confirm-critical disables rich mode; using plain", file=sys.stderr)
        use_rich = False
    if use_rich and RICH_AVAILABLE:
        from harness.tui import make_console, run_scan_tui
        console = make_console()
        _focus = args.focus
        if isinstance(_focus, str):
            _focus = [x.strip() for x in _focus.split(",") if x.strip()]
        out = Path(args.out)
        try:
            out.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"cannot create output dir {out}: {e}", file=sys.stderr)
            return 1
        scan_kwargs = {
            "confirm_critical": False,
            "threat_model_override": args.threat_model,
            "focus": _focus,
            "votes": args.votes,
            "vulns_file": args.vulns,
        }
        return run_scan_tui(args.repo, out=out, scan_kwargs=scan_kwargs, console=console)

    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"cannot create output dir {out}: {e}", file=sys.stderr)
        return 1
    # argparse guarantees every one of these: they are all registered on the
    # `scan` subparser in build_parser(), the only dispatcher of this command.
    confirm = bool(args.confirm_critical)
    _focus = args.focus
    _votes = args.votes
    # The driver pauses between validation and triage and calls prompt_confirm
    # when confirmed critical/high findings exist (only with --confirm-critical).
    # Record the target tree at scan start and compare it at teardown. The
    # finally also removes the run sandbox if the scan fails.
    from harness.sandbox import shutdown_run_sandbox
    from harness.scan_manifest import close_scan, record_scan_manifest
    scan_record: dict = {}
    try:
        out.mkdir(parents=True, exist_ok=True)
        record_scan_manifest(args.repo)
        (out / "scan.pid").write_text(str(__import__("os").getpid()))
        state = run_scan(args.repo, confirm_critical=confirm,
                         threat_model_override=args.threat_model,
                         focus=_focus, votes=_votes,
                         vulns_file=args.vulns,
                         confirm=prompt_confirm if confirm else None,
                         agent_events_path=out / "agents.jsonl")
        findings = state.get("verified", [])
        # CI gate: min-confidence + fail-on severity filter
        # --fail-on is choices-gated by build_parser(), and SEVERITY_ORDER
        # holds every allowed choice, so the lookup is total here.
        fail_at = SEVERITY_ORDER[args.fail_on]
        min_conf = args.min_confidence
        write_json(findings, out / "findings.json")
        write_sarif(findings, out / "results.sarif")
        write_markdown(findings, out / "report.md")
        write_html(findings, out / "report.html")
        write_junit(findings, out / "junit.xml")
        # Threat-model artifact (single writer: CLI). Full text, never truncated.
        threat_md = state.get("threat_model_md", "") or ""
        try:
            from harness import threat as _th2
            from harness.config import load_config as _lc
            _write_tm = _th2.threat_enabled(_lc(), "write_artifact", True)
        except Exception:
            _write_tm = True
        # Threat snapshot + persist: the graph's threat_update node already folded
        # validator-confirmed findings into state. CLI only writes (single writer).
        threat_persisted = ""
        if threat_md.strip() and _write_tm:
            (out / "THREAT_MODEL.md").write_text(threat_md)
        # Written triage audit trail (reference-harness style). Single writer: CLI.
        triage_log = state.get("triage_log", []) or []
        if triage_log:
            try:
                from harness.agents.triage import _resolve_batch, render_triage_log
                from harness.config import load_config as _lc_log
                try:
                    _batch = _resolve_batch(_lc_log())
                except Exception:
                    _batch = 30
                _calls = max((int(e.get("batch", 0) or 0) for e in triage_log
                              if isinstance(e, dict)), default=0)
                (out / "triage.log").write_text(
                    render_triage_log(triage_log, _calls, _batch))
            except Exception:
                pass
        # Persist for future runs: only when this scan generated the model
        # (bootstrap floor / swarm enrichment / machine cache). Owner files
        # and explicit --threat-model overrides are never overwritten; the
        # cache lives in .harness/.
        try:
            from harness import threat as _th4
            if (threat_md.strip() and _write_tm
                    and state.get("threat_model_source") not in ("override", "repo-file")):
                threat_persisted = _th4.persist_threat(args.repo, threat_md) or ""
        except Exception:
            threat_persisted = ""
    finally:
        # The run's shared sandbox container (docker mode) is run-level
        # state: remove it here so a crashed scan leaks no container.
        shutdown_run_sandbox()
        scan_record = close_scan(args.repo)
        try:
            import os as _os2
            (out / "scan.pid").unlink(missing_ok=True)
        except Exception:
            pass
    # Persist agent events/summary for on-demand status and inspection.
    try:
        _agent_events = state.get("agent_events", []) or []
        if isinstance(_agent_events, list):
            (out / "agents.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in _agent_events))
        _agent_summary = state.get("agent_summary")
        if _agent_summary is not None:
            (out / "agent_summary.json").write_text(
                json.dumps(_agent_summary, indent=2))
    except Exception:
        pass
    meta = {
        "repo": args.repo,
        "format": args.format,
        "fail_on": args.fail_on,
        "min_confidence": args.min_confidence,
        "files": len(state.get("files", [])),
        "findings": len(findings),
        "confirm_critical": confirm,
        "threat_model_source": state.get("threat_model_source", "summary"),
        "threat_model_persisted": threat_persisted,
        "threat_quality": state.get("threat_quality", {}) or {},
        "threat_verified": state.get("threat_verified", {}) or {},
        "threat_enrich": state.get("threat_enrich", {}) or {},
        "vulns": args.vulns,
        "focus": args.focus,
        "votes": args.votes,
        "n_duplicates": sum(1 for f in findings if f.get("duplicate_of")),
        "triage_log": "triage.log" if (out / "triage.log").is_file() else "",
        "tools_used": sorted(set(str(t) for t in state.get("tools_used", []))),
        "manifest": scan_record,
    }
    (out / "scan_meta.json").write_text(json.dumps(meta, indent=2))
    print(f"files={len(state.get('files', []))} findings={len(findings)} out={out}")
    failing = [f for f in findings
               if SEVERITY_ORDER.get(f.get("severity", "medium"), 2) <= fail_at
               and safe_float(f.get("confidence", 0)) >= min_conf
               and f.get("status") != "fp"]
    # Scaffold phase: info/needs-review never fails CI.
    failing = [f for f in failing if f.get("severity") in ("critical", "high")]
    return 1 if failing else 0


def cmd_threat_model(args: argparse.Namespace) -> int:
    """Create THREAT_MODEL.md for a repo (reference 8-section schema).

    Default path: deterministic bootstrap floor, then the LLM swarm
    (researcher + historian + synthesizer) enriches it on every run — the
    same default a scan uses; `threat.llm_enrich: false` (or
    HARNESS_THREAT_LLM=0) keeps it offline. With --interview, an LLM
    interviewer asks follow-ups on stdin and rewrites the document with the
    answers; without a key it degrades to the static Shostack set.
    """
    from harness import threat as _th
    from harness.pipeline import indexer_node

    repo = args.repo
    if bool(getattr(args, "verify", False)):
        dest = getattr(args, "out", None)
        if dest:
            try:
                md = Path(dest).read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                print(f"cannot read {dest}: {e}", file=sys.stderr)
                return 1
        else:
            _, md = _th.load_threat(repo, cfg={})
            if not md.strip():
                print("no threat model found for repo", file=sys.stderr)
                return 1
        try:
            st = indexer_node({"repo": repo})
            files, cands = list(st.get("files", [])), list(st.get("candidates", []))
        except Exception:
            files, cands = [], []
        q = _th.threat_quality(md, files, cands)
        print(f"threat quality: {q['score']}/100 ({q['sections_filled']} sections, "
              f"{q.get('threat_rows', 0)} threat rows)")
        for gap in q["gaps"][:10]:
            print(f"  gap: {gap}")
        fv = _th.verify_threat(repo, md, files, cands)
        print(f"factual check: {fv['score']}/100")
        for fail in fv["failures"][:10]:
            print(f"  FAILURE: {fail}")
        return 0 if not fv["failures"] else 2
    if getattr(args, "update_from", None):
        try:
            findings = json.loads(Path(args.update_from).read_text())
        except (OSError, ValueError) as e:
            print(f"cannot read findings: {e}", file=sys.stderr)
            return 1
        _, md = _th.load_threat(repo, cfg={})
        if not md.strip():
            print("no threat model found for repo", file=sys.stderr)
            return 1
        updated = _th.update_threat_with_findings(md, findings, repo)
        dest = _th.persist_threat(repo, updated)
        if not dest:
            print("persist failed", file=sys.stderr)
            return 1
        print(f"updated {dest}")
        return 0
    try:
        st = indexer_node({"repo": repo})
        files = list(st.get("files", []))
        cands = list(st.get("candidates", []))
    except Exception as e:
        print(f"indexer failed: {e}", file=sys.stderr)
        files, cands = [], []
    try:
        summary = next((c.get("snippet", "") for c in cands
                        if c.get("id") == "threat-model"), "")
    except Exception:
        summary = ""
    _vulns_path = getattr(args, "vulns", None) or ""
    vulns = _th.parse_vulns_file(_vulns_path) if _vulns_path else []
    if _vulns_path and not vulns:
        print(f"warning: --vulns {_vulns_path} parsed to 0 rows "
              "(missing or unrecognized format); continuing on git history")
    if bool(getattr(args, "interview", False)):
        import os as _os

        from harness.config import load_config as _lc_tm
        try:
            _cfg_tm = _lc_tm()
        except Exception:
            _cfg_tm = {}
        if not _os.environ.get("API_KEY"):
            answers: dict[str, str] = {}
            print("Answer Shostack's four questions (empty = skip):")
            for key, question in _th.INTERVIEW_QUESTIONS:
                try:
                    answers[key] = input(f"{question}\n> ").strip()
                except EOFError:
                    answers[key] = ""
            try:
                md = _th.bootstrap_threat(repo, files, cands, summary,
                                          vulns=vulns, vulns_path=_vulns_path)
            except Exception as e:
                print(f"bootstrap failed: {e}", file=sys.stderr)
                return 1
            md = _th.apply_interview(md, answers)
        else:
            def _ask(q: str) -> str:
                try:
                    return input(f"{q}\n> ").strip()
                except EOFError:
                    return ""

            def _say(t: str) -> None:
                print(t)

            md = _th.conduct_interview(repo, files, cands, summary, _cfg_tm,
                                       _ask, _say)
    else:
        try:
            md = _th.bootstrap_threat(repo, files, cands, summary,
                                      vulns=vulns, vulns_path=_vulns_path)
        except Exception as e:
            print(f"bootstrap failed: {e}", file=sys.stderr)
            return 1
        try:
            from harness.config import load_config as _lc_enrich
            _cfg_enrich = _lc_enrich()
            if _th.threat_enabled(_cfg_enrich, "llm_enrich", True):
                enriched, meta = _th.enrich_threat(
                    repo, files, cands, summary, md, _cfg_enrich,
                    vulns=vulns, vulns_path=_vulns_path,
                    measured_facts=_th.measured_facts(
                        repo, files, cands, summary, vulns))
                if enriched.strip():
                    md = enriched
                    dropped = meta.get("dropped") or []
                    print(f"swarm enrichment: ok "
                          f"({meta.get('threat_rows', 0)} threat rows"
                          + (f", dropped {len(dropped)} invalid row(s)"
                             if dropped else "") + ")")
                else:
                    print(f"swarm enrichment failed, kept deterministic floor: "
                          f"{meta.get('error', 'unknown')}")
        except Exception as e:
            print(f"swarm enrichment error, kept deterministic floor: {e}")
    dest = getattr(args, "out", None)
    if not dest:
        try:
            dest = str(Path(repo) / _th.FILENAME) if Path(repo).is_dir() else _th.FILENAME
        except Exception:
            dest = _th.FILENAME
    try:
        Path(dest).write_text(md)
    except OSError as e:
        print(f"cannot write {dest}: {e}", file=sys.stderr)
        return 1
    print(f"wrote {dest}")
    try:
        q = _th.threat_quality(md, files, cands)
        print(f"threat quality: {q['score']}/100 ({q['sections_filled']} sections)")
        for gap in q["gaps"][:10]:
            print(f"  gap: {gap}")
    except Exception:
        pass
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    from harness.tui import make_console, run_scan_tui, view_run

    console = make_console()
    target = Path(args.target)
    if target.is_dir() and (target / "scan_meta.json").is_file():
        return int(view_run(target, console=console) or 0)
    # Otherwise treat target as a repo and run a scan with the Rich monitor.
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"cannot create output dir {out}: {e}", file=sys.stderr)
        return 1
    _focus = args.focus
    if isinstance(_focus, str):
        _focus = [x.strip() for x in _focus.split(",") if x.strip()]
    scan_kwargs = {
        "confirm_critical": False,
        "threat_model_override": args.threat_model,
        "focus": _focus,
        "votes": args.votes,
        "vulns_file": args.vulns,
    }
    return int(run_scan_tui(str(target), out=out, scan_kwargs=scan_kwargs, console=console) or 0)


def cmd_runs(args: argparse.Namespace) -> int:
    from harness.tui import make_console, list_runs

    console = make_console()
    return int(list_runs(args.runs_dir, limit=args.limit, console=console) or 0)


def cmd_status(args: argparse.Namespace) -> int:
    import json as _json

    from harness.tui import make_console

    console = make_console()
    run_dir = Path(args.run)
    summary_path = run_dir / "agent_summary.json"
    events_path = run_dir / "agents.jsonl"
    summary = None
    try:
        summary = _json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        summary = None
    if console is None or (not __import__("harness.tui", fromlist=["RICH_AVAILABLE"]).RICH_AVAILABLE):
        print(f"run: {run_dir}")
        if summary:
            print(_json.dumps(summary, indent=2))
        if events_path.is_file():
            print(f"events: {sum(1 for _ in events_path.open())}")
        return 0 if summary is not None or events_path.is_file() else 1
    from rich.panel import Panel

    lines = [f"run: {run_dir}"]
    if isinstance(summary, dict):
        lines.append(f"total: {summary.get('total')}")
        lines.append("by state: " + ", ".join(f"{k}={v}" for k, v in (summary.get('by_state') or {}).items()))
        lines.append("by role: " + ", ".join(f"{k}={v}" for k, v in (summary.get('by_role') or {}).items()))
        if summary.get("running"):
            lines.append("running: " + ", ".join(summary.get("running", [])))
        if summary.get("failed"):
            lines.append("failed: " + ", ".join(summary.get("failed", [])))
    else:
        lines.append("no agent_summary.json found")
    if events_path.is_file():
        lines.append(f"events: {sum(1 for _ in events_path.open())} (agents.jsonl)")
    pid_path = run_dir / "scan.pid"
    if pid_path.is_file():
        lines.append(f"pid: {pid_path.read_text().strip()}")
    console.print(Panel("\n".join(lines), title="Agent status", border_style="cyan"))
    return 0 if (summary is not None or events_path.is_file()) else 1


def cmd_inspect(args: argparse.Namespace) -> int:
    from harness.tui import make_console, view_run

    console = make_console()
    return int(view_run(Path(args.run), console=console,
                        agent=getattr(args, "agent", None),
                        timeline=bool(getattr(args, "timeline", False))) or 0)


def cmd_cancel(args: argparse.Namespace) -> int:
    import os as _os
    import signal

    run_or_agent = args.target
    run_dir = Path(run_or_agent)
    pid = None
    if run_dir.is_dir():
        pid_path = run_dir / "scan.pid"
        try:
            pid = int(pid_path.read_text().strip())
        except (OSError, ValueError):
            pid = None
    if args.pid is not None:
        pid = args.pid
    if pid is None:
        print(f"no running scan pid found for {run_or_agent}", file=sys.stderr)
        return 1
    try:
        _os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print(f"process {pid} not running", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"cancel failed: {e}", file=sys.stderr)
        return 1
    print(f"sent SIGTERM to {pid}")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    import json as _json

    from harness.tui import make_console, render_findings

    console = make_console()
    run_dir = Path(args.run)
    findings_path = run_dir / "findings.json" if run_dir.is_dir() else Path(args.run)
    try:
        data = _json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"cannot read findings: {e}", file=sys.stderr)
        return 1
    if not isinstance(data, list):
        print("findings file is not a JSON array", file=sys.stderr)
        return 1
    findings = data
    if args.severity:
        findings = [f for f in findings if str(f.get("severity", "")).lower() == args.severity.lower()]
    if args.cwe:
        findings = [f for f in findings if str(f.get("cwe", "")).upper() == args.cwe.upper()]
    if args.status:
        findings = [f for f in findings if str(f.get("status", "")).lower() == args.status.lower()]
    render_findings(console, findings, limit=int(args.limit))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from harness.tui import make_console, doctor

    console = make_console()
    return int(doctor(args.config, console=console) or 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="harness", description="Agentic vuln harness (OpenAI-compatible)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a repo or directory")
    s.add_argument("repo", help="path to repo or file")
    s.add_argument("--out", default="runs/latest", help="output dir")
    s.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low"])
    s.add_argument("--min-confidence", type=float, default=0.6)
    s.add_argument("--config", default="config/default.yaml")
    s.add_argument("--format", default="all", help="compat only: ignored, all formats always written")
    s.add_argument("--confirm-critical", action="store_true",
                   help="pause for human approval when critical/high findings are confirmed")
    s.add_argument("--threat-model", default=None,
                   help="override THREAT_MODEL.md path (default: <repo>/THREAT_MODEL.md, else deterministic draft)")
    s.add_argument("--vulns", default=None, metavar="PATH",
                   help="past-vulnerabilities file (CVE id list, CSV, JSON "
                        "array, or markdown report) used as EVIDENCE for "
                        "section 4 threat rows")
    s.add_argument("--focus", default=None,
                   help="comma-separated focus hints, e.g. injection or CWE-89,CWE-78 (narrows hunter scope text only, never drops coverage)")
    s.add_argument("--votes", type=int, default=None,
                   help="verifier votes per finding 1-5 (default 1; majority-or-tie is final, no judge)")
    s.set_defaults(func=cmd_scan)
    t = sub.add_parser("threat-model", help="bootstrap THREAT_MODEL.md for a repo")
    t.add_argument("repo", help="path to repo or file")
    t.add_argument("--out", default=None, help="output path (default: <repo>/THREAT_MODEL.md)")
    t.add_argument("--vulns", default=None, metavar="PATH",
                   help="past-vulnerabilities file (CVE id list, CSV, JSON "
                        "array, or markdown report) used as EVIDENCE for "
                        "section 4 threat rows")
    t.add_argument("--interview", action="store_true",
                   help="ask Shostack's four questions on stdin and append answers")
    t.add_argument("--verify", action="store_true",
                   help="read-only: report quality score and factual failures, write nothing")
    t.add_argument("--update-from", default=None, metavar="FINDINGS_JSON",
                   help="fold validator-released findings into the machine cache "
                        "(.harness/THREAT_MODEL.md); owner files are never touched")
    t.set_defaults(func=cmd_threat_model)

    u = sub.add_parser("tui", help="interactive rich scan viewer / runner")
    u.add_argument("target", help="run dir with scan_meta.json, or repo path to scan")
    u.add_argument("--out", default="runs/latest", help="output dir when scanning")
    u.add_argument("--config", default="config/default.yaml")
    u.add_argument("--threat-model", default=None)
    u.add_argument("--vulns", default=None)
    u.add_argument("--focus", default=None)
    u.add_argument("--votes", type=int, default=None)
    u.set_defaults(func=cmd_tui)

    r = sub.add_parser("runs", help="list discovered scan runs")
    r.add_argument("--runs-dir", default="runs", dest="runs_dir")
    r.add_argument("--limit", type=int, default=50)
    r.set_defaults(func=cmd_runs)

    f = sub.add_parser("findings", help="browse findings.json for a run")
    f.add_argument("run", help="run dir (or findings.json path)")
    f.add_argument("--severity", default=None)
    f.add_argument("--cwe", default=None)
    f.add_argument("--status", default=None)
    f.add_argument("--limit", type=int, default=200)
    f.set_defaults(func=cmd_findings)

    d = sub.add_parser("doctor", help="diagnose config, binaries, and environment")
    d.add_argument("--config", default="config/default.yaml")
    d.set_defaults(func=cmd_doctor)

    st = sub.add_parser("status", help="show agent status for a run")
    st.add_argument("run", help="run dir")
    st.set_defaults(func=cmd_status)

    ins = sub.add_parser("inspect", help="inspect a completed run")
    ins.add_argument("run", help="run dir")
    ins.add_argument("--agent", default=None, help="filter timeline to one agent id")
    ins.add_argument("--timeline", action="store_true",
                    help="print agent timeline from agents.jsonl")
    ins.set_defaults(func=cmd_inspect)

    ca = sub.add_parser("cancel", help="request cancellation of a running scan")
    ca.add_argument("target", help="run dir or pid")
    ca.add_argument("--pid", type=int, default=None)
    ca.set_defaults(func=cmd_cancel)

    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
