"""Unit, contract, and adversarial security tests for the reproduction test loop:

1. Receipt stamper with two-sided sentinel contract (coupled stdout & exit_code 0).
2. Traceback reflected match rejection (sentinel on stderr must not count).
3. Crashing / invalid control check rejection.
4. Dual-path materialization (host persistence + container tmpfs).
5. Deduplication and triage primary election prioritizing proven receipts.
6. Validator dataflow preservation (_compact_finding).
"""

import base64 as _b64
import re as _re
from types import SimpleNamespace
from unittest.mock import MagicMock

from cerberus.agents.poc import materialize_poc, stamp_receipts
from cerberus.agents.poc_generator import (
    PocResultItem,
    _apply_poc_results,
    _close_poc_batch,
    _read_container_script,
)
from cerberus.agents.triage import _elect_primary
from cerberus.agents.validator import _compact_finding, _merge_verdict
from cerberus.pipeline import _merge_dup


class FakeExecResult:
    def __init__(self, exit_code: int = 0, stdout: str = "", stderr: str = ""):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class FakeBackend:
    def __init__(self, run_results=None, control_result=None):
        self.run_results = list(run_results or [])
        self.control_result = control_result or FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
        self.executed_commands: list[str] = []

    def execute(self, cmd: str, timeout: int = 30):
        self.executed_commands.append(cmd)
        if "mkdir -p" in cmd and "base64" in cmd:
            return FakeExecResult(0, "")
        if "--control" in cmd:
            return self.control_result
        if self.run_results:
            return self.run_results.pop(0)
        return FakeExecResult(0, "[POC_PROVEN]\n")


def test_poc_receipt_stamper_success_3_of_3(tmp_path):
    findings = [{
        "id": "SEC-01",
        "title": "SQL Injection in User Search",
        "path": "app/views.py",
        "poc": {
            "script": "import sys\nprint('[POC_PROVEN]')\nsys.exit(0)",
            "command": "python3 /work/_shared/poc/SEC_01/poc.py",
            "runs": 3,
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    res = stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="test-run")
    assert len(res) == 1
    poc = res[0]["poc"]
    assert poc["status"] == "proven"
    receipt = poc["receipt"]
    assert receipt["runs"] == 3
    assert receipt["successes"] == 3
    assert receipt["control_status"] == "passed"
    assert receipt["error"] is None


def test_poc_receipt_stamper_traceback_on_stderr_fails():
    # If the test crashes with exit_code=1 and puts [POC_PROVEN] only on stderr (traceback reflection)
    findings = [{
        "id": "SEC-02",
        "poc": {
            "script": "assert False, '[POC_PROVEN]'",
            "command": "python3 /work/_shared/poc/SEC_02/poc.py",
            "runs": 3,
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(1, stdout="", stderr="AssertionError: [POC_PROVEN]\n"),
            FakeExecResult(1, stdout="", stderr="AssertionError: [POC_PROVEN]\n"),
            FakeExecResult(1, stdout="", stderr="AssertionError: [POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    res = stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="test-run")
    poc = res[0]["poc"]
    assert poc["status"] == "attempted"
    assert poc["receipt"]["successes"] == 0


def test_poc_receipt_stamper_eager_echo_with_crash_fails():
    # If [POC_PROVEN] is flushed to stdout, but the process exits non-zero (crash)
    findings = [{
        "id": "SEC-03",
        "poc": {
            "script": "print('[POC_PROVEN]')\nraise RuntimeError('DB connection failed')",
            "command": "python3 test.py",
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(1, stdout="[POC_PROVEN]\n", stderr="RuntimeError\n"),
            FakeExecResult(1, stdout="[POC_PROVEN]\n", stderr="RuntimeError\n"),
            FakeExecResult(1, stdout="[POC_PROVEN]\n", stderr="RuntimeError\n"),
        ]
    )
    res = stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="test-run")
    poc = res[0]["poc"]
    assert poc["status"] == "attempted"
    assert poc["receipt"]["successes"] == 0


def test_poc_receipt_stamper_crashing_control_fails():
    # 3/3 runs succeed, but control run crashes (exit != 0)
    findings = [{
        "id": "SEC-04",
        "poc": {
            "script": "print('[POC_PROVEN]')",
            "command": "python3 test.py",
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(2, stdout="unrecognized arguments: --control\n")
    )
    res = stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="test-run")
    poc = res[0]["poc"]
    assert poc["status"] == "attempted"
    assert poc["receipt"]["control_status"] == "invalid"
    assert "invalid control" in poc["receipt"]["error"]


def test_poc_receipt_stamper_violated_control_fails():
    # Control run also emits [POC_PROVEN]
    findings = [{
        "id": "SEC-05",
        "poc": {
            "script": "print('[POC_PROVEN]')",
            "command": "python3 test.py",
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(0, stdout="[POC_PROVEN]\n")
    )
    res = stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="test-run")
    poc = res[0]["poc"]
    assert poc["status"] == "attempted"
    assert poc["receipt"]["control_status"] == "violated"
    assert "control violated" in poc["receipt"]["error"]


def test_materialize_poc_creates_host_and_container_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-123")
    finding = {
        "id": "FINDING-99",
        "poc": {
            "script": "print('hello poc')",
        }
    }
    backend = FakeBackend()
    host_file, container_file = materialize_poc(finding, backend, run_id="run-123", repo_path=tmp_path)
    assert host_file is not None
    assert host_file.exists()
    assert host_file.read_text(encoding="utf-8") == "print('hello poc')"
    assert container_file == "/work/_shared/poc/FINDING-99/poc.py"
    assert any("mkdir -p /work/_shared/poc/FINDING-99" in cmd for cmd in backend.executed_commands)


def test_merge_dup_prioritizes_proven_poc():
    # Candidate A has proven PoC (successes=3), Candidate B has no PoC but higher confidence
    cand_a = {
        "id": "A",
        "status": "needs-review",
        "confidence": 0.5,
        "poc": {"status": "proven", "receipt": {"successes": 3, "runs": 3}}
    }
    cand_b = {
        "id": "B",
        "status": "needs-review",
        "confidence": 0.9,
        "poc": {}
    }
    merged = _merge_dup(cand_a, cand_b)
    assert merged["id"] == "A"
    assert merged["poc"]["status"] == "proven"
    assert merged["confidence"] == 0.9  # Confidence elevated, but proven PoC retained


def test_triage_elect_primary_prioritizes_proven_poc():
    out = [
        {"id": "UNPROVEN", "confidence": 0.95, "poc": {}},
        {"id": "PROVEN", "confidence": 0.80, "poc": {"status": "proven"}},
    ]
    _elect_primary(out, [0, 1])
    assert out[1]["duplicate_of"] == ""  # PROVEN elected primary
    assert out[0]["duplicate_of"] == "PROVEN"  # UNPROVEN marked duplicate of PROVEN


def test_validator_compact_finding_preserves_poc_and_conditions():
    raw = {
        "id": "X1",
        "title": "Title",
        "cwe": "CWE-89",
        "path": "a.py",
        "poc": {"script": "repro()"},
        "conditions": ["auth_required"],
        "snippet": "sink()",
        "extra_field": "should_be_stripped"
    }
    compacted = _compact_finding(raw)
    assert "poc" in compacted
    assert compacted["poc"] == {"script": "repro()"}
    assert "conditions" in compacted
    assert compacted["conditions"] == ["auth_required"]
    assert "extra_field" not in compacted


def test_validator_compact_finding_handles_none():
    compacted = _compact_finding(None)
    assert compacted == {"id": "", "title": ""}


def test_poc_receipt_stamper_handles_docker_execute_response():
    # Production Docker Sandbox returns ExecuteResponse with .output and .exit_code, no .stdout
    from cerberus.sandbox.backend_base import ExecuteResponse

    findings = [{
        "id": "DOCKER-01",
        "poc": {
            "script": "print('[POC_PROVEN]')",
            "runs": 3,
        }
    }]
    backend = FakeBackend(
        run_results=[
            ExecuteResponse(output="[POC_PROVEN]\n", exit_code=0),
            ExecuteResponse(output="[POC_PROVEN]\r\n", exit_code=0),  # Also tests CRLF
            ExecuteResponse(output="[POC_PROVEN]\n", exit_code=0),
        ],
        control_result=ExecuteResponse(output="[POC_CONTROL_PASSED]\r\n", exit_code=0)
    )
    res = stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="test-docker")
    poc = res[0]["poc"]
    assert poc["status"] == "proven"
    assert poc["receipt"]["successes"] == 3
    assert poc["receipt"]["control_status"] == "passed"


def test_merge_dup_preserves_proven_poc_when_keep_is_confirmed():
    # Keep is confirmed but has no PoC; Drop has needs-review with proven PoC
    cand_keep = {
        "id": "KEEP-01",
        "status": "confirmed",
        "confidence": 0.8,
        "poc": {}
    }
    cand_drop = {
        "id": "DROP-01",
        "status": "needs-review",
        "confidence": 0.7,
        "poc": {"status": "proven", "receipt": {"successes": 3, "runs": 3}}
    }
    merged = _merge_dup(cand_keep, cand_drop)
    assert merged["id"] == "KEEP-01"
    assert merged["status"] == "confirmed"
    assert merged["poc"]["status"] == "proven"


def test_merge_verdict_protects_proven_poc_from_llm_downgrade():
    base = {
        "id": "V-01",
        "status": "needs-review",
        "poc": {
            "status": "proven",
            "receipt": {"successes": 3, "runs": 3, "control_status": "passed"}
        }
    }
    # LLM verdict erroneously claims poc_status = "attempted"
    verdict = {
        "status": "confirmed",
        "poc_status": "attempted",
    }
    merged = _merge_verdict(base, verdict)
    assert merged["status"] == "confirmed"
    assert merged["poc"]["status"] == "proven"  # Protected from downgrade!


def test_merge_verdict_accepts_repaired_poc_from_validator():
    base = {
        "id": "REPAIR-01",
        "status": "needs-review",
        "poc": {
            "status": "attempted",
            "script": "broken_code()",
            "receipt": {"successes": 0, "runs": 3}
        }
    }
    verdict = {
        "status": "confirmed",
        "poc_status": "proven",
        "poc_script": "import sys\nprint('[POC_PROVEN]')\nsys.exit(0)",
        "poc_command": "python3 /work/_shared/poc/REPAIR-01/test_repro.py",
    }
    merged = _merge_verdict(base, verdict)
    assert merged["status"] == "confirmed"
    assert merged["poc"]["script"] == "import sys\nprint('[POC_PROVEN]')\nsys.exit(0)"
    assert merged["poc"]["command"] == "python3 /work/_shared/poc/REPAIR-01/test_repro.py"
    assert merged["poc"]["status"] == "proven"



def test_polyglot_nodejs_repro_dispatches_node():
    findings = [{
        "id": "NODE-01",
        "poc": {
            "filename": "poc.js",
            "script": "console.log('[POC_PROVEN]'); process.exit(0);",
            "runs": 3,
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="run-node")
    assert findings[0]["poc"]["status"] == "proven"
    assert any("node /work/_shared/poc/NODE-01/poc.js" in cmd for cmd in backend.executed_commands)


def test_polyglot_go_repro_dispatches_go_run():
    findings = [{
        "id": "GO-01",
        "poc": {
            "filename": "poc.go",
            "script": "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"[POC_PROVEN]\") }",
            "runs": 3,
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="run-go")
    assert findings[0]["poc"]["status"] == "proven"
    assert any("go run /work/_shared/poc/GO-01/poc.go" in cmd for cmd in backend.executed_commands)


def test_polyglot_shebang_inference_bash():
    findings = [{
        "id": "BASH-01",
        "poc": {
            "script": "#!/usr/bin/env bash\necho '[POC_PROVEN]'\nexit 0",
            "runs": 3,
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="run-bash")
    assert findings[0]["poc"]["status"] == "proven"
    assert any("/work/_shared/poc/BASH-01/poc.sh" in cmd for cmd in backend.executed_commands)


def test_polyglot_arbitrary_language_custom_extension():
    # Agent specifies custom arbitrary extension like .lua without restriction
    findings = [{
        "id": "LUA-01",
        "poc": {
            "filename": "exploit.lua",
            "script": "#!/usr/bin/env lua\nprint('[POC_PROVEN]')\nos.exit(0)",
            "runs": 3,
        }
    }]
    backend = FakeBackend(
        run_results=[
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
            FakeExecResult(0, "[POC_PROVEN]\n"),
        ],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 3}}, run_id="run-lua")
    assert findings[0]["poc"]["status"] == "proven"
    assert any("/work/_shared/poc/LUA-01/exploit.lua" in cmd for cmd in backend.executed_commands)


def test_stamp_receipts_respects_agent_verified_command():
    findings = [{
        "id": "CMD-01",
        "poc": {
            "filename": "test_sqli.py",
            "script": "import sys\nprint('[POC_PROVEN]')\nsys.exit(0)",
            "command": "python3 -u /work/_shared/poc/CMD-01/test_sqli.py",
            "runs": 1,
        }
    }]
    backend = FakeBackend(
        run_results=[FakeExecResult(0, "[POC_PROVEN]\n")],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    stamp_receipts(findings, backend, cfg={"poc": {"repro_runs": 1}}, run_id="run-cmd")
    assert findings[0]["poc"]["status"] == "proven"
    assert any("python3 -u /work/_shared/poc/CMD-01/test_sqli.py" in cmd for cmd in backend.executed_commands)


def test_lightweight_poc_regen_clears_flag_and_stamps():
    from cerberus.agents.poc import run_poc_regen
    findings = [{
        "id": "REGEN-01",
        "_needs_poc_regen": True,
        "poc": {
            "filename": "test_repro.py",
            "script": "import sys\nprint('[POC_PROVEN]')\nsys.exit(0)",
            "runs": 1,
        }
    }]
    backend = FakeBackend(
        run_results=[FakeExecResult(0, "[POC_PROVEN]\n")],
        control_result=FakeExecResult(0, "[POC_CONTROL_PASSED]\n")
    )
    res = run_poc_regen(findings, backend, cfg={"poc": {"repro_runs": 1}}, run_id="run-regen")
    assert len(res) == 1
    assert res[0]["_needs_poc_regen"] is False
    assert res[0]["poc"]["status"] == "proven"


def test_poc_generator_filters_duplicates_and_fps(monkeypatch):
    """Test that PoC generation is strictly restricted to canonical non-FP findings."""
    from cerberus.agents.poc_generator import run_poc_generation

    findings = [
        {"id": "F-01", "status": "confirmed", "severity": "critical", "duplicate_of": ""},
        {"id": "F-02", "status": "fp", "severity": "critical", "duplicate_of": ""},  # FP should be skipped
        {"id": "F-03", "status": "confirmed", "severity": "high", "duplicate_of": "F-01"},  # Duplicate should be skipped
        {"id": "F-04", "status": "needs-review", "severity": "medium", "duplicate_of": None},  # Canonical
    ]

    processed_batches = []

    def fake_process_batch(batch_findings, cfg, backend, repo, batch_idx, threat_md="", agent_registry=None):
        processed_batches.append([f["id"] for f in batch_findings])
        for f in batch_findings:
            f["poc"] = {"script": "print('[POC_PROVEN]')", "status": "proven"}
        return batch_findings

    monkeypatch.setattr("cerberus.agents.poc_generator._process_poc_batch", fake_process_batch)

    backend = FakeBackend()
    res = run_poc_generation(findings, cfg={"poc": {"regen_batch": 10}}, backend=backend)

    # Only F-01 and F-04 should have been passed to _process_poc_batch
    assert len(processed_batches) == 1
    assert processed_batches[0] == ["F-01", "F-04"]
    assert res[0]["poc"]["status"] == "proven"
    assert "poc" not in res[1]  # F-02 (FP) not touched
    assert "poc" not in res[2]  # F-03 (Duplicate) not touched
    assert res[3]["poc"]["status"] == "proven"


def test_poc_generator_batch_cap(monkeypatch):
    """Canonical findings are chunked into batches of up to ``poc.cell_size``
    per agent (batch size is config-driven, driven from verification when
    unset) with a remainder batch for the tail."""
    from cerberus.agents.poc_generator import run_poc_generation

    # Create 25 canonical findings
    findings = [
        {"id": f"F-{i:02d}", "status": "confirmed", "severity": "high", "duplicate_of": None}
        for i in range(1, 26)
    ]

    batch_sizes = []

    def fake_process_batch(batch_findings, cfg, backend, repo, batch_idx, threat_md="", agent_registry=None):
        batch_sizes.append(len(batch_findings))
        return batch_findings

    monkeypatch.setattr("cerberus.agents.poc_generator._process_poc_batch", fake_process_batch)

    backend = FakeBackend()
    run_poc_generation(findings, cfg={"poc": {"cell_size": 10}, "concurrency": 1},
                       backend=backend)

    # 25 findings should be split into [10, 10, 5]
    assert batch_sizes == [10, 10, 5]

    # The poc cell size falls back to verification's, then the module default.
    batch_sizes.clear()
    run_poc_generation(findings, cfg={"verification": {"cell_size": 4}, "concurrency": 1},
                       backend=backend)
    assert batch_sizes == [4, 4, 4, 4, 4, 4, 1]


def test_poc_generator_sorts_by_severity(monkeypatch):
    """Test that findings are prioritized by severity: critical -> high -> medium -> low."""
    from cerberus.agents.poc_generator import run_poc_generation

    findings = [
        {"id": "LOW-1", "severity": "low", "status": "confirmed"},
        {"id": "CRIT-1", "severity": "critical", "status": "confirmed"},
        {"id": "MED-1", "severity": "medium", "status": "confirmed"},
        {"id": "HIGH-1", "severity": "high", "status": "confirmed"},
    ]

    dispatched_order = []

    def fake_process_batch(batch_findings, cfg, backend, repo, batch_idx, threat_md="", agent_registry=None):
        dispatched_order.extend([f["id"] for f in batch_findings])
        return batch_findings

    monkeypatch.setattr("cerberus.agents.poc_generator._process_poc_batch", fake_process_batch)

    backend = FakeBackend()
    run_poc_generation(findings, cfg={"poc": {"regen_batch": 10}}, backend=backend)

    assert dispatched_order == ["CRIT-1", "HIGH-1", "MED-1", "LOW-1"]


def test_poc_node_in_pipeline(monkeypatch):
    """Test poc_node execution in pipeline state update."""
    from cerberus.pipeline import Overwrite, poc_node

    findings = [
        {"id": "F-01", "status": "confirmed", "severity": "critical", "duplicate_of": ""},
    ]
    state = {
        "repo": ".",
        "verified": findings,
        "config": {"poc": {"enabled": True, "regen_batch": 10}},
    }

    class DummyBackendCtx:
        def __enter__(self):
            return FakeBackend()
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("cerberus.sandbox.acquired_backend", lambda *a, **kw: DummyBackendCtx())

    def fake_run_poc(f_list, cfg, backend, repo=".", threat_md="", agent_registry=None):
        out = list(f_list)
        out[0]["poc"] = {"status": "proven"}
        return out

    monkeypatch.setattr("cerberus.agents.poc_generator.run_poc_generation", fake_run_poc)

    res = poc_node(state)
    assert "verified" in res
    assert isinstance(res["verified"], Overwrite)
    assert res["verified"].value[0]["poc"]["status"] == "proven"




# --- path-based PoC transport (script by reference, not by inlining) ----------


class _B64Backend:
    """Executes only `base64 -w0 -- '<path>'`; serves canned container files."""

    def __init__(self, files=None, fail_paths=()):
        self.files = dict(files or {})
        self.fail_paths = set(fail_paths)
        self.commands = []

    def execute(self, cmd: str, timeout: int = 30):
        self.commands.append(cmd)
        # cmd tail is the quoted-or-bare path (shlex.quote omits quotes when safe)
        path = cmd.strip().rsplit(" ", 1)[-1].strip("'")
        if path is None or path in self.fail_paths or path not in self.files:
            return SimpleNamespace(stdout="", stderr="", exit_code=1)
        b64 = _b64.b64encode(self.files[path].encode("utf-8")).decode("ascii")
        return SimpleNamespace(stdout=b64, stderr="", exit_code=0)


def test_read_container_script_fetches_saved_file():
    backend = _B64Backend({"/work/_shared/poc/f1/test_repro.py": "print('[POC_PROVEN]')\n"})
    assert _read_container_script(backend, "/work/_shared/poc/f1/test_repro.py") == \
        "print('[POC_PROVEN]')\n"


def test_read_container_script_rejects_escape_and_failure():
    backend = _B64Backend()
    assert _read_container_script(backend, "/etc/passwd") == ""
    assert _read_container_script(backend, "/work/_shared/poc/a/../../x.py") == ""
    assert _read_container_script(None, "/work/_shared/poc/a/x.py") == ""
    missing = _B64Backend({"/work/_shared/poc/a/x.py": "print(1)"}, fail_paths={"/work/_shared/poc/a/x.py"})
    assert _read_container_script(missing, "/work/_shared/poc/a/x.py") == ""


def test_apply_poc_results_path_based_and_omissions():
    backend = _B64Backend({"/work/_shared/poc/f1/test_repro.py": "print(1)\nprint(2)\n"})
    findings = [
        {"id": "f1"},
        {"id": "f2"},   # result returned, but no script anywhere
        {"id": "f3"},   # not covered by the result at all
    ]
    results = {
        "f1": PocResultItem(finding_id="f1", script_path="/work/_shared/poc/f1/test_repro.py"),
        "f2": PocResultItem(finding_id="f2", notes="could not build repro"),
    }
    missing = _apply_poc_results(findings, results, backend)
    poc1 = findings[0]["poc"]
    assert poc1["script"] == "print(1)\nprint(2)\n"
    assert poc1["script_path"] == "/work/_shared/poc/f1/test_repro.py"
    assert poc1["status"] == "attempted"
    assert missing == {"f2": "result returned without a repro script",
                       "f3": "PoC agent result omitted this finding"}

    _close_poc_batch(findings, missing)
    assert findings[1]["poc"]["status"] == "blocked"
    assert "without a repro script" in findings[1]["poc"]["blocker"]
    assert findings[2]["poc"]["status"] == "blocked"
    assert "omitted this finding" in findings[2]["poc"]["blocker"]


def test_close_leaves_stamped_statuses_untouched():
    findings = [{"id": "a", "poc": {"status": "proven", "receipt": {}}},
                {"id": "b", "poc": {"status": "attempted", "receipt": {}}}]
    _close_poc_batch(findings, {"a": "x"})
    assert findings[0]["poc"]["status"] == "proven"
    assert findings[1]["poc"]["status"] == "attempted"


def test_materialize_poc_records_host_path(tmp_path):
    finding = {"id": "f-1", "poc": {"script": "print('[POC_PROVEN]')\n", "filename": "test_repro.py"}}
    backend = MagicMock()
    backend.execute.return_value = SimpleNamespace(output="", exit_code=0)
    materialize_poc(finding, backend, run_id="run1", repo_path=tmp_path)
    host_path = finding["poc"]["host_path"]
    assert host_path.replace("\\", "/").startswith(".cerberus/run1/scratch/poc/f-1/")
    assert (tmp_path / host_path).exists()
