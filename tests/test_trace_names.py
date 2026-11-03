"""Trace-name scope wiring: run_name = ``role:<unit[:c<cell>:v<vote>]>``.

Hermetic: conftest strips LANGFUSE_* env, so these exercise the inactive path
(value-identical configs) and a forced-active ``_STATE`` only — never the SDK.
"""
import cerberus.agents.deep as deep
import cerberus.agents.hunters as hunters_mod
from cerberus import observability as obs
from cerberus.agents import validator as vmod
from cerberus.agents.deep import run_structured
from pydantic import BaseModel


class Q(BaseModel):
    question: str


def _active(monkeypatch) -> None:
    monkeypatch.setattr(obs, "_STATE",
                        {"scan_id": "scan-x", "handler": object()})


def test_scope_path_segments():
    assert obs.scope_path("pages:c1:v1") == "pages:c1:v1"
    assert obs.scope_path("multi unit:name:c2:v1") == "multi-unit:name:c2:v1"
    assert obs.scope_path("a-b/c1:v1") == "a-b-c1:v1"
    assert obs.scope_path(":::") == ""
    assert obs.scope_path("") == ""
    assert obs.scope_path(None) == ""
    assert obs.scope_path("x" * 60) == "x" * 40


def test_scan_metadata_extra_and_inactive(monkeypatch):
    assert obs.scan_metadata(role="validator", extra={"cell": "1"}) == {}
    _active(monkeypatch)
    meta = obs.scan_metadata(role="validator", stage="validate", unit="pages",
                             extra={"cell": "1", "vote": "2", "": "x",
                                    "note": None})
    assert meta["langfuse_session_id"] == "scan-x"
    assert meta["langfuse_tags"] == ["validate", "validator"]
    assert meta["unit"] == "pages"
    assert meta["cell"] == "1" and meta["vote"] == "2"
    assert "" not in meta and "note" not in meta


def test_run_structured_run_name_composition(monkeypatch):
    seen: dict = {}

    class FakeAgent:
        def invoke(self, inp, **kwargs):
            seen["cfg"] = kwargs.get("config")
            return {"structured_response": Q(question="?"), "messages": []}

    monkeypatch.setattr(deep, "build_deep_agent", lambda *a, **k: FakeAgent())

    # Inactive: value-identical config even with scope kwargs.
    run_structured({}, Q, "s", "h", name="validator-pages",
                   trace_suffix="pages:c1:v1", meta_extra={"cell": "1"})
    cfg = seen["cfg"]
    assert "run_name" not in cfg and "metadata" not in cfg

    # Active: composed run_name + metadata.
    _active(monkeypatch)
    run_structured({}, Q, "s", "h", name="validator-pages",
                   trace_suffix="pages:c1:v2",
                   meta_extra={"cell": "1", "vote": "2"})
    cfg = seen["cfg"]
    assert cfg["run_name"] == "validator:pages:c1:v2"
    assert cfg["metadata"]["langfuse_session_id"] == "scan-x"
    assert cfg["metadata"]["cell"] == "1" and cfg["metadata"]["vote"] == "2"

    # Active without a suffix: bare role name (today's behavior).
    run_structured({}, Q, "s", "h", name="triage")
    assert seen["cfg"]["run_name"] == "triage"


def test_validate_unit_batch_scope_per_vote(monkeypatch):
    calls: list[dict] = []

    def fake(mk, model, system, human, **kw):
        calls.append(kw)
        return None, ""

    monkeypatch.setattr(deep, "run_structured", fake)
    finding = {"id": "a", "title": "t", "path": "p.py", "cwe": "CWE-1",
               "severity": "high", "status": "needs-review"}

    out = vmod._validate_unit_batch("pages", [finding, dict(finding, id="b")],
                                    {}, threat_md="", n_votes=2)
    assert [c["trace_suffix"] for c in calls] == [
        "pages:c1:v1", "pages:c1:v2"]
    assert calls[0]["meta_extra"] == {"unit": "pages", "cell": "1", "vote": "1"}
    assert calls[1]["meta_extra"]["vote"] == "2"
    assert len(out) == 2

    # Inactive-config identity is asserted via real run_structured above;
    # a second batch outside a scan must emit the same suffix shape.
    calls.clear()
    vmod._validate_unit_batch("g", [dict(finding, id="c")], {},
                              threat_md="x", n_votes=1)
    assert calls[0]["trace_suffix"] == "g:c1:v1"


def test_run_unit_hunter_run_name(monkeypatch):
    seen: dict = {}

    class FakeAgent:
        _visibility_callbacks = [object()]

        def invoke(self, inp, config=None):
            seen["config"] = config

    monkeypatch.setattr(hunters_mod, "build_unit_hunter_agent",
                        lambda *a, **k: FakeAgent())
    monkeypatch.setattr("cerberus.sandbox.resolve_backend",
                        lambda *a, **k: None)
    monkeypatch.setattr("cerberus.sandbox.close_backend", lambda *a: None)

    # Inactive: recursion_limit only, no run_name/metadata.
    hunters_mod._run_unit({"name": "small unit"}, "repo", [], [], {})
    assert "run_name" not in seen["config"]

    # Active: hunter:<sanitized unit>.
    _active(monkeypatch)
    hunters_mod._run_unit({"name": "small unit"}, "repo", [], [], {})
    assert seen["config"]["run_name"] == "hunter:small-unit"
    assert seen["config"]["metadata"]["unit"] == "small unit"
