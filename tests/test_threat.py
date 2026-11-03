"""THREAT_MODEL.md: reference 8-section schema, deterministic floor, LLM swarm."""
import json
from pathlib import Path

from cerberus import threat as th
from cerberus.agents.hunters import _cand_ctx
from cerberus.partitioning.llm import _structure_context
from cerberus.pipeline import hunters_router, threat_model_node


def _cands():
    return [
        {"id": "prefilter", "title": "p", "cwe": "", "severity": "info",
         "path": "r", "start_line": 0, "end_line": 0, "snippet": "## sqli-cursor\nfoo",
         "evidence": "e", "status": "needs-review"},
        {"id": "manifest", "title": "m", "cwe": "", "severity": "info",
         "path": "r", "start_line": 0, "end_line": 0, "snippet": "flask app",
         "evidence": "e", "status": "needs-review"},
        {"id": "sast", "title": "eval sink", "cwe": "CWE-78", "severity": "high",
         "path": "app.py", "start_line": 3, "end_line": 3,
         "snippet": "eval(x)", "evidence": "e", "status": "needs-review"},
    ]


def _rich_md():
    """A schema-valid enriched document (as the synthesizer should emit)."""
    return (
        "# Threat Model: demo\n\n"
        "## 1. System context\n\nFlask shop.\n\n"
        "## 2. Assets\n\n| asset | description | sensitivity |\n|---|---|---|\n"
        "| customer PII | order records | high |\n\n"
        "## 3. Entry points & trust boundaries\n\n"
        "| entry_point | description | trust_boundary | reachable_assets |\n"
        "|---|---|---|---|\n"
        "| HTTP handlers (2 routes) | routes GET /login | untrusted network → app | customer PII |\n\n"
        "## 4. Threats\n\n"
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| T1 | Auth bypass via SQL injection in login | remote_unauth | HTTP handlers (2 routes) | customer PII | critical | likely | unmitigated | none | app.py:12 |\n"
        "| T2 | Stored XSS in order comments | remote_auth | HTTP handlers (2 routes) | customer PII | high | possible | unmitigated | partial escaping | |\n\n"
        "## 5. Deprioritized\n\n| threat | reason |\n|---|---|\n"
        "| Repudiation | no multi-user audit trail |\n\n"
        "A threat model prioritizes, it never excludes: a parked row is not a scope decision.\n\n"
        "## 6. Open questions\n\n- Is there a WAF upstream?\n\n"
        "## 7. Provenance\n\n- mode: bootstrap\n- date: 2026-01-01\n- target: demo\n\n"
        "## 8. Recommended mitigations\n\n| mitigation | threat_ids | closes_class | effort |\n|---|---|---|---|\n"
        "| parameterized queries everywhere | T1 | yes | S |\n"
    )


def test_load_repo_file_wins(tmp_path):
    (tmp_path / "THREAT_MODEL.md").write_text("# custom\n\n## 4. Threats\n\nT1 rows")
    src, text = th.load_threat(str(tmp_path), cfg={})
    assert src == "repo-file"
    assert "T1 rows" in text


def test_load_none_without_file(tmp_path):
    assert th.load_threat(str(tmp_path), cfg={}) == ("none", "")


def test_load_override_missing_file_falls_back(tmp_path):
    assert th.load_threat(str(tmp_path), override=str(tmp_path / "nope.md")) == ("none", "")


def test_node_uses_repo_file(tmp_path):
    (tmp_path / "THREAT_MODEL.md").write_text("FULL-TRUST-MODEL " + "x" * 20000)
    st = {"repo": str(tmp_path), "files": ["a.py"], "candidates": _cands()}
    out = threat_model_node(st)
    assert out["threat_model_source"] == "repo-file"
    assert len(out["threat_model_md"]) > 20000  # no truncation
    assert any(c["id"] == "threat-model" for c in out["candidates"])


def test_node_falls_back_to_summary_on_bootstrap_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("THREAT_LLM", "0")
    monkeypatch.setattr(th, "bootstrap_threat", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    st = {"repo": str(tmp_path), "files": ["a.py"], "candidates": _cands()}
    out = threat_model_node(st)
    assert out["threat_model_source"] == "summary"
    assert "threat_model_md" not in out
    assert "STRIDE" in out["threat_model"]


def test_bootstrap_deterministic_offline(tmp_path):
    md = th.bootstrap_threat(str(tmp_path), ["a.py", "b/c.py"], _cands(), "summ")
    for section in th.SECTIONS:
        assert f"## {section}" in md
    assert "sqli-cursor" in md  # prefilter classes flow through as coverage


def test_cand_ctx_is_candidates_only_and_discovery_owns_the_model():
    """The threat model appears exactly once per unit prompt: the discovery
    task's labeled section. _cand_ctx used to prepend it too, doubling the
    document into every hunter prompt under a "Prefilter signals" label."""
    big = "BOUNDARY-MARKER " + "y" * 30000
    from cerberus.prompts.hunter import build_hunter_task
    ctx = _cand_ctx(_cands(), {}, big)
    assert big not in ctx
    assert "sast" in ctx  # slim coverage signals still present
    task = build_hunter_task("unit", "repo", ["a.py"], ctx, big, "ALL")
    assert task.count(big) == 1  # no truncation, no duplication
    assert "Threat model" in task


def test_cand_ctx_without_threat_is_slim_only():
    ctx = _cand_ctx(_cands(), {})
    assert "THREAT MODEL" not in ctx
    assert "sast" in ctx


def test_structure_context_full_threat():
    big = "PARTITION-MARKER " + "z" * 15000
    ctx = _structure_context("r", ["a.py"], _cands(), big)
    assert big in ctx


def test_fanout_payload_carries_threat_md(monkeypatch, tmp_path):
    monkeypatch.setenv("THREAT_LLM", "0")
    import cerberus.partitioning.llm as part
    monkeypatch.setattr(part, "run_partitioner_agent",
                        lambda repo, files, cands, cfg, threat_md="": [
                            {"name": "u", "files": files, "reason": "t"}])
    st = {"repo": str(tmp_path), "files": ["a.py"], "candidates": _cands(),
          "threat_model_md": "THREAT-CARRIED"}
    out = hunters_router(st)
    assert out["fanout_payloads"][0]["threat_model_md"] == "THREAT-CARRIED"


def test_cli_threat_model_writes_draft(monkeypatch, tmp_path):
    import argparse

    from cerberus.cli import cmd_threat_model
    monkeypatch.setenv("THREAT_LLM", "0")
    dest = tmp_path / "TM.md"
    rc = cmd_threat_model(argparse.Namespace(
        repo="tests/fixtures/pygoat-sample", out=str(dest), interview=False,
        verify=False, update_from=None, vulns=None))
    assert rc == 0
    text = dest.read_text()
    assert "## 4. Threats" in text
    assert "## 3. Entry points & trust boundaries" in text


def test_owner_file_beats_cache(tmp_path):
    (tmp_path / "THREAT_MODEL.md").write_text("OWNER")
    (tmp_path / ".cerberus").mkdir()
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text("CACHE")
    src, text = th.load_threat(str(tmp_path), cfg={})
    assert (src, text) == ("repo-file", "OWNER")


def test_cache_used_when_no_owner_file(tmp_path):
    (tmp_path / ".cerberus").mkdir()
    cached = th.bootstrap_threat(str(tmp_path), ["a.py"], [], "s")
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text(cached)
    src, text = th.load_threat(str(tmp_path), cfg={})
    assert src == "repo-cache"
    assert text.strip() == cached.strip()


def test_persist_writes_cache_not_owner(tmp_path):
    (tmp_path / "THREAT_MODEL.md").write_text("OWNER")
    dest = th.persist_threat(str(tmp_path), "# fresh")
    assert dest.endswith(".cerberus/THREAT_MODEL.md")
    assert Path(dest).read_text().startswith("<!-- machine-managed")
    assert (tmp_path / "THREAT_MODEL.md").read_text() == "OWNER"
    assert th.persist_threat(str(tmp_path), "  ") == ""


def test_threats_table_parses_and_detects_bad_enums():
    rows = th._parse_threats(_rich_md())
    assert [r["id"] for r in rows] == ["T1", "T2"]
    assert th._row_enum_gaps(rows[0]) == []
    assert th._row_enum_gaps(rows[1]) == []  # empty evidence is allowed
    bad = dict(rows[0], impact="apocalyptic")
    assert "impact=apocalyptic" in th._row_enum_gaps(bad)


def test_coverage_gaps_flag_uncovered_entry_points():
    md = _rich_md().replace(
        "| HTTP handlers (2 routes) | routes GET /login | untrusted network → app | customer PII |",
        "| HTTP handlers (2 routes) | routes GET /login | untrusted network → app | customer PII |\n"
        "| build pipeline | Dockerfile pins nothing | untrusted registry → artifact | host integrity |")
    gaps = th._coverage_gaps(md)
    assert any("build pipeline" in g for g in gaps)
    assert not any("HTTP handlers" in g for g in gaps)


def test_quality_scores_rich_model_high():
    q = th.threat_quality(_rich_md(), ["a.py"], [{"id": "routes", "snippet": "GET /login\nPOST /x"}])
    assert q["sections_filled"] == "8/8"   # fixture: every section filled
    assert q["threat_rows"] == 2           # fixture: exactly 2 threat rows
    assert q["gaps"] == []


def test_quality_flags_floor_and_bad_rows():
    rich = th.threat_quality(_rich_md(), ["a.py"],
                             [{"id": "routes", "snippet": "GET /login\nPOST /x"}])
    floor = th.bootstrap_threat(".", ["a.py"], [], "s")
    q = th.threat_quality(floor, ["a.py"], [])
    assert q["threat_rows"] == 0
    assert any("4. Threats" in g for g in q["gaps"])
    assert "deterministic floor" in " ".join(q["gaps"])
    # An unusable document (unranked / nearly empty) must score strictly
    # below the ranked rich model, so quality cannot read as excellent while
    # the threats half is empty. Relational: prod thresholds are not pinned.
    assert q["score"] < rich["score"]
    assert any("no rows" in g for g in q["gaps"])
    thin = "# T\n\n## 1. System context\n\nx\n"
    assert th.threat_quality(thin, [], [])["score"] < rich["score"]


def test_quality_requires_gap_fill_row():
    md = _rich_md().replace("| T2 | Stored XSS in order comments | remote_auth | HTTP handlers (2 routes) | customer PII | high | possible | unmitigated | partial escaping | |",
                            "| T2 | Stored XSS in order comments | remote_auth | HTTP handlers (2 routes) | customer PII | high | possible | unmitigated | partial escaping | app.py:40 |")
    gaps = th.threat_quality(md, [], [])["gaps"]
    assert any("gap-fill" in g for g in gaps)


def test_node_carries_quality(monkeypatch):
    monkeypatch.setenv("THREAT_LLM", "0")
    st = {"repo": "tests/fixtures/pygoat-sample",
           "files": ["a.py"],
           "candidates": [{"id": "prefilter", "snippet": "## sqli-cursor\nx"}]}
    out = threat_model_node(st)
    assert out["threat_quality"]["score"] >= 50
    assert out["threat_quality"]["threat_rows"] == 0  # floor, honestly flagged


# --- --vulns evidence input (reference harness's vuln-file parser) -----------

def test_parse_vulns_json_array(tmp_path):
    import json
    p = tmp_path / "v.json"
    p.write_text(json.dumps([
        {"id": "CVE-2026-29022", "title": "heap overflow in parser",
         "component": "parse_wav", "description": "chunk_size unchecked"},
        {"id": "GHSA-xxxx-yyyy", "summary": "ssti", "file": "render.py",
         "details": "eval on config"},
        {"nope": "no id -> skipped"}]))
    rows = th.parse_vulns_file(str(p))
    assert [r["id"] for r in rows] == ["CVE-2026-29022", "GHSA-xxxx-yyyy"]
    assert rows[0]["component"] == "parse_wav"
    assert rows[1]["title"] == "ssti" and rows[1]["component"] == "render.py"


def test_parse_vulns_csv(tmp_path):
    p = tmp_path / "v.csv"
    p.write_text("id,title,component,description\n"
                 "CVE-2025-14369,double free,decoder,unchecked alloc\n"
                 "CVE-2024-1,xss,web,notes\n")
    rows = th.parse_vulns_file(str(p))
    assert len(rows) == 2
    assert rows[0] == {"id": "CVE-2025-14369", "title": "double free",
                       "component": "decoder",
                       "description": "unchecked alloc"}


def test_parse_vulns_id_list(tmp_path):
    p = tmp_path / "v.txt"
    p.write_text("# past vulns\nCVE-2026-29022\n- GHSA-abcd-1234-efgh\n"
                 "not an id, just prose\nOSV-2023-9999\n")
    rows = th.parse_vulns_file(str(p))
    assert [r["id"] for r in rows] == ["CVE-2026-29022", "GHSA-abcd-1234-efgh",
                                       "OSV-2023-9999"]


def test_parse_vulns_markdown_report(tmp_path):
    p = tmp_path / "pentest.md"
    p.write_text("# Pentest report\n\n"
                 "## SQL injection in login (CVE-2026-11111)\n\n"
                 "The username field is interpolated into the query.\n\n"
                 "## Reflected XSS in search\n\n"
                 "query param rendered unescaped.\n")
    rows = th.parse_vulns_file(str(p))
    assert [r["id"] for r in rows] == ["CVE-2026-11111", "md-2"]
    assert "interpolated" in rows[0]["description"]
    assert "Reflected XSS" in rows[1]["title"]


def test_parse_vulns_fail_soft(tmp_path):
    assert th.parse_vulns_file(str(tmp_path / "missing.txt")) == []
    empty = tmp_path / "empty.txt"
    empty.write_text("   \n")
    assert th.parse_vulns_file(str(empty)) == []
    junk = tmp_path / "junk.json"
    junk.write_text("{not json at all")
    assert th.parse_vulns_file(str(junk)) == []


def test_vulns_feed_floor_facts_and_provenance(tmp_path):
    vulns = [{"id": "CVE-2026-29022", "title": "t", "component": "c",
              "description": "d"}]
    md = th.bootstrap_threat(str(tmp_path), ["a.py"], [], "summ",
                             vulns=vulns, vulns_path="past.txt")
    ctx = th._section(md, "1. System context")
    # Only test-supplied values are pinned here (data flow into doc sections).
    assert "CVE-2026-29022" in ctx
    prov = th._section(md, "7. Provenance")
    assert "past.txt" in prov
    assert th.parse_vulns_file("") == []
    assert th._vulns_note(None) == ""


def test_historian_task_includes_vulns_rows():
    from cerberus.prompts.threat import build_historian_task
    vulns = [{"id": "CVE-2026-29022", "title": "heap overflow",
              "component": "parser", "description": "chunk unchecked"}]
    task = build_historian_task("r", "abc123 fix overflow", "draft", vulns)
    # Test-supplied values flowing into the task (no prod wording pinned).
    assert "CVE-2026-29022" in task and "component: parser" in task


# --- LLM swarm enrichment: planner payload + deterministic merge ------------

def _fake_run_structured(monkeypatch, *, research=None, history=None,
                         plan=None, boom=False):
    """Script the three swarm calls through the real code paths."""
    calls = []

    def _fake(cfg, model, system, human):
        stage = ("threat:researcher" if system.startswith("You are a threat-model research")
                 else "threat:historian" if system.startswith("You are a threat-model history")
                 else "threat:synthesizer")
        calls.append((system[:40], stage))
        if boom:
            raise RuntimeError("transport down")
        if system.startswith("You are a threat-model research"):
            return research
        if system.startswith("You are a threat-model history"):
            return history
        return plan

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured", _fake)
    return calls


def _research_payload():
    from cerberus.prompts.threat import SwarmResearch
    return SwarmResearch(
        system_context="Flask shop with a login form.",
        entry_points=[{"entry_point": "HTTP route GET /login",
                       "description": "login form", "trust_boundary": "network → app",
                       "file_refs": ["app.py:12"]}],
        assets=[{"asset": "customer PII", "description": "orders", "sensitivity": "high"}],
        controls=["session cookie httponly"], open_questions=["WAF?"])


def _history_payload():
    from cerberus.prompts.threat import SwarmHistory
    return SwarmHistory(vulns=[{"id": "abc1234", "title": "fix sqli in login",
                                "component": "app.py", "vclass": "sqli",
                                "vector": "HTTP handlers"}])


def _plan_payload(*, threats=None):
    from cerberus.prompts.threat import SwarmPlan, SwarmThreat
    if threats is None:
        threats = [
            # deliberately out of rank order: ids must come from the sort
            SwarmThreat(threat="Stored XSS in order comments", actor="remote_auth",
                        surface="HTTP route GET /login", asset="customer PII",
                        impact="high", likelihood="possible", status="unmitigated",
                        controls="", evidence=""),
            SwarmThreat(threat="Auth bypass via SQL injection in login",
                        actor="remote_unauth", surface="HTTP route GET /login",
                        asset="customer PII", impact="critical", likelihood="likely",
                        status="unmitigated", controls="none",
                        evidence="app.py:12"),
        ]
    return SwarmPlan(
        context_prose="Flask shop with a login form.",
        entry_points=[{"entry_point": "HTTP route GET /login",
                       "description": "login form",
                       "trust_boundary": "untrusted network → app",
                       "file_refs": ["app.py:12"]}],
        assets=[{"asset": "customer PII", "description": "orders",
                 "sensitivity": "high"}],
        threats=threats,
        deprioritized=[{"threat": "Repudiation", "reason": "no multi-user audit trail"}],
        open_questions=["Is there a WAF upstream?"],
        mitigations=[{"mitigation": "parameterized queries everywhere",
                      "threat_numbers": [1, 2], "closes_class": "yes",
                      "effort": "S"}])


def test_llm_structured_patch_target_is_live(monkeypatch):
    """Canary for the patch target: the string patches in this suite must bind
    the function the swarm actually calls. If they name any other attribute the
    patch silently no-ops and the tests make live model calls."""
    import cerberus.threat as th
    import cerberus.threat.swarm as swarm

    assert th._llm_structured.__module__ == "cerberus.threat.swarm"
    calls = []

    def _fake(cfg, model, system, human):
        calls.append(system)
        return None

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured", _fake)
    assert swarm._swarm_plan("repo", "draft", {}, {}, {}) == {}
    assert calls, "patch target cold: the swarm does not resolve _llm_structured"


def test_enrich_merges_plan_into_deterministic_skeleton(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    calls = _fake_run_structured(monkeypatch, research=_research_payload(),
                                 history=_history_payload(), plan=_plan_payload())
    st = {"repo": str(tmp_path), "files": ["app.py"],
          "candidates": [{"id": "manifest", "snippet": "pyproject.toml"}]}
    floor = th.bootstrap_threat(st["repo"], st["files"], st["candidates"], "summ")
    md, meta = th.enrich_threat(st["repo"], st["files"], st["candidates"],
                                "summ", floor, {})
    for section in th.SECTIONS:
        assert f"## {section}" in md
    # Judgment payload landed, with CODE-assigned ids after ranking.
    rows = th._parse_threats(md)
    assert [r["id"] for r in rows] == ["T1", "T2"]
    assert "SQL injection" in rows[0]["threat"]       # critical sorts first
    assert "HTTP route GET /login" in md
    assert "customer PII" in th._section(md, "2. Assets")
    assert "WAF upstream" in th._section(md, "6. Open questions")
    # Deterministic cells are code-owned.
    assert "- enrichment: llm-swarm" in th._section(md, "7. Provenance")
    assert "declared dependencies" in th._section(md, "3. Entry points & trust boundaries")
    assert "prioritizes, it never excludes" in th._section(md, "5. Deprioritized")
    assert "measured facts" not in md and "Repo:" in th._section(md, "1. System context")
    assert meta["threat_rows"] == 2 and meta["dropped"] == []
    assert {name for _, name in calls} >= {"threat:researcher", "threat:historian",
                                           "threat:synthesizer"}
    # §8 maps the plan's 1-based threat_numbers onto the assigned ids:
    # input position 2 ("SQL injection", critical) became T1.
    # ids render in rank order (T1,T2) even though the planner's list put
    # the XSS row first.
    assert "| T1,T2 |" in th._section(md, "8. Recommended mitigations")


def test_enrich_ids_are_pure_function_of_content(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    cands = [{"id": "manifest", "snippet": "pyproject.toml"}]
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], cands, "s")
    _fake_run_structured(monkeypatch, research=_research_payload(),
                         history=_history_payload(), plan=_plan_payload())
    md_a, _ = th.enrich_threat(str(tmp_path), ["app.py"], cands, "s", floor, {})
    # Same payload, reversed threat order -> identical rendered ids.
    p = _plan_payload()
    p.threats = list(reversed(p.threats))
    _fake_run_structured(monkeypatch, research=_research_payload(),
                         history=_history_payload(), plan=p)
    md_b, _ = th.enrich_threat(str(tmp_path), ["app.py"], cands, "s", floor, {})
    rows_a = [r["threat"] for r in th._parse_threats(md_a)]
    rows_b = [r["threat"] for r in th._parse_threats(md_b)]
    assert rows_a == rows_b


def test_enrich_drops_invalid_rows_keeps_valid_ones(monkeypatch, tmp_path):
    from cerberus.prompts.threat import SwarmThreat
    (tmp_path / "app.py").write_text("x=1")
    cands = [{"id": "manifest", "snippet": "pyproject.toml"}]
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], cands, "s")
    bad = SwarmThreat(threat="Apocalyptic RCE", actor="remote_unauth",
                      surface="HTTP route GET /login", asset="customer PII",
                      impact="apocalyptic", likelihood="likely",
                      status="unmitigated", controls="none", evidence="")
    prose = SwarmThreat(threat="Grade tampering by a careless maintainer",
                        actor="a careless or compromised maintainer/ci account",
                        surface="HTTP route GET /login", asset="customer PII",
                        impact="high", likelihood="possible",
                        status="unmitigated", controls="none", evidence="")
    _fake_run_structured(monkeypatch, research=_research_payload(),
                         history=_history_payload(),
                         plan=_plan_payload(threats=[bad, prose]))
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], cands, "s", floor, {})
    rows = th._parse_threats(md)
    # Out-of-enum cells are classified into the closed set, never dropped:
    # the row carries the model's judgment; only the cell is ours to own.
    assert len(rows) == 2 and rows[0]["impact"] == "existential"
    assert rows[1]["actor"] == "insider"
    assert meta["dropped"] == []
    assert "- enrichment: llm-swarm" in md


def test_enrich_never_loses_a_code_detected_surface(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM x")
    (tmp_path / "app.py").write_text("x=1")
    files = ["app.py", "Dockerfile"]
    cands = [{"id": "manifest", "snippet": "pyproject.toml"}]
    floor = th.bootstrap_threat(str(tmp_path), files, cands, "s")
    skeleton = th._attack_surfaces(cands, files)
    assert len(skeleton) > 1
    _fake_run_structured(monkeypatch, research=_research_payload(),
                         history=_history_payload(), plan=_plan_payload())
    md, _ = th.enrich_threat(str(tmp_path), files, cands, "s", floor, {})
    ep_text = th._section(md, "3. Entry points & trust boundaries")
    for s in skeleton:
        assert s[:24] in ep_text, s   # plan cannot drop a measured surface


def test_enrich_fail_open_when_agents_fail(monkeypatch, tmp_path):
    _fake_run_structured(monkeypatch, boom=True)
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], [], "s", "", {})
    assert md == ""
    assert meta["agents"]["researcher"].startswith("failed")


def test_enrich_threads_vulns_into_historian_and_provenance(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    seen: dict = {}

    def _fake(cfg, model, system, human):
        if system.startswith("You are a threat-model history miner"):
            seen["task"] = human
        if system.startswith("You are a threat-model research agent"):
            return _research_payload()
        if system.startswith("You are a threat-model history miner"):
            return _history_payload()
        return _plan_payload()

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured", _fake)
    vulns = [{"id": "CVE-2026-29022", "title": "heap overflow",
              "component": "parser", "description": "chunk unchecked"}]
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], [], "s", vulns, "past.txt")
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], [], "s", floor, {},
                                vulns=vulns, vulns_path="past.txt")
    assert "CVE-2026-29022" in seen["task"]  # evidence reached the historian
    prov = th._section(md, "7. Provenance")
    assert "--vulns past.txt (1 rows)" in prov
    ctx = th._section(md, "1. System context")
    assert "supplied via --vulns" in ctx
    assert meta["threat_rows"] == 2


def test_enrich_fail_open_when_planner_returns_nothing(monkeypatch, tmp_path):
    _fake_run_structured(monkeypatch, research=_research_payload(),
                         history=_history_payload(), plan=None)
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], [], "s", "", {})
    assert md == ""
    assert "planner" in meta["error"]


def test_enrich_runs_planner_when_context_agents_return_empty(monkeypatch,
                                                             tmp_path):
    """A weak model fills no nested schema: both context agents answer with
    empty payloads (status 'failed', not a transport error) yet the endpoint
    is healthy. The floor + measured facts are self-sufficient input for the
    planner, so enrichment must still happen — the old 'swarm produced
    nothing' gate threw that enrichment away."""
    from cerberus.prompts.threat import SwarmHistory, SwarmResearch
    (tmp_path / "app.py").write_text("x=1")

    def _fake(cfg, model, system, human):
        if system.startswith("You are a threat-model research agent"):
            return SwarmResearch()   # reachable, empty
        if system.startswith("You are a threat-model history miner"):
            return SwarmHistory()    # reachable, empty
        return _plan_payload()

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured", _fake)
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], [], "s")
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], [], "s", floor, {})
    assert md.strip(), meta  # the planner alone still enriched
    assert meta["threat_rows"] == 2
    assert "swarm" not in meta.get("error", "")


def test_node_enriches_by_default_every_scan(monkeypatch, tmp_path):
    # A machine cache from a prior scan exists — enrichment still runs.
    (tmp_path / ".cerberus").mkdir()
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text("CACHED-MODEL")
    monkeypatch.setenv("THREAT_LLM", "1")
    _fake_run_structured(monkeypatch, research=_research_payload(),
                         history=_history_payload(), plan=_plan_payload())
    st = {"repo": str(tmp_path), "files": ["app.py"], "candidates": _cands()}
    out = threat_model_node(st)
    assert "SQL injection" in out["threat_model_md"]
    assert out["threat_enrich"]["threat_rows"] == 2
    assert "- enrichment: llm-swarm" in out["threat_model_md"]


def test_node_never_enriches_owner_file(monkeypatch, tmp_path):
    (tmp_path / "THREAT_MODEL.md").write_text("OWNER-AUTHORED-MODEL")
    calls = _fake_run_structured(monkeypatch, research=_research_payload(),
                                 history=_history_payload(), plan=_plan_payload())
    out = threat_model_node({"repo": str(tmp_path), "files": ["app.py"],
                             "candidates": _cands()})
    assert out["threat_model_md"] == "OWNER-AUTHORED-MODEL"
    assert "threat_enrich" not in out
    assert calls == []


def test_node_llm_enrich_config_off(monkeypatch, tmp_path):
    monkeypatch.setenv("THREAT_LLM", "0")
    calls = _fake_run_structured(monkeypatch, research=_research_payload(),
                                 history=_history_payload(), plan=_plan_payload())
    out = threat_model_node({"repo": str(tmp_path), "files": ["app.py"],
                             "candidates": _cands()})
    assert calls == []
    assert out["threat_model_source"] == "bootstrap"
    assert "threat_enrich" not in out


def test_feedback_loop_appends_and_replaces():
    md = _rich_md()
    findings = [
        {"id": "1", "cwe": "CWE-89", "severity": "high", "status": "confirmed",
         "path": "a.py", "duplicate_of": ""},
        {"id": "2", "cwe": "CWE-78", "severity": "high", "status": "confirmed",
         "path": "b.py", "duplicate_of": ""},
        {"id": "3", "cwe": "CWE-89", "severity": "info", "status": "fp",
         "path": "c.py", "duplicate_of": ""},  # fp + dup excluded
        {"id": "4", "cwe": "CWE-89", "severity": "high", "status": "confirmed",
         "path": "a.py", "duplicate_of": "1"},  # duplicate excluded
    ]
    once = th.update_threat_with_findings(md, findings, "r")
    assert "CWE-89 x1" in once and "CWE-78 x1" in once
    assert "Consider adding a threat row for: CWE-78" in once
    twice = th.update_threat_with_findings(once, findings, "r")
    assert twice.count("## Observed findings") == 1  # stable, not growing
    assert th.update_threat_with_findings(md, [], "r") == md


def test_llm_interview_conducts_and_finalizes(monkeypatch):
    asked = []
    seen: dict = {}
    monkeypatch.setattr("cerberus.threat.swarm.interview_questions",
                        lambda draft, hist, cfg, n=5: [] if hist else ["Is X trusted?"])

    valid = "\n\n".join(f"## {n}\n\nbody" for n in th.SECTIONS)

    def _final(draft, hist, cfg, root_dir=None):
        seen["n"] = len(hist)
        seen["answers"] = [a for _, a in hist]
        seen["root_dir"] = root_dir
        return valid

    monkeypatch.setattr("cerberus.threat.swarm.finalize_threat", _final)
    out = th.conduct_interview("r", ["a.py"], [], "summ", {},
                               ask=lambda q: asked.append(q) or "yes",
                               say=lambda t: None)
    assert "## Owner notes" not in out and out.count("## ") == len(th.SECTIONS)
    assert asked == ["Is X trusted?"]
    assert seen["n"] == 1 and seen["answers"] == ["yes"]
    assert seen["root_dir"] == "r"  # repo passed for the agent's backend


def test_interview_rejects_non_schema_finalize(monkeypatch):
    """A finalize reply that does not satisfy the schema must not ship: the
    deterministic floor plus the Q&A appendix does instead."""
    monkeypatch.setattr("cerberus.threat.swarm.interview_questions",
                        lambda draft, hist, cfg, n=5: [] if hist else ["Q1?"])
    monkeypatch.setattr("cerberus.threat.swarm.finalize_threat",
                        lambda *a, **k: "# Threat Model: r\n\nfreeform, no sections")
    out = th.conduct_interview("r", ["a.py"], [], "summ", {},
                               ask=lambda q: "yes", say=lambda t: None)
    assert "## Owner notes (interview)" in out
    assert "## 4. Threats" in out  # the floor's schema survived
    assert "freeform" not in out


def test_interview_static_fallback_without_llm(monkeypatch):
    monkeypatch.setattr("cerberus.threat.swarm.interview_questions",
                        lambda *a, **k: None)
    monkeypatch.setattr("cerberus.threat.swarm.finalize_threat",
                        lambda *a, **k: (_ for _ in ()).throw(ValueError("down")))
    out = th.conduct_interview("r", ["a.py"], [], "summ", {},
                               ask=lambda q: "ans",
                               say=lambda t: None)
    assert "## Owner notes (interview)" in out
    assert out.count("Q: ") == len(th.INTERVIEW_QUESTIONS)


def test_collect_docs_reads_day_one_files(tmp_path):
    (tmp_path / "README.md").write_text("# Shop\n\nA checkout service.")
    (tmp_path / "SECURITY.md").write_text("# Policy\n\nWe use sandboxed builds.")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "arch.md").write_text("# Arch\n\nThree-tier.")
    (tmp_path / "notes.txt").write_text("ignore me")
    got = dict(th.collect_docs(str(tmp_path)))
    assert set(got) == {"README.md", "SECURITY.md", "docs/arch.md"}
    assert "checkout" in got["README.md"]


def test_bootstrap_uses_docs_and_policies(tmp_path):
    (tmp_path / "README.md").write_text("# Shop\n\nA checkout service.")
    (tmp_path / "SECURITY.md").write_text("# Policy\n\nSandboxed builds only.")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "arch.md").write_text("# Arch\n\nThree-tier checkout.")
    md = th.bootstrap_threat(str(tmp_path), ["a.py"], [], "summ")
    assert "checkout" in md  # architecture context landed
    assert "SECURITY.md" in md and "Sandboxed" in md  # dep policy, not unknown


def test_bug_shapes_with_fix_history(tmp_path):
    import subprocess
    r = str(tmp_path)
    subprocess.run(["git", "init", "-q", r], check=True)
    subprocess.run(["git", "-C", r, "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", r, "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", r, "config", "commit.gpgsign", "false"], check=True)
    (tmp_path / "auth.py").write_text("x=1")
    subprocess.run(["git", "-C", r, "add", "."], check=True)
    subprocess.run(["git", "-C", r, "commit", "-qm", "fix XSS in auth view"], check=True)
    shapes = th._bug_shapes(r)
    assert "XSS" in shapes and "auth.py" in shapes
    assert "complete" in shapes  # the guide's two questions travel along


def test_only_confirmed_teaches_scope():
    md = _rich_md()
    reviewing = [{"id": "1", "cwe": "CWE-78", "severity": "high",
                  "status": "needs-review", "path": "b.py",
                  "start_line": 1, "end_line": 1, "snippet": "s",
                  "evidence": "e", "duplicate_of": ""}]
    assert th.update_threat_with_findings(md, reviewing, "r") == md


def test_threat_update_node_from_validator():
    from cerberus.pipeline import threat_update_node
    md = _rich_md()
    confirmed = [{"id": "1", "cwe": "CWE-78", "severity": "high",
                  "status": "confirmed", "path": "b.py",
                  "start_line": 1, "end_line": 1, "snippet": "s",
                  "evidence": "e", "duplicate_of": ""}]
    out = threat_update_node({"repo": "r", "verified": confirmed,
                              "threat_model_md": md})
    assert "Observed findings" in out["threat_model_md"]
    assert "CWE-78 x1" in out["threat_model_md"]
    assert threat_update_node({"repo": "r", "verified": [], "threat_model_md": md}) == {}
    assert threat_update_node({"repo": "r", "verified": confirmed}) == {}


def test_known_fps_recorded_with_reasons():
    md = _rich_md()
    fps = [{"id": "1", "cwe": "CWE-89", "severity": "high", "status": "fp",
            "path": "auth.py", "start_line": 8, "end_line": 8,
            "snippet": "execute(q, params)", "evidence": "parameterized query at auth.py:8",
            "duplicate_of": ""}]
    out = th.update_threat_with_findings(md, fps, "r")
    assert "## Known false positives" in out
    assert "CWE-89 x1" in out and "auth.py" in out
    assert "parameterized query" in out
    # An empty scan leaves history untouched (no new evidence: erase nothing).
    again = th.update_threat_with_findings(
        out + "\n## Owner notes\n\nkeep\n", [], "r")
    assert "Known false positives" in again
    assert "keep" in again


def test_verify_passes_on_bootstrap(tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    md = th.bootstrap_threat(str(tmp_path), ["app.py"],
                             [{"id": "prefilter", "snippet": "## sqli-cursor\nx"}], "s")
    fv = th.verify_threat(str(tmp_path), md, ["app.py"],
                          [{"id": "prefilter", "snippet": "## sqli-cursor\nx"}])
    assert fv == {"score": 100, "failures": []}


def test_verify_catches_ghost_files_and_stale_routes(tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    md = ("# T\n\n## 3. Entry points & trust boundaries\n\n"
          "Detected ~2 framework routes: GET /a\n\n"
          "| entry_point | description | trust_boundary | reachable_assets |\n"
          "|---|---|---|---|\n"
          "| ghost input | `ghost/missing.py` parses | untrusted → app | X |\n")
    fv = th.verify_threat(str(tmp_path), md, ["app.py"],
                          [{"id": "routes", "snippet": "GET /a"}])
    assert any("ghost/missing.py" in f for f in fv["failures"])
    assert any("stale entry points" in f for f in fv["failures"])
    assert fv["score"] < 100
    assert th.verify_threat(str(tmp_path), "", [], [])["failures"] == ["empty threat model"]


def test_verify_skips_unparseable_counts_and_urls(tmp_path):
    md = ("# T\n\n## 3. Entry points & trust boundaries\n\n"
          "Several routes, see https://x.\n\n"
          "| entry_point | description | trust_boundary | reachable_assets |\n"
          "|---|---|---|---|\n"
          "| webhook | `https://example.com/hook` inbound | untrusted → app | X |\n")
    fv = th.verify_threat(str(tmp_path), md, [], [{"id": "routes", "snippet": "GET /a"}])
    assert fv == {"score": 100, "failures": []}


def test_updater_preserves_owner_and_never_deprioritizes():
    md = _rich_md() + "\n\n## Owner notes (interview 2026-01-01)\n\nSacred owner text\n"
    findings = [
        {"id": "1", "cwe": "CWE-78", "severity": "high", "status": "confirmed",
         "path": "b.py", "start_line": 1, "end_line": 1, "snippet": "s",
         "evidence": "e", "duplicate_of": ""},
        {"id": "2", "cwe": "CWE-352", "severity": "medium", "status": "fp",
         "path": "c.py", "start_line": 1, "end_line": 1, "snippet": "s",
         "evidence": "deprioritized: trusted admin UI", "duplicate_of": ""},
    ]
    once = th.update_threat_with_findings(md, findings, "r")
    assert "Sacred owner text" in once  # owner sections untouched
    assert "CWE-78 x1" in once
    assert "Consider adding a threat row for: CWE-78" in once
    assert "Deprioritized" in once and "trusted admin UI" in once  # fp history only
    twice = th.update_threat_with_findings(once, findings, "r")
    assert twice.count("## Observed findings") == 1
    assert twice.count("## Scope proposals") == 1
    assert "Sacred owner text" in twice


def test_update_subcommand_and_verify_subcommand(tmp_path):
    import argparse

    from cerberus.cli import cmd_threat_model
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "app.py").write_text("x=1")
    (repo / ".cerberus").mkdir()
    (repo / ".cerberus" / "THREAT_MODEL.md").write_text(
        th.bootstrap_threat(str(repo), ["app.py"], [], "s"))
    fj = tmp_path / "findings.json"
    fj.write_text(json.dumps([
        {"id": "1", "cwe": "CWE-78", "severity": "high", "status": "confirmed",
         "path": "app.py", "start_line": 1, "end_line": 1, "snippet": "s",
         "evidence": "e", "duplicate_of": ""}]))
    rc = cmd_threat_model(argparse.Namespace(repo=str(repo), out=None,
                                             interview=False, verify=False,
                                             update_from=str(fj), vulns=None))
    assert rc == 0
    text = (repo / ".cerberus" / "THREAT_MODEL.md").read_text()
    assert "Scope proposals" in text and "CWE-78" in text
    rc = cmd_threat_model(argparse.Namespace(repo=str(repo), out=None,
                                             interview=False, verify=True,
                                             update_from=None, vulns=None))
    assert rc == 0


def test_persist_never_stacks_headers(tmp_path):
    once = th.persist_threat(str(tmp_path), "# doc")
    text = Path(once).read_text()
    assert text.count("machine-managed") == 1
    # Reload + re-persist (what a scan with a cache does): still one header.
    twice = th.persist_threat(str(tmp_path), text)
    assert Path(twice).read_text().count("machine-managed") == 1


def test_vulns_invalidate_machine_cache(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    (tmp_path / ".cerberus").mkdir()
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text(
        "CACHED-MODEL without the evidence base")
    monkeypatch.setenv("THREAT_LLM", "1")
    calls = _fake_run_structured(monkeypatch, research=_research_payload(),
                                 history=_history_payload(), plan=_plan_payload())
    vulns_file = tmp_path / "past.csv"
    vulns_file.write_text("id,title,component,description\n"
                          "CVE-2026-1,sqli,login,interpolated\n")
    out = threat_model_node({"repo": str(tmp_path), "files": ["app.py"],
                             "candidates": _cands(),
                             "vulns_file": str(vulns_file)})
    assert "CACHED-MODEL" not in out["threat_model_md"]
    assert "supplied via --vulns (1 rows" in out["threat_model_md"]
    assert out["threat_model_source"] == "bootstrap"
    # A SCHEMA-VALID cache is authoritative again without --vulns.
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text(
        th.bootstrap_threat(str(tmp_path), ["app.py"], _cands(), "s"))
    out2 = threat_model_node({"repo": str(tmp_path), "files": ["app.py"],
                              "candidates": _cands()})
    assert out2["threat_model_source"] == "repo-cache"
    # ...but an old-schema cache is rebuilt, never fed to consumers.
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text(
        "# old\n\n## In-scope classes\n\nsqli-cursor, shell-true\n")
    out3 = threat_model_node({"repo": str(tmp_path), "files": ["app.py"],
                              "candidates": _cands()})
    assert out3["threat_model_source"] == "bootstrap"
    assert "In-scope classes" not in out3["threat_model_md"]


# --- Tests covering fixes for Issues 3, 4, 5, 7, and 8 ----------------------

def test_find_repo_file_symlink_traversal_prevention(tmp_path):
    """Issue 3: find_repo_file prevents symlink traversal."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret_tm = outside / "THREAT_MODEL.md"
    secret_tm.write_text("# Outside sacred threat model")

    repo = tmp_path / "repo"
    repo.mkdir()

    # Case 1: Owner file is a symlink pointing outside the repo
    owner_symlink = repo / "THREAT_MODEL.md"
    owner_symlink.symlink_to(secret_tm)
    assert th.find_repo_file(str(repo)) is None

    # Case 2: Machine cache in .cerberus is a symlink pointing outside the repo
    owner_symlink.unlink()
    cerberus_dir = repo / ".cerberus"
    cerberus_dir.mkdir()
    cache_symlink = cerberus_dir / "THREAT_MODEL.md"
    cache_symlink.symlink_to(secret_tm)
    assert th.find_repo_file(str(repo)) is None

    # Case 3: Legitimate file inside repo resolves fine
    cache_symlink.unlink()
    real_tm = repo / "THREAT_MODEL.md"
    real_tm.write_text("# Legitimate in-repo threat model")
    assert th.find_repo_file(str(repo)) == real_tm


def test_persist_threat_symlink_traversal_prevention(tmp_path):
    """Issue 3: persist_threat refuses to write through symlinks."""
    # Case 1: .cerberus directory is a symlink pointing outside the repo
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    outside_cache = tmp_path / "outside_cache"
    outside_cache.mkdir()

    (repo1 / ".cerberus").symlink_to(outside_cache)
    written = th.persist_threat(str(repo1), "# Fresh threat content")
    assert written == ""
    assert list(outside_cache.iterdir()) == []

    # Case 2: .cerberus/THREAT_MODEL.md is a symlink pointing outside the repo
    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / ".cerberus").mkdir()
    outside_file = tmp_path / "outside_target.txt"
    outside_file.write_text("Original uncorrupted content")

    (repo2 / ".cerberus" / "THREAT_MODEL.md").symlink_to(outside_file)
    written2 = th.persist_threat(str(repo2), "# Fresh threat content")
    assert written2 == ""
    assert outside_file.read_text() == "Original uncorrupted content"


def test_section_line_anchored_regex_survives_inline_heading_mentions():
    """Issue 4: _section line-anchored regex survives inline heading mentions without losing threat tables."""
    doc = (
        "# Threat Model: test\n\n"
        "## 1. System context\n\n"
        "Our architecture is robust. As noted in ## 4. Threats earlier, login has flaws.\n"
        "Also see ## 5. Deprioritized for skipped items.\n\n"
        "## 4. Threats\n\n"
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| T1 | SQL Injection | remote_unauth | HTTP | PII | critical | likely | unmitigated | none | app.py:10 |\n\n"
        "## 5. Deprioritized\n\n"
        "| threat | reason |\n"
        "|---|---|\n"
        "| Repudiation | lack of logs |\n"
    )

    sec4 = th._section(doc, "4. Threats")
    assert "| T1 | SQL Injection |" in sec4
    assert "login has flaws" not in sec4  # did not capture the inline mention in section 1

    rows = th._parse_threats(doc)
    assert len(rows) == 1
    assert rows[0]["id"] == "T1"
    assert rows[0]["threat"] == "SQL Injection"


def test_replace_section_line_anchored_regex_survives_inline_heading_mentions():
    """Issue 4: _replace_section line-anchored regex replaces only headings and preserves inline mentions."""
    doc = (
        "# Threat Model: test\n\n"
        "## 1. System context\n\n"
        "We discuss ## Observed findings in documentation, but do not replace this.\n\n"
        "## Observed findings\n\n"
        "Old scan findings.\n\n"
        "## 2. Assets\n\n"
        "PII\n"
    )

    new_section = "## Observed findings\n\nNew verified findings: CWE-89 x2"
    replaced = th._replace_section(doc, "Observed findings", new_section)

    assert "We discuss ## Observed findings in documentation, but do not replace this." in replaced
    assert "New verified findings: CWE-89 x2" in replaced
    assert "Old scan findings" not in replaced
    assert "## 2. Assets\n\nPII" in replaced

    # Deleting section preserves inline mentions too
    deleted = th._replace_section(doc, "Observed findings", "")
    assert "We discuss ## Observed findings in documentation, but do not replace this." in deleted
    assert "Old scan findings" not in deleted
    assert "## 2. Assets" in deleted


def test_rank_table_case_insensitive_enum_sorting():
    """Issue 5: _rank_table case-insensitive enum sorting (CRITICAL before low).

    Normalization happens before validation, ranking AND rendering: a
    mixed-case cell must both sort into the right rank and render as a
    closed-set value the quality gate will not flag."""
    rows = [
        {"threat": "Low threat", "impact": "low", "likelihood": "rare",
         "actor": "remote_unauth", "surface": "s", "asset": "as", "status": "unmitigated", "controls": "", "evidence": ""},
        {"threat": "Critical threat", "impact": "CRITICAL", "likelihood": "LIKELY",
         "actor": "Remote_Unauth", "surface": "s", "asset": "as", "status": "Unmitigated", "controls": "", "evidence": ""},
        {"threat": "High threat", "impact": "High", "likelihood": "Possible",
         "actor": "remote_unauth", "surface": "s", "asset": "as", "status": "unmitigated", "controls": "", "evidence": ""},
        {"threat": "Medium threat", "impact": "mEdIuM", "likelihood": "almost_certain",
         "actor": "remote_unauth", "surface": "s", "asset": "as", "status": "unmitigated", "controls": "", "evidence": ""},
    ]

    table_md, id_by_pos, dropped = th._rank_threats(rows)
    parsed = th._parse_threats("# T\n\n## 4. Threats\n\n" + table_md)

    assert [r["id"] for r in parsed] == ["T1", "T2", "T3", "T4"]
    assert parsed[0]["threat"] == "Critical threat"
    assert parsed[1]["threat"] == "High threat"
    assert parsed[2]["threat"] == "Medium threat"
    assert parsed[3]["threat"] == "Low threat"
    assert dropped == []
    # ids map back to INPUT positions (T2 is the input's critical row)
    assert id_by_pos == {1: "T4", 2: "T1", 3: "T2", 4: "T3"}
    # ...and the rendered cells are normalized into the closed enums
    assert parsed[0]["impact"] == "critical"
    assert parsed[0]["actor"] == "remote_unauth"
    assert parsed[0]["status"] == "unmitigated"
    # the quality gate must not flag what normalization already fixed
    q = th.threat_quality("# T\n\n## 4. Threats\n\n" + table_md, [], [])
    assert not any("outside the closed enums" in g for g in q["gaps"])



def test_backticked_paths_skips_properties_and_routes():
    """Issue 7: _backticked_paths skips properties like req.body, user.id and routes like /api/..."""
    text = (
        "Properties like `req.body` and `user.id` or `res.status_code` are not paths. "
        "Neither are routes like `/api/v1/auth`, `/users/list`, `/login`, or url `https://example.com/api`. "
        "Function calls like `app.run()` or `do_work()` must be ignored. "
        "Valid files: `app.py`, `src/utils.py`, `Dockerfile`, `package.json`, `config/settings.yaml`."
    )
    paths = th._backticked_paths(text)

    # Excluded properties, routes, methods, and URLs
    for excluded in ("req.body", "user.id", "res.status_code",
                     "/api/v1/auth", "/users/list", "/login",
                     "https://example.com/api", "app.run()", "do_work()"):
        assert excluded not in paths, f"{excluded} should have been skipped by _backticked_paths"

    # Included file references
    for included in ("app.py", "src/utils.py", "Dockerfile", "package.json", "config/settings.yaml"):
        assert included in paths, f"{included} should have been kept by _backticked_paths"


def test_verify_threat_exists_rejects_ghost_paths(tmp_path):
    """Issue 7: verify_threat rejects ghost paths like fake/dir/app.py."""
    (tmp_path / "real.py").write_text("x = 1")

    md = (
        "# Threat Model\n\n"
        "## 3. Entry points & trust boundaries\n\n"
        "Legitimate file `real.py` handles input.\n"
        "Ghost path `fake/dir/app.py` and nonexistent `missing.py` parse payloads.\n\n"
        "## 4. Threats\n\n"
        "| id | threat |\n|---|---|\n| T1 | x |\n"
    )

    res = th.verify_threat(str(tmp_path), md, files=["real.py"])
    assert res["score"] < 100
    assert any("fake/dir/app.py" in f for f in res["failures"])
    assert any("missing.py" in f for f in res["failures"])
    assert not any("real.py" in f for f in res["failures"])


def test_bound_json_and_swarm_plan_valid_json_output(monkeypatch):
    """Issue 8: _swarm_plan valid JSON output (no truncated syntax) via _bound_json."""
    # 1. Direct check on _bound_json producing valid JSON even on large data structures
    large_data = {
        "entry_points": [
            {"entry_point": f"route_{i}", "description": "detail " * 100,
             "file_refs": [f"f_{i}.py"]} for i in range(50)
        ],
        "assets": [
            {"asset": f"asset_{i}", "description": "asset info " * 100,
             "sensitivity": "high"} for i in range(50)
        ]
    }

    bounded = th._bound_json(large_data, max_len=3000)
    assert len(bounded) <= 3000
    # Must be valid JSON (does not raise json.JSONDecodeError)
    parsed_bounded = json.loads(bounded)
    assert isinstance(parsed_bounded, dict)
    assert "entry_points" in parsed_bounded

    # 2. _swarm_plan passes valid JSON to the planner prompt
    captured_tasks = []

    def _mock_run_structured(cfg, schema, system, human):
        captured_tasks.append(human)
        from cerberus.prompts.threat import SwarmPlan
        return SwarmPlan(
            context_prose="Flask shop",
            entry_points=[{"entry_point": "GET /login", "description": "d",
                           "trust_boundary": "b", "file_refs": ["app.py"]}],
            assets=[{"asset": "PII", "description": "d", "sensitivity": "high"}],
            threats=[],
            deprioritized=[],
            open_questions=[],
            mitigations=[]
        )

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured",
                        _mock_run_structured)

    plan = th._swarm_plan("repo", "draft", large_data, large_data, {})
    assert captured_tasks
    task_prompt = captured_tasks[0]

    # The planner prompt must carry the research returns as JSON payloads,
    # verbatim — decoded independent of the brief's wording (no section-header
    # splitting): scan for every embedded JSON object and require the surface
    # payloads to survive the size cap inside them.
    dec = json.JSONDecoder()
    embedded: list[dict] = []
    i = task_prompt.find("{")
    while i != -1:
        try:
            obj, end = dec.raw_decode(task_prompt, i)
        except ValueError:
            obj, end = None, i + 1
        if isinstance(obj, dict):
            embedded.append(obj)
            i = task_prompt.find("{", end)
        else:
            i = task_prompt.find("{", i + 1)
    surfaces = [o for o in embedded if "entry_points" in o]
    assert len(surfaces) >= 2, (   # the research AND history returns, both embedded
        "planner prompt no longer embeds the research returns as JSON",
        len(surfaces), len(task_prompt))
    decoded_research = surfaces[0]
    assert decoded_research["entry_points"]

    # And plan itself is serializable to valid JSON
    dumped_plan = json.dumps(plan)
    assert json.loads(dumped_plan)["context_prose"] == "Flask shop"


def test_bug_shapes_never_cached_across_scans(tmp_path):
    """A process-wide cache keyed by (root, limit) made a second scan in the
    same process see STALE fix history — enrichment's contract is freshness
    on every run, so _bug_shapes must re-read git each call."""
    import subprocess
    r = str(tmp_path)
    subprocess.run(["git", "init", "-q", r], check=True)
    subprocess.run(["git", "-C", r, "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", r, "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", r, "config", "commit.gpgsign", "false"], check=True)
    (tmp_path / "service.py").write_text("code = 1")
    subprocess.run(["git", "-C", r, "add", "."], check=True)
    subprocess.run(["git", "-C", r, "commit", "-qm", "fix injection in service"], check=True)

    first = th._bug_shapes(r)
    assert "injection" in first and "[touched: service.py]" in first

    (tmp_path / "auth.py").write_text("x = 2")
    subprocess.run(["git", "-C", r, "add", "."], check=True)
    subprocess.run(["git", "-C", r, "commit", "-qm", "fix security hole in auth"], check=True)

    second = th._bug_shapes(r)
    assert "security hole" in second and "auth.py" in second, second




# --- adversarial-verifier regressions ---------------------------------------

def test_validate_rejects_duplicated_section_headings():
    md = ("# T\n\n## 4. Threats\n\n| id |\n|---|---|\n| T1 |\n\n"
          "## 4. Threats\n\n| id |\n|---|---|\n| T2 |\n")
    fails = th.validate_threat_md(md)
    assert any("more than once" in f for f in fails)


def test_threat_ids_resolve_to_named_rows_after_ranking():
    from cerberus.prompts.threat import SwarmThreat
    plan = {"threats": [
        SwarmThreat(threat="DoS", actor="remote_unauth", surface="s",
                    asset="a", impact="medium", likelihood="possible",
                    status="unmitigated").model_dump(),
        SwarmThreat(threat="RCE", actor="remote_unauth", surface="s",
                    asset="a", impact="critical", likelihood="likely",
                    status="unmitigated").model_dump(),
    ],
        "mitigations": [{"mitigation": "size-cap allocations",
                         "threat_numbers": [2], "closes_class": "yes",
                         "effort": "S"}]}
    md, _ = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"},
                           plan)
    rows = {r["id"]: r["threat"] for r in th._parse_threats(md)}
    assert rows == {"T1": "RCE", "T2": "DoS"}  # ranked by impact
    mits = th._section(md, "8. Recommended mitigations")
    assert "| size-cap allocations | T1 |" in mits, mits  # position 2 == RCE


def test_tie_broken_by_threat_text_ids_stable():
    a = {"threat": "Alpha XSS", "actor": "remote_unauth", "surface": "s",
         "asset": "a", "impact": "high", "likelihood": "possible",
         "status": "unmitigated"}
    b = {"threat": "Beta CSRF", "actor": "remote_unauth", "surface": "s",
         "asset": "a", "impact": "high", "likelihood": "possible",
         "status": "unmitigated"}
    t1, ids1, _ = th._rank_threats([dict(a), dict(b)])
    t2, ids2, _ = th._rank_threats([dict(b), dict(a)])
    assert t1 == t2 and ids1 != ids2  # same document, remapped positions


def test_surface_collision_keeps_code_owned_cells():
    blocks = {"ep_skeleton":
              "| entry_point | description | trust_boundary | reachable_assets |\n"
              "|---|---|---|---|\n"
              "| HTTP request handlers (1 routes detected) | reaches application code | "
              "untrusted input → application logic | unknown — owner to confirm |\n\n"
              "Detected ~1 framework routes: GET /a\n\n"
              "Trust defaults (deterministic): x",
              "context_facts": "F"}
    plan = {"entry_points": [{"entry_point": "HTTP request handlers (1 routes detected)",
                              "description": "", "trust_boundary": "",
                              "file_refs": ["app.py:1"]}]}
    md, _ = th._merge_plan("r", blocks, plan)
    ep = th._parse_entry_points(md)
    assert len(ep) == 1  # no duplicate row
    assert ep[0]["description"] == "reaches application code [refs: `app.py:1`]"
    assert ep[0]["trust_boundary"] == "untrusted input → application logic"


def test_llm_cells_are_capped_and_headings_stripped():
    huge = "x" * 5000
    plan = {"threats": [{"threat": "T " + huge, "actor": "remote_unauth",
                         "surface": "s", "asset": "a", "impact": "high",
                         "likelihood": "possible", "status": "unmitigated",
                         "controls": huge, "evidence": huge}]}
    md, _ = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"}, plan)
    rows = th._parse_threats(md)
    assert len(rows) == 1  # the row survives, only its cells are clipped
    assert len(rows[0]["threat"]) <= th.CELL_CAP + 1
    assert len(rows[0]["controls"]) <= th.CELL_CAP
    assert len(md) < 20000


def test_row_caps_bound_a_hostile_plan():
    plan = {"threats": [{"threat": f"T{i}", "actor": "remote_unauth",
                         "surface": "s", "asset": "a", "impact": "low",
                         "likelihood": "rare", "status": "unmitigated"}
                        for i in range(500)]}
    md, _ = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"}, plan)
    assert len(th._parse_threats(md)) == th.ROW_CAPS["threats"]


def test_sensitivity_enum_defaulted_and_recorded():
    plan = {"assets": [{"asset": "keys", "description": "d",
                        "sensitivity": "APOCALYPTIC"}]}
    md, meta = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"}, plan)
    assert "APOCALYPTIC" not in md
    assert "| keys | d | medium |" in md
    assert any("sensitivity=apocalyptic" in d for d in meta["dropped"])


def test_parse_vulns_strips_bom(tmp_path):
    bom = tmp_path / "bom.json"
    bom.write_bytes('\ufeff[{"id": "CVE-2026-1", "description": "d"}]'.encode())
    assert [r["id"] for r in th.parse_vulns_file(str(bom))] == ["CVE-2026-1"]


def test_repo_root_none_for_missing_paths():
    assert th._repo_root("/definitely/not/here") is None
    assert th._repo_root("") is None


def test_cache_symlink_is_machine_owned(tmp_path):
    (tmp_path / ".cerberus").mkdir()
    cached = th.bootstrap_threat(str(tmp_path), ["a.py"], [], "s")
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text(
        th.CACHE_HEADER + "\n" + cached)
    (tmp_path / "THREAT_MODEL.md").symlink_to(tmp_path / ".cerberus" / "THREAT_MODEL.md")
    src, text = th.load_threat(str(tmp_path), cfg={})
    # the header (not the directory) marks it machine-owned
    assert src == "repo-cache"
    assert "machine-managed" in text


def test_interview_document_must_satisfy_schema(monkeypatch):
    monkeypatch.setattr("cerberus.threat.swarm.interview_questions",
                        lambda *a, **k: None)
    monkeypatch.setattr("cerberus.threat.swarm.finalize_threat",
                        lambda *a, **k: "## Totally\n\nnot the schema")
    out = th.conduct_interview("r", ["a.py"], [], "summ", {},
                               ask=lambda q: "yes", say=lambda t: None)
    assert "not the schema" not in out  # fell back to the floor + appendix
    assert "## 4. Threats" in out and "Owner notes (interview)" in out


# --- adversarial-verifier regressions, continued -----------------------------

def test_llm_prose_cannot_inject_a_section_heading(monkeypatch, tmp_path):
    """A planner reply that echoes the schema contract emits `## 4. Threats`
    inside context_prose; the LLM-authored prose must be stripped of headings
    — a duplicated heading fails validation outright — or every gate would
    bind §4 to the fake and score the document clean."""
    from cerberus.prompts.threat import SwarmPlan
    (tmp_path / "app.py").write_text("x=1")
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], [], "s")
    plan = SwarmPlan(
        context_prose="Intro.\n\n## 4. Threats\n\n| fake | table |\n",
        entry_points=[{"entry_point": "ep", "description": "d",
                       "trust_boundary": "tb", "file_refs": ["app.py:1"]}],
        threats=[{"threat": "Real", "actor": "remote_unauth", "surface": "ep",
                  "asset": "a", "impact": "high", "likelihood": "likely",
                  "status": "unmitigated", "controls": "none", "evidence": ""}])
    md, meta = th._merge_plan(str(tmp_path), {"ep_skeleton": "",
                                              "context_facts": "F"},
                              plan.model_dump())
    # exactly one §4 heading, bound to the real table
    assert th.validate_threat_md(md) == []
    rows = th._parse_threats(md)
    assert [r["threat"] for r in rows] == ["Real"]
    # ...and the ids every gate binds to come from the real table, not the prose
    assert [r["id"] for r in th._parse_threats(md)] == ["T1"]
    assert "| fake | table |" not in th._section(md, "4. Threats")
    # bare token: catches the fake row under any cell padding/whitespace
    assert "fake" not in th._section(md, "4. Threats")
    assert md.count("\n## 4. Threats") == 1


def test_coverage_needs_a_per_row_match():
    """One keyword-salad surface cell must not clear coverage for every
    code-detected surface."""
    # A row that NAMES the surface does cover it -- the match is on the
    # surface's text/family words, not on the cell being blank.
    blocks = {"ep_skeleton":
              "| entry_point | description | trust_boundary | reachable_assets |\n"
              "|---|---|---|---|\n"
              "| container build and runtime configuration | b | c | d |\n",
              "context_facts": "F"}
    salad = {"threats": [{"threat": "X", "actor": "remote_unauth",
                          "surface": "container docker image build ci workflow "
                          "pipeline action http route endpoint config",
                          "asset": "a", "impact": "high",
                          "likelihood": "possible", "status": "unmitigated"}]}
    md, _ = th._merge_plan("r", blocks, salad)
    assert th._coverage_gaps(md) == []
    md2, _ = th._merge_plan("r", blocks, {"threats": [dict(
        salad["threats"][0], surface="something else entirely")]})
    assert any("container build" in g for g in th._coverage_gaps(md2))
    # ...and covering ONE surface clears only that surface: every other
    # code-detected surface still has to be named by some row.
    md3 = ("# T\n\n## 3. Entry points & trust boundaries\n\n"
           "| entry_point | description | trust_boundary | reachable_assets |\n"
           "|---|---|---|---|\n"
           "| HTTP request handlers (1 routes detected) | d | tb | a |\n"
           "| container build and runtime configuration | d | tb | a |\n\n"
           "## 4. Threats\n\n| id | threat | actor | surface | asset | impact "
           "| likelihood | status | controls | evidence |\n"
           "|---|---|---|---|---|---|---|---|---|---|\n"
           "| T1 | t | remote_unauth | http route endpoint | a | high | "
           "likely | unmitigated | none | |\n")
    gaps = th._coverage_gaps(md3)
    assert any("container build" in g for g in gaps), gaps


def test_machine_sections_survive_reenrichment():
    """A re-enrichment (_merge_plan over a draft that already carries scan
    history) must keep the machine-owned sections and land each count in the
    section that owns it -- the merge boundary is where they used to be wiped."""
    draft = th.bootstrap_threat("r", ["a.py"], [], "s")
    with_findings = th.update_threat_with_findings(draft, [
        {"id": "1", "cwe": "CWE-89", "severity": "high", "status": "confirmed",
         "path": "a.py", "duplicate_of": ""},
        {"id": "2", "cwe": "CWE-89", "severity": "high", "status": "fp",
         "path": "a.py", "duplicate_of": "",
         "evidence": "parameterized query"},
    ], "r")
    plan = {"threats": [{"threat": "X", "actor": "remote_unauth",
                         "surface": "s", "asset": "a", "impact": "high",
                         "likelihood": "likely", "status": "unmitigated",
                         "controls": "", "evidence": ""}]}
    md, _ = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"},
                           plan, draft=with_findings)
    # institutional memory carried, not wiped: confirmed counts, proposals and
    # the disproven-scan log all survive the merge.
    assert "Known false positives" in md
    for sec in ("Observed findings", "Scope proposals"):
        assert f"## {sec}" in md, sec
    assert "CWE-89 x1" in th._section(md, "Observed findings")


def test_old_schema_cache_is_dropped(tmp_path):
    (tmp_path / ".cerberus").mkdir()
    (tmp_path / ".cerberus" / "THREAT_MODEL.md").write_text(
        "# T\n\n## In-scope classes\n\nsqli-cursor, shell-true\n")
    assert th.load_threat(str(tmp_path), cfg={}) == ("none", "")


def test_replace_section_spares_owner_qualified_heading():
    """An owner heading that merely STARTS with the machine section's name is
    never matched: only the exact `## Scope proposals` heading is replaced."""
    base = ("## 5. Deprioritized\n\nmachine text\n\n"
            "## Scope proposals (Q3 planning)\n\nAdd mTLS\nDecommission SSH\n\n"
            "## Scope proposals\n\nstale machine row\n\n"
            "## Owner notes\n\nkeep\n")
    out = th._replace_section(base, "Scope proposals",
                              "## Scope proposals\n\nMACHINE\n")
    assert "Add mTLS" in out and "Decommission SSH" in out
    assert "MACHINE" in out and "stale machine row" not in out
    assert "machine text" in out and "keep" in out  # untouched neighbours


def test_replace_section_ignores_fenced_headings():
    md = ("## 1. System context\n\nProtocol:\n\n```\n## Observed findings\n"
          "never touch\n```\n\nend\n")
    out = th._replace_section(md, "Observed findings", "")
    assert "never touch" in out and out.count("```") == 2


def test_vulns_file_guards_non_regular_paths(tmp_path):
    import os
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert th.parse_vulns_file(str(fifo)) == []  # would hang unbounded
    big = tmp_path / "big.json"
    big.write_text("[" * (th.VULNS_BYTES_CAP + 10))
    assert th.parse_vulns_file(str(big)) == []
    assert th.parse_vulns_file(str(tmp_path)) == []  # directory


def test_vulns_markdown_skips_fenced_headings(tmp_path):
    p = tmp_path / "v.md"
    p.write_text("# Report\n\n## Finding A\n\nbody\n\n```\n## Not a finding\n"
                 "```\n\n## Finding B\n\nbody2\n")
    rows = th.parse_vulns_file(str(p))
    assert [r["id"] for r in rows] == ["md-1", "md-2"]
    assert "Not a finding" not in " ".join(r["title"] for r in rows)


def test_huge_threat_number_does_not_kill_the_document():
    plan = {"threats": [{"threat": "X", "actor": "remote_unauth",
                         "surface": "s", "asset": "a", "impact": "high",
                         "likelihood": "likely", "status": "unmitigated",
                         "controls": "", "evidence": ""}],
            "mitigations": [{"mitigation": "M", "threat_numbers": ["9" * 4400],
                             "closes_class": "yes", "effort": "S"}]}
    md, meta = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"}, plan)
    assert "| X |" in th._section(md, "4. Threats")
    assert any("no resolvable threat_ids" in d for d in meta["dropped"])


def test_node_survives_non_list_state(monkeypatch, tmp_path):
    """A state whose files/candidates arrive as something other than a list
    must degrade to the deterministic floor: the node's fail-open contract is
    that it never raises and always returns a usable document."""
    monkeypatch.setenv("THREAT_LLM", "0")
    out = threat_model_node({"repo": str(tmp_path), "files": None,
                             "candidates": None})
    assert out["threat_model_source"] == "bootstrap"
    assert "## 4. Threats" in out["threat_model_md"]  # a usable document
    assert out["threat_quality"]["threat_rows"] == 0  # honestly flagged floor


def test_update_threat_maps_findings_to_section4_and_adds_novel_rows():
    md = _rich_md()
    findings = [
        # 1. Matches existing T1 (SQLi in login):
        {"id": "claim-1", "cwe": "CWE-89", "severity": "critical", "status": "confirmed",
         "path": "auth/login.py", "start_line": 42, "title": "SQL Injection via username parameter",
         "duplicate_of": ""},
        # 2. Novel finding (Mass Assignment - CWE-915):
        {"id": "claim-2", "cwe": "CWE-915", "severity": "high", "status": "confirmed",
         "path": "controllers/users.js", "start_line": 245, "title": "Mass assignment admin via XML import",
         "duplicate_of": ""},
        # 3. Novel finding (JWT none algorithm - CWE-347):
        {"id": "claim-3", "cwe": "CWE-347", "severity": "critical", "status": "confirmed",
         "path": "app.js", "start_line": 56, "title": "JWT none algorithm accepted in token validation",
         "duplicate_of": ""}
    ]
    updated = th.update_threat_with_findings(md, findings, "demo_repo")

    threats = th._parse_threats(updated)
    assert len(threats) >= 4  # T1, T2 + at least 2 novel threats

    # Check T1 was updated with concrete evidence and unmitigated status
    t1 = next(t for t in threats if t["id"] == "T1")
    assert "auth/login.py:42" in t1["evidence"]
    assert "SQL Injection via username parameter" in t1["evidence"]
    assert t1["status"] == "unmitigated"
    assert t1["likelihood"] == "almost_certain"

    # Check novel threats were added
    t_mass = next(t for t in threats if "mass assignment" in t["threat"].lower())
    assert "controllers/users.js:245" in t_mass["evidence"]
    assert t_mass["status"] == "unmitigated"
    assert t_mass["likelihood"] == "almost_certain"

    t_jwt = next(t for t in threats if "jwt" in t["threat"].lower())
    assert "app.js:56" in t_jwt["evidence"]
    assert t_jwt["status"] == "unmitigated"
    assert t_jwt["impact"] == "critical"


def test_section3_formatting_and_route_presentation(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    candidates = [
        {"id": "routes", "snippet": "routes/users.py:10: [route] POST /api/users -> create_user\n"
                                    "routes/users.py:20: [route] GET /api/users -> list_users\n"
                                    "routes/users.py:10: [route] POST /api/users -> create_user\n"},  # duplicate
        {"id": "manifest", "snippet": "requirements.txt: flask==2.0.1"},
    ]
    md = th.bootstrap_threat(str(tmp_path), ["app.py", "requirements.txt", "Dockerfile"], candidates)

    sec3 = th._section(md, "3. Entry points & trust boundaries")
    assert "### Key Detected Endpoints" in sec3
    assert "*Detected ~3 framework routes:*" in sec3
    assert "- `POST /api/users` (`routes/users.py:10`)" in sec3
    assert "- `GET /api/users` (`routes/users.py:20`)" in sec3
    assert "### Trust Boundaries & Assumptions" in sec3
    assert "Trust defaults (deterministic):" in sec3
    assert "- **UNTRUSTED**:" in sec3
    assert "- **TRUSTED (by default)**:" in sec3

    # Table rows should have rich context-aware cells
    eps = th._parse_entry_points(md)
    assert len(eps) >= 2
    http_ep = next(e for e in eps if "http" in e["entry_point"].lower())
    assert "Web and REST API endpoints (~3 routes detected)" in http_ep["description"]
    assert "untrusted network / client → application logic" in http_ep["trust_boundary"]
    assert "application data, session state, process integrity" in http_ep["reachable_assets"]

    # Quality check
    q = th.threat_quality(md, ["app.py", "requirements.txt", "Dockerfile"], candidates)
    assert not any("entry points" in g for g in q["gaps"])
    fv = th.verify_threat(str(tmp_path), md, ["app.py", "requirements.txt", "Dockerfile"], candidates)
    assert not any("stale entry points" in f for f in fv["failures"])
