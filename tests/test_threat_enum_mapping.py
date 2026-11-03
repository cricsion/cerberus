"""Prose enum cells must be classified, not dropped.

Observed live (realvuln flask repo, step-5-preview-free): the planner wrote
13 threat rows whose actor cells were sentences — "a careless or compromised
maintainer/ci account", "an upstream package maintainer, a compromised
registry, or a lockfile merge" — and `_rank_threats` dropped every one.
The document shipped with an empty §4 while the model had done the work.
Code owns the enum cells, so code classifies the prose.
"""
from cerberus import threat as th

REAL_DROPPED = [
    ("a malicious detector submitting crafted findings, or a careless edit "
     "to the answer set itself", "remote_unauth"),
    ("a jailbroken or over-eager benchmarked llm agent during headless runs",
     "remote_unauth"),
    ("a careless or compromised maintainer/ci account", "insider"),
    ("an upstream package maintainer, a compromised registry, or a lockfile "
     "merge", "supply_chain"),
    ("an authenticated user of the dashboard", "remote_auth"),
    ("a local process with shell access", "local_user"),
    ("an attacker on the same network", "adjacent_network"),
    ("a local administrator on the host", "local_admin"),
]


def test_real_prose_actors_map_to_the_closed_set():
    for prose, expected in REAL_DROPPED:
        got = th._map_row_enums({"actor": prose})["actor"]
        assert got == expected, f"{prose!r} -> {got!r}, wanted {expected!r}"
        assert got in th.ACTORS


def test_unmappable_prose_falls_back_conservatively_and_survives():
    row = th._map_row_enums({"actor": "a committee of owls",
                             "impact": "vibes",
                             "likelihood": "sometimes",
                             "status": "whatever"})
    # err toward more scrutiny, never toward dropping the row
    assert row == {"actor": "remote_unauth", "impact": "medium",
                   "likelihood": "possible", "status": "unmitigated"}


def test_impact_likelihood_status_prose_classified():
    row = th._map_row_enums({"impact": "likely leads to a data breach",
                             "likelihood": "trivial to exploit",
                             "status": "no control in place"})
    assert row["impact"] == "high"
    assert row["likelihood"] == "almost_certain"
    assert row["status"] == "unmitigated"


def test_prose_enum_rows_survive_the_rank_stage_end_to_end():
    """The observed failure: rows written by the model, dropped by validation,
    document shipped with no ranked threats."""
    plan = {"threats": [
        {"threat": "Oracle corruption of the ground-truth answer set",
         "actor": "a malicious detector submitting crafted findings",
         "surface": "ep", "asset": "dataset integrity", "impact": "high",
         "likelihood": "possible", "status": "no control",
         "controls": "", "evidence": ""},
        {"threat": "Supply-chain substitution of pinned dependencies",
         "actor": "an upstream package maintainer or compromised registry",
         "surface": "ep", "asset": "build integrity", "impact": "critical",
         "likelihood": "likely", "status": "unmitigated",
         "controls": "pinned versions", "evidence": "abc1234"},
    ]}
    table, _ids, dropped = th._rank_threats(plan["threats"])
    assert dropped == []
    assert table.count("\n| T") == 2
    md, meta = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"},
                              plan)
    rows = th._parse_threats(md)
    assert len(rows) == 2 and meta["dropped"] == []
    assert rows[0]["actor"] in th.ACTORS
    assert th.validate_threat_md(md) == []


def test_empty_threat_text_is_still_dropped():
    table, _ids, dropped = th._rank_threats([{"threat": "  "}])
    assert "empty" in dropped[0]
    assert "T1" not in table


def test_mitigation_effort_and_closes_class_prose_survive():
    """Observed live: 6 mitigations written by the model, 6 dropped on
    effort='MEDIUM' and closes_class='eliminate interpreter sinks…'."""
    plan = {"threats": [
        {"threat": "SQL injection in login", "actor": "remote_unauth",
         "surface": "ep", "asset": "customer PII", "impact": "critical",
         "likelihood": "likely", "status": "unmitigated", "controls": "none",
         "evidence": ""}],
        "mitigations": [
            {"mitigation": "parameterize every query", "threat_numbers": [1],
             "closes_class": "eliminate interpreter sinks across the app",
             "effort": "MEDIUM"},
            {"mitigation": "harden data handling with allowlists",
             "threat_numbers": [1], "closes_class": "harden data handling",
             "effort": "low effort"},
        ]}
    md, meta = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"},
                              plan)
    s8 = th._section(md, "8. Recommended mitigations")
    assert "| parameterize every query | T1 | yes | M |" in s8
    assert "| harden data handling with allowlists | T1 | partial | S |" in s8
    assert meta["dropped"] == []
    assert th._map_enum_text("garbage", "closes_class") == "partial"
    assert th._map_enum_text("garbage", "effort") == "M"


def test_unresolvable_mitigation_ids_still_dropped():
    plan = {"threats": [
        {"threat": "X", "actor": "remote_unauth", "surface": "s",
         "asset": "a", "impact": "high", "likelihood": "likely",
         "status": "unmitigated", "controls": "", "evidence": ""}],
        "mitigations": [{"mitigation": "m", "threat_numbers": [99],
                         "closes_class": "yes", "effort": "S"}]}
    md, meta = th._merge_plan("r", {"ep_skeleton": "", "context_facts": "F"},
                              plan)
    assert any("no resolvable threat_ids" in d for d in meta["dropped"])
    assert "| m |" not in th._section(md, "8. Recommended mitigations")
