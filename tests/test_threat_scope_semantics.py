"""Threat scope must be derived from the repo's own surfaces, never from the
prefilter's detector rule names.

The old bootstrap copied regex-prefilter rule IDs (sqli-cursor, shell-true, ...)
into the in-scope section, and the quality gates rewarded copying them. Hunters
read that as a filter, so any vulnerability class without a matching regex rule
-- ReDoS was the largest bucket at 16 labels -- looked out of scope.

Under the reference 8-section schema the same failure mode reappears if threat
rows are filled from detector coverage or if Deprioritized reads as a filter:
detector rule names are coverage (section 1), scope comes from the repo's
surfaces (section 3), and section 5 must state that a threat model
prioritizes and never excludes.
"""
import cerberus.threat as th


def _cands(**snippets):
    return [{"id": k, "snippet": v} for k, v in snippets.items()]


def test_threat_rows_have_no_detector_rule_names():
    cands = _cands(prefilter="## sqli-cursor\n## shell-true\nplain prose line",
                   routes="GET /login\nPOST /submit",
                   manifest="pyproject.toml")
    # Only the prefilter's `## ` headings are signal; prose lines are not.
    assert th._detector_signals(cands) == ["sqli-cursor", "shell-true"]
    md = th.bootstrap_threat(".", ["a.py", ".github/ci.yml"], cands, "s")
    assert th._parse_threats(md) == []  # floor carries no threat rows at all
    # The information survives, but as coverage in section 1.
    assert "sqli-cursor" in th._section(md, "1. System context")
    assert "sqli-cursor" not in th._section(md, "4. Threats")


def test_entry_points_derived_from_this_repo_surfaces():
    cands = _cands(routes="GET /a\nGET /b\nGET /c")
    files = ["app/routes.py", "Dockerfile", "tpl/page.html.j2", "conf/settings.yaml"]
    surfaces = th._attack_surfaces(cands, files)
    joined = " ".join(surfaces).lower()
    assert "http request handlers (3 routes" in joined
    assert "container build" in joined
    assert "template rendering" in joined
    assert "configuration" in joined
    # Surfaces, never bug types.
    for bug in ("sqli", "xss", "injection", "redos", "ssrf"):
        assert bug not in joined
    # The floor's section 3 is built from those surfaces.
    md = th.bootstrap_threat(".", files, cands, "s")
    eps = th._parse_entry_points(md)
    assert len(eps) == len(surfaces)


def test_deprioritized_states_prioritization_never_excludes():
    cands = _cands(routes="GET /a")
    md = th.bootstrap_threat(".", ["a.py"], cands, "s")
    dep = th._section(md, "5. Deprioritized")
    assert th._SCOPE_SEMANTICS_RE.search(dep), dep


def test_quality_gate_rewards_non_exclusion_semantics():
    cands = _cands(prefilter="## sqli-cursor", routes="GET /a")
    good = th.bootstrap_threat(".", ["a.py"], cands, "s")
    assert not any("Deprioritized" in g for g in th.threat_quality(good, ["a.py"], cands)["gaps"])
    # A deprioritized section that reads as a bare filter is flagged.
    bare = good.replace(th._section(good, "5. Deprioritized"), "sqli-cursor is out of scope")
    gaps = th.threat_quality(bare, ["a.py"], cands)["gaps"]
    assert any("prioritizes" in g for g in gaps)
