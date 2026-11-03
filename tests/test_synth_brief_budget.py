"""Structural contract for the planner brief (`build_synth_task`).

The schema says threats are CLASS-LEVEL, but the brief used to ask for an
unbounded "generalize every past vuln + STRIDE every entry point" — the ask
where small models die: prose and lists come back filled while `threats` and
`mitigations` come back empty. These tests pin what policy allows: the
code↔code markers the merge code and the rest of the suite split on, and the
*narrow* retry brief being a tightening of the default one. Prompt wording
and the row-budget numbers themselves are not pinned (tests must not pin
prompt text or production constants).

No network, no env, no LLM: pure structural assertions on the brief.
"""
import inspect

import pytest
from cerberus.prompts.threat import THREAT_ROW_BUDGET, THREAT_ROW_BUDGET_NARROW, build_synth_task

# Byte-exact markers other code splits on (tests/test_threat.py cuts the
# research JSON out of the prompt between the first two), plus the
# code-owned canon label.
MEASURED_FACTS = ("MEASURED FACTS (code-owned canon — route counts, stack "
                  "hint, detector coverage; never contradict these):")
RESEARCH_MARKER = ("Research return — surface mapper + asset finder + infra "
                   "reader:")
HISTORY_MARKER = "Research return — history miner"

_RESEARCH = '{"entry_points": [], "assets": []}'
_HISTORY = '{"vulns": []}'


def _brief(**kw):
    return build_synth_task("repo", "draft md", _RESEARCH, _HISTORY,
                            "routes: 3\nstack: python", **kw)


def test_narrow_brief_is_strictly_tighter():
    """`narrow=True` is a tightening of the same brief: shorter, and not a
    different document. Stage/row wording belongs to prod, not to tests."""
    default = _brief()
    narrow = _brief(narrow=True)
    assert narrow != default
    assert len(narrow) < len(default)


def test_markers_survive_both_variants():
    for kw in ({}, {"narrow": True}):
        brief = _brief(**kw)
        for marker in (MEASURED_FACTS, RESEARCH_MARKER, HISTORY_MARKER):
            assert marker in brief, (marker, kw)
        # The research JSON is still splittable out of the prompt the way
        # tests/test_threat.py and the merge code do it.
        part = brief.split(RESEARCH_MARKER + "\n")[1]
        between = part.split("\n\n" + HISTORY_MARKER)[0]
        assert between == _RESEARCH


def test_signature_positional_backcompat_and_narrow_keyword_only():
    # Positional call, 4 args and 5 args, still works.
    assert isinstance(build_synth_task("r", "d", "{}", "{}"), str)
    assert isinstance(build_synth_task("r", "d", "{}", "{}", "facts"), str)
    task = build_synth_task("r", "d", "{}", "{}")
    assert MEASURED_FACTS in task
    # `narrow` cannot be passed positionally — it is keyword-only.
    with pytest.raises(TypeError):
        build_synth_task("r", "d", "{}", "{}", "", True)
    params = inspect.signature(build_synth_task).parameters
    assert params["narrow"].kind is inspect.Parameter.KEYWORD_ONLY
    assert (params["measured_facts"].kind
            is inspect.Parameter.POSITIONAL_OR_KEYWORD)


def test_narrow_row_budget_is_below_the_default():
    # Relational only: the retry brief must ask for strictly fewer rows than
    # the default brief. The numbers themselves live in prod, not here.
    assert THREAT_ROW_BUDGET_NARROW < THREAT_ROW_BUDGET
