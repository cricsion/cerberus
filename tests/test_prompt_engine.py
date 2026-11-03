"""Prompt template engine + template hygiene (cerberus/prompts_templates/).

Contract under test (cerberus/prompts/engine.py):
- every template parses with valid frontmatter (role == directory, module
  importable);
- bodies render byte-preserved, placeholders strict, missing/empty fails
  closed;
- the composed builders never leak an unresolved placeholder into a prompt.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import cerberus.prompts.engine as engine
import pytest


def _templates() -> list[Path]:
    return sorted(path for path in engine.TEMPLATES_DIR.rglob("*.md")
                  if path.name != "README.md")


def test_engine_ships_templates() -> None:
    assert _templates(), "no templates under prompts/templates"


def test_frontmatter_role_matches_directory_and_module_exists() -> None:
    for path in _templates():
        name = str(path.relative_to(engine.TEMPLATES_DIR).with_suffix(""))
        front, _body = engine._read(name, engine.TEMPLATES_DIR)
        assert front.get("role") == path.parent.name, path
        module = front.get("module")
        assert isinstance(module, str) and module, path
        importlib.import_module(module)  # provenance pointer resolves


def test_missing_template_fails_closed() -> None:
    with pytest.raises(FileNotFoundError, match="prompt template not found"):
        engine.block("hunter/does_not_exist")


def test_body_required(tmp_path: Path) -> None:
    hunter = tmp_path / "hunter"
    hunter.mkdir()
    (hunter / "empty.md").write_text(
        "---\nrole: hunter\nmodule: cerberus.prompts.hunter\n---\n\n")
    with pytest.raises(ValueError, match="body is empty"):
        engine.block("hunter/empty", base=tmp_path)


def test_frontmatter_required(tmp_path: Path) -> None:
    (tmp_path / "rogue.md").write_text("no frontmatter here\n")
    with pytest.raises(ValueError, match="frontmatter"):
        engine.block("rogue", base=tmp_path)


def test_role_must_match_directory(tmp_path: Path) -> None:
    validator = tmp_path / "validator"
    validator.mkdir()
    (validator / "x.md").write_text(
        "---\nrole: hunter\nmodule: cerberus.prompts.hunter\n---\nbody\n")
    with pytest.raises(ValueError, match="does not match"):
        engine.block("validator/x", base=tmp_path)


def test_placeholder_block_strict_and_pinned() -> None:
    from cerberus.prompts.hunter import FINDING_SPEC

    # Engine fail-closed behavior only: unresolved/unused placeholders are
    # hard errors. No prompt text is pinned (policy: tests must not pin
    # prompt wording — the template body is a ship artifact owned elsewhere).
    with pytest.raises(ValueError, match="unresolved placeholders"):
        engine.block("hunter/contract")
    with pytest.raises(ValueError, match="unused variables"):
        engine.block("hunter/contract",
                     finding_spec=FINDING_SPEC, other=1)


def test_builders_render_without_placeholder_leak() -> None:
    from cerberus.partitioning.prompts import build_partition_task
    from cerberus.prompts.hunter import (
        build_hunter_task,
        build_system_pass_task,
        build_unit_system_prompt,
    )
    from cerberus.prompts.threat import (
        build_finalize_task,
        build_historian_task,
        build_interview_task,
        build_research_task,
        build_synth_task,
    )
    from cerberus.prompts.triage import build_triage_batch_task
    from cerberus.prompts.validator import build_batch_task

    rendered = {
        "unit_system_prompt": build_unit_system_prompt("focus", None),
        "discovery_task": build_hunter_task(
            "u", "/repo", ["a.py"], cand_ctx="cand", threat_md="tm", focus="f"),
        "system_pass_task": build_system_pass_task(
            "/repo", "scope", "ctx", ["a.py"]),
        "validator_batch": build_batch_task(
            "grp", "## threat model\n", [{"id": "f1"}],
            "/repo", ["codegraph_explore"]),
        "validator_bare": build_batch_task("grp", "", [{"id": "f1"}]),
        "triage_batch": build_triage_batch_task("scope", "[]"),
        "research_task": build_research_task("/repo", "draft", ["a.py"]),
        "historian_task": build_historian_task("/repo", "commits", "draft"),
        "synth_task": build_synth_task("/repo", "draft", "{}", "{}", "facts"),
        "synth_narrow": build_synth_task("/repo", "draft", "{}", "{}",
                                         narrow=True),
        "interview_task": build_interview_task("draft", "hist", 3),
        "finalize_task": build_finalize_task("draft", "hist"),
        "partition_task": build_partition_task("ctx", 7),
    }
    assert rendered
    for name, text in rendered.items():
        assert "{{" not in text, f"unresolved placeholder leaked into {name}"
