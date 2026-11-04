"""Scanner skills: layout, content guardrails, and delivery to agents.

Delivery rides deepagents' own mechanism: build_deep_agent wraps the sandbox
backend in a CompositeBackend whose /opt/cerberus-skills/ route serves this
directory to the agent (no write tool exists, and a route-scoped deny rule
backstops it), SkillsMiddleware indexes each SKILL.md into the system
prompt, and the agent opens the full doc with `read_file` (progressive
disclosure). The scan image also bakes the same docs at the same path, so
in-container reads (`cat` via execute) agree with the routed file tools.
These tests lock that contract: every skill parses under deepagents'
metadata parser AND is loadable through the routed backend the agent gets.
"""
import re
from pathlib import Path

import pytest
from deepagents.middleware.skills import (
    MAX_SKILL_DESCRIPTION_LENGTH,
    MAX_SKILL_FILE_SIZE,
    _parse_skill_metadata,
)

SKILLS_ROOT = Path(__file__).resolve().parents[1] / "skills"

# SAST scanner ensemble: the skills rules + prompts hard-wire. These must
# always be present, parse, and be served; the rest of the tree is generic
# kit content (top-level flat skills plus category dirs of nested skills).
CORE_SKILLS = ("atheris", "bandit", "bearer", "flawfinder", "gosec",
               "codegraph", "njsscan", "opengrep", "semgrep",
               "trufflehog")


def _top_level_dirs() -> list[Path]:
    return sorted(p for p in SKILLS_ROOT.iterdir() if p.is_dir())


def _skill_dirs() -> list[Path]:
    """Skill dirs the SkillsMiddleware actually indexes: SKILL.md at top."""
    return sorted(p for p in _top_level_dirs() if (p / "SKILL.md").is_file())


def _all_skill_mds() -> list[Path]:
    """Every SKILL.md that ships in the image, at any nesting depth."""
    return sorted(SKILLS_ROOT.rglob("SKILL.md"))


def _read(path: Path) -> str:
    return path.read_text(errors="replace")


# --- layout ----------------------------------------------------------------


def test_skill_layout_is_skill_or_category():
    """Every top-level entry under cerberus/skills is either a skill (own
    SKILL.md) or a kit category dir whose children are all skills; the SAST
    ensemble the product hard-wires must always be among the indexed skills.
    """
    for path in _top_level_dirs():
        if (path / "SKILL.md").is_file():
            continue
        children = sorted(p for p in path.iterdir() if p.is_dir())
        assert children, f"{path.name}: empty category dir ships nothing"
        for child in children:
            assert (child / "SKILL.md").is_file(), (
                f"{path.name}: child {child.name} is not a skill")
    shipped = {p.name for p in _skill_dirs()}
    assert not set(CORE_SKILLS) - shipped, sorted(set(CORE_SKILLS) - shipped)


def test_no_repo_or_ci_junk_under_skills():
    """A nested git clone / CI workflows would ship in the image and leak
    the skill source repo into every container layer."""
    junk = [p for p in SKILLS_ROOT.rglob("*")
            if p.name in (".git", ".github") or p.name == ".gitignore"]
    assert junk == [], junk


@pytest.mark.parametrize("name", CORE_SKILLS)
def test_skill_parses_under_deepagents_metadata(name):
    """deepagents' own parser must accept it: name == dir name, frontmatter
    present, description within the documented length cap."""
    skill_md = SKILLS_ROOT / name / "SKILL.md"
    meta = _parse_skill_metadata(_read(skill_md), str(skill_md), name)
    assert meta is not None, name
    assert meta["name"] == name
    assert 0 < len(meta["description"]) <= MAX_SKILL_DESCRIPTION_LENGTH
    assert skill_md.stat().st_size < MAX_SKILL_FILE_SIZE


def test_every_shipped_skill_parses_under_deepagents_metadata():
    """Beyond the pinned ensemble, every top-level skill (everything the
    SkillsMiddleware indexes at the route root) parses and carries a usable
    name + description. Nested kit skill docs are vendor reference material,
    not indexed skills: they only cannot ship junk (see the layout test)."""
    for skill_dir in _skill_dirs():
        name = skill_dir.name
        skill_md = skill_dir / "SKILL.md"
        meta = _parse_skill_metadata(_read(skill_md), str(skill_md), name)
        assert meta is not None, name
        assert meta["name"] == name, (name, meta["name"])
        assert 0 < len(meta["description"]) <= MAX_SKILL_DESCRIPTION_LENGTH, name


# --- sandbox wiring --------------------------------------------------------


def _settings():
    import tempfile

    import cerberus.sandbox as sbx
    from cerberus.config import load_config

    cfg = load_config()
    return sbx._docker_settings(cfg, tempfile.mkdtemp())


def test_settings_carry_rules_dir_only(tmp_path):
    """Skills ride the agent's route (cerberus/agents/deep.py), not the
    sandbox image: no skills_dir setting to thread -- or drift."""
    import cerberus.sandbox.docker_backend as db

    settings = _settings()
    module_backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        # The path is code-owned in two places; the test pins their AGREEMENT
        # (wiring), not the literal (policy: no hardcoded prod values here).
        assert settings["rules_dir"] == module_backend.rules_dir
    finally:
        module_backend.close()
    assert "skills_dir" not in settings


def test_backend_exposes_rules_dir_only(tmp_path, monkeypatch):
    """A built sandbox backend carries the in-image rules path (the prompt
    points at it); skills no longer travel as a backend path -- they are
    served through the agent's skills route."""
    import cerberus.sandbox.docker_backend as db

    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        assert backend.rules_dir == _settings()["rules_dir"]
        assert not hasattr(backend, "skills_dir")
    finally:
        backend.close()


def test_image_bakes_skills_next_to_rules():
    """The Dockerfile must ship the skill docs at the skills route's own
    path (deep.py SKILLS_ROUTE), so in-container `cat` (execute) resolves
    the same docs the routed file tools serve."""
    from cerberus.agents.deep import SKILLS_ROUTE

    rules_dir = _settings()["rules_dir"].rstrip("/")
    dockerfile = Path(__file__).resolve().parents[1] / "sandbox/docker/Dockerfile"
    text = dockerfile.read_text()
    assert re.search(rf"^COPY rules {re.escape(rules_dir)}$",
                     text, re.M)
    assert re.search(
        rf"^COPY skills {re.escape(SKILLS_ROUTE.rstrip('/'))}$",
        text, re.M)


def test_local_mode_gets_neither_shell_nor_skills(monkeypatch, tmp_path):
    """Local backend: no `execute`, so the sandbox section stays out
    entirely (and the wiring test below: no skills route either)."""
    monkeypatch.setenv("SANDBOX_BACKEND", "local")
    from cerberus.prompts.hunter import sandbox_system_section
    from cerberus.sandbox.local_backend import RepoLocalBackend

    backend = RepoLocalBackend(repo_path=tmp_path)
    assert sandbox_system_section(backend=backend) == ""


# --- extra scanners (image-only delivery) ------------------------------------
#
# bandit/bearer/trufflehog are delivered ONLY by the sandbox image: never
# installed on the host, so no harness-side wrapper exists for them and the
# agent reaches them through `execute`. This locks the whole delivery chain:
# pinned versions, an install block, skill docs, and the prompt
# pointer that names them.

# name -> release-repo substring that identifies the install block
BINARY_TOOLS = {
    "bearer": "Bearer/bearer",
    "gosec": "securego/gosec",
    "trufflehog": "trufflesecurity/trufflehog",
}
# Tools that ride the pip line (pip's own integrity, the
# same story as semgrep/checkov/bearer).
PIP_TOOLS = ("atheris", "bandit", "flawfinder", "njsscan")
ROOT = SKILLS_ROOT.parent  # the cerberus repo root


def test_versions_env_pins_every_extra_tool():
    versions = _read(ROOT / "sandbox/docker/versions.env")
    for tool in list(BINARY_TOOLS) + list(PIP_TOOLS):
        assert f"{tool.upper()}_VERSION=" in versions, tool


def test_dockerfile_installs_every_extra_tool():
    text = _read(ROOT / "sandbox/docker/Dockerfile")
    for repo in BINARY_TOOLS.values():
        assert repo in text, repo
    for tool in BINARY_TOOLS:
        assert f"{tool.upper()}_VERSION" in text, tool          # ARG declared
    # Every pip tool rides the shared pip line with the same quoted form
    # (name==${NAME_VERSION}): the promise is per-tool, not per-wording.
    for tool in PIP_TOOLS:
        pin = '"' + tool + '==${' + tool.upper() + '_VERSION}"'
        assert pin in text, tool
    # ...and the toolchain semgrep is still pinned exactly once.
    assert text.count('"semgrep==${SEMGREP_VERSION}"') == 1


def test_sandbox_build_selects_go_for_target_arch_and_requires_enabled_pins():
    dockerfile = _read(ROOT / "sandbox/docker/Dockerfile")
    build_sh = _read(ROOT / "sandbox/docker/build.sh")
    assert "ARG PYTHON_BASE_IMAGE" in dockerfile
    assert "FROM ${PYTHON_BASE_IMAGE}" in dockerfile
    assert "build-essential clang libclang-rt-dev" in dockerfile
    assert "CLANG_BIN=/usr/bin/clang pip install" in dockerfile
    assert "amd64) go_arch=amd64" in dockerfile
    assert "arm64) go_arch=arm64" in dockerfile
    assert 'go${GO_VERSION}.linux-${go_arch}.tar.gz' in dockerfile
    assert 'GO_VERSION is required when WITH_GO=1' in build_sh
    assert 'NODE_VERSION is required when WITH_NODE=1' in build_sh


def test_every_build_script_arg_is_declared_in_dockerfile():
    dockerfile = _read(ROOT / "sandbox/docker/Dockerfile")
    build_sh = _read(ROOT / "sandbox/docker/build.sh")
    loop = re.search(r"for v in (.*?); do", build_sh, re.S)
    assert loop, "build.sh must keep its build-arg list in one loop"
    passed = set(re.findall(r"\b[A-Z][A-Z0-9_]*\b", loop.group(1)))
    declared = set(re.findall(r"^ARG ([A-Z][A-Z0-9_]*)(?:=|$)",
                              dockerfile, re.M))
    assert passed <= declared, f"build args missing Dockerfile ARG: {passed - declared}"


def test_trivy_is_not_shipped_anywhere():
    """Trivy was deliberately dropped (with vuln off it duplicated checkov/
    gitleaks/trufflehog). Nothing may silently reintroduce it: no pin, no
    install block, no skill, no prompt mention. The guard covers our authored
    Scanner skills AND the Dockerfile/install chain; vendored kit reference
    docs may historically mention the name in comparison tables -- that is
    discussion, not a shipped install."""
    dockerfile = _read(ROOT / "sandbox/docker/Dockerfile")
    versions = _read(ROOT / "sandbox/docker/versions.env")
    build_sh = _read(ROOT / "sandbox/docker/build.sh")

    assert "TRIVY" not in dockerfile
    assert "TRIVY" not in versions
    assert "TRIVY" not in build_sh
    for skill_md in _all_skill_mds():
        text = _read(skill_md).lower()
        # A genuine reintroduction claims trivy as this skill's tool
        # ("# trivy", "## trivy", install/usage lines) -- not a mere table row.
        if re.search(r"(?m)^#{1,3}\s*trivy\b|^#+ trivy .*install|^\s*trivy\s+image\b", text):
            raise AssertionError(f"trivy skill content shipped: {skill_md}")


def test_sandbox_prompt_defers_skills_to_the_middleware(tmp_path, monkeypatch):
    """The sandbox section leaves skill delivery to the Skills System the
    middleware injects: the prompt carries no second hardcoded doc list.
    Structural tripwires only — the wording itself is not pinned."""
    import cerberus.sandbox.docker_backend as db
    from cerberus.agents.deep import SKILLS_ROUTE
    from cerberus.prompts.hunter import sandbox_system_section

    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        text = sandbox_system_section(backend=backend, repo=str(tmp_path))
    finally:
        backend.close()
    assert "trivy" not in text.lower()
    assert SKILLS_ROUTE not in text  # nor the in-image skills path
    # Tripwire: a reintroduced `cat ... SKILL.md` pointer list trips even
    # when reworded.
    assert not re.search(r"(?i)\bcat\b.{0,120}SKILL\.md", text)
    # No leftover format placeholders from the mixed f/% string build.
    assert "%s" not in text and "%d" not in text


def test_skills_route_serves_every_skill(tmp_path, monkeypatch):
    """The backend the agent actually gets must serve all skill docs to the
    skills middleware -- and resolve `read_file` at exactly the path the
    middleware advertises."""
    import cerberus.sandbox.docker_backend as db
    from cerberus.agents.deep import (
        FS_TOOLS,
        SHELL_TOOL,
        SKILLS_DIR,
        SKILLS_ROUTE,
        SKILLS_SOURCES,
        _fs_tools,
        _supports_shell,
        _with_skills_route,
    )
    from deepagents.backends import CompositeBackend, FilesystemBackend
    from deepagents.middleware.skills import _list_skills

    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        assert [path for path, _ in SKILLS_SOURCES] == [SKILLS_ROUTE]
        routed = _with_skills_route(backend)
        assert isinstance(routed, CompositeBackend)
        assert routed.default is backend  # fs tools + execute still ride the sandbox
        # The route exposes exactly cerberus/skills...
        assert set(routed.routes) == {SKILLS_ROUTE}
        route = routed.routes[SKILLS_ROUTE]
        assert isinstance(route, FilesystemBackend)
        assert route.cwd == SKILLS_DIR.resolve()
        # ...while the wrapper still reads as shell-capable to the wiring:
        # execute stays, write tools stay out.
        assert _supports_shell(routed) is True
        assert set(_fs_tools(routed)) == set(FS_TOOLS) | {SHELL_TOOL}
        assert not set(_fs_tools(routed)) & {"write_file", "edit_file", "delete"}
        metas = {m["name"]: m for m in _list_skills(routed, SKILLS_ROUTE)}
        shipped = {p.name for p in _skill_dirs()}
        assert sorted(metas) == sorted(shipped)
        assert not set(CORE_SKILLS) - set(metas)
        for name, meta in metas.items():
            assert meta["description"], name
            assert meta["path"] == f"{SKILLS_ROUTE}{name}/SKILL.md", name
        read = routed.read(metas["semgrep"]["path"])
        assert not getattr(read, "error", None)
    finally:
        backend.close()


@pytest.mark.parametrize("shape", ["dir", "file", "broken-symlink"])
def test_repo_skills_path_collision_warns_once(tmp_path, monkeypatch, capsys,
                                               shape):
    """A target repo owning opt/cerberus-skills (any shape: dir, file, dangling
    symlink) would be shadowed for read_file/ls/grep by the route; the wrap
    surfaces it -- exactly once per process, however many agents get wrapped."""
    import cerberus.sandbox.docker_backend as db
    from cerberus.agents import deep as deep_mod

    target = tmp_path / "opt" / "cerberus-skills"
    target.parent.mkdir(parents=True)
    if shape == "dir":
        target.mkdir()
    elif shape == "file":
        target.write_text("not a directory\n")
    else:
        target.symlink_to(tmp_path / "missing", target_is_directory=True)

    monkeypatch.setattr(deep_mod, "_skills_shadow_warned", False)
    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        deep_mod._with_skills_route(backend)
        deep_mod._with_skills_route(backend)  # once per process, not per wrap
    finally:
        backend.close()
    assert capsys.readouterr().err.count("shadowed by the skills route") == 1


def _capture_agent_kwargs(monkeypatch) -> dict:
    import deepagents

    captured: dict = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(deepagents, "create_deep_agent", _capture)
    return captured


def test_build_deep_agent_wires_skills_for_sandbox_backends(tmp_path, monkeypatch):
    """The contract this harness originally missed: a sandbox agent must get
    `skills=` (so SkillsMiddleware runs) and a backend whose route serves the
    docs -- not a prompt-side `cat` list."""
    import itertools

    import cerberus.sandbox.docker_backend as db
    from cerberus.agents.deep import SHELL_TOOL, SKILLS_ROUTE, build_deep_agent
    from deepagents.backends import CompositeBackend
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

    captured = _capture_agent_kwargs(monkeypatch)
    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        llm = GenericFakeChatModel(messages=itertools.repeat("ok"))
        build_deep_agent(llm, system_prompt="x", tools=[], backend=backend)
    finally:
        backend.close()
    assert captured["skills"] == [(SKILLS_ROUTE, "Scanner")]
    routed = captured["backend"]
    assert isinstance(routed, CompositeBackend)
    assert routed.default is backend
    # The one fs middleware rides the wrapped backend: execute retained, write
    # tools absent, and the skills route carries the scoped deny-write rule.
    mw = next(m for m in captured["middleware"]
              if type(m).__name__ == "FilesystemMiddleware")
    names = {t.name for t in mw.tools}
    assert SHELL_TOOL in names
    assert not names & {"write_file", "edit_file", "delete"}
    assert [p.mode for p in mw._permissions] == ["deny"]
    assert mw._permissions[0].paths == [f"{SKILLS_ROUTE}**"]


def test_nested_composite_still_reads_as_sandbox(tmp_path, monkeypatch):
    """_supports_shell must unwrap to the real default: with a single-level
    peek, an already-composite input silently loses `execute` (and the whole
    skills wiring) instead of keeping the sandbox tool surface."""
    import itertools

    import cerberus.sandbox.docker_backend as db
    from cerberus.agents.deep import (
        SHELL_TOOL,
        SKILLS_ROUTE,
        _fs_tools,
        _supports_shell,
        build_deep_agent,
    )
    from deepagents.backends import CompositeBackend, FilesystemBackend
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        inner = CompositeBackend(default=backend, routes={
            "/notes/": FilesystemBackend(root_dir=str(tmp_path),
                                         virtual_mode=True)})
        nested = CompositeBackend(default=inner, routes={
            "/extra/": FilesystemBackend(root_dir=str(tmp_path),
                                         virtual_mode=True)})
        assert _supports_shell(nested) is True
        assert SHELL_TOOL in _fs_tools(nested)
        captured = _capture_agent_kwargs(monkeypatch)
        llm = GenericFakeChatModel(messages=itertools.repeat("ok"))
        build_deep_agent(llm, system_prompt="x", tools=[], backend=nested)
    finally:
        backend.close()
    assert captured["skills"] == [(SKILLS_ROUTE, "Scanner")]
    mw = next(m for m in captured["middleware"]
              if type(m).__name__ == "FilesystemMiddleware")
    assert SHELL_TOOL in {t.name for t in mw.tools}


def test_build_deep_agent_leaves_local_backend_skill_less(tmp_path, monkeypatch):
    import itertools

    from cerberus.agents.deep import build_deep_agent
    from cerberus.sandbox.local_backend import RepoLocalBackend
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

    captured = _capture_agent_kwargs(monkeypatch)
    backend = RepoLocalBackend(repo_path=tmp_path)
    llm = GenericFakeChatModel(messages=itertools.repeat("ok"))
    build_deep_agent(llm, system_prompt="x", tools=[], backend=backend)
    assert "skills" not in captured
    assert captured["backend"] is backend


def test_agent_receives_skill_index_in_system_prompt(tmp_path, monkeypatch):
    """End to end: the system message the model actually gets carries the
    Skills System index (every skill, its description, its read_file path) --
    the outcome the old prompt-side `cat` list never delivered through the
    framework."""
    import cerberus.sandbox.docker_backend as db
    from cerberus.agents.deep import build_deep_agent
    from llm_fakes import ToolCallableLLM

    seen: list = []
    capture_llm = ToolCallableLLM(capture=seen)

    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        agent = build_deep_agent(capture_llm, system_prompt="TEST-SYSTEM",
                                 tools=[], backend=backend)
        agent.invoke({"messages": [{"role": "user", "content": "hi"}]})
    finally:
        backend.close()
    from cerberus.agents.deep import SKILLS_ROUTE

    system = str(seen[0][0].content)
    assert "TEST-SYSTEM" in system
    for skill in CORE_SKILLS:
        assert f"{SKILLS_ROUTE.rstrip('/')}/{skill}/SKILL.md" in system, skill
