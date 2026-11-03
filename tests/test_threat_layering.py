"""Layering contract for the cerberus.threat package (plan-threat-split §2).

A module-level edge outside the declared one-way DAG, or a hoisted import
that closes a cycle, would be swallowed by the fail-open `except Exception`
handlers at runtime — so the graph is asserted here instead.
"""
from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "threat"

# module -> allowed module-level intra-package dependencies (the §2 DAG).
DAG: dict[str, frozenset[str]] = {
    "util": frozenset(),
    "render": frozenset({"util"}),
    "vulns": frozenset({"render"}),
    "quality": frozenset({"render", "util"}),
    "floor": frozenset({"render", "util"}),
    "assemble": frozenset({"render", "quality", "floor"}),
    "synthesizer": frozenset(),
    "swarm": frozenset({"util", "render", "floor", "assemble"}),
}

# harness.* imports that must stay function-local (lazy), per module.
LAZY_harness_IMPORTS: dict[str, frozenset[str]] = {
    "synthesizer": frozenset({
        "cerberus.prompts.contract",
        "cerberus.prompts.threat",
    }),
    "swarm": frozenset({
        "cerberus.agents.deep",
        "cerberus.config",
        "cerberus.fallback",
        "cerberus.prompts.threat",
        "cerberus.sandbox",
        "cerberus.schemas",
    }),
}


def _tree(name: str) -> ast.Module:
    return ast.parse((PKG / f"{name}.py").read_text(encoding="utf-8"))


def _imported_modules(node: ast.AST) -> set[str]:
    """Absolute dotted modules named by one import node (relative imports skipped)."""
    if isinstance(node, ast.Import):
        return {a.name for a in node.names}
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        return {node.module}
    return set()


def _module_level_intra_package_deps(tree: ast.Module) -> set[str]:
    deps: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level:
            if node.module is None:  # `from . import util, render`
                deps.update(a.name for a in node.names)
            else:  # `from .util import x`
                deps.add(node.module.split(".")[0])
    return deps


def test_module_level_edges_match_declared_dag() -> None:
    for name, allowed in DAG.items():
        got = _module_level_intra_package_deps(_tree(name))
        assert got == set(allowed), (
            f"{name}.py module-level edges {sorted(got)} != declared {sorted(allowed)}")


def test_declared_dag_is_acyclic() -> None:
    visiting: set[str] = set()
    done: set[str] = set()

    def visit(mod: str) -> None:
        if mod in done:
            return
        assert mod not in visiting, f"cycle through {mod}"
        visiting.add(mod)
        for dep in DAG[mod]:
            visit(dep)
        visiting.discard(mod)
        done.add(mod)

    for mod in DAG:
        visit(mod)


def test_no_harness_imports_at_module_level() -> None:
    for name in DAG:
        hoisted: set[str] = set()
        for node in _tree(name).body:
            hoisted |= {m for m in _imported_modules(node)
                        if m.split(".")[0] == "cerberus"}
        assert not hoisted, f"{name}.py hoists harness imports: {sorted(hoisted)}"


def test_lazy_harness_imports_stay_function_local() -> None:
    for name, lazy in LAZY_harness_IMPORTS.items():
        in_functions: set[str] = set()
        for fn in ast.walk(_tree(name)):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    in_functions |= _imported_modules(node)
        got = {m for m in in_functions if m.split(".")[0] == "cerberus"}
        assert got == set(lazy), (
            f"{name}.py function-local harness imports {sorted(got)} != "
            f"expected {sorted(lazy)}")


def test_facade_imports_every_submodule() -> None:
    got = _module_level_intra_package_deps(_tree("__init__"))
    assert got == set(DAG), (
        f"facade imports {sorted(got)} != submodules {sorted(DAG)}")
