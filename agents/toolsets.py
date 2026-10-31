"""Agent tool surfaces, defined once so the roles cannot drift apart."""
from __future__ import annotations


def graph_tools() -> list:
    """Read/code-intelligence tools shared by hunters and validators.

    Scanners are not bound as tools: the sandbox `execute` shell + scanner
    skills are the scan surface.
    """
    from harness.tools.codegraph import (
        affected,
        build_context,
        callees,
        callers,
        codegraph_explore,
        codegraph_tools,
        detect_circular_and_dead_code,
        find_path,
        framework_routes,
        get_routing_manifest,
        impact_radius,
        type_hierarchy,
    )
    from harness.tools.verify import reachability_check

    return [
        codegraph_explore,
        find_path,
        impact_radius,
        build_context,
        get_routing_manifest,
        type_hierarchy,
        callers,
        callees,
        framework_routes,
        affected,
        reachability_check,
        *codegraph_tools(),
        detect_circular_and_dead_code,
    ]
