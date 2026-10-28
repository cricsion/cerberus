"""Agent tool surfaces, defined once so the roles cannot drift apart."""
from __future__ import annotations


def graph_tools() -> list:
    """Read/code-intelligence tools shared by hunters and validators.

    Scanners are not bound as tools: the sandbox `execute` shell + scanner
    skills are the scan surface.
    """
    from harness.tools.code import ast_query
    from harness.tools.codegraph import (
        affected,
        build_context,
        callees,
        callers,
        codegraph_explore,
        compare_sibling_route_security,
        detect_circular_and_dead_code,
        find_path,
        framework_routes,
        get_ast_slice,
        get_routing_manifest,
        impact_radius,
        resolve_blind_spot,
        trace_effect_category,
        trace_interprocedural_hop,
        trace_state_machine_transitions,
    )
    from harness.tools.verify import reachability_check

    return [
        ast_query,
        codegraph_explore,
        find_path,
        impact_radius,
        build_context,
        get_routing_manifest,
        callers,
        callees,
        framework_routes,
        affected,
        reachability_check,
        get_ast_slice,
        trace_interprocedural_hop,
        resolve_blind_spot,
        compare_sibling_route_security,
        trace_state_machine_transitions,
        trace_effect_category,
        detect_circular_and_dead_code,
    ]
