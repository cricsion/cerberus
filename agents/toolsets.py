"""Agent tool surfaces, defined once so the roles cannot drift apart."""
from __future__ import annotations


def graph_tools() -> list:
    """Read/code-intelligence tools shared by hunters and validators.

    Scanners are not bound as tools: the sandbox `execute` shell + scanner
    skills are the scan surface.
    """
    from harness.tools.code import ast_query
    from harness.tools.codegraph import callees, callers, framework_routes
    from harness.tools.graphify import (graph_affected, graph_neighbors,
                                         graph_path, graph_query)
    from harness.tools.verify import reachability_check

    return [ast_query, callers, callees, framework_routes,
            graph_neighbors, graph_path, graph_query, graph_affected,
            reachability_check]
