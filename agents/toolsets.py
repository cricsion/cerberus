"""Agent tool surfaces, defined once so the roles cannot drift apart.

The hunter and the validator read the same repo with the same
code-intelligence tools; the validator additionally gets the reachability
helper. Keep this the single source of truth: a tool added for hunters should
reach validators too, unless there is an explicit reason to withhold it.

The SAST wrapper surface is backend-dependent. A sandbox backend
(docker/sbx) satisfies ``SandboxBackendProtocol`` and materializes a real
``execute`` shell, and the hunter prompt's SCAN PROTOCOL directive has the
agent run the preinstalled semgrep/opengrep binaries directly -- so the capped
``semgrep_scan``/``opengrep_scan`` wrappers are omitted there (otherwise the
model picks one scan path arbitrarily and recall drops). Without a sandbox
(local backend) there is no shell at all, so the wrappers are the only scanner
surface and stay.
"""
from __future__ import annotations


def code_intel_tools(backend=None) -> list:
    """Read/code-intelligence tools shared by hunters and validators.

    Backend-aware: the capped SAST wrappers appear only when no sandbox shell
    is available (see the module docstring).
    """
    from deepagents.backends.protocol import SandboxBackendProtocol
    from harness.tools.code import ast_query
    from harness.tools.codegraph import callees, callers, framework_routes
    from harness.tools.graphify import (graph_affected, graph_neighbors,
                                         graph_path, graph_query)
    from harness.tools.sast import opengrep_scan, semgrep_scan

    scan_tools: list = ([] if isinstance(backend, SandboxBackendProtocol)
                        else [semgrep_scan, opengrep_scan])
    return [ast_query, callers, callees, framework_routes,
            graph_neighbors, graph_path, graph_query, graph_affected,
            *scan_tools]


def validator_tools(backend=None) -> list:
    """Hunter code-intelligence parity plus the reachability helper.

    ``reachability_check`` surfaces obvious sanitizer signals in file context
    so the validator's adversarial pass has static evidence; the LLM still
    makes the final call (see ``harness.tools.verify``).
    """
    from harness.tools.verify import reachability_check

    return [*code_intel_tools(backend), reachability_check]
