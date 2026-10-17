"""CodeGraph + tree-sitter backed tools for the agentic SAST system.

This package is the bridge between the local CodeGraph index
(``.codegraph/codegraph.db`` — nodes, edges, files, unresolved references, FTS5)
and the hunter/validator/verifier agents. It is deliberately read-only against
the target repo: the index is opened ``mode=ro`` everywhere, and the only
writable artifact is a small sidecar next to it (``.codegraph/sast_summaries.db``)
holding the agents' own memory — per-node sanitizer/guard verdicts, triage
decisions, and analyst variant rules.

Design law: never give a security agent open-ended filesystem tools. Every
``@tool`` here accepts structured graph/AST coordinates (node ids, route ids,
edge ids) and returns bounded, high-signal telemetry; raw file reads are
confined to the exact spans the graph points at
(:func:`harness.tools.code._safe_path`), and every failure is a success-shaped
string (``ERROR: ...`` or :func:`harness.codegraph._db.guidance_no_db`), never
an exception.

Foundation:
    ``_db``        — contained, mtime-cached, always-read-only SQLite access to
                     the index, every helper degrading to ``[]``/``None`` and
                     :func:`guidance_no_db` when the repo is not indexed.
    ``_ts``        — tree-sitter helpers (parser per extension/language, the
                     CodeGraph 1 MB per-file cap, enclosing function, calls in
                     a span, signature-parameter parsing, numbered windows).
    ``sinks``      — a faithful port of CodeGraph's 12-category curated effects
                     taxonomy (``codegraph/src/ui-server/api/effects.ts``), so
                     "what does this call leave the process for?" is one call
                     away.
    ``summaries``  — the sidecar memory store described above.

Tool modules (the micro-agent partition from the SAST tool suite design):
    ``navigation`` — Taint & Injection agent's context tools:
                     :func:`get_ast_slice`, :func:`trace_interprocedural_hop`,
                     :func:`resolve_blind_spot`.
    ``authz``      — AuthZ & Business Logic agent:
                     :func:`compare_sibling_route_security`,
                     :func:`find_shared_state_readers_writers`,
                     :func:`trace_state_machine_transitions`.
    ``contracts``  — Taint & Verifier agents:
                     :func:`inspect_type_contract`,
                     :func:`record_function_security_summary`,
                     :func:`get_function_security_summary`,
                     :func:`validate_remediation_patch`.
    ``variants``   — Verifier & Remediation agent:
                     :func:`synthesize_and_sweep_variant_rule`,
                     :func:`query_historical_triage_memory`.
    ``supply``     — Supply-Chain & Polyglot agents:
                     :func:`verify_cve_symbol_reachability`,
                     :func:`inspect_config_and_secret_hygiene`,
                     :func:`trace_egress_and_ssrf_targets`.
    ``polyglot``   — Polyglot, Async & AI-native agent:
                     :func:`inspect_cross_language_bridge`,
                     :func:`audit_llm_and_mcp_tool_sinks`,
                     :func:`verify_exploit_poc_in_harness`.
"""
from __future__ import annotations

from harness.codegraph.authz import (
    compare_sibling_route_security,
    find_shared_state_readers_writers,
    trace_state_machine_transitions,
)
from harness.codegraph.contracts import (
    get_function_security_summary,
    inspect_type_contract,
    record_function_security_summary,
    validate_remediation_patch,
)
from harness.codegraph.navigation import (
    get_ast_slice,
    resolve_blind_spot,
    trace_interprocedural_hop,
)
from harness.codegraph.polyglot import (
    audit_llm_and_mcp_tool_sinks,
    inspect_cross_language_bridge,
    verify_exploit_poc_in_harness,
)
from harness.codegraph.supply import (
    inspect_config_and_secret_hygiene,
    trace_egress_and_ssrf_targets,
    verify_cve_symbol_reachability,
)
from harness.codegraph.variants import (
    query_historical_triage_memory,
    synthesize_and_sweep_variant_rule,
)

__all__: list = [
    "get_ast_slice",
    "trace_interprocedural_hop",
    "resolve_blind_spot",
    "compare_sibling_route_security",
    "find_shared_state_readers_writers",
    "trace_state_machine_transitions",
    "inspect_type_contract",
    "record_function_security_summary",
    "get_function_security_summary",
    "validate_remediation_patch",
    "synthesize_and_sweep_variant_rule",
    "query_historical_triage_memory",
    "verify_cve_symbol_reachability",
    "inspect_config_and_secret_hygiene",
    "trace_egress_and_ssrf_targets",
    "inspect_cross_language_bridge",
    "audit_llm_and_mcp_tool_sinks",
    "verify_exploit_poc_in_harness",
]
