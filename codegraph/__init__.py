"""CodeGraph + tree-sitter backed tools for the agentic SAST system.

This package is the bridge between the local CodeGraph index
(``.codegraph/codegraph.db`` — nodes, edges, files, unresolved references, FTS5)
and the hunter/validator/verifier agents. It is deliberately read-only against
the target repo: the index is opened ``mode=ro`` everywhere, and the only
writable artifact is a small sidecar next to it (``.codegraph/sast_summaries.db``)
holding the agents' own memory — per-node sanitizer/guard verdicts.

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
                     :func:`inspect_type_contract`.
    ``supply``     — Supply-Chain agents:
                     :func:`trace_egress_and_ssrf_targets`.
    ``effects``    — Effect-category tracing (the egress view generalized to
                     every curated category): :func:`trace_effect_category`.
    ``manifests``  — Manifest-vs-import reconciliation:
                     :func:`reconcile_manifest_imports`.
    ``graphql``    — GraphQL attack-surface mapping: :func:`graphql_surface`.
"""
from __future__ import annotations

from harness.codegraph.authz import (
    compare_sibling_route_security,
    find_shared_state_readers_writers,
    trace_state_machine_transitions,
)
from harness.codegraph.contracts import (
    inspect_type_contract,
)
from harness.codegraph.navigation import (
    get_ast_slice,
    resolve_blind_spot,
    trace_interprocedural_hop,
)
from harness.codegraph.supply import (
    trace_egress_and_ssrf_targets,
)
from harness.codegraph.effects import (
    trace_effect_category,
)
from harness.codegraph.manifests import (
    reconcile_manifest_imports,
)
from harness.codegraph.graphql import (
    graphql_surface,
)
from harness.codegraph import native

__all__: list = [
    "get_ast_slice",
    "trace_interprocedural_hop",
    "resolve_blind_spot",
    "compare_sibling_route_security",
    "find_shared_state_readers_writers",
    "trace_state_machine_transitions",
    "inspect_type_contract",
    "trace_egress_and_ssrf_targets",
    "trace_effect_category",
    "reconcile_manifest_imports",
    "graphql_surface",
]
