# CodeGraph package

This package provides the 9 CodeGraph tools used by the harness. It reads a
repository's CodeGraph index, renders bounded source and relationship evidence,
and surfaces cached security summaries from the sidecar database. The tool names
and their order are a pinned interface.

## Tool surface

The harness exposes these tools in this order:

1. `get_ast_slice`
2. `trace_interprocedural_hop`
3. `resolve_blind_spot`
4. `compare_sibling_route_security`
5. `find_shared_state_readers_writers`
6. `trace_state_machine_transitions`
7. `inspect_type_contract`
8. `trace_egress_and_ssrf_targets`
9. `trace_effect_category`

The native bridge (`native.py`) additionally backs `type_hierarchy`, bound
separately by `cerberus.agents.toolsets`; the 9-name package surface above is
unchanged.

The order is defined by `cerberus.tools.codegraph.CODEGRAPH_TOOL_NAMES`.
Keep package and binding containment helpers distinct: they have intentionally
different path rules.

## On-disk data

- The index lives at `.codegraph/codegraph.db` under the indexed repository.
  It contains the node and edge data used by index-first tools. Index access is
  root-pinned; an index for a different repository is not reused.
- Security summaries and related memory live in the sidecar selected by
  `SAST_SUMMARIES_DB`. Its `summaries` rows are keyed by node and role and store
  CWE scope, notes, and update time.
- `_db.py` owns bounded database reads; `_index.py` checks index readiness and
  containment; `_ts.py` owns parser and source-text helpers. `_common.py`
  contains shared formatting, parsing, containment, and gate helpers.

Tools return bounded text with stable headings and error-shaped results. A
missing or stale index is reported as guidance or an `ERROR:` result; it does
not silently switch to another repository's database.
