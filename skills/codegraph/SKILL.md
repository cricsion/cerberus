---
name: codegraph
description: >-
  Use the bound `harness.codegraph` tools for STRUCTURAL questions file search
  cannot answer: which functions call or contain a symbol, the call hop between
  two nodes, route-node entry points with their handler file:line, and every
  reach path into a sink with call-site lines. The index is prebuilt by the
  indexer before the hunt and the tools are in-process and bounded — never
  shell `codegraph`.
---

# CodeGraph — AST-Proven Call Graph

The index is a **call graph for the whole repo**: nodes are the real, resolvable
in-project entities CodeGraph extracted (functions, methods, classes, route
declarations), edges are AST-derived `calls`, `references`, `imports`, and
`contains` relations. It answers *who reaches whom* that the file tools cannot,
without whole-repo greps.

## In this environment

- The index lives at `<repo>/.codegraph/codegraph.db` and is **prebuilt by the
  indexer before units are hunted**, then opened **read-only** by every tool
  here — agents never write it. Do not try `codegraph index` / `codegraph sync`
  in the shell: the CLI is baked into the image for the **indexer only**, and
  the repo mounts are **read-only** for agents. The index is built once per
  scan, before fan-out.
- The tools are **in-process and bounded** — bound to you as ordinary agent
  tools: no `execute`, no install, no upgrade, no network. Each returns a
  size-capped, high-signal summary, and the underlying helpers clamp to a hard
  maximum row count (`limit<=0` means unlimited, still capped). Keep the
  returned summaries as evidence; never paste a raw dump into a finding.
- The index is **static and whole-repo**, so it is safe to query beyond your
  unit's files for reachability evidence — but findings still attach only to
  your unit's assigned files.

## The boundary: call graph ≠ taint

This is the most important fact about these tools. **A call graph proves
reachability only. Never report on graph edges alone. Verify argument flow in
source.**

- A `calls` edge fires when a callee resolves to a real in-project entity; a
  `references` edge carries framework route→handler wiring. There is **no
  intra-function dataflow** and **no stdlib-sink nodes**.
- So proving a sink is reached from an entry point proves *who can call* it,
  not that the argument is attacker-controlled. After the graph narrows your
  walk, open the code and verify WHO controls the input and HOW it reaches the
  sink before reporting. Symmetrically, a missing path is an absence of *graph*
  evidence — the graph is not proof that no path exists either.

## Reading the graph honestly

Two markers bound what the graph can claim:

- **Numeric edge confidence.** Resolution lives in `edges.metadata`
  (`{confidence, resolvedBy, refName}`), not in `edges.provenance` (NULL
  everywhere). CodeGraph's cutoff is `UNCERTAIN_BELOW = 0.6`: **below 0.6 a hop
  is a name-only guess, not a call — do not follow it as if it were proven.**
  `resolvedBy`/`refName` say how an edge was bound; treat a bare name match as
  the weak evidence it is.
- **`unresolved_refs` is an explicit under-approximation marker.** Every
  reference the resolver saw and failed on is kept (`status='failed'` rows
  survive on purpose so a later sync can retry them; `pending` means the
  resolution pass has not run). Either way the SAST reading is the same: the
  graph may be **missing an edge here** — say so explicitly rather than
  reporting the node as unreachable. `resolve_blind_spot(node_id)` ranks the
  repo symbols such a reference could actually point at.

Node ids are content hashes and edge ids are autoincrement — **not stable
across re-indexes**; fingerprint a `(source, target, kind, line, col)` tuple
when you need a durable reference.

## Entry seeding: route nodes

Routes are first-class nodes (`kind='route'`). `framework_routes` and the
routing-manifest join a route node to its handler exactly like CodeGraph's
`getRoutingManifest`: **URL → handler file:line** (plus the handler's name and
kind), through a `references` or `calls` edge, ordered by the route's own file
and line, with the same test/generated hygiene filter the UI applies. Start a
cross-file hunt from a route, not from a grep for `@app.get`. Route ids are
what route authorization tools take (`compare_sibling_route_security`).

## The sidecar: agent memory, not the graph

Writes never touch the index. The one writable artifact is
`<repo>/.codegraph/sast_summaries.db` (redirectable via `SAST_SUMMARIES_DB`) —
the **sidecar** for reusable security-role summaries: per-node
**sanitizer/guard** verdicts (`SANITIZER | VALIDATOR | AUTH_GUARD |
TAINT_PASSTHROUGH | SAFE_WRAPPER`). It is triage memory across agents; recorded
rows are prepended to later tool calls as a `[CACHED SUMMARY: …]` hint, so do
not re-derive what is already decided. The tool surface only reads it — the
index and the sidecar stay read-only for agents.

A summary is a claim, not a finding: it is an analyst's verdict you can act on
and, when wrong, overwrite.

## Choosing the tool by the shape of the question

| You want to know | Tool |
|---|---|
| **1-shot exploration: verbatim source + call path + blast radius** | `codegraph_explore` (Reach for this FIRST instead of multi-step read/grep) |
| **Shortest call path between entry point and sink across dynamic hops** | `find_path` (traces exact call-site lines & edge confidence) |
| **Multi-hop blast radius / transitive downstream dependents** | `impact_radius` (walks transitive dependencies up to depth N) |
| **Assemble focused context for a task (entry points + related files)** | `build_context` |
| **Compile web framework route table & detected frameworks (Express, FastAPI, Django...)** | `get_routing_manifest` |
| **Identify dependency cycles and dead/orphaned code** | `detect_circular_and_dead_code` |
| What is this symbol connected to (both directions) | `callers` / `callees` (`_db`-first index search, optional JSON mode) |
| Where do routes enter, and which handler serves each | `framework_routes` (route nodes → handler file:line) |
| The exact source span of one node, without flooding context | `get_ast_slice` |
| Where one call hop happens and what argument crossed it | `trace_interprocedural_hop` |
| Every repo symbol an unresolved reference could point at | `resolve_blind_spot` |
| Can an entry point reach a sink across files | `reachability_check` |
| What does this DTO / request body guarantee about its fields | `inspect_type_contract` |
| Does this class inherit auth/validation from a base, or who extends/implements it | `type_hierarchy` |
| Does this endpoint enforce what its sibling endpoints enforce | `compare_sibling_route_security` |
| Who reads/writes this shared state, and is it unguarded | `find_shared_state_readers_writers` |
| Which state transitions skip the workflow | `trace_state_machine_transitions` |
| Do this function's network calls go to a fixed URL or an attacker's | `trace_egress_and_ssrf_targets` |
| Which security-sensitive sinks (shell, db, crypto, network, etc.) are reached | `trace_effect_category` |

Pick the narrowest tool: the domain tools already carry the route-node, guard,
and contract semantics you would otherwise reconstruct by hand.

## Querying with the graph's vocabulary

Node search matches **names, qualified names, signatures, and docstrings**
(FTS5, with a LIKE fallback when FTS is unavailable). There is **no stemming and
no synonym resolution**: if your wording differs from the code's vocabulary,
recall collapses toward noise.

- Feed the terms the CODE actually uses: exact function/class names, the
  distinctive part of an identifier, the source file name. Prefer a couple of
  precise terms over a prose sentence.
- If a query returns nothing or noise, re-ask with vocabulary taken from the
  source you have already read (or from a `callers`/`callees` dump). Do not
  invent terms the index cannot contain, and do not substitute near-synonyms
  from memory.

## When to use them

- Cross-file provenance: "who calls this sink wrapper?" — where `grep` would
  flood you with import sites, `callers` gives call sites.
- Entry-to-sink reachability: route → handler → dangerous function chains.
- Checking for variants: when a helper is vulnerable, enumerate its callers and
  audit each site.
- Skipping dead weight: if no call path reaches a suspicious function, that is
  signal to spend budget elsewhere — but only *reachability* signal, never a
  claim that the path does not exist.

## Remember

The CodeGraph index finds WHO calls WHOM and which route reaches which handler.
Grep and the scanners find sinks and words. You join the two and **verify the
argument flow in source** before you claim taint — never report on the graph's
edges alone.
