---
name: graphify
description: >-
  Use the code-graph tools (graph_neighbors, graph_path, graph_query,
  graph_affected) for STRUCTURAL questions file search cannot answer: which
  functions call or contain a symbol, the shortest caller-to-callee path from
  an entry point to a sink, and every reach path into a function with call-site
  lines. The graph is built by the indexer before the hunt; the tools are bound
  directly to the agent, so no shell command or installation is needed.
---

# Graphify — AST-Proven Call Graph

The graph is a **call graph for the whole repo**: nodes are real, resolvable
in-project callables, edges are AST-extracted imports, calls, containment,
and indirect (by-name) dispatch. It answers *who reaches whom* that the file
tools cannot, without whole-repo greps.

## In this environment

- The `graphify` package is **preinstalled in the harness environment only**
  (requirements.txt) — it is **not installed in the scan container**. Do not try
  `graphify ...` or `python -m graphify ...` in the shell — neither exists
  there, and installs are forbidden. The graph tools are bound to you as
  ordinary agent tools in sandbox and local modes alike — no `execute`, no
  install, no upgrade, no network. The prebuilt `graphify-out/graph.json`
  is visible (read-only) in the mounted repo, but the tools serve it with
  slicing and truncation — use them, not a raw read.
- The indexer builds the graph at the repo root (`graphify-out/graph.json`)
  before units are hunted, with `--code-only` (source only, no generated
  artifacts, no `node_modules`, no VCS dirs). A code-only build has only
  AST-extracted (EXTRACTED-confidence) edges — there are no semantic
  INFERRED/AMBIGUOUS edges to be cautious of, and no stdlib sink nodes.
- Output is already size-capped by each tool. Keep the returned summaries as
  evidence; never paste a raw dump into your answer or into a finding. If a
  result is capped and you need more, narrow the query or read a deeper slice
  and write it under `/work` rather than inlining it.
- The graph is **static and whole-repo**, so it is safe to query beyond your
  unit's files for reachability evidence — but findings still attach only to
  your unit's assigned files.

## The boundary: call graph ≠ taint

This is the most important fact about these tools. The graph proves
**reachability** only:

- cross-file `calls` edges fire when a callee resolves to a real in-project
  callable; `indirect_call` covers by-name callbacks and `getattr` string refs;
- there is **no intra-function dataflow** and **no stdlib-sink nodes**.

So `graph_affected(sink)` proves *who can call* a sink, not that the argument
is attacker-controlled; `graph_path(entry, sink)` proves a *call* path exists,
not that the input flows unmodified. After the graph narrows your walk, open
the code and verify the argument flow in source (WHO controls the input, HOW
it reaches the sink) before reporting a finding. **Never report on graph
edges alone.** Symmetrically, a missing path is an absence of *graph* evidence
— the graph is not proof that no path exists either.

## Choosing the traversal

Pick the tool by the SHAPE of the question, same as the engine's BFS/DFS split:

| You want to know | Tool |
|---|---|
| What is this symbol connected to (broad context) | `graph_query` (BFS) or `graph_neighbors` |
| How does entry X reach sink Y (one specific chain) | `graph_path` (directed caller→callee) |
| Who can call this function at all, with call sites | `graph_affected` (reverse, depth 2) |

`graph_query` is the broad "what is X connected to" pass; `graph_path` /
`graph_affected` are the "trace a specific chain" passes. Undirected thinking
is a trap: `graph_path` is a **directed** caller→callee path, so read each hop
in direction.

## Querying with the graph's vocabulary

`graph_query` matches its terms against node **labels, source files, and
rationale text** — exact matches outrank prefixes, which outrank substrings,
which outrank source-path hits. There is **no stemming and no synonym
resolution**: if your wording is different from the code's vocabulary, scores
collapse toward noise.

- Feed the terms the CODE actually uses: exact function/class names, the
  distinctive part of an identifier, the name of the source file. Prefer a
  couple of precise terms over a prose sentence.
- If a question returns nothing or noise, re-ask with vocabulary taken from
  the source you have already read (or from a `graph_neighbors` dump). Do not
  invent terms the graph cannot contain (`_score_query` can only match text
  that exists); and do not substitute near-synonyms from memory.
- Handle morphology: "handlers" should be asked as `handler` if that is the
  symbol, not assumed to match.

## Tool-by-tool

- `graph_neighbors(symbol)` — both directions: what the symbol calls/imports/
  contains and who calls/imports/contains it, each with file:line, plus
  relation labels. Start here to fan out from a function you care about, or
  to read a symbol's vocabulary before crafting a query.
- `graph_path(source, sink)` — shortest **directed** caller→callee path.
  Seeds resolve by label scoring: exact symbol names, `name()`, or
  repo-relative paths. Use it to prove an entry point can reach a sink across
  files, then verify each hop's argument in source.
- `graph_query(question)` — BFS subgraph for a plain-language structural
  question, depth 3, token-budgeted. Use it for broad context ("how does user
  input reach the database layer") and restate it with in-graph vocabulary if
  it flops.
- `graph_affected(symbol)` — reverse traversal (callers up to depth 2) with
  CALL-SITE lines (`via_file:via_location`). Enumerates every reach path into
  a function such as a sink wrapper — the strongest structure evidence for a
  cross-unit claim, still only *reachability*.

All four accept `limit`/`budget` for pagination (0 = unlimited), and all
return file:line per hit — quote those locations when you cite graph evidence.

## When to use them

- Cross-file provenance: "who calls this sink wrapper?" — where `grep` would
  flood you with import sites, `graph_affected` gives call sites.
- Entry-to-sink reachability: route → handler → dangerous function chains.
- Checking for variants: when a helper is vulnerable, enumerate its callers
  and audit each site.
- Skipping dead weight: if no call path reaches a suspicious function, that
  is signal to spend budget elsewhere — but only *reachability* signal, never
  a claim that the path does not exist.

## When they are NOT available

- A single-file unit has nothing to map: the tools tell you to use `grep`
  (`callers`/`callees`) and `ast_query` instead.
- If the graph is missing or disabled ("no graph for this repo", "(no graph)"):
  fall back to `grep` codegraph and `ast_query` — the graph is an accelerator,
  not a dependency.

## Remember

Graphify finds WHO calls WHOM. Grep and the scanners find sinks and words.
You join the two and verify the argument flow in source before you claim taint.