# Partitioning lessons

Everything here was paid for: design decisions argued out, then a blocker found by
adversarial validation of our own work. Written down so the next person doesn't
re-buy the lesson. Code lives in `harness/partitioning/` (units.py, llm.py);
current invariants are asserted in `tests/test_units.py`.

---

## 1. Budget-first partitioning, not count-first

File-count caps (`MAX_FILES`, `max_units`) answer the wrong question. The old
`PARTITION_FILES` cap also hid the inventory tail from the semantic planner;
it has been removed so every path is considered. What bounds work per agent is
**how much code one hunter can depth-audit**, not how many files exist. The
per-agent review budget governs unit size; hunters read their assigned files
through tools rather than receiving truncated source inline.

**Rule:** pick the per-agent budget first; derive every count-shaped limit from
it (`max_units = ceil(total / budget)`). A number that cannot be derived is a
number nobody can justify.

**Rule:** dropping a cap means fixing the O(n×k) hotspots that only survived
because of it (graphify community match was O(files × communities); it is now a
suffix index, O(files)).

## 2. Bytes as the weight, LOC as the knob

Weights are `stat().st_size` — no file reads, no tokenizer dependency, and
proportional to tokens for source code. The user-facing knob stays in LOC
(`loc_budget`, 10k) converted at `bytes_per_loc` (40 default; measure on real
targets — dense C and verbose Python break the constant in both directions).

**Rule:** weight by what you can measure for free; expose the unit humans think
in.

## 3. `max(nominal, ⌈total / MAX_UNITS⌉)` — the ceiling formula

10k LOC is a *quality* ceiling (what a hunter can depth-audit), not a context
ceiling (the window holds ~20k). For repos too big to fit in `MAX_UNITS` units
at the nominal budget, the ceiling **rises** to `total / MAX_UNITS` so the repo
spreads across the configured number of units. The alternatives all fail: merge overflow
re-creates the giant-unit blob; queueing contradicts a fixed `max_units`;
failing blocks large repos.

**Rule:** when a hard cap and a quality budget conflict, raise the budget —
never silently violate it, never merge your way out.

## 4. The LLM proposes; deterministic code disposes

An LLM partitioner is a *semantic planner*: business domains, bounded contexts,
"this utils.py function is just a date formatter." It is not an invariant
enforcer — it cannot do token arithmetic and drops things at scale. So:

- deterministic scaffold (graph, summaries) feeds the planner, never raw source;
- **after** the planner returns, `_enforce_coverage` + the balancer assert the
  invariants: every file exactly once, every unit within budget. Whoever proposed
  the units.

**Rule:** LLM output is a proposal. Invariants are enforced by code downstream of
it, on every path (planner output *and* the deterministic fallback).

## 5. Deterministic baseline, LLM enrichment — in that order

The original order was LLM-first-with-stats-fallback: every scan pays the planner,
and a planner failure degrades to directories. The rest of the harness runs the
other way (deterministic gate → LLM verdict → fail-open down the deterministic
path, cf. the validator's `evidence_gate` → `run_validation`). Partitioning now
matches: a valid baseline always exists; the LLM improves it or is ignored.

**Rule:** the fast deterministic path must be viable on its own; the LLM is an
enhancement, never a dependency.

## 6. No source inlining in hunter prompts

The orchestrator used to paste ~30k chars of unit source into the task prompt.
Removed: agents read assigned files via the built-in `read_file`/`grep`/`glob`
tools (already confined to the repo). The inline budget was a *truncating* core —
for any real unit most files weren't inlined anyway, and the truncation marker
contradicted the prompt's claim that review "does not depend on tool calls."

**Consequence:** hunters read assigned files through tools, but scan results do
not currently expose per-agent coverage. Keep the output contract limited to
consumed fields; if coverage reporting is added, wire it through the parser and
scan metadata before asking the model to emit it.

**Rule:** don't duplicate what the agent can fetch itself; if you remove a
mechanism, make its replacement observable.

## 7. The call graph proves reachability

Verified by spike: cross-file `calls` with extracted confidence, **no
intra-function dataflow, no stdlib-sink nodes**. `affected(sink)` proves
*who can reach* a function; it says nothing about whether the argument is
attacker-controlled. The tool docstring promising "ideal taint-chain evidence"
oversells it — an agent trusting that reports false positives.

**Rule:** a tool's capability boundary belongs in its docstring (the only
guidance the model sees), not in a module docstring only humans read. Skills are
for large, variable, on-demand knowledge; small always-relevant procedures belong
inline in the task prompt.

## 8. SAST runs per unit, not whole-repo

Semgrep/OpenGrep are agent tools invoked on the unit's own files, not an
indexer-stage whole-repo scan. Per-unit avoids semgrep's git-tracking surprises
(zero results in non-git trees), duplicated work across units, and a dead
normalization layer. Cost: the model parses raw JSON itself — the adversarial
validator is the backstop when it misreads.

---

## What adversarial validation of our own work caught

We ran a validator against this session's changes. It found a **blocker our own
tests missed**. The generalizable lessons:

### The invariant must hold at the END of the pipeline

The balancer split oversized units at step 1b — *before* the tiny-merge and the
`MAX_UNITS` cap-fold, both of which re-unite files size-blind into `misc`.
100 one-file packages (1MB) re-formed one `misc` blob at 2.5× target; a 40×100KB
monorepo hit 10×. My tests passed because they called `_balance_units` on
pre-split units and never exercised the merge path.

**Fix:** step 3b re-enforces the budget *after* merge/cap, and (added later)
refuses a fold that would re-form an over-budget blob: the byte budget is the
asserted invariant, the cap is a soft bound.

**Rule:** for "no unit over budget," the enforcement point is the last mutation,
not the first. Enumerate every later stage that can violate the invariant —
especially stages written for a different purpose (dedup, capping, merging).

### Wire the invariant checker into production

`verify_partition` existed but only tests called it, so violations would have
shipped silently. It now asserts in tests; production logs loudly on violation
(a scan must never die on a report, but nothing is silent).

**Rule:** an invariant only tests assert on is an invariant only tests see.
Log violations in production even when you believe they're impossible.

### Small ones with real bite

- **Mixed separators:** `PurePosixPath` treats `\` as an ordinary character, so
  `a\b\c.py` grouped under `.` — backslash paths silently lost directory
  affinity while the dir-based partitioner handled them. Normalize separators
  at every grouping site, not just the one you're looking at.
- **Absolute paths → empty keys:** `parts[0]` is `""` for `/abs/a.py`, producing
  units named `""` downstream (`hunter-`, `unit: ""`). Reachable the moment a
  single-file scan emits an absolute path.
- **Prompt/code drift:** removing the inlining left `UNIT_SYSTEM` promising
  files are "listed under Starting paths **and inlined in Source**" — the system
  prompt contradicting the task prompt. When you delete a mechanism, grep the
  prompts that describe it.
- **Vacuous tests:** `test_indexer_needs_no_whole_repo_semgrep` spied on
  `semgrep_full`/`opengrep_full` — functions nothing called anymore, so it
  passed trivially and guarded nothing. A test that can never fail is worse than
  no test: it reads as coverage.
- **Coercion edges:** YAML env interpolation delivers strings (`"10000"`, `"40"`);
  `0` must follow the codebase convention (unlimited), float budgets get
  truncated. Pin coercion in tests, don't assume.

---

## Process lessons

1. **Measure before you pick the number.** 10k LOC was argued from first
   principles; set it using measured review depth and eval F2 on a real benchmark
   at 2-3 budgets. Make it a config change, run the sweep.
2. **Read the tree before editing it.** A concurrent workstream refactored
   partitioning into its own package and extended the balancer mid-session; edit
   anchors from memory went stale. Verify on-disk state (or a diff) first.
3. **Attribute failures, don't assume.** 14 suite failures appeared that were
   none of ours (a concurrent sandbox-semantics change). We reproduced each and
   attributed by file before reporting — the same discipline the adversarial
   validator demands.
4. **Flaky tests poison determinism claims.** The balancer's whole value is
   reproducible partitioning; a nondeterministic test in the same subsystem
   undermines it. Fix or delete flakes before trusting a green suite.
5. **`.env` re-populates `API_KEY` even under `env -u API_KEY`** (only pytest
   skips dotenv). A "keyless" smoke run became a real, billable scan. The
   containment that protects the *agent* doesn't protect the *operator* from
   their own shell.

## Still open

- Hierarchical planner: the complete file inventory now reaches the planner,
  but very large repos still send it as one flat path list. Add hierarchical
  summaries that preserve every file while reducing prompt size.
- Doc rot: `pipeline.py` comments and `eval/partition_grade.py` still cite the
  pre-move `harness/units.py` path
