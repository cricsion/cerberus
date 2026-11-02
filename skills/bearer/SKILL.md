---
name: bearer
description: >-
  Run Bearer, the dataflow and privacy scanner. Use when you need
  source-to-sink dataflow evidence or privacy/PII flows (logging, telemetry,
  unencrypted transmission) that pattern rules structurally miss — framework
  handlers, ORMs, template rendering, cloud SDK calls.
---

# Bearer — Dataflow + Privacy Scanner

A different engine lineage from the semgrep family: Bearer builds a
per-language analysis that follows data from sources to sinks and applies a
privacy lens on top. That overlap difference is the point — its misses and
hits are not the semgrep engines'.

## In this environment

- Bearer is **preinstalled, pinned** (sha256-verified release binary in the
  scan image). Never install or upgrade it: the repo is read-only and egress
  may be denied.
- Bearer resolves imports, so it always analyzes a **directory**, not loose
  files. Point it at the unit's directory, or a `/work` scratch dir with the
  unit's files copied in — never at the repo root: there is no whole-repo
  scanner in Cerberus, so a root scan is yours alone and nothing else
  covers it.
- Output discipline: `--format json`, then select with `jq`, cap with
  `head`, or write full output under `/work` (a writable tmpfs) and read
  back slices. Never paste raw scanner output into your answer.
- Each `execute` is killed after the sandbox's command timeout (~120s);
  Bearer is the slowest of the scanners, so keep the tree small.

## Running it

```bash
bearer scan <dir> --format json --report security --quiet
bearer scan <dir> --format json --report privacy --quiet
bearer scan <dir> --format sarif --report security   # SARIF form
bearer --version
```

`--report security` gives the vulnerability rules (dangerous sinks, weak
crypto, insecure deserialization). `--report privacy` gives PII/telemetry
flows — data leaking into logs, error reporting, analytics, or third-party
SDKs. Run both when the unit handles user data; security alone when it does
not.

## Reading the output

JSON: `findings[]` (older versions: `reports[]`/`results[]` — check what
you actually get, and adapt rather than guess).

| Field | Meaning |
|---|---|
| `id` | rule id, e.g. `python_lang_remote_code_execution` |
| `severity` | `critical` / `high` / `medium` / `low` / `warning` / `info` |
| `cwe_ids[]` | CWE numbers, e.g. `[78]` |
| `title` + `description` | what and why |
| `location.filename` / `location.line_number` | where the SINK is |
| `audit_context.locations` | every line involved in the match |
| `trace[]` (dataflow rules) | the source → sink chain, with file:line per hop |

Mapping to your finding contract: `cwe` from `cwe_ids[0]` (`CWE-<n>`),
`severity` lowercased, `path`/`start_line` from `location`, `snippet` from
the source lines. Dataflow findings carry `trace` — **that trace is real
taint evidence**; include it in the finding's `taint.path` rather than
re-deriving it.

## What bearer is not

Coverage is language-dependent (Python/JS/TS/Java/Ruby/Go/PHP in varying
depth) and it only sees dataflow it can resolve through imports — a wholly
dynamic call chain will not appear. Absence of a Bearer finding is not a
clean bill; union it with the semgrep engines and, on Python, bandit.
