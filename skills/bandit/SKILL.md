---
name: bandit
description: >-
  Run Bandit, the Python-specific security linter. Use when your unit's
  files are Python and you want AST-level checks (subprocess, SQL, eval,
  crypto, deserialization) that complement the semgrep/opengrep engines,
  and when you need CWE-tagged findings straight from Python's own AST.
---

# Bandit — Python Security Linter

Python's own specialist: direct AST checks with CWE tags, complementary to
the generic pattern rules of the semgrep family. Bandit answers "what does
this Python file *actually parse into*", not "what does it look like".

## In this environment

- Bandit is **preinstalled, pinned** (pip install in the scan image). Never
  install or upgrade it: the repo is read-only and egress may be denied.
- Pass **explicit file paths** (your unit's assigned `.py` files) or `-r` on
  the unit's directory. Bandit has no git-tracking filter, so a directory
  scan sees everything under it.
- Output discipline: `-f json`, then select with `jq`, cap with `head`, or
  write full output under `/work` (a writable tmpfs) and read back slices.
  Never paste raw scanner output into your answer — report findings only.
- Each `execute` is killed after the sandbox's command timeout (~120s).

## Running it

```bash
bandit -q -f json <files>                 # one file or many, space-separated
bandit -q -f json -r <dir>                # recursive over the unit dir
bandit -q -f json -s B101,B105 <files>    # skip noisy check ids
bandit --help                             # full flag list
```

`-q` keeps stderr quiet; `-f json` is the machine-readable form. Use `-s`
to silence checks the unit legitimately does not care about (e.g. `B101`
assert_used in a test fixture) rather than reporting them as noise.

**Exit codes**: bandit exits **1 when it finds issues** (and 2 on an internal
error). A non-zero exit after a `-o` write is a normal scan-with-findings,
not a failure — the JSON file is still complete.

## Reading the output

Top level: `results[]` of findings plus `errors[]` (parse failures — check
those, a failed parse means un-audited code, not clean code).

| Field | Meaning |
|---|---|
| `test_id` | rule id, e.g. `B608` (`hardcoded_sql_expressions`) |
| `issue_severity` | `HIGH` / `MEDIUM` / `LOW` |
| `issue_confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `issue_cwe.id` | CWE number, e.g. `89` |
| `filename` + `line_number` | location |
| `code` | the offending lines |
| `more_info` | URL to the rule's rationale |

Mapping a result to your finding contract: `cwe` from `issue_cwe.id`
(`CWE-<id>`), `severity` = `issue_severity` lowercased, and confidence
≈ 0.8 when both severity and confidence are HIGH, else 0.6.

## What bandit is not

Bandit flags **potential issues, not proven vulnerabilities**. An
`assert`-based finding, a `subprocess` call, or a `yaml.load` needs your own
reachability and sanitizer analysis before it becomes anything more than a
lead — the finding's `confidence` says how sure bandit is that the *pattern*
is present, not that it is exploitable. Run your own reachability reasoning
(statically via `read_file`/`grep`, or with the semgrep engines' taint mode
on the same lines) before reporting anything above `needs-review`.
