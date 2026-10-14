---
name: flawfinder
description: >-
  Run Flawfinder for C/C++ security checks. Use when your unit's files are
  C/C/C++ (*.c, *.h, *.cpp) — buffer functions, format strings, /tmp paths,
  integer conversions — the native-code breadth that the generic engines
  and opengrep's weaker C/C++ AST both miss.
---

# Flawfinder — C/C++ Security Scanner

A CWE-tagged pattern scanner for native code: ranked hits on the dangerous C
library functions (`strcpy`, `sprintf`, `gets`, `system`, `mktemp`,
`tmpnam`), format-string sinks, and unsafe integer conversions. Shallow —
pattern-level, CWE-mapped breadth for the language the semgrep family
covers least.

## In this environment

- Flawfinder is **preinstalled, pinned** (pip package — pure Python, no
  compilation needed). Never install or upgrade it: the repo is read-only and
  egress may be denied.
- Pass **explicit paths** — the unit's `.c`/`.h`/`.cpp` files or the unit
  directory. Never scan the repo root: there is no whole-repo scanner in this
  harness, and a bare directory only sees git-tracked files (the target tree
  may have no `.git` at all).
- Output discipline: `--csv` for machine reading or `-Q` for quiet text;
  write large output under `/work` (writable tmpfs) and read back slices
  with `jq`/`head`. Never paste raw output into your answer.

## Running it

```bash
flawfinder --csv -Q <files>                 # CSV, parse with jq/awk
flawfinder -Q -m 3 <files>                  # only level >= 3 (of 5)
flawfinder --html -Q . > /work/ff.html      # browsable report
flawfinder --minlevel=4 --columns <files>   # high-only, with context columns
```

Levels run 0–5 (5 = almost certainly a vulnerability, e.g. `gets`; 1 =
worth a look, e.g. `snprintf`). `--minlevel=4` (alias `-m 4`) is the good
default; drop it when recall matters more than signal-to-noise. Both spell
filter identically (verified: same row counts).

## Reading the output

CSV columns (verified against 2.0.20; there are **two** level columns and the
CWE column is named `CWEs`):

```
File,Line,Column,DefaultLevel,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context,Fingerprint,ToolVersion,RuleId,HelpUri
```

| Field | Meaning |
|---|---|
| `DefaultLevel` | the rule's built-in level, before any `-m` filtering |
| `Level` | the level actually reported (respects `-m`; read THIS one) |
| `Category` | e.g. `buffer`, `format`, `random`, `tmp` |
| `Name` | the dangerous function/variable, e.g. `strcpy` |
| `Warning` | what is wrong, per level |
| `CWEs` | comma-separated CWEs, e.g. `CWE-120` or `CWE-119!/CWE-120` |
| `Code`/`Context` | the offending line (in `--columns` output) |

The text form prints the same fields plus a histogram (`Hits@level`) and a
lines-analyzed summary. The C/C++ ruleset carries **222** rules — a bare
`strcpy` is a call site, not a vulnerability: it is exploitable only when the
source can exceed the destination, so confirm reachability before reporting
above `needs-review`.

## Suppressions and exit codes (verified)

- A comment containing `flawfinder:` on the hit's line **suppresses** that
  hit (`/* flawfinder: ignore */`, also `/* flawfinder: */`). A plain comment
  does not. The text form reports `Suppressed hits = N`; `--neverignore`
  shows everything.
- Exit code is **0 even with findings** (unlike bandit, which exits 1).

## What flawfinder is not

A lexical scanner: it matches known-dangerous names, so misses anything
behind a wrapper (`safe_copy(dst, src)`), anything with dataflow, and any
memory-safety bug that is not one of its ~50 built-in patterns. For native
dataflow you need manual reasoning (or a language server) — union it with
opengrep/semgrep (broad, structural) and reading the code.
