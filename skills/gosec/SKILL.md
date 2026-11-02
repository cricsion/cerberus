---
name: gosec
description: >-
  Run gosec, the Go security specialist. Use when your unit's files are Go
  (*.go) — command exec, SQL, file paths, crypto, race conditions, unsafe
  usage — where the generic pattern engines are weakest and Go's own idioms
  decide what is dangerous.
---

# gosec — Go Security Scanner

Bandit's Go counterpart: the Go specialist, with rules built around Go's
own idioms (`exec.Command`, `sql.Query`, `filepath.Join`, `crypto/md5`,
goroutines + shared state). Generic pattern rules miss most of these.

## In this environment

- gosec is **preinstalled, pinned** (sha256-verified release binary in the
  scan image). Never install or upgrade it: the repo is read-only and egress
  may be denied.
- Pass **explicit paths** — the unit's `.go` files, or `./...` from the unit
  directory. Never scan the repo root: there is no whole-repo scanner in Cerberus, and a bare directory only sees git-tracked files (the target tree
  may have no `.git` at all).
- gosec compiles a Go package, so the unit must be parseable Go; a file with
  syntax errors is reported, not scanned.
- Output discipline: `-fmt=json` (or `-fmt=sarif`), then select with `jq`,
  cap with `head`, or write full output under `/work` (writable tmpfs) and
  read back slices. Never paste raw output into your answer.

## Running it

```bash
gosec -fmt=json -quiet ./...                      # from the unit dir
gosec -fmt=json -quiet <files>                    # explicit files
gosec -fmt=json -quiet -include=G201,G204 <files> # only chosen rules
gosec -fmt=json -quiet -exclude=G104 <files>      # skip a noisy rule
gosec -rules rules.yaml -fmt=json ./...           # custom rule set
gosec -help                                       # full flag list
```

Rule ids: `G1xx` = misconfig/broad, `G2xx` = injection, `G3xx` = crypto,
`G4xx` = dangerous constructs, `G5xx` = misc, `G6xx` = file/path. `G104`
(unhandled errors) is the classic noise source — exclude it unless the unit
genuinely cares.

## Reading the output

```json
{
  "Issues": [
    {
      "severity": "HIGH", "confidence": "MEDIUM",
      "cwe": {"id": "CWE-78", "url": "..."},
      "rule_id": "G204",
      "details": "Subprocess launched with variable",
      "file": "main.go", "line": "42", "code": "..."
    }
  ],
  "Stats": {"files": 12, "lines": 840}
}
```

Map to the finding contract: `cwe` from `cwe.id`, `severity` lowercased,
`confidence` ≈ 0.8 when both severity and confidence are HIGH else 0.6,
`path`/`start_line` from `file`/`line`, `snippet` from `code`. Check
`Stats`/`Golang errors` in the output: a package that failed to compile was
not analyzed.

## What gosec is not

A compiler-level scanner, not a dataflow engine: it flags the dangerous
*construct*, not whether an attacker reaches it. `exec.Command(cmd)` where
`cmd` comes from config is a G204 finding whether or not it is reachable —
run your own reachability reasoning (and the semgrep engines' taint mode on
the same lines) before reporting anything above `needs-review`.
