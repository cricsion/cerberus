---
name: njsscan
description: >-
  Run njsscan (NodeJsScan) for Node.js/JavaScript-specific security rules.
  Use when your unit's files are .js/.ts/.jsx and you want Node-idiomatic
  checks — DOM XSS sinks, express misconfig, eval/Function, reverse
  shells, insecure randomness — that complement the generic engines.
---

# njsscan — Node.js Security Scanner

The Node specialist: rules written against the JS ecosystem's own footguns
(express, DOM APIs, `child_process`, template literals in SQL, `eval`/
`new Function`, weak randomness, serialization). Bandit's JavaScript
counterpart.

## In this environment

- njsscan is **preinstalled, pinned**. It is installed **isolated** into its
  own directory (`/opt/njsscan`) and exposed through a wrapper script, because
  it pins its own semgrep version that conflicts with the image's pinned
  semgrep. Just run `njsscan` — the wrapper sets the paths. Nothing to
  install or upgrade (the repo is read-only and egress may be denied).
- **No Node.js is required**: njsscan is pure Python over its bundled
  semgrep. (Node in the image is a separate opt-in for running *targets'*
  JS tests, not for this tool.)
- Pass **explicit paths** — the unit's `.js`/`.ts` files, or the unit
  directory. Never scan the repo root: there is no whole-repo scanner in this
  harness, and a bare directory only sees git-tracked files (the target tree
  may have no `.git` at all).
- Output discipline: `-o` to a JSON file under `/work` (writable tmpfs),
  then select with `jq`, cap with `head`, read back slices. Never paste raw
  output into your answer.

## Running it

```bash
njsscan <file-or-dir> -o /work/njsscan.json --json   # --json is REQUIRED
```

**`--json` is required**: without it, `-o` writes a colored text table
(box-drawing characters), not JSON — a JSON parse will fail. Its output
formats are `--json` / `--sarif` / `--sonarqube` / `--html`; `-c CONFIG`
adds custom rule files; `--missing-controls` reports missing security
controls rather than vulnerabilities. Do **not** pass semgrep's flags
(`--metrics off` etc.) — njsscan does not accept them.

## Reading the output

A JSON **dict**, not an array (verified against 1.0.1):

```json
{
  "errors": [],
  "njsscan_version": "0.4.2",
  "nodejs": {
    "eval_nodejs": {
      "files": [
        {
          "file_path": "canon.js",
          "match_lines": [4, 4],
          "match_position": [3, 23],
          "match_string": "requires login"
        }
      ],
      "metadata": {
        "cwe": "CWE-95: ...",
        "description": "...",
        "owasp-web": "A1: Injection",
        "severity": "ERROR"
      }
    }
  },
  "templates": {}
}
```

| Path | Meaning |
|---|---|
| `nodejs.<rule_id>.files[]` | one entry per hit: `file_path`, `match_lines[0]` (start line), `match_position`, `match_string` |
| `nodejs.<rule_id>.metadata` | `cwe` (full CWE **title** string), `description`, `owasp-web`, **`severity`** — the severity lives here, not on the finding |
| `templates` | non-Node template findings (Jinja etc.); empty dict for pure JS/TS |
| `errors` | files it could not analyze — check it |
| `njsscan_version` | the internal banner version, which lags the package (reports 0.4.2 on 1.0.1) — do not use it for verification |

Mapping to the finding contract: `cwe` from `metadata.cwe` (strip the title
after the colon — e.g. `CWE-79: ...` → `CWE-79`; leave blank if absent),
`severity` = `metadata.severity` lowercased, `path`/`start_line` from
`file_path`/`match_lines[0]`, and confidence ≈ 0.7 (pattern rules, not
dataflow). **`match_string` is semgrep's placeholder text** ("requires
login"), NOT the offending code — read the actual line with `read_file` for
the snippet. The Node ecosystem is template-literal heavy, so an "XSS"/"SQL
injection" hit needs your reachability reasoning before it is more than a
lead.

## What njsscan is not

Pattern-based and Node-version sensitive: a rule written for Express 4 may
fire on Express 5 idioms and vice versa. It also only sees what the bundled
rules cover — union it with the semgrep/opengrep engines (whose JS coverage
is broad) and, for dataflow across handlers, bearer.
