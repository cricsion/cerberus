## Invocation

### Primary: directory scan to JSON under `$HOME`

```bash
checkov -d "$TARGET" -o json --skip-download --quiet --output-file-path $HOME
```

At 3.3.26 `--output-file-path` takes an **output directory** (it is created if
missing) and writes one file per requested format. For `-o json` the exact file
is:

```
$HOME/results_json.json
```

Other formats use the same scheme, for example `results_sarif.sarif`,
`results_junitxml.xml`, `results_cli.txt`. The JSON is also echoed to stdout;
redirect it when you do not want it in the transcript:

```bash
checkov -d "$TARGET" -o json --skip-download --quiet --output-file-path $HOME >/dev/null
jq -r '(if type == "array" then .[] else . end)
       | [.check_type, ((.results.failed_checks // []) | length)] | @tsv' \
  $HOME/results_json.json
```

Prefer the file over stdout: the JSON path is deterministic, while stdout can
also carry log lines or notices (for example API-key warnings). In a clean
3.3.26 run with `-o json` we observed no banner on stdout, but that is not a
contract — the file is.

### Single file or template

```bash
checkov -f "$TARGET/main.tf" -o json --skip-download --quiet --output-file-path $HOME/tf
checkov -f "$TARGET/template.yaml" --framework cloudformation -o json --skip-download --quiet --output-file-path $HOME/cfn
checkov -f "$TARGET/plan.json" --framework terraform_plan -o json --skip-download --quiet --output-file-path $HOME/plan
```

Each directory receives its own `results_json.json`; use separate output
directories so one scan does not overwrite another's report.

`-f` / `--file` selects **what to scan**; it accepts one or more paths and
cannot be combined with `-d` / `--directory`. It is not framework selection.
`--framework` selects **which runners** analyze the target. Using
`-f main.tf --framework kubernetes` does not error; it silently yields an empty
scan.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No failed checks. Also returned when `--soft-fail` (or `--soft-fail-on`) suppresses the failure. |
| `1` | At least one failed check. **Valid JSON is still produced** — this is the normal findings case. |
| `2` | Usage error or internal crash (argparse errors, unhandled exception). `--no-fail-on-crash` turns crashes into `0`, so do not use it for triage. |
| other nonzero | Treat as a tool/usage error; read stderr. |

Do not use exit code `1` as an error signal in a pipeline, and do not use
`--soft-fail` when you need to distinguish a clean scan from a scan with
findings — read the JSON counts instead.

### `--quiet` and `--compact`

`--quiet` disables progress bars and narrows CLI output to failed checks.
`--compact` removes code blocks from CLI output. At 3.3.26 both flags also reach
the JSON writer:

- `--quiet` makes each report emit only `results.failed_checks` — passed,
  skipped, and parsing-error arrays are dropped, as is the top-level `url`.
- `--compact` sets `code_block` and `connected_node` to `null`.

The `--help` text describes them as display flags, but the JSON behavior above
is what the pinned version does. Do not rely on either flag to shape JSON:
request the fields you need and filter with `jq`. Drop `--quiet` if you need
passed/skipped counts or parsing errors.

### JSON envelope

One scanned framework produces an object:

```json
{
  "check_type": "terraform",
  "results": {
    "passed_checks": [],
    "failed_checks": [],
    "skipped_checks": [],
    "parsing_errors": []
  },
  "summary": {"passed": 0, "failed": 0, "skipped": 0},
  "url": "..."
}
```

Multiple frameworks (for example Terraform plus Kubernetes in one directory)
produce a **top-level array** of those objects. A scan that finds no resources
produces a summary-only object (`passed`, `failed`, `skipped`,
`parsing_errors`, `resource_count`, `checkov_version`). Filters must therefore
handle object-or-array and a missing `results`, as shown in
[patterns.md](patterns.md).
