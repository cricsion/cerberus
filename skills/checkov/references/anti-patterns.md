## Anti-patterns

- **Don't parse the CLI table.** The human output is colored, wraps at terminal
  width, and changes wording between versions. Always request `-o json`, write
  it to `$HOME`, and select fields with `jq`.
- **Don't treat `--quiet` as "no output".** It still emits the JSON report
  (including to stdout when `--output-file-path` is used). At 3.3.26 it also
  narrows the JSON to `results.failed_checks` and drops passed/skipped/parsing
  errors. If you need those arrays, scan without `--quiet`.
- **Don't assume stdout is banner-free.** A clean `-o json` run at 3.3.26 did
  not print the CLI banner, but stdout can also carry notices and log lines in
  other configurations. Parse `$HOME/results_json.json`; only fall back to
  stdout if the file was not written.
- **Don't run without `--skip-download`.** It is the switch that disables
  Prisma Cloud API enrichment (metadata, severities, doc links, suppressions).
  The image also sets `BC_SKIP_MAPPING=TRUE` and
  `CKV_SKIP_PACKAGE_UPDATE_CHECK=True`, but passing the flag explicitly keeps
  the scan offline even if the environment changes.
- **Don't confuse IaC misconfiguration with code or secret scanning.**
  Checkov evaluates declarative resource configuration. Application-code
  patterns and taint flows belong to semgrep/opengrep; leaked credentials
  belong to gitleaks/trufflehog. A clean Checkov report says nothing about
  either.
- **Don't trust exit code `1` as a tool error.** `1` is the normal findings
  result and the JSON is still valid. `2` is the usage/crash code; check stderr
  for argparse errors or a traceback.
- **Don't filter by severity when offline.** With `--skip-download`,
  `severity`, `guideline`, and `bc_check_id` are `null`. Rank by check id,
  resource, and your own triage, not by a missing severity field.
- **Don't expect `--compact` to leave JSON intact.** At 3.3.26 `--compact`
  sets `code_block` and `connected_node` to `null` in JSON, despite the
  display-oriented help text. Request a normal scan when you need code blocks.
- **Don't run `--create-baseline` against the read-only mount.** It tries to
  write `.checkov.baseline` into the scanned directory and dies with `OSError`
  / exit `2`. Produce baselines from a writable copy under `$HOME`, or consume
  an existing baseline with `--baseline`.
- **Don't treat an empty scan as a clean scan.** A framework mismatch, a
  missing chart dependency, or a path outside the IaC tree yields
  `resource_count: 0`. Confirm the framework and target before reporting "no
  findings".
- **Don't assume the JSON is always an object.** A directory containing
  several frameworks produces a top-level array; a scan with no resources
  produces a summary-only object. Use the object-or-array normalization in
  [patterns.md](patterns.md).
- **Don't install, upgrade, or pin a different Checkov.** The Cerberus image is
  the only supported runtime, and the target tree is read-only. A host install
  will not match 3.3.26 behavior.
- **Don't use `--skip-check` to silence noise you have not triaged.** It
  removes checks from the run, so they disappear from the report entirely.
  Use per-resource `#checkov:skip=<ID>:<reason>` for accepted exceptions, and
  keep the reason with the code.
