## Invocation

Every command below is verified against the pinned **8.30.1** in the scan image.

```bash
# Default for a mounted target tree: works with or without .git
gitleaks dir <target> --no-banner

# Only when <target> actually has a .git directory: scan commit history
gitleaks git [repo] --no-banner

# Pre-commit / pre-push: staged diff only (requires a git repo)
gitleaks git --staged --no-banner

# Machine-readable report — write it under $HOME, never into the read-only mount
gitleaks dir <target> --report-format json --report-path $HOME/leaks.json --no-banner --redact

# JSON on stdout: banner and logs are stderr, so stdout stays pure JSON
gitleaks dir <target> --report-format json --report-path - --no-banner
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | no leaks |
| `1` | leaks **or** a scan error |
| `126` | unknown flag — a bad CLI invocation |

`1` is deliberately ambiguous: leaks and failures share the code, so the code alone cannot tell you which happened. A scan error exits `1` even with zero findings (nonexistent target, unwritable report path, fatal config error), and so does a run with real findings. Read the artifacts to separate them:

- **Leaks:** the report file contains entries and stderr ends with `leaks found: N` (verbose/human output also lists them).
- **Scan error:** stderr carries an `FTL`/`ERR` line such as `stat <path>: no such file or directory` or `Report path is not writable`, and the report file is missing, empty, or `[]`.

`--exit-code N` overrides the code used *when leaks are found* (default `1`); it does not change error handling, which still exits `1`. Use it only when a caller needs to distinguish leaks from failure by code — otherwise leave it at the default.

The inverse trap also exists: not every git plumbing problem is fatal. `gitleaks git` on a path with no `.git` logs `fatal: not a git repository` and `0 commits scanned`, then exits **0**; `gitleaks git --staged` outside a repo logs `error: unknown option 'staged'` and also exits **0**. Treat exit 0 as clean only when the report is empty **and** stderr shows no `ERR`/`FTL` lines.

The banner is written to **stderr**, along with all log output. `--report-path -` (and `--no-banner`) therefore leave stdout as pure JSON ready to pipe, while `--no-banner` only removes the ASCII banner — it does not silence the `INF`/`WRN` lines.

### Filesystem

The target tree is mounted read-only. Keep `--report-path`, `--baseline-path`, and any generated `.gitleaks.toml` under `$HOME`; anything written into the target mount fails the run with exit `1`.
