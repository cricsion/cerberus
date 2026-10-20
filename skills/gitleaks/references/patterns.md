## Patterns

### Pattern A — `git` (history) vs `git --staged` (pre-commit)

`gitleaks git` scans **commit history** (what is already in the object graph). `gitleaks git --staged` scans the **staged diff** only — it cannot see history, and it needs a real git repo. For a mounted target tree here, `git --staged` is usually the wrong tool: pick `dir` for the tree and `git` for history. Use `--staged` only when the unit is actually about what a commit is about to contain.

Running only `--staged` and never a history scan misses anything already merged — including leaks a hook once let through. `detect` and `protect` are deprecated aliases since v8.19.0: still functional at this pin, but hidden from `--help`, and their flags (`--source`, `--no-git`) do not exist on `dir`/`git`.

```bash
gitleaks git --no-banner                      # all of history
gitleaks git --staged --no-banner             # pre-commit
```

Verified on a throwaway repo: a secret committed then removed in a later commit is found by `git` (exit 1) and missed by `dir` (exit 0), because `dir` only sees the current tree.

### Pattern B — scope the history scan

Full-history scans get slow on old repos, and the sandbox kills a command at ~120s. `--log-opts` (no shorthand; `-l` is `--log-level`) accepts any `git log` flag set:

```bash
gitleaks git --log-opts="--all --since=6.months.ago" --no-banner
gitleaks git --log-opts="main..HEAD" --no-banner        # branch diff only
gitleaks git --log-opts="<sha1>..<sha2>" --no-banner    # just this push
```

Narrow by path too — the repository path is positional, and a subtree keeps both the object walk and the working set small:

```bash
gitleaks git ./services/api --no-banner
gitleaks dir ./services/api --no-banner
```

### Pattern C — JSON reporting

```bash
gitleaks dir <target> --report-format json --report-path $HOME/leaks.json --no-banner
gitleaks dir <target> --report-format json --report-path - --no-banner   # stdout
```

Formats at this pin are `json`, `csv`, `junit`, `sarif`, and `template`. JSON is the one to default to: it is stable to parse and carries the fields you need to report. Each finding has `RuleID`, `Description`, `File`, `StartLine`/`EndLine`, `Match`, `Secret`, `Commit`, `Author`, `Date`, `Fingerprint`, and `Tags`; `dir` findings have an empty `Commit` (and a `<file>:<rule>:<line>` fingerprint), `git` findings carry the commit.

Select before you read — never dump the file into your answer:

```bash
jq -r '.[] | "\(.RuleID)\t\(.File):\(.StartLine)\t\(.Commit[0:8])"' $HOME/leaks.json
head -c 2000 $HOME/leaks.json      # raw slice when you only need a peek
```

If the image you are on has no `jq` (`command -v jq`), `python3` is always present and the equivalent is:

```bash
python3 -c '
import json, os
for f in json.load(open(os.path.expanduser("~/leaks.json"))):
    print(f["RuleID"], f["File"] + ":" + str(f["StartLine"]), f["Commit"][:8], sep="\t")
'
```

The scan image ships `jq` (1.6), so the `jq` form above is the default; the
`python3` form is only a fallback for a stripped environment.

`--report-path -` plus `--no-banner` is the streaming form: stdout is the report, stderr is only banner/log noise, so `... --report-path - 2>/dev/null | head` works.

### Pattern D — baseline known-and-accepted leaks

Some hits are intentional fixtures (test keys, expired tokens). Snapshot them once, then ignore them on later runs:

```bash
# Generate the baseline under $HOME (the target is read-only), review it, then keep it
gitleaks dir <target> --report-format json --report-path $HOME/baseline.json --no-banner

# Later runs ignore anything present in the baseline
gitleaks dir <target> --baseline-path $HOME/baseline.json --no-banner
```

A baseline is a security artifact: review every entry before you rely on it, and regenerate it when fixtures change. In this sandbox the baseline lives under `$HOME` — scratch space for the run, not part of the read-only repo — so treat it as a filter for the current analysis rather than a committed, durable allowlist.

### Pattern E — `.gitleaks.toml` config

Default rules cover most providers. Extend with allowlists and custom rules. A `.gitleaks.toml` at the target root is picked up automatically (it is read-only, which is fine — reading works). If you generate one instead, write it to `$HOME` and pass `--config $HOME/my.toml`.

```toml
# .gitleaks.toml
title = "Project rules"
[extend]
useDefault = true

[allowlist]
description = "Test fixtures and example tokens"
paths = [
  '''testdata/.*''',
  '''docs/examples/.*\.md''',
]
regexes = [
  '''AKIAIOSFODNN7EXAMPLE''',           # provider docs example
  '''ghp_[A-Za-z0-9]{36}_FAKE_FIXTURE''',
]

[[rules]]
id = "internal-api-token"
description = "Acme internal API token"
regex = '''acme_(live|test)_[A-Za-z0-9]{32}'''
keywords = ["acme_live_", "acme_test_"]
entropy = 3.5
path = '''.*\.(go|ts|py)$'''
```

Config resolution order is `--config/-c`, then `GITLEAKS_CONFIG`, then `GITLEAKS_CONFIG_TOML` (inline TOML), then `<target>/.gitleaks.toml`. Pass `--config` explicitly when you are not sure.

### Pattern F — pre-commit hook (target repo's tooling, not the sandbox)

The sandbox never commits, and the mount is read-only, so a hook cannot be installed here. It is still worth recommending to the repo owner:

```bash
# .git/hooks/pre-commit
#!/usr/bin/env bash
gitleaks git --staged --redact --no-banner || {
  echo "gitleaks: secret detected in staged changes — abort." >&2
  exit 1
}
```

`--redact` in the hook keeps the leaked value out of terminal scrollback. When *fixing* a leak, re-run without `--redact` so you can see exactly what to rotate.

### Pattern G — performance and noise control

```bash
gitleaks dir <target> --max-target-megabytes 50 --no-banner   # skip huge blobs
gitleaks dir <target> --no-color --no-banner                  # plain text for logs
gitleaks dir <target> --max-archive-depth 1 --no-banner       # look inside archives
```

`--max-target-megabytes N` adds a size cutoff (default `0` = no limit) so large vendored blobs cannot dominate runtime; `--max-archive-depth` is opt-in because nested archives are a runtime cliff. `dir` walks the filesystem and does **not** apply `.gitignore` (verified: ignored files, dotfiles, and untracked files are all scanned), but the default config's **global allowlist still skips** `node_modules`, vendor trees, lockfiles, binary/media files, and `.git`; symlinks and empty files are skipped unless you opt in (`--follow-symlinks`; empty files are always skipped). Scope a noisy tree by subtree or an explicit allowlist instead of expecting `.gitignore` to do it. For a monorepo, scan the unit's subtree rather than the root, and keep one scan per `execute` so a slow history walk cannot hit the command timeout mid-run.

### Pattern H — remediation, not just detection

A finding is the start of the fix, not the fix. The order that actually works:

1. **Rotate first.** Assume the credential is compromised the moment it was committed; revoke/rotate at the provider before touching the repo.
2. **Purge history** for real leaks — `git filter-repo` (or BFG) plus a force-push. A follow-up commit that deletes the line leaves the blob reachable forever.
3. **Re-scan** (`git` over history, then `dir` over the tree) and confirm the report is empty.
4. Only then add a shape-based allowlist entry for legitimate fixtures, so the next scan is quiet for the right reason.
