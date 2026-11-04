---
name: gitleaks
description: "Use when the user wants to find secrets, credentials, API keys, tokens, or passwords accidentally committed to a repository or sitting in a working tree. Use for secret and credential leak detection in worktrees, staged files, or history."
---


# gitleaks

Rule-based, entropy-aware secret detection over a working tree or a git history.

## In this environment

- gitleaks is **preinstalled in the scan image, pinned to 8.30.1** (release binary downloaded at image build; no checksum step — the image build is the trust anchor). It is never installed on the host — the shell `execute` tool is the only way to run it. Do not install, upgrade, or fetch a release; gitleaks itself needs no network.
- The target repo is mounted **read-only**. Write reports, baselines, and generated configs under **`$HOME`** — your per-agent scratch (`/work/agent-<id>`) inside the writable `/work` tmpfs. Concurrent agents share `/work`, so never use fixed `/work/<name>` paths; they race. Pointing `--report-path` at the mount fails with `Report path is not writable` and exit 1.
- Default to **`gitleaks dir <target>`**. `dir` reads files as files, so it works whether or not the tree has a `.git` directory. Use **`gitleaks git [repo]`** only when the target really contains `.git` and history is what you need: pointed at a non-repo it logs `fatal: not a git repository`, scans 0 commits, and still exits 0 — a silent blank, not a clean bill.
- Machine-readable output: `--report-format json --report-path <file>` (plus `--no-banner` and `--redact`). Never paste raw report JSON into an answer — summarize or filter it with `jq`/`head` (`jq` is installed in the image).
- The banner and every log line go to **stderr**, so `--report-path -` yields pure JSON on stdout.
- Each `execute` is killed at the sandbox command timeout (~120s): scope history scans with `--log-opts` or a subtree path instead of walking a whole monorepo's history.

## When to use

See [references/when-to-use.md](references/when-to-use.md). Load only when this section is needed.

## Invocation

See [references/invocation.md](references/invocation.md). Load only when this section is needed.

## Patterns

See [references/patterns.md](references/patterns.md). Load only when this section is needed.

## Anti-patterns

See [references/anti-patterns.md](references/anti-patterns.md). Load only when this section is needed.

## Cross-refs

See [references/cross-refs.md](references/cross-refs.md). Load only when this section is needed.
