---
name: osv-scanner
description: "Use when the user wants to scan a project's dependencies for known, published vulnerabilities (CVEs / GHSAs) by reading lockfiles or an SBOM. Prefer osv-scanner over ecosystem audit tools for lockfiles and SBOMs."
---

# osv-scanner

## In this environment

- **Pinned: osv-scanner 1.9.2, image-only in the sandbox container.** Never install, upgrade, or fetch another build. It is not installed on the host; run it through the shell `execute` tool inside the sandbox.
- **Flat v1 CLI.** At 1.9.2 `scan` is the default command and takes flags plus paths directly: write `osv-scanner -r <dir> ...`. There is no separate `source` / `image` subcommand layer at this pin; do not use v2 subcommand syntax. Flags must precede the positional directory (`osv-scanner --format json -r /scan`); anything after `<dir>` is parsed as another path.
- **The target repo mount is read-only.** Write every report under `$HOME` — your per-agent scratch (`/work/agent-<id>`) inside the writable `/work` tmpfs. Concurrent agents share `/work`, so never use fixed `/work/<name>` paths; they race. Use `--output $HOME/osv.json` or `> $HOME/osv.json`.
- **Egress is required at scan time.** The scanner queries `api.osv.dev`. The sbx backend's allowlist covers `osv.dev` and `api.osv.dev`; the Docker backend defaults to `bridge` (full egress). Under `network=none` (or any allowlist that omits them) expect exit **129**, not a clean scan.
- **Output discipline.** Use `--format json` plus `--output $HOME/osv.json` (or a stdout redirect). Never paste raw JSON into your answer: select with `jq`, cap with `head`, and report findings only.
- **Exit codes.** `0` = no vulnerabilities; `1` = vulnerabilities found; `127` = general error; `128` = no packages found / nothing scanned (**not** clean); `129` = API or networking error (egress denial looks like this).

Verify the pin before relying on flags:

```bash
osv-scanner --version    # expect 1.9.2
```

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
