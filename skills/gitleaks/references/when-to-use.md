## When to use

- The user asks to scan a repo for committed secrets — keys, tokens, passwords, private keys.
- The user wants a gate that blocks accidentally staged or pushed credentials.
- The user is preparing a repo for open-sourcing and needs to audit history (not just HEAD) for leaks.
- The user wants a build to fail when a change introduces a credential pattern.
- The user has a non-git directory (a tarball, a vendored snapshot, an extracted artifact) and wants the same rule pack applied — this is `gitleaks dir`, and it is the default here.

**Skip** for: code-quality / SAST scans (use `semgrep` / `opengrep`); dependency vulnerabilities (use `osv-scanner`); license checks; secrets that already escaped to runtime logs (rotate first, then audit upstream); a generic `grep` for one specific known string; checking whether a found credential is still live (use `trufflehog`, and note it needs egress).

Scan the **unit's** subtree, not the repo root: the harness gives no whole-repo scanner, so the root scan is yours alone and nothing else covers it.
