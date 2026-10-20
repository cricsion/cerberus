## Cross-refs

Installed sibling skills in this harness:

- **Code pattern and taint analysis** — [semgrep](../../semgrep/SKILL.md) and
  [opengrep](../../opengrep/SKILL.md). Use them on application source (and on
  IaC-adjacent code such as CDK, Pulumi, or custom Terraform providers) where
  Checkov's resource-configuration checks do not apply.
- **Secrets and credential leaks** — [gitleaks](../../gitleaks/SKILL.md) for
  worktree/history rule scanning, and
  [trufflehog](../../trufflehog/SKILL.md) when live-key verification is required.
  A Checkov IaC pass is not a secret scan.
- **Language-specific SAST** — [bandit](../../bandit/SKILL.md) for Python and
  [gosec](../../gosec/SKILL.md) for Go.
- **Data-flow and privacy review of application code** —
  [bearer](../../bearer/SKILL.md).

Composition pattern for a unit that contains both infrastructure and code:

1. Run Checkov on the IaC directory/template (`--skip-download`, JSON under
   `$HOME`).
2. Run semgrep/opengrep on the application source, and the language specialist
   (bandit or gosec) when the language matches.
3. Run gitleaks on the tree; use trufflehog only if verification is needed.
4. De-duplicate by `file_path` + line: an IaC finding and a code finding on the
   same line are usually different issues, not duplicates.

Do not use Checkov as a substitute for any of the above, and do not merge its
severity model with the code scanners' models — offline Checkov has no
severity metadata.
