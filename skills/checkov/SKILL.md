---
name: checkov
description: >-
  Runs Checkov (pinned 3.3.26) against infrastructure-as-code to find
  misconfigurations: public buckets, permissive security groups, missing
  encryption, privileged containers, and weak Dockerfile or Helm defaults
  across Terraform and Terraform plan JSON, CloudFormation, Kubernetes
  manifests, Helm charts, Dockerfiles, ARM/Bicep, Kustomize, and Serverless
  templates. Use when the task is to audit IaC configuration and emit
  machine-readable JSON for triage. Not for application source-code pattern or
  taint analysis (use semgrep/opengrep) and not for secret or credential
  detection in code or git history (use gitleaks/trufflehog).
---

# checkov

## In this environment

- Checkov is **preinstalled in the scan image, pinned to 3.3.26**. It is
  image-only: never install, upgrade, or run another build on the host. Invoke
  it through the shell `execute` tool.
- The target repo is mounted **read-only**. Write JSON, stderr, and baselines
  under `$HOME` — your per-agent scratch (`/work/agent-<id>`) inside the
  writable `/work` tmpfs. Concurrent agents share `/work`, so never use fixed
  `/work/<name>` paths; they race. Never try to write into the target tree.
- Scans must be **offline by default**. Always pass `--skip-download`: it is
  the switch that stops Prisma Cloud API enrichment (policy metadata,
  severities, doc links, suppressions). The image also sets
  `BC_SKIP_MAPPING=TRUE` and `CKV_SKIP_PACKAGE_UPDATE_CHECK=True`; still pass
  the flag explicitly. Do not pass `--download-external-modules`, and block
  remote Helm/Kustomize dependencies when those frameworks are in scope.
- Output discipline: request `-o json` and write it under `$HOME`; select with
  `jq`, cap with `head`. Never paste raw JSON into the answer — report only the
  filtered findings.
- Exit code `1` means **findings**, and valid JSON is still produced. It is not
  a crash. Exit `0` means no failed checks (or a soft-fail configuration);
  other nonzero codes are usage/tool errors.

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
