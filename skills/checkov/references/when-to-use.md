## When to use

Use Checkov when the target is **declarative infrastructure** and the question
is whether the configuration is insecure or non-compliant:

- **Terraform** — `.tf` and `.tf.json`: public S3 buckets, open security
  groups, unencrypted volumes/databases, wildcard IAM policies, missing logging
  or versioning, weak provider defaults.
- **Terraform plan JSON** — scan the rendered plan with
  `--framework terraform_plan` when the plan file already exists; this catches
  values produced by variables and modules that are not visible in source.
- **CloudFormation** — YAML or JSON templates, including nested stacks and
  resource `Metadata`.
- **Kubernetes manifests** — Pod/Deployment/DaemonSet specs: privileged
  containers, host networking, missing resource limits, writable root
  filesystems, weak RBAC.
- **Helm charts** — rendered chart templates, with values-driven defaults.
- **Dockerfiles** — root user, unpinned base images, missing healthchecks,
  secrets passed as build args.
- **ARM and Bicep** — Azure Resource Manager templates and Bicep sources
  (both frameworks are present at 3.3.26).
- **Kustomize overlays and Serverless Framework templates** — when those are
  the unit's deployment format.

Typical triggers: "audit our Terraform", "is this bucket public?", "check the
Kubernetes manifests for privileged containers", "scan the Helm chart", "why
does this Dockerfile fail our baseline?", "IaC misconfiguration scan", "CIS
benchmark for our templates", "policy check before `terraform apply`".

### Skip / disambiguate

- **Application source code** (Python, JavaScript, Go, Java, etc.) — use
  **semgrep** or **opengrep** for pattern and taint analysis. Checkov does not
  model application data flow and will not find injection sinks in business
  logic.
- **Secrets and credentials** — use **gitleaks** for worktree/history scanning
  or **trufflehog** when provider-side verification is needed. Do not treat a
  Checkov pass as evidence that no secret is committed.
- **Language-specific code SAST** — **bandit** for Python and **gosec** for Go.
  These understand language idioms that a resource-configuration scanner does
  not.
- **Privacy/data-flow review of application code** — **bearer** complements the
  code scanners; it is not an IaC policy engine.
- **Dependency vulnerabilities, license compliance, or container image
  scanning** — out of scope for this skill. Checkov's IaC frameworks answer
  configuration questions, not package CVEs.
- **One known string or a single grep** — no scanner needed; use `rg`.
- **Non-IaC configuration** (CI YAML with no deployable resources, app config
  files) — Checkov may parse generic `yaml`/`json`, but its checks are written
  for infrastructure resources; expect noise rather than coverage.

### Choosing between a directory and a file

Use `-d` for a unit's IaC directory (Terraform module, chart, manifest
directory). Use `-f` for one template or a plan file. If a directory contains
several deployment formats, scope with `--framework` rather than scanning
everything and guessing which report is which.
