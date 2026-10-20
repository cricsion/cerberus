## Patterns

### Pattern A — targeted directory scan with framework scoping

Point `-d` at the smallest directory that contains the unit's IaC. Checkov
walks recursively; on a monorepo a repo-root scan is slow and mixes unrelated
frameworks.

```bash
checkov -d "$TARGET/infra" --framework terraform \
  -o json --skip-download --quiet --output-file-path $HOME
```

Repeat `--framework` or use a comma-separated list for more than one runner:

```bash
checkov -d "$TARGET/deploy" --framework kubernetes --framework helm \
  -o json --skip-download --quiet --output-file-path $HOME
```

Common values at 3.3.26:

| Target | `--framework` |
|--------|---------------|
| Terraform (`.tf`, `.tf.json`) | `terraform` |
| Rendered Terraform plan JSON | `terraform_plan` |
| CloudFormation YAML/JSON | `cloudformation` |
| Kubernetes manifests | `kubernetes` |
| Helm chart directory | `helm` |
| `Dockerfile` | `dockerfile` |
| ARM templates | `arm` |
| Bicep files | `bicep` |
| Kustomize overlays | `kustomize` |
| Serverless Framework | `serverless` |

A framework that does not match the target does not raise an error; it produces
an empty scan. The no-resource shape is a top-level summary object (no
`.results`), so check `.summary.resource_count // .resource_count // 0`: if it
is `0`, suspect the framework flag before concluding the IaC is clean.

### Pattern B — one file, or an already-rendered template

```bash
# Single Terraform file
checkov -f "$TARGET/main.tf" -o json --skip-download --quiet --output-file-path $HOME

# CloudFormation template
checkov -f "$TARGET/template.yaml" --framework cloudformation \
  -o json --skip-download --quiet --output-file-path $HOME

# Terraform plan JSON (must already exist)
checkov -f "$TARGET/plan.json" --framework terraform_plan \
  -o json --skip-download --quiet --output-file-path $HOME
```

`-f` and `-d` are mutually exclusive. `-f` auto-selects runners from the file
extension; add `--framework` only to narrow that set or to pin
`terraform_plan` / `cloudformation` explicitly. Generating a plan
(`terraform init && terraform plan && terraform show -json`) needs write access
and usually network, so in this harness scan a plan only if it is already in
the mounted tree or was produced under `$HOME`.

### Pattern C — filter JSON with jq

The report is an object for one framework and an array for several, and a
summary-only object when nothing was scanned. Normalize first, then select.
Failed checks only, one TSV row per finding:

```bash
jq -r '
  (if type == "array" then .[] else . end)
  | .results.failed_checks[]?
  | [.check_id, (.severity // "unknown"), .file_path,
     (.file_line_range[0] // 0), .resource]
  | @tsv
' $HOME/results_json.json
```

`file_path` is relative to the scan root and starts with `/` (for example
`/main.tf`); `file_line_range` is `[start, end]`. With `--skip-download`,
`severity`, `guideline`, and `bc_check_id` are `null` because that metadata
comes from the Prisma Cloud API — never filter or rank by severity offline.

Counts and grouping:

```bash
# Total failed across every report in the file
jq '[ (if type == "array" then .[] else . end) | .summary.failed // 0 ] | add' \
  $HOME/results_json.json

# Most frequent check ids
jq -r '(if type == "array" then .[] else . end)
       | .results.failed_checks[]? | .check_id' $HOME/results_json.json \
  | sort | uniq -c | sort -rn | head -20
```

Inspect one finding without dumping the file:

```bash
jq '(if type == "array" then .[] else . end)
    | .results.failed_checks[]? | select(.check_id == "CKV_AWS_20")' \
  $HOME/results_json.json | head -60
```

If you need passed/skipped counts or `parsing_errors`, omit `--quiet`; at
3.3.26 quiet JSON contains only `results.failed_checks` (see
[invocation.md](invocation.md)).

### Pattern D — suppress an accepted finding inline

Terraform/CloudFormation/HCL-style comment inside the resource block:

```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "org-logs"
  #checkov:skip=CKV_AWS_18:access logging is configured by the org baseline
  acl    = "private"
}
```

Dockerfile:

```dockerfile
#checkov:skip=CKV_DOCKER_2:healthcheck is injected by the platform
FROM alpine:3.20
```

Kubernetes uses annotations rather than a comment:

```yaml
metadata:
  annotations:
    checkov.io/skip1: CKV_K8S_20=privilege escalation is blocked by admission policy
    checkov.io/skip2: CKV_K8S_14
```

CloudFormation can also use resource `Metadata`:

```yaml
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Metadata:
      checkov:
        skip:
          - id: "CKV_AWS_157"
            comment: "Multi-AZ is enforced by the account baseline"
```

The syntax is `#checkov:skip=<CHECK_ID>:<reason>` (the reason is optional but
should always be present). One comment per check; put multiple comments on
separate lines. A suppressed check becomes `SKIPPED`, not `FAILED`, and the
reason is preserved in the output. Suppress only accepted risk — not noise you
have not triaged.

### Pattern E — run-level check selection

```bash
# Run only specific checks (useful for verifying one remediation)
checkov -d "$TARGET" --check CKV_AWS_18,CKV2_AWS_6 \
  -o json --skip-download --quiet

# Remove noisy or out-of-scope checks for this run
checkov -d "$TARGET" --skip-check CKV_AWS_20,CKV2_AWS_62 \
  -o json --skip-download --quiet
```

`--skip-check` removes checks from the run entirely, so they never appear as
skipped and cannot be audited later. Prefer the inline suppression in Pattern D
when a specific resource is the accepted exception, and keep `--skip-check` for
checks that are genuinely out of scope.

### Pattern F — baseline for known-and-accepted findings

`--baseline` takes a `.checkov.baseline` file and reports only failures that
are new relative to it:

```bash
checkov -d "$TARGET" --baseline $HOME/accepted.checkov.baseline \
  -o json --skip-download --quiet --output-file-path $HOME
```

`--create-baseline` writes `.checkov.baseline` **into the scanned directory**,
so against the read-only target mount it fails with
`OSError: [Errno 30] Read-only file system` and exit `2` (verified at 3.3.26).
Create a baseline from a writable copy under `$HOME`, review it, then pass it
back with `--baseline`. A baseline is a security artifact: regenerate and
review it when the IaC changes, and never use it to hide a new class of finding.

### Pattern G — keep auxiliary fetches offline

`--skip-download` stops Prisma Cloud API calls, but it does not govern module
or chart fetching. Keep those off as well:

```bash
# Never do this in the harness:
#   --download-external-modules true

# Helm/Kustomize: block every remote dependency source
CHECKOV_HELM_ALLOWED_REMOTE_REPOS=none \
CHECKOV_KUSTOMIZE_ALLOWED_REMOTE_PREFIXES=none \
  checkov -d "$TARGET/chart" --framework helm \
    -o json --skip-download --quiet --output-file-path $HOME
```

If a chart or overlay needs a remote base that is not already vendored, report
it as unscannable rather than enabling network access.
