---
name: trufflehog
description: >-
  Run Trufflehog for verified secret detection. Use when a unit may contain
  credentials (API keys, tokens, private keys, connection strings) and you
  need candidates checked against the real service — a verified hit is far
  stronger evidence than a regex match.
---

# Trufflehog — Verified Secrets

Secret detection that goes past regex: Trufflehog's detectors identify
credential *formats* and, where the service supports it, **verify** the
candidate against the real API. A verified credential is evidence; an
unverified regex match is a lead.

## In this environment

- Trufflehog is **preinstalled, pinned** (sha256-verified release binary in
  the scan image). Never install or upgrade it: the repo is read-only and
  egress may be denied.
- **Always pass `--no-update`**: detector-set updates are a network fetch,
  and egress may be denied or restricted. The pinned detector set is what
  the image ships with.
- Current tree by default: `filesystem <dir>`. History scanning (git
  objects) is slow and duplicates gitleaks' role — only add it when a
  secret's history specifically matters.
- Pass the unit's directory, or a `/work` scratch dir with its files —
  never the repo root: there is no whole-repo scanner in Cerberus, so a
  root scan is yours alone and nothing else covers it.
- Output discipline: JSON lines; select with `jq`, cap with `head`, write
  full output under `/work` (writable tmpfs) and read back slices. Never
  paste raw output into your answer.

## Running it

```bash
trufflehog filesystem <dir> --json --no-update
trufflehog filesystem <file> --json --no-update        # a single file
trufflehog filesystem <dir> --json --no-update --results=verified   # verified only
trufflehog --version
```

Each line of stdout is one JSON object (JSON lines, not a JSON array).

## Reading the output

| Field | Meaning |
|---|---|
| `DetectorName` / `DetectorType` | what kind of credential, e.g. `Github`, `PrivateKey` |
| `Verified` | `true` = the real service confirmed this credential is live |
| `Raw` / `Redacted` | the secret itself / a masked form |
| `SourceMetadata.filename` / `linenumber` | where |

Mapping to your finding contract: CWE-798 (hardcoded credentials) for
embedded secrets, CWE-522 for weakly-protected ones; severity `high` for a
verified hit, `low`-to-`medium` for unverified; confidence ≈ 0.8 verified,
0.4 unverified. **Never put the raw secret in your report** — report path,
line, detector name, and verified status only (the snippet field is
`Redacted` or the detector name, never `Raw`).

## What trufflehog is not

Verification means live calls to third-party services **with the target
repo's credentials embedded** — under `bridge` egress that traffic leaves
the sandbox by design, and a verified hit silently tells the service
"someone is testing this key". That is the tool working as intended, but it
is a behavior to be deliberate about: unverified-only scans (`--results=unverified`
is the wrong flag — default JSON already carries `Verified`) or gitleaks are
the quieter option when egress is restricted. Absence of a finding is not
clean — a format the detector set does not know (an internal token scheme)
will pass silently, so union with the secret rules of the semgrep engines
and your own reading of the code.
