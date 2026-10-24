## Patterns

### Pattern A — recursive vs explicit lockfile

`-r` / `--recursive` walks the tree and discovers every supported lockfile and SBOM. Use it for monorepos and unfamiliar trees. Use `-L` / `--lockfile` when you want a focused, deterministic scan (one service, one CI job per ecosystem):

```bash
osv-scanner --format json --output $HOME/osv-recursive.json -r <dir>   # discover everything
osv-scanner -L services/api/package-lock.json --format json            # one lockfile
osv-scanner -L services/api/package-lock.json \
             -L services/billing/Cargo.lock \
             --format json                                             # multiple
```

`-L` is repeatable. A recursive scan of a very large tree can be slow and may hit the per-`execute` timeout, so scope it to the project or service you are auditing.

### Pattern B — output formats

```bash
osv-scanner --format table -r <dir>                          # human-readable (default)
osv-scanner --format json --output $HOME/osv.json -r <dir>    # machine-readable
osv-scanner --format markdown --output $HOME/osv.md -r <dir>  # report-friendly
```

JSON goes to the `--output` file (or stdout with a redirect), with diagnostics on stderr. Summarize it with `jq` rather than dumping it:

```bash
jq -r '
  .results[] as $r
  | $r.packages[]
  | select((.vulnerabilities // []) | length > 0)
  | [$r.source.path, .package.name, .package.version,
     ([.vulnerabilities[].id] | join(","))]
  | @tsv
' $HOME/osv.json | head -40
```

Each finding carries the source lockfile/SBOM path, package name and version, and one or more advisory IDs (aliases group the same issue).

### Pattern C — `osv-scanner.toml` for time-boxed ignores

Some advisories are not exploitable in a given application (server-side path, dev-only dependency, mitigated by config). Acknowledge them with a *time-boxed* ignore:

```toml
# $HOME/osv-scanner.toml  (the target mount is read-only; keep it under $HOME)
[[IgnoredVulns]]
id = "GHSA-xxxx-xxxx-xxxx"
ignoreUntil = 2027-07-01
reason = "Dev-only dep; not in production bundle. Re-evaluate when upstream lands a fix."

[[PackageOverrides]]
name = "lodash"
ecosystem = "npm"
ignore = true
effectiveUntil = 2027-07-01
reason = "Pinned to internal fork; CVEs already patched in fork."
```

Pass it explicitly because you cannot write into the target tree:

```bash
osv-scanner --config $HOME/osv-scanner.toml --format json -r <dir>
```

1.9.2 treats `ignoreUntil` (and `PackageOverrides.effectiveUntil`) as optional in the file format. **Harness policy makes `ignoreUntil` mandatory**: an ignore without an expiry rots silently, and the scanner will never re-flag the dependency. Always set a date and re-review.

### Pattern D — SBOM input

When the project ships an SBOM (release artifact, supply-chain attestation), scan against the SBOM rather than re-reading lockfiles. Faster, and it matches what consumers see:

```bash
osv-scanner --sbom=$HOME/build/sbom.spdx.json --format json --output $HOME/osv-sbom.json
osv-scanner --sbom=$HOME/build/sbom.cdx.json --format json
```

SPDX and CycloneDX are both auto-detected. When scanning a directory recursively, only SBOMs with the specification's recognized filenames are picked up; use `--sbom=` to point at an arbitrarily named file.

### Pattern E — manifests, lockfiles, and `--experimental-no-resolve`

Lockfiles and SBOMs list *resolved* versions, so they are the deterministic input. Manifest-only trees are weaker: at 1.9.2, Maven `pom.xml` transitive resolution is enabled by default and fetches package metadata from the deps.dev API. That API may be unreachable under `network=none`, so resolution can fail with exit `129` (or produce a partial graph).

`--experimental-no-resolve` disables transitive resolution:

```bash
osv-scanner --experimental-no-resolve --format json -r <dir>   # only OK with a lockfile/SBOM present
```

It is **only safe when a vendored lockfile (`gradle.lockfile`, dependency locking, or a CycloneDX SBOM) already lists the resolved versions**. Otherwise you will scan zero transitive dependencies and get a misleadingly small result set. `gradle.lockfile` and the other supported lockfiles need no resolution step.

### Pattern F — license reporting (experimental, usually unavailable)

1.9.2 has license reporting, but only behind experimental flags, and the data comes from the deps.dev API:

```bash
osv-scanner --experimental-licenses-summary <dir>
osv-scanner --experimental-licenses="MIT,Apache-2.0,BSD-3-Clause" <dir>
```

Because deps.dev may be unreachable under `network=none`, treat these commands as unavailable in the normal scan path; a deps.dev failure surfaces as exit `129`. If the flag does run, the output is a triage hint, not legal compliance — license strings in package metadata are inconsistent (`SEE LICENSE IN file`, mis-tagged dual licenses, vendored sub-deps with their own terms).
