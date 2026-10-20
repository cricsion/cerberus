## Invocation

Pinned osv-scanner **1.9.2** — the flat v1 CLI. Run `osv-scanner ...` directly. At this pin `scan` is the default command and accepts flags plus paths; there is no separate `source` / `image` subcommand layer. Do not use v2 subcommand syntax.

```bash
# Recursive scan: walks subdirs, discovers every supported lockfile/SBOM
osv-scanner --format json --output $HOME/osv.json -r <dir>

# Same, writing via stdout redirect
osv-scanner --format json -r <dir> > $HOME/osv.json

# Single lockfile
osv-scanner -L path/to/package-lock.json --format json
osv-scanner -L path/to/Cargo.lock --format json
osv-scanner -L path/to/go.mod --format json

# Multiple lockfiles: --lockfile / -L is repeatable
osv-scanner -L path/to/package-lock.json \
             -L path/to/Cargo.lock \
             --format json

# Parser override: force the requirements.txt parser on an oddly named file
osv-scanner --lockfile 'requirements.txt:/path/to/extra-deps.txt' --format json

# SBOM input (SPDX or CycloneDX; format auto-detected)
osv-scanner --sbom=/path/to/sbom.spdx.json --format json
osv-scanner --sbom=/path/to/sbom.cdx.json --format json

# Also scan files that .gitignore would skip (default: ignored files are skipped)
osv-scanner --format json --output $HOME/osv.json --no-ignore -r <dir>
```

**Flag order matters at 1.9.2.** The CLI stops parsing flags at the first
positional argument, so `osv-scanner -r /scan --format json` treats `--format`
as another directory to scan and exits `127` (`lstat --format`). Put every flag
before `-r <dir>`:

```bash
osv-scanner --format json --output $HOME/osv.json -r /scan   # correct
osv-scanner -r /scan --format json                           # WRONG: --format becomes a path
```

`-L <file>` consumes its value, so `osv-scanner -L package-lock.json --format
json` happens to work — but keep flags first for every form so the ordering
rule does not have to be remembered per flag.

Exit codes at 1.9.2:

| Code | Meaning | What to do |
| ---: | --- | --- |
| `0` | No vulnerabilities found | Clean — but only trust it if packages were actually scanned. |
| `1` | Vulnerabilities found | Hard fail; report them. |
| `127` | General error | Fix the invocation, config, or permissions. |
| `128` | No packages found / nothing scanned | **Not clean.** Fix the target path, lockfile selection, or parser override. |
| `129` | API or networking error | Egress to `api.osv.dev` failed. Retry where the allowlist covers `osv.dev` / `api.osv.dev`. |

`128` and `129` are both traps for CI: a wrong path can look like a clean scan, and a blocked network call is not "no vulnerabilities". Never `|| true` either one into a pass.
