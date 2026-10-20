## When to use

- The user wants a vulnerability audit of installed dependencies and the tree has at least one supported **lockfile**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.mod`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pdm.lock`, `composer.lock`, `Gemfile.lock`, `pom.xml`, `gradle.lockfile`, `pubspec.lock`, `mix.lock`, `conan.lock`, `renv.lock`.
- The user wants one scan covering many languages instead of stitching `npm audit` + `cargo audit` + `bundler-audit` + `govulncheck` together.
- The user has an SBOM (SPDX or CycloneDX, using Package URLs) and wants to look up published vulnerabilities against it.
- The user wants a **dependency** view of a project — which resolved packages are known-vulnerable — not a source-code review.

**Skip** for:

- Secret scanning → `gitleaks` / `trufflehog`.
- Code-flaw / SAST → `semgrep` / `opengrep`.
- Finding *unused* deps → `knip`, `depcheck`.
- Container-filesystem and OS-package CVE scans → out of scope at this pin; image scanning needs a docker daemon the sandbox does not have.
- License-policy enforcement → 1.9.2 only has *experimental* license flags, and they depend on the deps.dev API, which is not in the sbx allowlist and may be unreachable under `network=none`. Treat licensing as out of scope.

Scanning needs egress to `api.osv.dev` at run time. The target repo mount is read-only, so choose a lockfile/SBOM path and write output under `$HOME` (per-agent scratch; `/work` itself is shared by concurrent agents).
