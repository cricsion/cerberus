## Cross-refs

- Working tree vs history, `--log-opts` scoping, baselines, config, remediation: `references/patterns.md` (Patterns A–H).
- Exit-code handling and `--report-path -`: `references/invocation.md`; failure modes that look clean: `references/anti-patterns.md`.

Companion skills in this harness (all installed image-only, run through `execute`):

- `skills/semgrep/SKILL.md` and `skills/opengrep/SKILL.md` — pattern and taint SAST. Use them for code weaknesses; they will also flag some hardcoded-credential rules, but gitleaks is the dedicated sweep.
- `skills/trufflehog/SKILL.md` — verified secrets. gitleaks gives you the offline, rule-based sweep; trufflehog checks a candidate against the issuing provider. Verification is a network call, so it is unavailable or limited in a zero-egress sandbox; unverified trufflehog hits are leads, and gitleaks is the quieter cross-check.
- `skills/bearer/SKILL.md` — dataflow and privacy/PII flows; catches secrets that reach logs, telemetry, or third-party SDKs, which a string scan cannot see.
- `skills/osv-scanner/SKILL.md` — dependency vulnerabilities; a different question from committed credentials.

Upstream and references:

- <https://github.com/gitleaks/gitleaks>
- Config reference: <https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml>
- `gitleaks version` confirms the pin (8.30.1) inside the sandbox.
