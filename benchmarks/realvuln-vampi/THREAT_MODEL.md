# Threat Model: realvuln-vampi

## 1. System context

Repo: realvuln-vampi. Threat model for realvuln-vampi | stack: unknown stack | entry points: ~0 routes | prefilter signal classes: sqli-cursor, redos-regex, jwt-decode-verify-false, path-open-join, debug-exposure | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): sqli-cursor, redos-regex, jwt-decode-verify-false, path-open-join, debug-exposure.

Day-one docs read: README.md.

## 2. Assets

| source code integrity | .github (2 files), api_views (5 files), database (1 files), models (3 files), openapi_specs (1 files), root (4 files) | high |
| data assets | _unknown — owner to confirm_ | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Database compromise and sensitive data exfiltration via SQL injection | remote_unauth | models/user_model.py | application data and system state | critical | almost_certain | unmitigated | none | models/user_model.py:72 [SQL Injection in User.get_user] |
| T2 | Information disclosure of sensitive application or configuration data | remote_unauth | api_views/users.py | application data and system state | high | almost_certain | unmitigated | none | api_views/users.py:24 [Unauthenticated debug endpoint exposes all user passwords and admin flags] |
| T3 | Security compromise via Unauthenticated database reset endpoint allows arbitrary DB wipe | remote_unauth | api_views/books.py, api_views/main.py, api_views/users.py | application data and system state | high | almost_certain | unmitigated | none | api_views/main.py:6 [Unauthenticated database reset endpoint allows arbitrary DB wipe]; api_views/users.py:19 [Missing authentication on user-list endpoint exposes all users]; api_views/users.py:45 [Missing authentication on user lookup endpoint enables unauthenticated enumeration]; api_views/books.py:12 [Missing authentication on book-list endpoint exposes inventory] |
| T4 | Horizontal privilege escalation via Insecure Direct Object References (IDOR) | remote_auth | api_views/books.py, api_views/users.py | application data and system state | critical | almost_certain | unmitigated | none | api_views/books.py:50 [Broken Object Level Authorization allows any user to read any book secret]; api_views/users.py:186 [Missing authorization allows any authenticated user to overwrite any user's password] |
| T5 | Privilege escalation or unauthorized state tampering via mass assignment | remote_auth | api_views/users.py | application data and system state | critical | almost_certain | unmitigated | none | api_views/users.py:60 [Mass-assignment in registration allows unauthenticated admin account creation] |
| T6 | Security compromise via Hardcoded default credentials with plaintext password storage | remote_unauth | models/user_model.py | application data and system state | high | almost_certain | unmitigated | none | models/user_model.py:97 [Hardcoded default credentials with plaintext password storage] |
| T7 | Security compromise via Login oracle enables username and password enumeration | remote_unauth | api_views/users.py | application data and system state | medium | almost_certain | unmitigated | none | api_views/users.py:101 [Login oracle enables username and password enumeration] |
| T8 | Security compromise via Flask debug mode enabled on public interface | remote_unauth | app.py | application data and system state | medium | almost_certain | unmitigated | none | app.py:17 [Flask debug mode enabled on public interface] |
| T9 | Security compromise via Regular expression denial of service in email update via nested-quantifier regex | remote_unauth | api_views/users.py | application data and system state | medium | almost_certain | unmitigated | none | api_views/users.py:144 [Regular expression denial of service in email update via nested-quantifier regex] |

## 5. Deprioritized

None recorded by the deterministic floor. A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-vampi
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history
- owner: unset
- enrichment: deterministic
- stored scan signals:
  - prefilter: .cerberus/realvuln-vampi/signals/prefilter.txt (12 entries)
  - secrets: .cerberus/realvuln-vampi/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-vampi/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-vampi/signals/iac.json (2 entries)
  - codegraph-index: .cerberus/realvuln-vampi/signals/codegraph-index.txt (1 entries)
## 8. Recommended mitigations

_unknown — owner to confirm (one class-level control per threat cluster; deterministic floor proposes none_).

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-vampi).
Confirmed primary claims: 13.

By class: CWE-306 x4, CWE-639 x2, CWE-89 x1, CWE-200 x1, CWE-915 x1, CWE-798 x1, CWE-203 x1, CWE-215 x1, CWE-1333 x1

Affected paths: api_views/users.py x7, models/user_model.py x2, api_views/books.py x2, api_views/main.py x1, app.py x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-1333 x1, CWE-200 x1, CWE-203 x1, CWE-215 x1, CWE-306 x4, CWE-639 x2, CWE-798 x1, CWE-89 x1, CWE-915 x1
