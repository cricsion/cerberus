# Threat Model: realvuln-vulnnodeapp

## 1. System context

Repo: realvuln-vulnnodeapp. Threat model for realvuln-vulnnodeapp | stack: unknown stack | entry points: ~8 routes | prefilter signal classes: hardcoded-secret, js-exec, js-xss, debug-exposure, log-inject, weak-random, plaintext-creds, crlf | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-exec, js-xss, debug-exposure, log-inject, weak-random, plaintext-creds, crlf.

Day-one docs read: README.md.

## 2. Assets

| source code integrity | .github (1 files), bin (1 files), config (1 files), controllers (1 files), models (1 files), public (12 files), root (2 files), routes (2 files), utils (5 files), views (23 files) | high |
| data assets | _unknown — owner to confirm_ | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP request handlers (8 routes detected) | Web and REST API endpoints (~8 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~8 framework routes:*

- `USE /` (`app.js:42`)
- `POST /register` (`routes/users/index.js:12`)
- `POST /blind-sqli-blacklist` (`routes/users/index.js:26`)
- `POST /change-password` (`routes/users/index.js:46`)
- `POST /command-injection` (`routes/users/index.js:50`)
- `GET /arbitrary-file-retrieval` (`routes/users/index.js:52`)
- `POST /regex-injection` (`routes/users/index.js:56`)
- `POST /xxe` (`routes/users/index.js:60`)

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Database compromise and sensitive data exfiltration via SQL injection | remote_unauth | models/usersModel.js | application data and system state | critical | almost_certain | unmitigated | none | models/usersModel.js:7 [SQL Injection in UsersModel.findUserById]; models/usersModel.js:15 [Cross-unit SQL injection authentication bypass in login flow] |
| T2 | Remote code execution via untrusted operating system command injection | remote_unauth | utils/utility.js | application data and system state | medium | almost_certain | unmitigated | none | utils/utility.js:63 [Cross-unit OS command injection in ping feature] |
| T3 | Remote code execution via untrusted object deserialization | remote_unauth | utils/utility.js | application data and system state | medium | almost_certain | unmitigated | none | utils/utility.js:140 [Cross-unit insecure deserialization RCE via user cookie] |
| T4 | Security compromise via Plaintext password storage and comparison without hashing | remote_unauth | models/usersModel.js | application data and system state | high | almost_certain | unmitigated | none | models/usersModel.js:56 [Plaintext password storage and comparison without hashing] |
| T5 | Arbitrary file disclosure or tampering via path traversal | remote_unauth | utils/utility.js | application data and system state | medium | almost_certain | unmitigated | none | utils/utility.js:81 [Cross-unit path traversal arbitrary file read] |
| T6 | Arbitrary file disclosure via XML External Entity (XXE) injection | remote_unauth | utils/utility.js | application data and system state | medium | almost_certain | unmitigated | none | utils/utility.js:127 [Cross-unit XXE with external entity expansion] |
| T7 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | controllers/usersController.js, views/body-header.ejs | application data and system state | medium | almost_certain | unmitigated | none | controllers/usersController.js:58 [Cross-unit stored reflected XSS via unescaped EJS output]; views/body-header.ejs:34 [Cross-unit stored XSS via registration persisted to dashboard header]; views/body-header.ejs:16 [DOM-based XSS via default parameter] |
| T8 | Horizontal privilege escalation via Insecure Direct Object References (IDOR) | remote_auth | routes/users/index.js, routes/users/user.js | application data and system state | medium | almost_certain | unmitigated | none | routes/users/index.js:40 [Missing authorization IDOR on profile and password endpoints]; routes/users/user.js:122 [Insecure password change allows arbitrary account takeover via client-supplied id]; routes/users/index.js:16 [Missing authorization (IDOR) on error-based-sqli profile read/update] |
| T9 | Security compromise via Hardcoded session secret with insecure cookie flags | remote_unauth | app.js, config/config.js | application data and system state | high | almost_certain | unmitigated | none | app.js:25 [Hardcoded session secret with insecure cookie flags]; config/config.js:5 [Hardcoded default database credentials in application config] |
| T10 | Security compromise via Cross-unit regex injection ReDoS in log search | remote_unauth | utils/utility.js | application data and system state | medium | almost_certain | unmitigated | none | utils/utility.js:94 [Cross-unit regex injection ReDoS in log search] |
| T11 | Unauthorized state change via cross-site request forgery (CSRF) | remote_unauth | routes/users/index.js | application data and system state | medium | almost_certain | unmitigated | none | routes/users/index.js:16 [Missing CSRF protection on state-changing POST endpoints] |
| T12 | Security compromise via Sensitive information exposure via raw database error responses | remote_unauth | routes/users/user.js | application data and system state | medium | almost_certain | unmitigated | none | routes/users/user.js:36 [Sensitive information exposure via raw database error responses] |
| T13 | Security compromise via Missing rate limiting / brute-force protection on login and registration | remote_unauth | routes/users/index.js | application data and system state | medium | almost_certain | unmitigated | none | routes/users/index.js:8 [Missing rate limiting / brute-force protection on login and registration] |
| T14 | Security compromise via Insufficient session expiration: logout does not invalidate server session | remote_unauth | views/body-header.ejs | application data and system state | medium | almost_certain | unmitigated | none | views/body-header.ejs:64 [Insufficient session expiration: logout does not invalidate server session] |

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
- target: realvuln-vulnnodeapp
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history
- owner: unset
- enrichment: deterministic
- stored scan signals:
  - prefilter: .cerberus/realvuln-vulnnodeapp/signals/prefilter.txt (274 entries)
  - secrets: .cerberus/realvuln-vulnnodeapp/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-vulnnodeapp/signals/sca.json (1 entries)
  - iac: .cerberus/realvuln-vulnnodeapp/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-vulnnodeapp/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-vulnnodeapp/signals/routes.txt (8 entries)
## 8. Recommended mitigations

_unknown — owner to confirm (one class-level control per threat cluster; deterministic floor proposes none_).

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-vulnnodeapp).
Confirmed primary claims: 20.

By class: CWE-79 x3, CWE-639 x3, CWE-89 x2, CWE-798 x2, CWE-78 x1, CWE-502 x1, CWE-256 x1, CWE-22 x1, CWE-611 x1, CWE-1333 x1, CWE-352 x1, CWE-209 x1, CWE-307 x1, CWE-613 x1

Affected paths: utils/utility.js x5, routes/users/index.js x4, models/usersModel.js x3, views/body-header.ejs x3, routes/users/user.js x2, controllers/usersController.js x1, app.js x1, config/config.js x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-1333 x1, CWE-209 x1, CWE-22 x1, CWE-256 x1, CWE-307 x1, CWE-352 x1, CWE-502 x1, CWE-611 x1, CWE-613 x1, CWE-639 x3, CWE-78 x1, CWE-79 x3, CWE-798 x2, CWE-89 x2
