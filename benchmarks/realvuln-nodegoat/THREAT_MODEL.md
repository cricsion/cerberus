# Threat Model: realvuln-nodegoat

## 1. System context

Repo: realvuln-nodegoat. Threat model for realvuln-nodegoat | stack: unknown stack | entry points: ~20 routes | prefilter signal classes: hardcoded-secret, js-exec, js-xss, debug-exposure, log-inject, open-redirect, weak-random, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-exec, js-xss, debug-exposure, log-inject, open-redirect, weak-random, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.md.

## 2. Assets

| source code integrity | .github (2 files), app (43 files), artifacts (1 files), config (5 files), root (5 files), test (17 files) | high |
| data assets | _unknown — owner to confirm_ | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP request handlers (20 routes detected) | Web and REST API endpoints (~20 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~20 framework routes:*

- `GET /` (`app/routes/index.js:30`)
- `GET /login` (`app/routes/index.js:33`)
- `POST /login` (`app/routes/index.js:34`)
- `GET /signup` (`app/routes/index.js:37`)
- `POST /signup` (`app/routes/index.js:38`)
- `GET /logout` (`app/routes/index.js:41`)
- `GET /dashboard` (`app/routes/index.js:44`)
- `GET /profile` (`app/routes/index.js:47`)
- `POST /profile` (`app/routes/index.js:48`)
- `GET /contributions` (`app/routes/index.js:51`)
- `POST /contributions` (`app/routes/index.js:52`)
- `GET /benefits` (`app/routes/index.js:55`)
- `POST /benefits` (`app/routes/index.js:56`)
- `GET /allocations/:userId` (`app/routes/index.js:63`)
- `GET /memos` (`app/routes/index.js:66`)
- *(and ~5 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Arbitrary code execution via dynamic code evaluation | remote_unauth | app/routes/contributions.js | application data and system state | critical | almost_certain | unmitigated | none | app/routes/contributions.js:32 [Server-Side JS Injection via eval(req.body.preTax) in handleContributionsUpdate] |
| T2 | Security compromise via Plaintext Password Storage in UserDAO.addUser | remote_unauth | app/data/user-dao.js | application data and system state | high | almost_certain | unmitigated | none | app/data/user-dao.js:30 [Plaintext Password Storage in UserDAO.addUser]; app/data/user-dao.js:62 [Plaintext Password Comparison in validateLogin] |
| T3 | Security compromise via Hardcoded Session Secret and Crypto Key in default config | remote_unauth | artifacts/cert/server.key, artifacts/db-reset.js, config/env/all.js | application data and system state | critical | almost_certain | unmitigated | none | config/env/all.js:8 [Hardcoded Session Secret and Crypto Key in default config]; artifacts/db-reset.js:20 [Default Administrative Credentials in db-reset.js]; config/env/test.js:6 [Hardcoded ZAP API Key in test config]; artifacts/cert/server.key:1 [Committed TLS Private Key in artifacts/cert/server.key] |
| T4 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | app/routes/benefits.js, app/routes/error.js, app/routes/memos.js | application data and system state | high | almost_certain | unmitigated | none | server.js:137 [Global Template Autoescape Disabled in server.js]; app/routes/memos.js:15 [Stored XSS via memo Markdown rendering in MemosHandler]; app/routes/research.js:23 [Reflected XSS via unsanitized SSRF body in displayResearch]; app/routes/profile.js:60 [Cross-Site Scripting via unescaped firstNameSafeString in handleProfileUpdate error path]; app/routes/profile.js:95 [Stored XSS via profile fields rendered unescaped on update success]; app/views/login.html:110 [Reflected XSS via userName in login.html]; app/routes/benefits.js:19 [Spoofed Admin Flag in BenefitsHandler.displayBenefits]; app/views/benefits.html:57 [Stored XSS via benefitStartDate in benefits.html]; app/views/benefits.html:51 [Stored XSS via firstName in benefits.html]; app/views/allocations.html:35 [Stored XSS via allo |
| T5 | Security compromise via NoSQL/JavaScript Injection via $where threshold interpolation in getByUserIdAndThreshold | remote_unauth | app/data/allocations-dao.js, app/data/user-dao.js | application data and system state | critical | almost_certain | unmitigated | none | app/data/allocations-dao.js:78 [NoSQL/JavaScript Injection via $where threshold interpolation in getByUserIdAndThreshold]; app/data/user-dao.js:97 [NoSQL Operator Injection Authentication Bypass in validateLogin]; app/data/user-dao.js:104 [NoSQL Operator Injection in getUserByUserName] |
| T6 | Horizontal privilege escalation via Insecure Direct Object References (IDOR) | remote_auth | app/routes/allocations.js, app/routes/benefits.js | application data and system state | high | almost_certain | unmitigated | none | app/routes/allocations.js:22 [Insecure Direct Object Reference in displayAllocations uses URL userId]; app/routes/benefits.js:35 [Horizontal IDOR / Missing Authorization in POST /benefits updateBenefits] |
| T7 | Phishing or credential theft via unvalidated open URL redirection | remote_unauth | app/routes/index.js | application data and system state | medium | almost_certain | unmitigated | none | app/routes/index.js:72 [Open Redirect in /learn via req.query.url] |
| T8 | Internal service access and cloud metadata exposure via Server-Side Request Forgery (SSRF) | remote_unauth | app/routes/research.js | application data and system state | high | almost_certain | unmitigated | none | app/routes/research.js:16 [Server-Side Request Forgery in displayResearch via url+symbol] |
| T9 | Security compromise via Regular Expression DoS (ReDoS) in bankRouting validation | remote_unauth | app/routes/profile.js | application data and system state | medium | almost_certain | unmitigated | none | app/routes/profile.js:57 [Regular Expression DoS (ReDoS) in bankRouting validation] |
| T10 | Security compromise via Insecure Session Cookie Configuration (missing HttpOnly/Secure) in server.js | remote_unauth | server.js | application data and system state | medium | almost_certain | unmitigated | none | server.js:73 [Insecure Session Cookie Configuration (missing HttpOnly/Secure) in server.js] |
| T11 | Unauthorized state change via cross-site request forgery (CSRF) | remote_unauth | app/routes/index.js, server.js | application data and system state | high | almost_certain | unmitigated | none | server.js:108 [Missing CSRF Protection (csurf disabled) in server.js]; app/routes/index.js:41 [Logout CSRF via State-Changing GET /logout] |
| T12 | Unauthorized access via missing authorization checks | remote_auth | app/routes/benefits.js, app/routes/index.js | application data and system state | high | almost_certain | unmitigated | none | app/routes/index.js:55 [Missing Function-Level Authorization on GET /benefits]; app/routes/benefits.js:44 [Spoofed Admin Flag in BenefitsHandler.updateBenefits] |
| T13 | Security compromise via User Enumeration via Distinct Login Error Messages in handleLoginRequest | remote_unauth | app/routes/session.js | application data and system state | medium | almost_certain | unmitigated | none | app/routes/session.js:65 [User Enumeration via Distinct Login Error Messages in handleLoginRequest] |
| T14 | Security compromise via Session Fixation in handleLoginRequest (no session regeneration) | remote_unauth | app/routes/session.js | application data and system state | high | almost_certain | unmitigated | none | app/routes/session.js:118 [Session Fixation in handleLoginRequest (no session regeneration)] |
| T15 | Security compromise via Weak Password Policy in validateSignup | remote_unauth | app/routes/session.js | application data and system state | medium | almost_certain | unmitigated | none | app/routes/session.js:150 [Weak Password Policy in validateSignup] |
| T16 | Security compromise via Disabled Helmet Security Headers in server.js | remote_unauth | server.js | application data and system state | medium | almost_certain | unmitigated | none | server.js:90 [Disabled Helmet Security Headers in server.js] |
| T17 | Security compromise via Cleartext HTTP Transport (HTTPS disabled) in server.js | remote_unauth | server.js | application data and system state | high | almost_certain | unmitigated | none | server.js:145 [Cleartext HTTP Transport (HTTPS disabled) in server.js] |
| T18 | Security compromise via Verbose Error Disclosure and XSS in errorHandler | remote_unauth | app/routes/error.js | application data and system state | medium | almost_certain | unmitigated | none | app/routes/error.js:11 [Verbose Error Disclosure and XSS in errorHandler] |
| T19 | Security compromise via Unencrypted Sensitive PII Storage in ProfileDAO.updateUser | remote_unauth | app/data/profile-dao.js | application data and system state | high | almost_certain | unmitigated | none | app/data/profile-dao.js:86 [Unencrypted Sensitive PII Storage in ProfileDAO.updateUser] |
| T20 | Audit log tampering or log injection via unneutralized log input | remote_unauth | app/routes/session.js | application data and system state | medium | almost_certain | unmitigated | none | app/routes/session.js:64 [Log Forging via Unsanitized userName in handleLoginRequest] |
| T21 | Security compromise via Secret Disclosure via Config Dump to Logs | remote_unauth | config/config.js | application data and system state | medium | almost_certain | unmitigated | none | config/config.js:13 [Secret Disclosure via Config Dump to Logs] |
| T22 | Security compromise via Missing Rate Limiting / Brute-Force Protection on POST /login | remote_unauth | app/routes/index.js | application data and system state | medium | almost_certain | unmitigated | none | app/routes/index.js:34 [Missing Rate Limiting / Brute-Force Protection on POST /login] |

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
- target: realvuln-nodegoat
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history
- owner: unset
- enrichment: deterministic
- stored scan signals:
  - prefilter: .cerberus/realvuln-nodegoat/signals/prefilter.txt (46 entries)
  - secrets: .cerberus/realvuln-nodegoat/signals/secrets.json (1 entries)
  - iac: .cerberus/realvuln-nodegoat/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-nodegoat/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-nodegoat/signals/routes.txt (20 entries)
## 8. Recommended mitigations

_unknown — owner to confirm (one class-level control per threat cluster; deterministic floor proposes none_).

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-nodegoat).
Confirmed primary claims: 44.

By class: CWE-79 x14, CWE-798 x4, CWE-943 x3, CWE-256 x2, CWE-639 x2, CWE-352 x2, CWE-862 x2, CWE-94 x1, CWE-601 x1, CWE-918 x1, CWE-1333 x1, CWE-614 x1, CWE-204 x1, CWE-384 x1, CWE-521 x1

Affected paths: server.js x5, app/data/user-dao.js x4, app/routes/index.js x4, app/routes/session.js x4, app/routes/profile.js x3, app/routes/benefits.js x3, app/routes/research.js x2, app/routes/error.js x2, app/views/benefits.html x2, app/routes/contributions.js x1, config/env/all.js x1, artifacts/db-reset.js x1, app/data/allocations-dao.js x1, app/routes/allocations.js x1, app/routes/memos.js x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-117 x1, CWE-1333 x1, CWE-204 x1, CWE-209 x1, CWE-256 x2, CWE-307 x1, CWE-312 x1, CWE-319 x1, CWE-352 x2, CWE-384 x1, CWE-521 x1, CWE-532 x1, CWE-601 x1, CWE-614 x1, CWE-639 x2, CWE-693 x1, CWE-79 x14, CWE-798 x4, CWE-862 x2, CWE-918 x1, CWE-94 x1, CWE-943 x3

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x9 at app/routes/profile.js, app/views/allocations.html, app/views/benefits.html, app/views/contributions.html, app/views/layout.html — doc.website = ESAPI.encoder().encodeForHTML(doc.website); | validator: app/views/profile.html:78 href uses firstNameSafeString not website; app/routes/profile.js:43-52 handleProfileUpdate never reads 
- CWE-798 x1 at config/env/development.js — zapApiKey: "v9dn0balpqas1pcc281tn5ood1", | validator: config/env/development.js:6 test zapApiKey used only by test/security/profile-test.js:28 local ZAP harness; config/env/development.js:9-12 environ
- CWE-338 x1 at app/routes/session.js — const stocks = Math.floor((Math.random() * 40) + 1); | validator: app/routes/session.js:14-16 Math.random only for stock/fund percentages; app/data/user-dao.js:50-55 Math.random only for display benef
- CWE-200 x1 at app/routes/memos.js — memosDAO.getAllMemos((err, docs) => { | validator: app/data/memos-dao.js:16-24 insert stores memo+timestamp with no owner; app/data/memos-dao.js:28 find({}) global board by design; app/routes/memos.js
- CWE-20 x1 at app/routes/index.js — app/routes/index.js:67 POST /memos registered with only isLoggedIn; app/routes/memos.js:11-13 inserts req.body.memo with no type/length/allowlist check; app/data/memos-dao.js:26-30 getAllMemos unbound
- CWE-307 x1 at app/routes/index.js — app/routes/index.js:38 POST /signup has no rate-limit, throttle, or CAPTCHA middleware; server.js registers no global rate limiter (no express-rate-limit), enabling unlimited account creation | valida
