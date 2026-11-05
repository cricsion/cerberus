# Threat Model: realvuln-vulpy

## 1. System context

Vulpy is an intentionally dual-variant Flask/SQLite teaching lab (bad/ deliberately vulnerable, good/ best-effort hardened) for secure-development courses. It implements login/logout, user creation, password change, per-user posts, MFA enrollment/verification with pyotp and QR codes, JSON API for key issuance and posts, CSP tester page, and optional SSL runner. Users are students acting as attackers against a local instance initialized with three default accounts and no permission model, using SQLite files for users/posts, /tmp files (bad) or short-lived JWTs (good) for API keys, and base64-JSON (bad) or Fernet-encrypted geo-bound (good) cookies for sessions.

Repo: realvuln-vulpy. Threat model for realvuln-vulpy | stack: unknown stack | entry points: ~35 routes | prefilter signal classes: hardcoded-secret, sqli-cursor, shell-true, jinja-render, ssrf-requests, jwt-decode-verify-false, path-open-join, cookie-flags, tpl-xss, debug-exposure, plaintext-creds, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, sqli-cursor, shell-true, jinja-render, ssrf-requests, jwt-decode-verify-false, path-open-join, cookie-flags, tpl-xss, debug-exposure, plaintext-creds, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.rst.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB) | Passwords and password hashes in SQLite users DB seeded with defaults | critical |
| Session tokens (base64 JSON cookie in bad; Fernet-encrypted geo-bound cookie in good; Flask SECRET_KEY) | vulpy_session cookies driving authentication and authorization | critical |
| MFA secrets and TOTP enrollment (mfa_secret column, QR provisioning URI) | Per-user TOTP secrets and enrollment QR codes | high |
| Posts data (db_posts.sqlite user-generated content) | User-generated posts read and written via web and API | medium |
| API keys (tmp file keys in bad; JWT bearer tokens in good) | Bearer tokens authorizing API post creation | high |
| Hardcoded crypto secrets (Flask SECRET_KEY, Fernet key, JWT secret MYSUPERSECRETKEY) | Static keys used for sessions and JWT signing | high |
| SQLite database files and /tmp key files (integrity/availability) | Local DB files and shared tmp key files | high |
| Process integrity and availability (Flask dev server, debug mode) | Local Flask dev server execution and availability | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP POST /user/login (form) | Form fields username/password/otp cross into libuser.login (bad raw SQL) and libmfa.mfa_validate; creates vulpy_session cookie on success bad/mod_user.py:9 good/mod_user.py:9 [refs: `bad/mod_user.py:9`, `good/mod_user.py:9`] | untrusted network client → Flask app / SQLite users DB | User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB), Session tokens (base64 JSON cookie in bad; Fernet-encrypted geo-bound cookie in good; Flask SECRET_KEY), MFA secrets and TOTP enrollment (mfa_secret column, QR provisioning URI) |
| HTTP POST /user/create (form) | Form username/password cross into libuser.create/user_create doing raw INSERT; no complexity check in bad bad/mod_user.py:38 good/mod_user.py:38 [refs: `bad/mod_user.py:38`, `good/mod_user.py:38`] | untrusted network client → application / DB | User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB), SQLite database files and /tmp key files (integrity/availability) |
| HTTP POST /user/chpasswd (form) | Form password/password_again (bad, no auth check, uses g.session username) and current/new passwords (good, re-authenticates) cross into password_change UPDATE bad/mod_user.py:64 good/mod_user.py:63 [refs: `bad/mod_user.py:64`, `good/mod_user.py:63`] | untrusted client (CSRF-able) → credential store; bad lacks current-password/authz check | User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB) |
| HTTP /posts (+ /posts/<username> GET, /posts/ POST) | Path param username and form field text cross into libposts.get_posts/post; view renders posts.view.html with /safe bad/mod_posts.py:11 bad/mod_posts.py:28 good/mod_posts.py:11 bad/templates/posts.view.html:30 [refs: `bad/mod_posts.py:11`, `bad/mod_posts.py:28`, `good/mod_posts.py:11`, `bad/templates/posts.view.html:30`] | untrusted path/form + stored posts → SQLite + Jinja render (stored XSS sink) | Posts data (db_posts.sqlite user-generated content), Session tokens (base64 JSON cookie in bad; Fernet-encrypted geo-bound cookie in good; Flask SECRET_KEY) |
| HTTP /mfa (GET/POST) + /mfa/disable GET | Form otp crosses into pyotp TOTP verify; GET view resets secret and emits provisioning URI + QR base64; /disable mutates mfa_enabled without OTP bad/mod_mfa.py:35 bad/mod_mfa.py:57 good/mod_mfa.py:24 [refs: `bad/mod_mfa.py:35`, `bad/mod_mfa.py:57`, `good/mod_mfa.py:24`] | authenticated session + OTP input → MFA enrollment store | MFA secrets and TOTP enrollment (mfa_secret column, QR provisioning URI), Session tokens (base64 JSON cookie in bad; Fernet-encrypted geo-bound cookie in good; Flask SECRET_KEY) |
| HTTP POST /api/key (JSON) | JSON body username/password crosses jsonschema validate then libuser.login / libapi.keygen; returns file-based key (bad) or JWT (good) bad/mod_api.py:30 good/mod_api.py:35 bad/libapi.py:7 good/libapi.py:15 [refs: `bad/mod_api.py:30`, `good/mod_api.py:35`, `bad/libapi.py:7`, `good/libapi.py:15`] | untrusted JSON → auth check → key issuance | User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB), API keys (tmp file keys in bad; JWT bearer tokens in good) |
| HTTP GET /api/post/<username> | Path username flows unsanitized into libposts.get_posts SELECT and JSON response; no auth required bad/mod_api.py:47 good/mod_api.py:50 [refs: `bad/mod_api.py:47`, `good/mod_api.py:50`] | untrusted URL path → DB read → JSON response | Posts data (db_posts.sqlite user-generated content) |
| HTTP POST /api/post (JSON + API key) | JSON text plus X-APIKEY header (bad, /tmp glob match) or Authorization: Bearer JWT (good) cross into libapi.authenticate then libposts.post bad/mod_api.py:54 good/mod_api.py:56 bad/libapi.py:24 good/libapi.py:28 [refs: `bad/mod_api.py:54`, `good/mod_api.py:56`, `bad/libapi.py:24`, `good/libapi.py:28`] | untrusted JSON + header token → auth → DB write | API keys (tmp file keys in bad; JWT bearer tokens in good), Posts data (db_posts.sqlite user-generated content) |
| HTTP GET /, /hello/, /csp/ | Trivial GET handlers; / redirects to /posts; /csp renders csp.html with external image/XHR/JS test vectors bad/vulpy.py:33 bad/mod_hello.py:7 bad/mod_csp.py:6 bad/templates/csp.html:1 [refs: `bad/vulpy.py:33`, `bad/mod_hello.py:7`, `bad/mod_csp.py:6`, `bad/templates/csp.html:1`] | untrusted network → Flask router / template render | application data and system state |
| Cookie vulpy_session deserialization | Cookie vulpy_session decoded via base64+json loads (bad, no integrity) or Fernet decrypt+TTL+country split (good); username drives g.session authz bad/libsession.py:12 good/libsession.py:33 [refs: `bad/libsession.py:12`, `good/libsession.py:33`] | client-controlled cookie → server session trust (auth boundary) | Session tokens (base64 JSON cookie in bad; Fernet-encrypted geo-bound cookie in good; Flask SECRET_KEY), MFA secrets and TOTP enrollment (mfa_secret column, QR provisioning URI), Posts data (db_posts.sqlite user-generated content) |
| Local file inputs (csp.txt, SQLite DBs, GeoIP DB) | csp.txt line-joined into Content-Security-Policy header; SQLite files db_users.sqlite/db_posts.sqlite opened per-request; GeoLite2-Country.mmdb read for country binding bad/vulpy.py:20 good/vulpy.py:19 bad/libuser.py:7 good/libsession.py:13 bad/db_init.py:7 [refs: `bad/vulpy.py:20`, `good/vulpy.py:19`, `bad/libuser.py:7`, `good/libsession.py:13`, `bad/db_init.py:7`] | local filesystem → process memory / HTTP headers | SQLite database files and /tmp key files (integrity/availability), Session tokens (base64 JSON cookie in bad; Fernet-encrypted geo-bound cookie in good; Flask SECRET_KEY) |
| CLI clients and utils (argv) | argv username/message/password drive requests to live API (api_list/api_post click clients) and subprocess-spawned login attempts (brute.py); utils expose similar argv/env crypto helpers bad/api_list.py:7 bad/api_post.py:9 bad/brute.py:1 good/httpbrute.py:1 [refs: `bad/api_list.py:7`, `bad/api_post.py:9`, `bad/brute.py:1`, `good/httpbrute.py:1`] | local operator args → network requests / subprocess spawn | User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB), API keys (tmp file keys in bad; JWT bearer tokens in good), Process integrity and availability (Flask dev server, debug mode) |
| Supply-chain / build (requirements.txt, install-on-kali.sh) | Unpinned deps (Flask, cryptography, PyJWT, pyotp, requests, etc.) and apt install script; no lockfile, Dockerfile, k8s, Terraform, or CI workflows requirements.txt:1 install-on-kali.sh:1 [refs: `requirements.txt:1`, `install-on-kali.sh:1`] | upstream packages / install-time root shell → deployed app integrity (no runtime input, but build-time entry) | Process integrity and availability (Flask dev server, debug mode) |
| /tmp API-key file store (bad) | /tmp/vulpy.apikey.<user>.<key> touched on keygen, glob-matched on authenticate; predictable tmp + glob split()[2] as identity bad/libapi.py:7 bad/libapi.py:24 [refs: `bad/libapi.py:7`, `bad/libapi.py:24`] | shared /tmp filesystem → API auth decision | API keys (tmp file keys in bad; JWT bearer tokens in good), SQLite database files and /tmp key files (integrity/availability) |
| HTTP request handlers (35 routes detected) | Web and REST API endpoints (~35 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |

### Key Detected Endpoints
*Detected ~35 framework routes:*

- `POST /key` (`bad/mod_api.py:30`)
- `GET /post/<username>` (`bad/mod_api.py:47`)
- `POST /post` (`bad/mod_api.py:54`)
- `GET /` (`bad/mod_csp.py:6`)
- `POST /` (`bad/mod_mfa.py:35`)
- `GET /disable` (`bad/mod_mfa.py:57`)
- `GET /<username>` (`bad/mod_posts.py:11`)
- `GET /login` (`bad/mod_user.py:9`)
- `GET /create` (`bad/mod_user.py:38`)
- `GET /chpasswd` (`bad/mod_user.py:64`)
- `POST /chpasswd` (`good/mod_user.py:63`)
- `POST post` (`good/mod_welcome1.py:20`)
- *(and ~23 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attackers forge or replay sessions and API tokens via tamperable cookies, predictable /tmp keys and hardcoded JWT/Fernet secrets to impersonate users | remote_unauth | Cookie vulpy_session deserialization, HTTP POST /user/login (form), HTTP POST /api/key (JSON), HTTP POST /api/post (JSON + API key), /tmp API-key file store (bad) | Session tokens (base64 JSON cookie in bad; Fernet-encrypted geo-bound cookie in good; Flask SECRET_KEY) | critical | almost_certain | unmitigated | good/libsession.py Fernet-encrypted session with TTL 7200s + GeoIP country binding; good/libapi.py JWT HS256 with nbf/exp window; bad uses base64 JSON with no integrity and static secrets | bad/vulpy.py:16 [Hardcoded secrets and default credentials]; bad/libapi.py:14 [Predictable API keys from non-cryptographic PRNG] |
| T2 | Attackers inject SQL through login, signup, posts and API inputs to bypass authentication and read or modify accounts and posts | remote_unauth | HTTP POST /user/login (form), HTTP POST /user/create (form), HTTP POST /user/chpasswd (form), HTTP /posts (+ /posts/<username> GET, /posts/ POST), HTTP POST /api/key (JSON), HTTP GET /api/post/<username>, HTTP POST /api/post (JSON + API key) | User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB) | critical | almost_certain | unmitigated | good/libuser.py parameterized SELECT with ? placeholder; good/mod_api.py jsonschema additionalProperties:False + username pattern; bad/libposts.py partial ? use; bad remains string-format SQL | bad/libsession.py:20 [Broken authentication: unsigned base64 session cookie allows forgery]; bad/libapi.py:30 [API authentication bypass via glob injection in /tmp key lookup] |
| T3 | Attackers steal plaintext passwords and hardcoded Flask/Fernet/JWT secrets from DB files, debug pages and source to take over accounts | remote_unauth | HTTP POST /user/login (form), HTTP POST /user/create (form), HTTP POST /user/chpasswd (form), Local file inputs (csp.txt, SQLite DBs, GeoIP DB) | User credentials (plaintext passwords in bad DB; scrypt hash+salt in good DB) | critical | almost_certain | unmitigated | good/libuser.py scrypt KDF with random salt + is_password_allowed length and denylist; bad stores plaintext with no policy and debug exposure | bad/libuser.py:53 [SQL injection in password_change via chpasswd (cross-unit)] |
| T4 | Attackers bypass, reset or disable MFA and change passwords via CSRF, missing re-authentication and brute-forced OTPs to elevate to victim accounts | remote_auth | HTTP POST /user/chpasswd (form), HTTP /mfa (GET/POST) + /mfa/disable GET, Cookie vulpy_session deserialization, CLI clients and utils (argv) | MFA secrets and TOTP enrollment (mfa_secret column, QR provisioning URI) | critical | almost_certain | unmitigated | good/mod_user.py chpasswd requires current_password re-auth; good/mod_mfa.py weak Referer check on /mfa/disable; bad has no CSRF/current-password check | bad/libapi.py:10 [API key issuance authentication bypass with empty password]; bad/mod_user.py:64 [Missing authentication/CSRF controls on chpasswd and MFA disable]; bad/libsession.py:7 [Insecure configuration: cookie without flags, debug mode, no brute-force protection]; good/mod_mfa.py:64 [MFA disable protected only by spoofable Referer check plus state-changing GET]; bad/mod_posts.py:25 [Missing CSRF on POST /posts enables forced stored-post creation] |
| T5 | Attackers execute commands, exhaust the dev server and poison unpinned dependencies or install scripts to compromise integrity and deny service | local_user | CLI clients and utils (argv), Supply-chain / build (requirements.txt, install-on-kali.sh), HTTP GET /, /hello/, /csp/ | Process integrity and availability (Flask dev server, debug mode) | high | possible | unmitigated | none |  |
| T6 | Attackers inject stored and reflected scripts via posts and form fields rendered unescaped to hijack sessions of viewers | remote_unauth | HTTP /posts (+ /posts/<username> GET, /posts/ POST), HTTP GET /, /hello/, /csp/ | Posts data (db_posts.sqlite user-generated content) | high | almost_certain | unmitigated | Flask after_request CSP header from csp.txt if present; bad/templates/posts.view.html uses /safe with no encoding | good/templates/posts.view.html [template reflection surface]; bad/templates/posts.view.html:23 [Stored XSS via posts rendered with /safe (cross-unit web+API to template)] |
| T7 | Attackers traverse paths, poison CSP headers, squat predictable /tmp keys and trigger SSRF to read or corrupt server files and sessions | remote_unauth | Local file inputs (csp.txt, SQLite DBs, GeoIP DB), /tmp API-key file store (bad), HTTP GET /, /hello/, /csp/ | SQLite database files and /tmp key files (integrity/availability) | high | possible | unmitigated | none |  |
| T8 | Database compromise and sensitive data exfiltration via SQL injection | remote_unauth | bad/libuser.py | application data and system state | critical | almost_certain | unmitigated | none | bad/libuser.py:12 [SQL injection in bad libuser.login] |
| T9 | Privilege escalation via incorrect authorization enforcement | remote_auth | bad/mod_api.py | application data and system state | high | almost_certain | unmitigated | none | bad/mod_api.py:69 [API mass-assignment allows forging posts as arbitrary user] |
| T10 | Security compromise via Glob-injection arbitrary file deletion in API key rotation | remote_unauth | bad/libapi.py | application data and system state | high | almost_certain | unmitigated | none | bad/libapi.py:16 [Glob-injection arbitrary file deletion in API key rotation] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Cryptographic downgrade or privacy-deanonymization of posts beyond session/credential theft | No parsers, crypto agility, or privacy-regulated data observed in lab scope; generic hardening deferred to hardening backlog rather than distinct attacker goal. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is only bad/ in scope or is good/ also deployed, given no SECURITY.md or scope manifest beyond requirements.txt?
- Is Flask dev server with debug=True on 127.0.1.1:5000/5001 exposed beyond loopback, and is there production WSGI, TLS termination (vulpy-ssl.py /tmp/acme.cert/key), WAF or reverse proxy?
- Do csp.txt, GeoLite2-Country.mmdb and leaked_passwords.txt ship with deployment and with what permissions?
- Are seeded defaults admin/SuperSecret, elliot/123123123, tim/12345678 lab-only or present in any shared deployment, and who owns residual /tmp keys and SQLite files?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-vulpy
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-vulpy/signals/prefilter.txt (138 entries)
  - secrets: .cerberus/realvuln-vulpy/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-vulpy/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-vulpy/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-vulpy/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-vulpy/signals/routes.txt (35 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Enforce parameterized queries and least-privilege DB access on every SQL path | T2 | partial | M |
| Replace client-controllable sessions and static secrets with random server-side secrets and integrity-protected tokens | T1,T4 | partial | M |
| Hash passwords with salted KDF, enforce allowlist and leaked-password check, and remove debug/default-credential exposure | T3 | partial | M |
| Require current-password re-auth, anti-CSRF tokens, and no state-changing GETs for credential and MFA changes with rate-limiting | T4 | partial | M |
| Autoescape by default, context-aware output encoding, and restrictive CSP with no inline/external test vectors | T6 | partial | M |
| Validate and confine all filesystem and network egress with allowlists, safe joins, and no shared-/tmp auth state | T7 | partial | M |
| Pin dependencies with hashes, avoid shell=True/subprocess, disable debug, and add attributable audit logging | T5 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-vulpy).
Confirmed primary claims: 15.

By class: CWE-287 x3, CWE-352 x3, CWE-79 x2, CWE-89 x2, CWE-798 x1, CWE-614 x1, CWE-863 x1, CWE-73 x1, CWE-338 x1

Affected paths: bad/libapi.py x4, bad/libuser.py x2, bad/libsession.py x2, good/templates/posts.view.html x1, bad/templates/posts.view.html x1, bad/vulpy.py x1, bad/mod_user.py x1, bad/mod_api.py x1, good/mod_mfa.py x1, bad/mod_posts.py x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-287 x3, CWE-338 x1, CWE-352 x3, CWE-614 x1, CWE-73 x1, CWE-79 x2, CWE-798 x1, CWE-863 x1, CWE-89 x2

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x5 at bad/templates/mfa.enable.html, bad/templates/posts.view.html, bad/templates/welcome.html, good/templates/mfa.enable.html, good/templates/welcome.html — heuristic: form + {{ }} co-occurrence | validator: bad/templates/mfa.enable.html:6 {{ img_str }} and :16 {{ secret_url }} have no |safe (Jinja autoescaped); values are server-generated at bad/mod_mfa.
- CWE-285 x1 at bad/mod_posts.py — bad/mod_posts.py:11-12 and bad/mod_api.py:47-50 return any username posts with no login check; enumeration via /posts/<user> and /api/post/<user> | validator: Hardened variant good/mod_posts.py:11 als
