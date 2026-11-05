# Threat Model: realvuln-vulnerable-nodejs

## 1. System context

Deliberately vulnerable RESTful course demo (Vanderbilt 2019) for OWASP Top 10: Node.js/Express + Jade frontend with login/profile/modify/order flows, an admin user-management UI, and a /order.php bridge that shells out to server-side PHP (execphp.js + phpFiles/) including XML processing. Backed by unauthenticated localhost MongoDB (nodetest2.userlist) holding plaintext passwords, PII and credit-card numbers, with hardcoded express-session secret and plaintext login forms. Runs as a local node process (bin/www default port 3000) with no Dockerfile, IaC, CI, or SECURITY.md; README documents the flaws and candidate fixes without implementing them.

Repo: realvuln-vulnerable-nodejs. Threat model for realvuln-vulnerable-nodejs | stack: unknown stack | entry points: ~8 routes | prefilter signal classes: hardcoded-secret, js-exec, log-inject, plaintext-creds | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-exec, log-inject, plaintext-creds.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User credentials (usernames + plaintext passwords in Mongo userlist) | Mongo nodetest2.userlist stores usernames with plaintext passwords retrievable in bulk | critical |
| PII + payment data (fullname, email, age, location, credit-card in userlist) | Full user profiles including credit-card numbers collected and disclosed via admin UI and bulk API | critical |
| Session state and session-signing secret | Express session integrity keyed by hardcoded secret Shh, its a secret! plus in-memory session store | high |
| MongoDB nodetest2.userlist integrity and availability | Authoritative user store on unauthenticated localhost Mongo subject to unauth insert/update/delete | high |
| Server process integrity / OS command execution via PHP bridge | Node process ability to execute arbitrary OS commands via child_process.exec to /usr/bin/php | critical |
| Filesystem confidentiality (e.g. /etc/passwd via XXE in phpFiles) | Server files readable via XML external entities expanded in phpFiles/order.php | high |
| Service availability (Express on :3000 + Mongo on localhost:27017) | Liveness of local node process and MongoDB with no rate limits, size limits, or sandboxing | medium |
| Application source, views and static assets integrity | Jade views, static JS, and PHP bridge files rendered and served to browsers | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP GET / login page | Anonymous GET renders login UI; entry to auth flow, session init via global.js initUserSession (routes/index.js:5, views/login.jade:1) [refs: `routes/index.js:5`, `views/login.jade:1`, `public/javascripts/global.js:141`] | untrusted network/client -> Express view render + session | User credentials (usernames + plaintext passwords in Mongo userlist), Session state and session-signing secret |
| HTTP GET /admin unauthenticated admin UI | Admin UI rendered with no server-side auth check; client fetches full userlist and PII/card data (routes/admin.js:5, views/admin.jade:1) [refs: `routes/admin.js:5`, `views/admin.jade:1`, `public/javascripts/global.js:12`] | untrusted network/client -> privileged admin function (missing authz) | PII + payment data (fullname, email, age, location, credit-card in userlist), User credentials (usernames + plaintext passwords in Mongo userlist), MongoDB nodetest2.userlist integrity and availability |
| HTTP GET /users/userlist bulk disclosure | Returns all docs in userlist collection with no auth, pagination, or field filtering (routes/users.js:7) [refs: `routes/users.js:7`] | untrusted network/client -> MongoDB read | PII + payment data (fullname, email, age, location, credit-card in userlist), User credentials (usernames + plaintext passwords in Mongo userlist) |
| HTTP POST /users/adduser document insert | Inserts req.body verbatim after only duplicate-username check; password defaults to username client-side; NoSQL operator injection possible (routes/users.js:16, public/javascripts/global.js:72) [refs: `routes/users.js:16`, `public/javascripts/global.js:72`] | untrusted JSON/form body -> MongoDB write | MongoDB nodetest2.userlist integrity and availability, User credentials (usernames + plaintext passwords in Mongo userlist), PII + payment data (fullname, email, age, location, credit-card in userlist) |
| HTTP DELETE /users/deleteuser/:id | ID from URL passed directly to collection.remove with no ownership check (routes/users.js:32, public/javascripts/global.js:112) [refs: `routes/users.js:32`, `public/javascripts/global.js:112`] | untrusted URL path param -> MongoDB delete | MongoDB nodetest2.userlist integrity and availability, Service availability (Express on :3000 + Mongo on localhost:27017) |
| HTTP POST /users/session login (NoSQL injection + log) | username/password from body interpolated into Mongo findOne with no type check; qs-encoded $gt bypass documented in README; username logged to console (routes/users.js:47, README.md:150) [refs: `routes/users.js:47`, `public/javascripts/global.js:160`, `README.md:150`] | untrusted request body -> MongoDB query + server log + session | User credentials (usernames + plaintext passwords in Mongo userlist), Session state and session-signing secret, Service availability (Express on :3000 + Mongo on localhost:27017) |
| HTTP PUT /users/modify mass-assignment update | Whole req.body used as $set against session username; mass-assignment allows overwriting arbitrary fields including username/password (routes/users.js:103) [refs: `routes/users.js:103`] | untrusted request body (authenticated session) -> MongoDB update + session | MongoDB nodetest2.userlist integrity and availability, User credentials (usernames + plaintext passwords in Mongo userlist), Session state and session-signing secret |
| HTTP GET /order?name= reflected order page | Query param name rendered into order view; form GETs to /order.php bridging to PHP exec path (routes/order.js:5, views/order.jade:3) [refs: `routes/order.js:5`, `views/order.jade:3`, `views/order.jade:24`] | untrusted query string -> Jade render + PHP bridge URL | Application source, views and static assets integrity, Server process integrity / OS command execution via PHP bridge |
| HTTP GET *.php PHP-bridge command injection + XXE | originalUrl manually sliced for path/item/price then shell-concatenated into /usr/bin/php <file> <arg> via child_process.exec; item flows into order.php XML with LIBXML_NOENT/DTDLOAD and external entities, echoing $name/$price unescaped (routes/php.js:28, execphp.js:18, phpFiles/order.php:20) [refs: `routes/php.js:28`, `routes/php.js:6`, `execphp.js:18`, `phpFiles/order.php:20`, `phpFiles/test.php:11`] | untrusted URL path/query -> shell command + PHP runtime + XML parser + filesystem | Server process integrity / OS command execution via PHP bridge, Filesystem confidentiality (e.g. /etc/passwd via XXE in phpFiles), Service availability (Express on :3000 + Mongo on localhost:27017) |
| View/static + third-party script load | Plaintext password field, credit-card collection form, external http:// jquery; secret pikachu page with no auth (views/login.jade:33, views/layout.jade:8, routes/pikachu.js:6) [refs: `views/login.jade:33`, `views/layout.jade:8`, `routes/pikachu.js:6`] | untrusted browser input / external CDN -> credential capture + stored PII | User credentials (usernames + plaintext passwords in Mongo userlist), PII + payment data (fullname, email, age, location, credit-card in userlist), Application source, views and static assets integrity |
| Env/config + embedded Mongo connection | PORT env selects listen port (default 3000); monk connects to unauthenticated localhost:27017/nodetest2 injected into every req.db (bin/www:5, app.js:38) [refs: `bin/www:5`, `app.js:11`, `app.js:38`] | operator env / network-adjacent DB -> application data plane | MongoDB nodetest2.userlist integrity and availability, Service availability (Express on :3000 + Mongo on localhost:27017), Session state and session-signing secret |
| Supply-chain lockfile and vendored deps | Pinned old Express/Jade/Mongo stack with known audit findings (README notes 7 vulns); no CI/IaC in tree (package.json:10, README.md:130) [refs: `package.json:10`, `package-lock.json:1`, `README.md:130`] | upstream registry/maintainer -> build/install -> runtime (no runtime input, install-time trust) | Server process integrity / OS command execution via PHP bridge, Service availability (Express on :3000 + Mongo on localhost:27017), Application source, views and static assets integrity |
| HTTP request handlers (8 routes detected) | Web and REST API endpoints (~8 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |

### Key Detected Endpoints
*Detected ~8 framework routes:*

- `USE /` (`app.js:47`)
- `USE /users` (`app.js:48`)
- `GET *.php` (`routes/php.js:28`)
- *(and ~5 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker bypasses authentication and hijacks or overwrites accounts via NoSQL operator injection and mass-assignment | remote_unauth | HTTP POST /users/session login (NoSQL injection + log), HTTP POST /users/adduser document insert, HTTP PUT /users/modify mass-assignment update, HTTP GET / login page | User credentials (usernames + plaintext passwords in Mongo userlist) | critical | almost_certain | unmitigated | Empty-field check on POST /users/session (routes/users.js:54) does not block operator injection; session regeneration on login (routes/users.js:66) does not prevent bypass | routes/users.js:47, README.md:150, routes/users.js:103, routes/users.js:16; routes/users.js:58 [NoSQL auth bypass in login]; routes/users.js:113 [Mass-assignment in PUT modify] |
| T2 | Attacker executes arbitrary OS commands by injecting shell metacharacters into PHP-bridge URL parameters | remote_unauth | HTTP GET *.php PHP-bridge command injection + XXE, HTTP GET /order?name= reflected order page | Server process integrity / OS command execution via PHP bridge | critical | almost_certain | unmitigated | none | routes/php.js:28, routes/php.js:6, execphp.js:18, phpFiles/order.php:20; execphp.js:22 [OS command injection in ExecPHP parseFile]; routes/php.js:23 [Log injection via unsanitized PHP-bridge parameters] |
| T3 | Attacker reads bulk PII and credentials and deletes arbitrary users via unauthenticated admin and IDOR endpoints | remote_unauth | HTTP GET /admin unauthenticated admin UI, HTTP GET /users/userlist bulk disclosure, HTTP DELETE /users/deleteuser/:id | PII + payment data (fullname, email, age, location, credit-card in userlist) | critical | almost_certain | unmitigated | none | routes/admin.js:5, routes/users.js:7, routes/users.js:32; routes/users.js:10 [Unauthenticated bulk disclosure]; routes/users.js:38 [IDOR on DELETE deleteuser]; routes/users.js:16 [Missing authentication allows unauthenticated account creation via POST /users/adduser]; routes/users.js:104 [Missing CSRF protection on PUT /users/modify]; routes/users.js:46 [Missing rate limiting on POST /users/session login]; routes/users.js:97 [Sensitive data exposure: GET /users returns full user object with password and credit-card] |
| T4 | Attacker steals plaintext credentials and forges sessions using hardcoded secret and unprotected credential flows | remote_unauth | View/static + third-party script load, HTTP GET / login page, Env/config + embedded Mongo connection, HTTP GET /admin unauthenticated admin UI | User credentials (usernames + plaintext passwords in Mongo userlist) | critical | almost_certain | unmitigated | none — hardcoded session secret in app.js:30, plaintext password storage, type=text password field | app.js:30, views/login.jade:33, routes/users.js:7 |
| T5 | Attacker exfiltrates server files via external-entity expansion in PHP XML parser | remote_unauth | HTTP GET *.php PHP-bridge command injection + XXE | Filesystem confidentiality (e.g. /etc/passwd via XXE in phpFiles) | high | likely | unmitigated | none | phpFiles/order.php:20, phpFiles/test.php:11, routes/php.js:28 |
| T6 | Attacker injects scripts into victim browsers via reflected order parameters and unescaped PHP output | remote_unauth | HTTP GET /order?name= reflected order page, HTTP GET *.php PHP-bridge command injection + XXE, View/static + third-party script load | Application source, views and static assets integrity | high | almost_certain | unmitigated | Jade = auto-escaping in views (e.g. views/order.jade:3) — partial output-encoding only, no protection for PHP echo or CDN script | views/order.jade:3, views/order.jade:24, phpFiles/order.php:20, views/layout.jade:8; phpFiles/order.php:21 [XXE in PHP order bridge]; phpFiles/order.php:27 [Reflected XSS via unescaped PHP echo] |
| T7 | Attacker exhausts service, tampers with data, or persists via unauthenticated Mongo, unbounded exec/XML parsing, and vulnerable dependencies without attributable logging | remote_unauth | Env/config + embedded Mongo connection, Supply-chain lockfile and vendored deps, HTTP POST /users/session login (NoSQL injection + log) | Service availability (Express on :3000 + Mongo on localhost:27017) | high | possible | unmitigated | none |  |
| T8 | Security compromise via Missing authentication on GET *.php code-execution bridge | remote_unauth | routes/php.js | application data and system state | critical | almost_certain | unmitigated | none | routes/php.js:28 [Missing authentication on GET *.php code-execution bridge] |
| T9 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | public/javascripts/global.js | application data and system state | high | almost_certain | unmitigated | none | public/javascripts/global.js:46 [Stored XSS in admin table] |
| T10 | Security compromise via Session cookie missing Secure/HttpOnly/SameSite hardening | remote_unauth | app.js | application data and system state | medium | almost_certain | unmitigated | none | app.js:30 [Session cookie missing Secure/HttpOnly/SameSite hardening] |
| T11 | Security compromise via Stack-trace disclosure in development error handler | remote_unauth | views/error.jade | application data and system state | medium | almost_certain | unmitigated | none | views/error.jade:6 [Stack-trace disclosure in development error handler] |
| T12 | Security compromise via Active content loaded over plaintext HTTP without integrity | remote_unauth | views/layout.jade | application data and system state | high | almost_certain | unmitigated | none | views/layout.jade:9 [Active content loaded over plaintext HTTP without integrity] |
| T13 | Security compromise via Weak default credential: new-user password set equal to username | remote_unauth | public/javascripts/global.js | application data and system state | high | almost_certain | unmitigated | none | public/javascripts/global.js:85 [Weak default credential: new-user password set equal to username] |
| T14 | Security compromise via Unsanitized insert in adduser | remote_unauth | routes/users.js | application data and system state | high | almost_certain | unmitigated | none | routes/users.js:25 [Unsanitized insert in adduser] |
| T15 | Security compromise via Plaintext password handling | remote_unauth | views/login.jade | application data and system state | high | almost_certain | unmitigated | none | views/login.jade:40 [Plaintext password handling] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Isolated Jade-template XSS bypass despite auto-escaping | Jade = provides auto-escaping for title/name in order view, so pure Jade reflected XSS is partially bounded; PHP echo path and bulk PII disclosure dominate the same surfaces and are modeled instead. |
| Clickjacking / UI redress against admin UI | No X-Frame-Options/CSP or clickjacking helper observed, but unauthenticated bulk PII disclosure and RCE allow strictly worse outcomes via the same unauthenticated surfaces without needing UI redressing. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is this intentionally-vulnerable demo ever exposed beyond localhost:3000, and is MongoDB localhost:27017/nodetest2 authenticated or network-isolated?
- Where are session data and the hardcoded secret 'Shh, its a secret!' (app.js:30) stored/managed in any deployment — memory store vs external store, rotation plan?
- Are there any upstream controls (WAF, reverse proxy, security headers like X-Frame-Options/CSP, rate limiting, logging/monitoring) not visible in this tree?
- Is the /usr/bin/php bridge (execphp.js:11 phpPath/phpFolder) required in production, and what OS user/sandbox bounds it?
- Which README-documented fixes (hashing, $ sanitization, type=password, removing card storage, npm audit fix, helmet) are in-scope vs intentionally left vulnerable?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-vulnerable-nodejs
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-vulnerable-nodejs/signals/prefilter.txt (10 entries)
  - secrets: .cerberus/realvuln-vulnerable-nodejs/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-vulnerable-nodejs/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-vulnerable-nodejs/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-vulnerable-nodejs/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-vulnerable-nodejs/signals/routes.txt (8 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Remove shell-concatenated PHP bridge; replace exec with allowlisted file dispatch plus execFile with argument arrays or eliminate /usr/bin/php path entirely | T2,T7 | yes | M |
| Enforce server-side authorization on every privileged route and replace bulk userlist with authenticated paginated field-filtered queries plus ownership checks on delete | T3 | yes | M |
| Parameterize all Mongo access with strict type/schema validation, deny query operators ($ prefix), and allowlist updatable fields to block NoSQL injection and mass-assignment | T1 | yes | M |
| Hash passwords with bcrypt/argon2, stop storing credit-cards, use type=password + TLS, and load session secret from env/KMS with rotation and hardened store | T4 | yes | M |
| Harden XML and output encoding: disable external entities/DTDLOAD/NOENT, validate order schema, and context-encode all PHP/Jade interpolation | T5,T6 | partial | M |
| Harden deployment and supply chain: authenticate and isolate MongoDB, enforce security headers/CSP/SRI, structured sanitized logging, rate-limiting, and npm audit upgrades with lockfile review | T6,T7 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-vulnerable-nodejs).
Confirmed primary claims: 22.

By class: CWE-306 x3, CWE-200 x2, CWE-79 x2, CWE-943 x2, CWE-78 x1, CWE-611 x1, CWE-639 x1, CWE-915 x1, CWE-117 x1, CWE-614 x1, CWE-209 x1, CWE-829 x1, CWE-521 x1, CWE-256 x1, CWE-352 x1

Affected paths: routes/users.js x9, execphp.js x2, phpFiles/order.php x2, routes/php.js x2, public/javascripts/global.js x2, routes/admin.js x1, app.js x1, views/error.jade x1, views/layout.jade x1, views/login.jade x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-117 x1, CWE-200 x2, CWE-209 x1, CWE-22 x1, CWE-256 x1, CWE-306 x3, CWE-307 x1, CWE-352 x1, CWE-521 x1, CWE-611 x1, CWE-614 x1, CWE-639 x1, CWE-78 x1, CWE-79 x2, CWE-829 x1, CWE-915 x1, CWE-943 x2

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-400 x1 at routes/php.js — routes/php.js:18 takes query.split("?")[1] without existence check; routes/php.js:20 calls query.indexOf on potentially undefined, throwing TypeError for GET /order.php with no query string | validato
