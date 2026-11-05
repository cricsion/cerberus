# Threat Model: realvuln-vuln-node-express-swagger

## 1. System context

This is SirAppSec's deliberately vulnerable beer-shop: Express JSON APIs under /v1/* with Swagger UI plus Nunjucks server-rendered pages for register/login/profile/beer, backed by Sequelize over SQLite, express-session plus JWT, multer uploads, libxmljs, node-serialize, otplib and axios/curl helpers. It is published for pentest and scanner evaluation with intended flaws (SQLi, XXE, RCE, IDOR/BOLA, SSTI/XSS, SSRF, auth bypass) documented as features. It runs via docker-compose or npm run dev on port 5000 with NODE_ENV=development, loading .env, with commented-out security headers and logging and no in-repo SECURITY.md fix policy.

Repo: realvuln-vuln-node-express-swagger. Threat model for realvuln-vuln-node-express-swagger | stack: unknown stack | entry points: ~27 routes | prefilter signal classes: hardcoded-secret, js-exec, tpl-xss, debug-exposure, upload, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-exec, tpl-xss, debug-exposure, upload, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User records incl. email, MD5/plaintext password, address, profile_pic, role (Sequelize `user` model backed by SQLite db.sqlite) | Credential store and PII targeted by SQLi and excessive-data exposure | critical |
| Session state + JWT bearer tokens (24h payload id/role, secrets 'SuperSecret'/'superSecretPassword') — account takeover / privilege escalation target | Authentication and session integrity undermined by hardcoded secrets and missing authz | critical |
| Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target | Host execution and file confidentiality targeted by command injection, XXE, traversal and uploads | critical |
| Beer catalog + user-beer associations (`beer`, `beer_users` join) served with excessive-data exposure via GET /v1/order | Business data integrity and confidentiality targeted by unauthenticated writes and oversharing | medium |
| Application availability (Express on PORT 5000, db.sequelize.sync alter:true, ReDoS email regex, unthrottled OTP/login endpoints) | Liveness and log integrity targeted by DoS and repudiation gaps | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| POST /v1/admin/new-beer/ | Unauthenticated JSON body name/price/picture -> db.beer.create() with no auth check; reachable admin asset [refs: `src/router/routes/admin.js:16`] | untrusted network / JSON body → Sequelize create (missing authz) | Beer catalog + user-beer associations (`beer`, `beer_users` join) served with excessive-data exposure via GET /v1/order, Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target |
| POST /v1/admin/upload-pic/ file upload | Multipart file binary -> multer dest ./uploads/ then JSON echo of file metadata; no type/size/auth check in handler [refs: `src/router/routes/admin.js:51`] | untrusted file bytes → server filesystem (uploads/) | Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target, Application availability (Express on PORT 5000, db.sequelize.sync alter:true, ReDoS email regex, unthrottled OTP/login endpoints) |
| POST /v1/admin/new-beer-xml/ XXE | Multipart XML file buffer -> libxmljs.parseXml(buf,{noent:true}) with external entities enabled then db.beer.create() [refs: `src/router/routes/admin.js:83`] | untrusted XML file → libxmljs parser with noent | Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target, Beer catalog + user-beer associations (`beer`, `beer_users` join) served with excessive-data exposure via GET /v1/order |
| GET /v1/order | No-arg GET returns all beers with include users (excessive data / PII oversharing per jsdoc) [refs: `src/router/routes/order.js:12`] | untrusted network → Sequelize findAll + JSON serializer | Beer catalog + user-beer associations (`beer`, `beer_users` join) served with excessive-data exposure via GET /v1/order, User records incl. email, MD5/plaintext password, address, profile_pic, role (Sequelize `user` model backed by SQLite db.sqlite) |
| GET /v1/beer-pic/ path traversal | Query ?picture= joined as `../../../uploads/${filename}` into fs.readFile(path.join(__dirname,...)); ../.env example in jsdoc; extension check only changes content-type [refs: `src/router/routes/order.js:25`] | untrusted query string → filesystem read | Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target, User records incl. email, MD5/plaintext password, address, profile_pic, role (Sequelize `user` model backed by SQLite db.sqlite) |
| GET /v1/search/:filter/:query SQLi | Path params interpolated as `SELECT * FROM beers WHERE ${filter} = '${query}'` via sequelize.query RAW; sqlmap string in jsdoc [refs: `src/router/routes/order.js:62`] | untrusted URL path → raw SQL string | User records incl. email, MD5/plaintext password, address, profile_pic, role (Sequelize `user` model backed by SQLite db.sqlite), Beer catalog + user-beer associations (`beer`, `beer_users` join) served with excessive-data exposure via GET /v1/order |
| GET /v1/status/:brand RCE | Path :brand interpolated into execSync(`curl https://letmegooglethat.com/?q=${brand}`) and returned [refs: `src/router/routes/system.js:13`] | untrusted URL path → shell command | Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target |
| GET /v1/redirect/ open redirect | Query ?url= passed to res.redirect(url) with no allowlist (open redirect per jsdoc) [refs: `src/router/routes/system.js:33`] | untrusted query string → HTTP redirect | Session state + JWT bearer tokens (24h payload id/role, secrets 'SuperSecret'/'superSecretPassword') — account takeover / privilege escalation target |
| HTTP request handlers (27 routes detected) | Web and REST API endpoints (~27 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~27 framework routes:*

- `POST /v1/admin/new-beer/` (`src/router/routes/admin.js:16`)
- `POST /v1/admin/upload-pic/` (`src/router/routes/admin.js:51`)
- `POST /v1/admin/new-beer-xml/` (`src/router/routes/admin.js:83`)
- `GET /` (`src/router/routes/frontend.js:12`)
- `GET /register` (`src/router/routes/frontend.js:36`)
- `GET /registerform` (`src/router/routes/frontend.js:63`)
- `GET /login` (`src/router/routes/frontend.js:110`)
- `GET /profile` (`src/router/routes/frontend.js:144`)
- `GET /beer` (`src/router/routes/frontend.js:180`)
- `GET /v1/order` (`src/router/routes/order.js:12`)
- `GET /v1/beer-pic/` (`src/router/routes/order.js:25`)
- `GET /v1/search/:filter/:query` (`src/router/routes/order.js:62`)
- `GET /v1/status/:brand` (`src/router/routes/system.js:13`)
- `GET /v1/redirect/` (`src/router/routes/system.js:33`)
- `POST /v1/init` (`src/router/routes/system.js:61`)
- *(and ~12 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker executes arbitrary OS commands or reads local files via shell injection and external-entity expansion | remote_unauth | GET /v1/status/:brand RCE, POST /v1/admin/new-beer-xml/ XXE | Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target | critical | almost_certain | unmitigated | Container runs as non-root USER `user` | src/router/routes/system.js:13 execSync curl interpolation; src/router/routes/admin.js:83 libxmljs noent:true; src/router/routes/system.js:17 [OS Command Injection in GET /v1/status/:brand] |
| T2 | Attacker extracts or modifies database contents via unsanitized SQL string interpolation | remote_unauth | GET /v1/search/:filter/:query SQLi | User records incl. email, MD5/plaintext password, address, profile_pic, role (Sequelize `user` model backed by SQLite db.sqlite) | critical | almost_certain | unmitigated | none | src/router/routes/order.js:62 raw SELECT WHERE ${filter}='${query}' |
| T3 | Attacker invokes privileged admin operations and forges or replays credentials via missing authorization and hardcoded JWT secrets | remote_unauth | POST /v1/admin/new-beer/, GET /v1/order | Session state + JWT bearer tokens (24h payload id/role, secrets 'SuperSecret'/'superSecretPassword') — account takeover / privilege escalation target | critical | almost_certain | unmitigated | none | src/router/routes/admin.js:16 missing authz; src/middleware/verifySignup.js defined but never imported; jwt.decode without verification; src/router/routes/user.js:356 [Unauthenticated Vertical Privilege Escalation in PUT /v1/admin/promote/:id]; src/router/routes/admin.js:93 [XXE via libxmljs noent:true in POST /v1/admin/new-beer-xml]; src/router/routes/frontend.js:122 [Broken Authentication Bypass in GET /login]; src/router/routes/user.js:18 [Hardcoded JWT Secret in GET /v1/admin/users]; src/router/routes/user.js:52 [IDOR in GET /v1/user/:id]; src/router/routes/user.js:65 [Broken Function-Level Authorization in DELETE /v1/user/:id]; src/router/routes/user.js:251 [Hardcoded Secret and Broken Password Check in POST /v1/user/token]; src/router/routes/frontend.js:148 [IDOR in GET /profile]; sr |
| T4 | Attacker reads arbitrary server files including secrets and database via directory traversal | remote_unauth | GET /v1/beer-pic/ path traversal | Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target | critical | almost_certain | unmitigated | none | src/router/routes/order.js:25 path.join(__dirname, ../../../uploads/${filename}) with ../.env jsdoc; src/router/routes/order.js:33 [Path Traversal Arbitrary File Read in GET /v1/beer-pic]; src/server.js:19 [Missing Security Headers (CSP/HSTS/X-Frame) Disabled in Server] |
| T5 | Attacker persists malicious files on the server via unrestricted upload without validation | remote_unauth | POST /v1/admin/upload-pic/ file upload | Server filesystem + process integrity (uploads/ via multer, ../../../uploads path join, child_process.execSync, libxmljs, node-serialize) — RCE/file-read target | critical | almost_certain | unmitigated | none | src/router/routes/admin.js:51 multer dest ./uploads/ with no type/size/auth check; src/router/routes/admin.js:50 [Unrestricted File Upload in POST /v1/admin/upload-pic] |
| T6 | Attacker steals sessions or executes scripts in victims browsers via stored and reflected template injection/XSS | remote_unauth | POST /v1/admin/new-beer/, GET /v1/order | Session state + JWT bearer tokens (24h payload id/role, secrets 'SuperSecret'/'superSecretPassword') — account takeover / privilege escalation target | high | almost_certain | unmitigated | none | src/router/routes/frontend.js Nunjucks rendering; prefilter tpl-xss + tpl-form-reflect signals; src/templates/user.html:139 [Reflected XSS via /safe in user.html]; src/templates/user-register.html:139 [Reflected XSS via /safe in user-register.html]; src/templates/beer.html:136 [Stored XSS via /safe in beer.html]; src/templates/profile.html:136 [Stored XSS via /safe in profile.html]; src/router/routes/frontend.js:126 [Session Fixation in GET /login: No Session Regeneration on Authentication]; src/router/routes/user.js:87 [Cross-Unit Stored XSS: POST /v1/user/ address to GET /profile /safe] |
| T7 | Attacker phishes credentials or tokens by redirecting users to arbitrary external URLs | remote_unauth | GET /v1/redirect/ open redirect | Session state + JWT bearer tokens (24h payload id/role, secrets 'SuperSecret'/'superSecretPassword') — account takeover / privilege escalation target | high | almost_certain | unmitigated | none | src/router/routes/system.js:33 res.redirect(url) with no allowlist; src/router/routes/system.js:37 [Open Redirect in GET /v1/redirect]; src/router/routes/user.js:299 [Broken Login and User Enumeration in POST /v1/user/login]; src/router/routes/user.js:393 [Broken OTP Validation with Seed Control and Token Leak] |
| T8 | Attacker exhausts CPU, memory or disk or acts without attributable audit trail via unbounded inputs and debug exposure | remote_unauth | POST /v1/admin/upload-pic/ file upload, GET /v1/order, GET /v1/search/:filter/:query SQLi, GET /v1/status/:brand RCE | Application availability (Express on PORT 5000, db.sequelize.sync alter:true, ReDoS email regex, unthrottled OTP/login endpoints) | medium | possible | unmitigated | none |  |
| T9 | Database compromise and sensitive data exfiltration via SQL injection | remote_unauth | src/router/routes/order.js | application data and system state | critical | almost_certain | unmitigated | none | src/router/routes/order.js:65 [SQL Injection in GET /v1/search/:filter/:query] |
| T10 | Remote code execution via untrusted object deserialization | remote_unauth | src/router/routes/system.js | application data and system state | critical | almost_certain | unmitigated | none | src/router/routes/system.js:64 [Insecure Deserialization RCE in POST /v1/init] |
| T11 | Internal service access and cloud metadata exposure via Server-Side Request Forgery (SSRF) | remote_unauth | src/router/routes/system.js | application data and system state | high | almost_certain | unmitigated | none | src/router/routes/system.js:81 [SSRF in GET /v1/test] |
| T12 | Arbitrary code execution via dynamic code evaluation | remote_unauth | src/router/routes/frontend.js | application data and system state | critical | almost_certain | unmitigated | none | src/router/routes/frontend.js:16 [SSTI in GET / via nunjucks.renderString]; src/router/routes/frontend.js:39 [SSTI in GET /register via nunjucks.renderString] |
| T13 | Privilege escalation or unauthorized state tampering via mass assignment | remote_auth | src/router/routes/user.js | application data and system state | critical | almost_certain | unmitigated | none | src/router/routes/user.js:328 [Mass Assignment BOLA in PUT /v1/user/:id]; src/router/routes/user.js:86 [Mass Assignment to Admin Role and Plaintext Password in POST /v1/user] |
| T14 | Information disclosure of sensitive application or configuration data | remote_unauth | src/router/routes/order.js | application data and system state | high | almost_certain | unmitigated | none | src/router/routes/order.js:13 [Excessive Data Exposure in GET /v1/order] |
| T15 | Security compromise via Credentials in URL and Weak MD5 Storage in GET /registerform | remote_unauth | src/router/routes/frontend.js | application data and system state | high | almost_certain | unmitigated | none | src/router/routes/frontend.js:68 [Credentials in URL and Weak MD5 Storage in GET /registerform] |
| T16 | Unauthorized state change via cross-site request forgery (CSRF) | remote_unauth | src/router/routes/user.js | application data and system state | medium | almost_certain | unmitigated | none | src/router/routes/user.js:118 [CSRF and IDOR in GET /v1/love/:beer_id] |
| T17 | Security compromise via Hardcoded OTP Seed Default Enables OTP Prediction | remote_unauth | src/router/routes/user.js | application data and system state | high | almost_certain | unmitigated | none | src/router/routes/user.js:395 [Hardcoded OTP Seed Default Enables OTP Prediction] |
| T18 | Security compromise via Missing Response Hanging Request in POST /v1/init | remote_unauth | src/router/routes/system.js | application data and system state | medium | almost_certain | unmitigated | none | src/router/routes/system.js:61 [Missing Response Hanging Request in POST /v1/init]; src/router/routes/system.js:20 [Unhandled Exception Hanging Response DoS in GET /v1/status/:brand] |
| T19 | Security compromise via Missing Rate Limiting on OTP Validation Enables Brute-Force | remote_unauth | src/router/routes/user.js | application data and system state | high | almost_certain | unmitigated | none | src/router/routes/user.js:381 [Missing Rate Limiting on OTP Validation Enables Brute-Force] |
| T20 | Security compromise via Verbose Database Error Disclosure in Search Endpoint | remote_unauth | src/router/routes/order.js, src/router/routes/system.js | application data and system state | medium | almost_certain | unmitigated | none | src/router/routes/order.js:71 [Verbose Database Error Disclosure in Search Endpoint]; src/router/routes/system.js:89 [Sensitive Error Disclosure in GET /v1/test SSRF Handler] |
| T21 | Security compromise via Credentials in URL Query in GET /login | remote_unauth | src/router/routes/frontend.js | application data and system state | medium | almost_certain | unmitigated | none | src/router/routes/frontend.js:110 [Credentials in URL Query in GET /login] |
| T22 | Security compromise via ReDoS via Nested-Quantifier Email Regex on Unauthenticated Endpoints | remote_unauth | src/router/routes/user.js | application data and system state | medium | almost_certain | unmitigated | none | src/router/routes/user.js:89 [ReDoS via Nested-Quantifier Email Regex on Unauthenticated Endpoints] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Supply-chain compromise via stale container base image or transitive npm dependency | No vendored native add-on or custom crypto in tree; generic base-image CVEs are scanner noise until a deployed digest and prod patch window are stated — revisit if image is promoted beyond lab use. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is this deployment network-reachable and by whom? README invites pentest/DAST use via docker run -p 5000:5000 but no prod boundary is stated.
- Who supplies .env / DATABASE_URL / JWT_SECRET? src/config/index.js falls back to superSecretPassword and SQLite file when env is absent — is any live secret stored there?
- Which controls sit upstream (WAF, auth gateway, upload AV/size caps, egress rules for SSRF/curl/axios)? None were found in tree; commented-out security headers/logging in src/server.js confirm absence in-app.
- Do authJwt.verifyToken/isAdmin and verifySignup checks actually protect any route? No route file requires them, isAdmin calls undefined isModerator, and verifyToken uses jwt.decode (no signature check).
- What bounds uploads/ retention, SQLite file (db/db.sqlite vs /db/sqlite.db) persistence, and debug logs (app.log/app_err.log, DEBUG=*) across container rebuild/migration?
- Are swagger /api-docs and populate.sh seed users (amit/shir + promote/1 + hardcoded Bearer token) part of the deployed surface or test-only?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-vuln-node-express-swagger
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-vuln-node-express-swagger/signals/prefilter.txt (30 entries)
  - secrets: .cerberus/realvuln-vuln-node-express-swagger/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-vuln-node-express-swagger/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-vuln-node-express-swagger/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-vuln-node-express-swagger/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-vuln-node-express-swagger/signals/routes.txt (27 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Eliminate shell string construction: replace execSync curl with allowlisted fetch library and no shell | T1 | yes | M |
| Enforce parameterized ORM queries everywhere and forbid raw string-interpolated sequelize.query | T2 | yes | M |
| Constrain file reads to canonicalized allowlisted directory with basename validation and no user-controlled traversal | T4 | yes | M |
| Enforce authentication and role authorization on every /v1/admin/* and /v1/order route with strongly random JWT secrets verified by signature | T3,T5 | partial | M |
| Harden uploads with auth, type/size caps, random names, storage outside webroot and no execution | T1,T5 | partial | M |
| Auto-escape all template output, disable SSTI-capable constructs, and emit Content-Security-Policy plus HttpOnly/Secure cookies | T6 | partial | M |
| Allowlist redirect destinations and reject absolute untrusted URLs | T7 | yes | M |
| Minimize PII in API responses, rotate secrets out of code into vault, and enable structured audit logging with rate limits | T3,T8 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-vuln-node-express-swagger).
Confirmed primary claims: 49.

By class: CWE-862 x9, CWE-79 x5, CWE-287 x3, CWE-798 x3, CWE-639 x3, CWE-94 x2, CWE-915 x2, CWE-248 x2, CWE-209 x2, CWE-89 x1, CWE-78 x1, CWE-434 x1, CWE-611 x1, CWE-22 x1, CWE-502 x1

Affected paths: src/router/routes/user.js x15, src/router/routes/system.js x10, src/router/routes/frontend.js x8, src/router/routes/order.js x5, src/router/routes/admin.js x5, src/server.js x2, src/templates/user.html x1, src/templates/user-register.html x1, src/templates/beer.html x1, src/templates/profile.html x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-1333 x1, CWE-200 x1, CWE-209 x2, CWE-22 x1, CWE-248 x2, CWE-287 x3, CWE-307 x1, CWE-308 x1, CWE-352 x1, CWE-384 x1, CWE-434 x1, CWE-502 x1, CWE-523 x1, CWE-598 x1, CWE-601 x1, CWE-611 x1, CWE-614 x1, CWE-639 x3, CWE-693 x1, CWE-78 x1, CWE-79 x5, CWE-798 x3, CWE-862 x9, CWE-89 x1, CWE-915 x2, CWE-918 x1, CWE-94 x2

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x4 at src/templates/auth-login-basic.html, src/templates/user-register.html, src/templates/user.html — heuristic: form + {{ }} co-occurrence | validator: src/templates/auth-login-basic.html:139 has {{message|safe}} but no route renders it; src/router/routes/frontend.js:17-18,40-41,164,218 only render u
- CWE-327 x1 at src/middleware/authJwt.js — jwt.decode(token, (err, decoded) => { | validator: src/middleware/authJwt.js:13 jwt.decode in verifyToken but module never imported/mounted: src/router/index.js:3-9 mounts only order/user/system/admin
- CWE-798 x1 at src/config/index.js — jwtSecret: process.env.JWT_SECRET | "superSecretPassword", | validator: src/config/index.js:12 bitwise-OR bug is real but config.jwtSecret is never used: live sign/verify use literal SuperSecret (src/
- CWE-863 x1 at src/middleware/authJwt.js — user.getRoles().then(roles => { | validator: src/middleware/authJwt.js:25 calls user.getRoles() with no such association and src/middleware/authJwt.js:44 references undefined isModerator; no route imp
- CWE-248 x1 at src/router/routes/system.js — src/router/routes/system.js:33 handler signature (req,res) has no next param but line 39 calls next() when ?url missing -> ReferenceError | validator: src/router/routes/system.js:33 handler signature 
- CWE-476 x1 at src/router/routes/user.js — src/router/routes/user.js:177 dereferences req.session.user.id without null check; when session has no user throws TypeError. Line 186 then unconditionally overwrites with req.query.id making prior ch
