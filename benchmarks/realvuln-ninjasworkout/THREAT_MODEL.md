# Threat Model: realvuln-ninjasworkout

## 1. System context

NinjasWorkout (Damn Vulnerable NodeJS Application) is an intentionally vulnerable Express+Pug+Mongoose training app for learning web attacks. It runs as a single Node process serving Pug views and static content, persisting users, posts and reset tokens to a local MongoDB and sending password-reset mail via Gmail SMTP. Users are learners/attackers running it locally via node app.js with no production hardening, SECURITY policy, or trust boundary beyond the demo login, blog, OAuth callback, SSRF demo, and deserialization demo routes.

Repo: realvuln-ninjasworkout. Threat model for realvuln-ninjasworkout | stack: unknown stack | entry points: ~5 routes | prefilter signal classes: hardcoded-secret, js-ssrf, debug-exposure, log-inject, upload | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-ssrf, debug-exposure, log-inject, upload.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users' |  | critical |
| JWT session authority: hardcoded signing secret 'hello' and session secret 'Your_Secret_Key' + Auth cookie sessions |  | critical |
| Password-reset tokens (Token collection, 1h TTL) + reset links sent by email |  | high |
| Blog post data + uploaded image files (images/ dir, posts collection with username/title/description/file) |  | medium |
| Gmail SMTP identity in config/mail.js and utils/sendemail.js (tester876905@gmail.com / placeholder pass) |  | medium |
| MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 |  | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP POST /secret/login | Unauthenticated JSON/form body {username,password} crosses network into Mongoose findOne for login; issues Auth cookie JWT on match (routers/index.js:118, routers/index.js:141) [refs: `routers/index.js:118`, `routers/index.js:141`] | untrusted network/client → Express route → MongoDB query + session issuer | User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users', JWT session authority: hardcoded signing secret 'hello' and session secret 'Your_Secret_Key' + Auth cookie sessions |
| HTTP POST /secret/signup | Unauthenticated body {username,email,password,admin} crosses network into user creation; admin flag client-controllable; email normalized then saved (routers/index.js:292, models/strict.js:1) [refs: `routers/index.js:292`, `models/strict.js:1`] | untrusted network/client → application logic → MongoDB users collection | User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users' |
| HTTP POST /secret/?user + POST /secret/username | Unauthenticated query ?user= and body {username} cross network into findOne and full document res.json (user-enumeration/dump oracle) (routers/index.js:230, routers/index.js:259) [refs: `routers/index.js:230`, `routers/index.js:259`] | untrusted network/client → MongoDB query → HTTP response | User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users' |
| HTTP POST /secret/addpost + GET /secret/posts/:username | Authenticated title/description body plus multer single-file upload crosses network into images/ disk write (original extension) and posts collection with global.hello attribution (routers/index.js:434, routers/index.js:366, app.js:47) [refs: `routers/index.js:434`, `routers/index.js:366`, `app.js:47`] | untrusted file upload + form fields → server filesystem + MongoDB | Blog post data + uploaded image files (images/ dir, posts collection with username/title/description/file), User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users' |
| HTTP password-reset flow (forgot + password-reset) | Unauthenticated email body crosses network into user lookup + JWT reset-token create/update and Gmail send; later :username/:token + new password cross network into verify() + findOneAndUpdate (routers/index.js:499, routers/index.js:563, routers/index.js:595, models/token.js:7, utils/sendemail.js:7) [refs: `routers/index.js:499`, `routers/index.js:563`, `routers/index.js:595`, `models/token.js:7`, `utils/sendemail.js:7`] | untrusted network/client → token store + SMTP + password writer | Password-reset tokens (Token collection, 1h TTL) + reset links sent by email, User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users' |
| HTTP GET /secret/ SSRF proxy | Unauthenticated ?url= and ?mime= query params cross network into needle.get(url) server-side fetch and reflected body/URL in response (routers/index.js:685) [refs: `routers/index.js:685`] | untrusted URL string → server HTTP client → server response + internal network | MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 |
| HTTP POST /secret/shell deserialization | Authenticated arbitrary JSON body crosses network into node-serialize serialize/unserialize with immediate RCE gadget; empty-body branch echoes serialized form (routers/index.js:718) [refs: `routers/index.js:718`] | untrusted serialized object → Node.js deserializer → process memory/exec | MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 |
| HTTP POST /auth/callback OAuth exchange | Unauthenticated {token} body crosses network into axios GET to googleapis userinfo, then server mints Auth JWT from returned name/email with admin:false (routers/index.js:79) [refs: `routers/index.js:79`] | untrusted bearer token + third-party userinfo → session issuer | JWT session authority: hardcoded signing secret 'hello' and session secret 'Your_Secret_Key' + Auth cookie sessions, User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users' |
| OAuth redirect pages hash handling | Browser URL hash fragment access_token parsed client-side, postMessage'd with targetOrigin * to opener, and POSTed to /auth/callback; duplicate copies in public/ and views/ (public/redirect.html:11, views/redirect.html:11) [refs: `public/redirect.html:11`, `views/redirect.html:11`] | untrusted URL fragment / opener window → browser JS → network | JWT session authority: hardcoded signing secret 'hello' and session secret 'Your_Secret_Key' + Auth cookie sessions |
| Static file / directory-traversal surface | Static file serving of public/ and blinker-mounted images/ basePath plus /home and / redirects; blinker etag/cache wrapper around directory (app.js:28, app.js:117, app.js:128, app.js:153) [refs: `app.js:28`, `app.js:117`, `app.js:128`, `app.js:153`] | untrusted URL path → filesystem read → HTTP response | Blog post data + uploaded image files (images/ dir, posts collection with username/title/description/file), MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 |
| Parsed config and env (db, mail, sendemail) | Startup/local config values (mongo URI, gmail user/pass, service) cross filesystem/env into DB connection and nodemailer transport (database/db.js:1, config/mail.js:1, utils/sendemail.js:7) [refs: `database/db.js:1`, `config/mail.js:1`, `utils/sendemail.js:7`] | local config file → DB/SMTP clients → external services | Gmail SMTP identity in config/mail.js and utils/sendemail.js (tester876905@gmail.com / placeholder pass), MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 |
| Supply-chain / CI pipeline surface | Lockfile + vendored deps (node-serialize 0.0.4, jsonwebtoken 0.4.0, axios 0.22.0, mongoose, multer, pug) and CI definitions that fetch actions and run docker build / snyk / njsscan / codacy; Jenkins credential IDs SNYK_TOKEN/DEFECT_DOJO (package.json:10, package-lock.json:1, .github/workflows/docker-image.yml:1, .github/workflows/codacy-analysis.yml:1, .github/workflows/njsscan-analysis.yml:1, Jenkinsfile:1, Jenkinsfile1:1) [refs: `package.json:10`, `package-lock.json:1`, `.github/workflows/docker-image.yml:1`, `.github/workflows/codacy-analysis.yml:1`, `.github/workflows/njsscan-analysis.yml:1`, `Jenkinsfile:1`, `Jenkinsfile1:1`] | untrusted PR / external action / registry artifact → CI runner → source integrity + secrets | MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 |
| HTTP request handlers (5 routes detected) | Web and REST API endpoints (~5 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~5 framework routes:*

- `POST /secret/signup` (`routers/index.js:292`)
- `POST /secret/addpost` (`routers/index.js:434`)
- `POST /secret/forgot` (`routers/index.js:499`)
- `POST /secret/password-reset/:username/:token` (`routers/index.js:595`)
- *(and ~1 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker bypasses authentication and exfiltrates user records via NoSQL operator injection in login and lookup queries | remote_unauth | HTTP POST /secret/login, HTTP POST /secret/signup, HTTP POST /secret/?user + POST /secret/username, HTTP password-reset flow (forgot + password-reset) | User account PII and credentials (username, email, plaintext password, admin flag) in MongoDB collection 'users' | critical | almost_certain | unmitigated | express-validator notEmpty/isLength checks on login/signup (routers/index.js:119-130,294-303) — insufficient for operator injection | models/user.js:11 [Typeless password field disables casting and preserves operator injection]; routers/index.js:148 [NoSQL operator injection in login findOne enables authentication bypass]; routers/index.js:235 [NoSQL injection and full user dump via query param]; routers/index.js:263 [NoSQL injection and user disclosure via username lookup]; routers/index.js:168 [Login Auth cookie lacks HttpOnly/Secure/SameSite and has no expiry]; routers/index.js:206 [JWT verification without algorithm allowlist or expiry enables forgery]; routers/index.js:727 [Unauthenticated RCE via alg=none JWT forgery chaining into node-serialize shell sink] |
| T2 | Attacker forges sessions and escalates to admin via mass-assigned flags, predictable reset tokens and hardcoded JWT secrets | remote_unauth | HTTP POST /secret/login, HTTP POST /secret/signup, HTTP password-reset flow (forgot + password-reset), HTTP POST /auth/callback OAuth exchange, OAuth redirect pages hash handling | JWT session authority: hardcoded signing secret 'hello' and session secret 'Your_Secret_Key' + Auth cookie sessions | critical | almost_certain | unmitigated | authenticateToken JWT check on profile/addpost/shell (routers/index.js:202-218) — undermined by hardcoded secret | routers/index.js:613 [Password reset overwrites plaintext password without token invalidation or expiry]; routers/index.js:546 [Password-reset user enumeration and Host-header poisonable reset link]; routers/index.js:10 [Hardcoded JWT signing secret 'hello' enables universal token forgery]; app.js:92 [Hardcoded express-session secret with insecure cookie defaults]; routers/index.js:320 [Mass-assignment of admin flag plus plaintext password storage on signup]; routers/index.js:539 [Password-reset token rotation no-op leaves old token valid]; routers/index.js:487 [Logout clears cookie but does not invalidate JWT/server session]; routers/index.js:529 [Password-reset first request never sends email (inverted Token branch)] |
| T3 | Authenticated attacker executes arbitrary code on server via unsafe node-serialize deserialization gadget | remote_auth | HTTP POST /secret/shell deserialization | MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 | critical | almost_certain | unmitigated | authenticateToken gate on /secret/shell (routers/index.js:202-218) — still reachable by any authenticated user | routers/index.js:727 [Authenticated node-serialize deserialization leads to RCE] |
| T4 | Attacker backdoors source or steals CI secrets via vulnerable dependencies and over-privileged PR-triggered pipelines | supply_chain | Supply-chain / CI pipeline surface | MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 | high | possible | partially_mitigated | snyk/njsscan/codacy scan steps in CI — detection only, no pinning or least-privilege |  |
| T5 | Attacker hijacks mail and database trust via hardcoded credentials committed in config and data files | remote_unauth | Parsed config and env (db, mail, sendemail), HTTP password-reset flow (forgot + password-reset), Static file / directory-traversal surface | Gmail SMTP identity in config/mail.js and utils/sendemail.js (tester876905@gmail.com / placeholder pass) | high | possible | unmitigated | none |  |
| T6 | Attacker pivots through server to probe internal network and exfiltrate internal responses via unvalidated URL fetch | remote_unauth | HTTP GET /secret/ SSRF proxy | MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 | high | almost_certain | unmitigated | express-rate-limit 30 req/min (app.js:25-30) | routers/index.js:696 [Unauthenticated SSRF with reflected content via needle fetch] |
| T7 | Attacker uploads malicious files and injects stored XSS via unsanitized post fields and traversable static serving | remote_auth | HTTP POST /secret/addpost + GET /secret/posts/:username, Static file / directory-traversal surface | Blog post data + uploaded image files (images/ dir, posts collection with username/title/description/file) | high | almost_certain | unmitigated | multer fileFilter /\.(png/jpg)$/ + fileSize limits (app.js:56-72) and authenticateToken — weak extension-only check | routers/index.js:436 [Global-state post attribution enables cross-user forgery and stored XSS]; app.js:61 [Weak upload validation allows malicious file persistence in webroot]; routers/index.js:700 [Reflected XSS via SSRF url in success branch]; routers/index.js:706 [Reflected XSS via SSRF url in error branch]; routers/index.js:438 [Null dereference and global pollution on missing upload file]; utils/sendemail.js:212 [Href attribute injection via poisonable reset link]; app.js:74 [Global multer middleware enables unauthenticated file persistence via any POST endpoint] |
| T8 | Attacker exhausts disk/CPU or acts without attribution via unbounded inputs, missing CSRF and log-injection-prone logging | remote_unauth | HTTP POST /secret/login, HTTP POST /secret/addpost + GET /secret/posts/:username, HTTP GET /secret/ SSRF proxy, HTTP POST /secret/shell deserialization | MongoDB datastore integrity/availability (mongodb://localhost:27017/User) and Express service availability on :3000 | medium | almost_certain | unmitigated | express-rate-limit 30 req/min (app.js:25-30); csurf imported but never mounted | routers/index.js:33 [CSRF protection defined but never enforced on state-changing routes]; routers/index.js:79 [OAuth implicit flow with static state never validated enables login CSRF] |
| T9 | Security compromise via Unrestricted CORS allows cross-origin reads of sensitive data | remote_unauth | routers/index.js | application data and system state | medium | almost_certain | unmitigated | none | routers/index.js:46 [Unrestricted CORS allows cross-origin reads of sensitive data] |
| T10 | Arbitrary file disclosure or tampering via path traversal | remote_unauth | app.js | application data and system state | high | almost_certain | unmitigated | none | app.js:27 [Directory traversal via express-blinker static mount] |
| T11 | Horizontal privilege escalation via Insecure Direct Object References (IDOR) | remote_auth | routers/index.js | application data and system state | high | almost_certain | unmitigated | none | routers/index.js:381 [Broken access control allows reading any user's posts] |
| T12 | Information disclosure of sensitive application or configuration data | remote_unauth | public/redirect.html | application data and system state | high | almost_certain | unmitigated | none | public/redirect.html:31 [OAuth token exfiltration via wildcard postMessage] |
| T13 | Security compromise via OAuth bearer token logged in auth callback | remote_unauth | routers/index.js | application data and system state | medium | almost_certain | unmitigated | none | routers/index.js:82 [OAuth bearer token logged in auth callback]; routers/index.js:138 [Plaintext login password written to logs]; routers/index.js:166 [Minted session JWT logged after login]; routers/index.js:54 [Session JWT written to server logs in profile handler] |
| T14 | Security compromise via DOM XSS via eval of URL id parameter | remote_unauth | home.html | application data and system state | high | almost_certain | unmitigated | none | home.html:249 [DOM XSS via eval of URL id parameter] |
| T15 | Security compromise via Auth cookie in OAuth callback lacks HttpOnly/Secure/SameSite | remote_unauth | routers/index.js | application data and system state | medium | almost_certain | unmitigated | none | routers/index.js:99 [Auth cookie in OAuth callback lacks HttpOnly/Secure/SameSite] |
| T16 | Security compromise via Unchecked email dereference DoS in forgot handler | remote_unauth | routers/index.js | application data and system state | medium | almost_certain | unmitigated | none | routers/index.js:501 [Unchecked email dereference DoS in forgot handler] |
| T17 | Security compromise via Password-reset mailer references undefined res causing crash on success | remote_unauth | utils/sendemail.js | application data and system state | medium | almost_certain | unmitigated | none | utils/sendemail.js:294 [Password-reset mailer references undefined res causing crash on success] |
| T18 | Security compromise via Sensitive SSRF and user-dump endpoints lack authentication | remote_unauth | routers/index.js | application data and system state | high | almost_certain | unmitigated | none | routers/index.js:685 [Sensitive SSRF and user-dump endpoints lack authentication] |
| T19 | Security compromise via Implicit global assignments enable cross-request state pollution and data leakage | remote_unauth | models/strict.js | application data and system state | medium | almost_certain | unmitigated | none | models/strict.js:5 [Implicit global assignments enable cross-request state pollution and data leakage] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Direct remote exploitation of unauthenticated MongoDB from internet | MongoDB binds to unauthenticated localhost URI by design for local training; direct remote DB compromise requires local network access already covered by app-layer RCE/SSRF threats. |
| Volumetric network-layer DDoS against Node process | Intentionally vulnerable demo with no production deployment, WAF, or SLO; transport DoS via rate-limit bypass is lower priority than RCE/auth-takeover classes that already achieve availability loss. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is this deployment network-reachable and by whom? README shows local `node app.js` on :3000 with localhost Mongo; no prod topology, WAF, or reverse-proxy documented.
- Who supplies inputs for each entry point (anonymous internet vs authenticated user vs admin)? Auth is JWT-cookie with hardcoded secret; role checks are ad-hoc.
- Are config/mail.js and utils/sendemail.js Gmail values real or placeholders? PASS is empty/underscores and README says SMTP must be configured.
- What MongoDB auth/network controls exist? database/db.js uses unauthenticated localhost URI with no secret management.
- csurf is imported and csrfProtection defined (routers/index.js:30) but never mounted (commented out in app.js:103) and templates use secrettoken=random string — is any CSRF check enforced?
- What bounds Jenkins/GitHub Actions approvals and secret scope (SNYK_TOKEN, DEFECT_DOJO, CODACY_PROJECT_TOKEN)? No path allowlist, environment protection, or reviewer set in tree.
- No SECURITY.md/CHANGELOG/docs found — owner to confirm supported versions, reporting channel, and which README-listed bugs are intentional vs fixed.

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-ninjasworkout
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-ninjasworkout/signals/prefilter.txt (25 entries)
  - secrets: .cerberus/realvuln-ninjasworkout/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-ninjasworkout/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-ninjasworkout/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-ninjasworkout/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-ninjasworkout/signals/routes.txt (5 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Enforce strict-typed parameterized Mongoose queries everywhere and reject Mongo operators in user input | T1 | yes | M |
| Replace hardcoded JWT/session secrets with env-managed strong secrets, short expiry, secure HttpOnly cookies and server-side role checks | T2 | yes | M |
| Remove node-serialize and accept only JSON.parse with schema validation, never eval/unserialize | T3 | yes | M |
| Deny SSRF by allowlisting outbound hosts, blocking internal/metadata IPs, and validating mime/redirects | T6 | partial | M |
| Harden uploads with content-sniffed allowlist, randomized names, storage outside webroot, no-exec and output-encoding | T7 | partial | M |
| Remove secrets from repo into env/secret manager, rotate Gmail/Mongo credentials and enforce auth | T5 | yes | M |
| Pin, patch and scan dependencies and harden CI with pinned actions, least-privilege tokens and required reviews | T4 | partial | M |
| Add authenticated structured logging, CSRF tokens, and per-route rate-limiting with size caps | T8 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-ninjasworkout).
Confirmed primary claims: 40.

By class: CWE-532 x4, CWE-79 x3, CWE-943 x3, CWE-362 x2, CWE-620 x2, CWE-434 x2, CWE-352 x2, CWE-915 x2, CWE-798 x2, CWE-614 x2, CWE-287 x2, CWE-942 x1, CWE-22 x1, CWE-639 x1, CWE-203 x1

Affected paths: routers/index.js x30, app.js x4, utils/sendemail.js x2, models/user.js x1, public/redirect.html x1, home.html x1, models/strict.js x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-200 x1, CWE-203 x1, CWE-22 x1, CWE-248 x1, CWE-252 x1, CWE-287 x2, CWE-306 x1, CWE-352 x2, CWE-362 x2, CWE-434 x2, CWE-476 x1, CWE-502 x1, CWE-532 x4, CWE-613 x1, CWE-614 x2, CWE-620 x2, CWE-639 x1, CWE-640 x1, CWE-79 x3, CWE-798 x2, CWE-915 x2, CWE-918 x1, CWE-942 x1, CWE-943 x3, CWE-95 x1

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x9 at public/hack.js, routers/index.js, utils/sendemail.js — $objectivesContainer.append('<li> ' + chat['/'][i].replace('#{nickname}', nickname) + '</li>'); | validator: public/hack.js:149 nickname=$nicknameInput.val() local only; public/hack.js:154 append with
- CWE-287 x3 at routers/index.js — Token.findOne({username: req.params.username,token: req.params.token},function(err, reset){ | validator: routers/index.js:569-583 GET only renders resetpassword form; routers/index.js:602-610 POST enf
- CWE-829 x3 at .github/workflows/codacy-analysis.yml, .github/workflows/docker-image.yml, .github/workflows/njsscan-analysis.yml — uses: codacy/codacy-analysis-cli-action@1.1.0 | validator: .github/workflows/codacy-analysis.yml:30 CI workflow manifest explicitly out of scope per exclusion rules | refute: exclusion_rule | consensu
- CWE-285 x2 at routers/index.js — router.get('/secret/profile', function(req, res){ | validator: routers/index.js:53 first GET /secret/profile has authenticateToken and ends with res.render; routers/index.js:218 second identical route
- CWE-200 x2 at routers/index.js, views/redirect.html — window.opener.postMessage({"accesstoken":params.access_token},"*"); | validator: views/redirect.html:33 same wildcard postMessage but app.js:119 only serves public/ and no router renders views/redirec
- CWE-1321 x2 at home.html, proto.html — var query = deparam(location.search.slice(1)); | validator: home.html:256 var query=deparam(...) result never merged/used; sink is third-party jquery-deparam client lib, SCA out of scope | refute: exc
- CWE-798 x2 at config/mail.js, utils/sendemail.js — USER = "tester876905@gmail.com" | validator: config/mail.js:1-4 shows USER email literal with PASS="" empty placeholder and SERVICE gmail; email address alone is not a secret and no credential is disc
- CWE-306 x1 at database/db.js — db: 'mongodb://localhost:27017/User' | validator: database/db.js:2 mongodb://localhost:27017/User localhost-only URI; no remote untrusted path to DB shown, only via app layer | refute: not_a_vulnerabi
- CWE-185 x1 at models/strict.js — var validRegex = /^[a-zA-Z0-9.!#$&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*.com$/; | validator: models/strict.js:23 concatenates email into invalidemail but views/Register.pug:159 uses h3=inv
- CWE-476 x1 at routers/index.js — console.log(!decoded.username == req.params.username) | validator: routers/index.js:658-668 verify() returns boolean false on failure, so routers/index.js:601 false.username yields undefined not a nul
- CWE-532 x1 at routers/index.js — console.log(secretstring); | validator: routers/index.js:19 secretstring rendered publicly at routers/index.js:70 and views/login.pug:350 hidden _csrf field; csrfProtection at routers/index.js:30 neve
- CWE-248 x1 at routers/index.js — if (err) throw err; | validator: routers/index.js:148-156 err only on DB failure; invalid creds yield result==null not err, no evidence remote input forces err to reach routers/index.js:153 throw | re
- CWE-346 x1 at views/login.pug — views/login.pug:365 registers message handler with comment claiming origin check but code at views/login.pug:366 reads event.data without any event.origin validation; sender in public/redirect.html:31
