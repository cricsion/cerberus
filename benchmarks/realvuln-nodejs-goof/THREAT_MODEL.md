# Threat Model: realvuln-nodejs-goof

## 1. System context

Goof is Snyk's intentionally vulnerable Node.js/Express todo-list demo (Dreamers Lab tutorial base) used for AppSec training. It serves EJS/Dust/HBS views, persists Todos/Users in MongoDB via mongoose 4.2.4 and Users in MySQL via TypeORM, with in-memory chat store, file import, markdown rendering and shell-assisted image handling. It runs locally via npm start on port 3001 or via Dockerfile/docker-compose with mongo:3/mysql:5 sidecars, and documents its own exploits for shell injection, XSS, open redirect, NoSQL injection and prototype pollution. No SECURITY.md hardening or production scope is claimed; it is a training target not a hardened service.

Repo: realvuln-nodejs-goof. Threat model for realvuln-nodejs-goof | stack: unknown stack | entry points: ~14 routes | prefilter signal classes: hardcoded-secret, js-exec, debug-exposure, log-inject, weak-random, plaintext-creds | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-exec, debug-exposure, log-inject, weak-random, plaintext-creds.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User credentials and session state (Mongo User collection + express-session) | Mongo User records, passwords, express-session sessions | critical |
| Todo items in MongoDB (user-controlled content) | Todo items stored via mongoose, rendered to browsers | medium |
| Users table in MySQL (name, address, role) | TypeORM Users rows backed by MySQL | high |
| Hardcoded secrets (admin password, session secret, SECRET_TOKEN) | Embedded passwords, session secret keyboard cat, tokens | critical |
| Application process integrity (Node runtime, command execution) | Node process, ability to execute OS commands and templates | critical |
| Filesystem contents (extracted zips, backup.txt, package.json, views) | Server files, /tmp extracts, backups, view templates | high |
| Service availability (Mongo/MySQL/Node, ReDoS-sensitive parsers) | Availability of app and DBs under parser/zip/ReDoS load | medium |
| Source-code and supply-chain integrity (dependencies, image, CI) | GitHub code, npm deps, container image, CI secrets and runners | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP POST /login | Unauthenticated username, password, redirectPage form fields into User.find query, console.log and open redirect via adminLoginSuccess; refs routes/index.js:42 app.js:55 [refs: `app.js:55`, `routes/index.js:42`] | untrusted network client -> application auth logic | User credentials and session state (Mongo User collection + express-session), Hardcoded secrets (admin password, session secret, SECRET_TOKEN) |
| HTTP POST /create todo | Unauthenticated content field into markdown render, ImageMagick identify shell string and Mongo Todo.save with base64 Location echo; refs routes/index.js:152 app.js:60 [refs: `app.js:60`, `routes/index.js:152`] | untrusted network client -> shell + DB + template | Todo items in MongoDB (user-controlled content), Application process integrity (Node runtime, command execution), Service availability (Mongo/MySQL/Node, ReDoS-sensitive parsers) |
| HTTP POST /import file upload | Multipart importFile bytes via express-fileupload, file-type sniff then AdmZip.extractAllTo(/tmp/extracted_files), backup.txt read, CSV split, moment locale/format; refs routes/index.js:232 app.js:64 [refs: `app.js:64`, `routes/index.js:232`] | untrusted file upload -> filesystem + parser + DB | Filesystem contents (extracted zips, backup.txt, package.json, views), Todo items in MongoDB (user-controlled content), Service availability (Mongo/MySQL/Node, ReDoS-sensitive parsers) |
| HTTP POST /account_details | Authenticated JSON profile including attacker-added layout passed to res.render account.hbs enabling LFI/layout control; refs routes/index.js:82 app.js:58 [refs: `app.js:58`, `routes/index.js:82`] | authenticated (weak) client -> server-side template engine | Filesystem contents (extracted zips, backup.txt, package.json, views), User credentials and session state (Mongo User collection + express-session) |
| HTTP GET /about_new dust render | Query param device passed to res.render about_new.dust via consolidate/dust; refs routes/index.js:294 app.js:65 [refs: `app.js:65`, `routes/index.js:294`] | untrusted query string -> template engine | Application process integrity (Node runtime, command execution), Filesystem contents (extracted zips, backup.txt, package.json, views) |
| HTTP PUT /chat and GET/DELETE /chat | JSON auth plus message object merged via _.merge into defaults, stored in-memory; prototype-pollution gadget; refs routes/index.js:322 app.js:66 [refs: `app.js:66`, `routes/index.js:322`] | untrusted JSON body -> lodash merge + in-memory store | Application process integrity (Node runtime, command execution), Service availability (Mongo/MySQL/Node, ReDoS-sensitive parsers) |
| HTTP POST /users TypeORM create | JSON name/address/role saved via TypeORM repo.save; nested __proto__/where payload poisons prototype and overrides find({id:1}); refs routes/users.js:23 app.js:69 [refs: `app.js:69`, `routes/users.js:23`, `entity/Users.js:1`, `typeorm-db.js:1`] | untrusted JSON -> ORM deserializer -> SQL | Users table in MySQL (name, address, role), Application process integrity (Node runtime, command execution) |
| HTTP GET /users profile fetch | No-auth GET returns repo.find({id:1}) but polluted Object.where takes precedence allowing IDOR/enumeration; refs routes/users.js:8 app.js:69 [refs: `app.js:69`, `routes/users.js:8`] | untrusted network client -> MySQL-backed API | Users table in MySQL (name, address, role) |
| HTTP GET /destroy/:id, GET /edit/:id, POST /update/:id | Path :id into Todo.findById/remove and save without ownership check and without isLoggedIn on destroy/edit/update; refs routes/index.js:180 app.js:61 app.js:62 app.js:63 [refs: `app.js:61`, `app.js:62`, `app.js:63`, `routes/index.js:180`] | untrusted URL path -> Mongo object lifecycle | Todo items in MongoDB (user-controlled content) |
| HTTP GET /login redirectPage reflector | Query redirectPage reflected unescaped via hidden field and used as res.redirect target; refs views/admin.ejs:14 routes/index.js:52 app.js:54 [refs: `app.js:54`, `routes/index.js:62`, `views/admin.ejs:14`] | untrusted query -> HTML response + redirect | User credentials and session state (Mongo User collection + express-session) |
| HTTP GET / todo list XSS sink | Todo content rendered with unescaped marked() in index.ejs; marked 0.3.5 XSS; refs views/index.ejs:20 routes/index.js:21 app.js:53 [refs: `app.js:53`, `routes/index.js:21`, `views/index.ejs:20`] | stored untrusted DB content -> browser DOM | Todo items in MongoDB (user-controlled content) |
| Static GET /public/* | Static middleware st serves ./public at /public (vuln st 0.2.4 traversal); refs app.js:71 public/about.html:1 [refs: `app.js:71`, `public/about.html:1`] | untrusted URL path -> filesystem read | Filesystem contents (extracted zips, backup.txt, package.json, views) |
| Env/config CloudFoundry/Heroku/Docker | PORT, DOCKER, MONGOLAB_URI/MONGODB_URI, cfenv binding select Mongo URI and log to console; refs mongoose-db.js:21 app.js:32 [refs: `app.js:32`, `mongoose-db.js:21`, `typeorm-db.js:5`] | deployment environment -> DB connection string | User credentials and session state (Mongo User collection + express-session), Service availability (Mongo/MySQL/Node, ReDoS-sensitive parsers) |
| DB seed hardcoded credentials | Seed creates admin@snyk.io/SuperSecretPassword if absent; hardcoded MySQL root/root/acme and Math.random password; refs mongoose-db.js:50 typeorm-db.js:5 routes/index.js:309 [refs: `mongoose-db.js:50`, `typeorm-db.js:5`, `routes/index.js:309`] | hardcoded secret in source -> database + logs | Hardcoded secrets (admin password, session secret, SECRET_TOKEN), User credentials and session state (Mongo User collection + express-session), Users table in MySQL (name, address, role) |
| Container build and runtime config | Dockerfile base node:18.13.0 no USER (root) EXPOSE 3001+9229, npm update/install; compose exposes mongo/mysql and MYSQL_ROOT_PASSWORD=root; refs Dockerfile:1 docker-compose.yml:1 [refs: `Dockerfile:1`, `docker-compose.yml:1`] | untrusted base image / host runtime -> container namespace | Source-code and supply-chain integrity (dependencies, image, CI), Users table in MySQL (name, address, role) |
| CI workflows and dependency supply chain | Workflows checkout and run Snyk/CodeQL with SNYK_TOKEN/SNYK_ORG on push/PR; package.json pins old vuln deps; refs snyk-code.yml:1 codeql-analysis.yml:1 package.json:18 [refs: `.github/workflows/snyk-code.yml:1`, `.github/workflows/codeql-analysis.yml:1`, `package.json:18`] | untrusted PR / external action -> CI runner with secrets | Source-code and supply-chain integrity (dependencies, image, CI), Hardcoded secrets (admin password, session secret, SECRET_TOKEN) |
| HTTP request handlers (14 routes detected) | Web and REST API endpoints (~14 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~14 framework routes:*

- `GET /` (`app.js:53`)
- `GET /login` (`app.js:54`)
- `POST /login` (`app.js:55`)
- `GET /admin` (`app.js:56`)
- `GET /account_details` (`app.js:57`)
- `POST /account_details` (`app.js:58`)
- `GET /logout` (`app.js:59`)
- `POST /create` (`app.js:60`)
- `GET /destroy/:id` (`app.js:61`)
- `GET /edit/:id` (`app.js:62`)
- `POST /update/:id` (`app.js:63`)
- `POST /import` (`app.js:64`)
- `GET /about_new` (`app.js:65`)
- `USE /users` (`app.js:69`)

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker injects OS commands, template directives or prototype keys to execute code and take over the Node process | remote_unauth | HTTP POST /create todo, HTTP POST /account_details, HTTP GET /about_new dust render, HTTP PUT /chat and GET/DELETE /chat, HTTP POST /users TypeORM create | Application process integrity (Node runtime, command execution) | critical | almost_certain | unmitigated | none | routes/index.js:152 (identify shell concat), routes/index.js:82 (hbs layout control), routes/index.js:294 (dust device render), routes/index.js:322 (_.merge pollution), routes/users.js:23 (TypeORM __proto__/where); routes/index.js:161 [OS Command Injection in create via identify URL] |
| T2 | Attacker bypasses or reuses weak authentication and missing ownership checks to hijack sessions and modify others data | remote_unauth | HTTP POST /login, HTTP GET /destroy/:id, GET /edit/:id, POST /update/:id, HTTP GET /users profile fetch, DB seed hardcoded credentials, Env/config CloudFoundry/Heroku/Docker | User credentials and session state (Mongo User collection + express-session) | critical | almost_certain | unmitigated | Session gate routes.isLoggedIn checks req.session.loggedIn===1 before /admin and /account_details; loginHandler requires validator.isEmail before query | routes/index.js:42 (User.find NoSQL query), routes/index.js:180 (destroy/edit/update without isLoggedIn), routes/users.js:8 (find id:1 overridable), mongoose-db.js:50 + typeorm-db.js:5 (seed/default creds); routes/index.js:219 [Null-Dereference DoS in update missing existence check]; routes/index.js:55 [Session Fixation in adminLoginSuccess missing regeneration]; app.js:69 [Missing Authentication on /users API Allows Unauthenticated Admin Creation and Enumeration]; app.js:66 [Missing Authentication on GET /chat Exposes In-Memory Chat History]; routes/index.js:107 [Cross-Unit Authentication Bypass to Template Takeover via Session (NoSQLi to HBS Layout Control)]; routes/index.js:115 [Cross-Unit Prototype-Pollution Authentication Bypass (PUT /chat to isLoggedIn via Object.prototype.loggedIn)] |
| T3 | Attacker reuses hardcoded or weakly generated secrets and leaked connection strings to impersonate admins and decrypt sessions | remote_unauth | DB seed hardcoded credentials, Env/config CloudFoundry/Heroku/Docker, HTTP POST /login | Hardcoded secrets (admin password, session secret, SECRET_TOKEN) | critical | almost_certain | unmitigated | express-session configured with secret keyboard cat (weak but present) | mongoose-db.js:50 (admin@snyk.io/SuperSecretPassword), typeorm-db.js:5 (root/root/acme), routes/index.js:309 (Math.random password), app.js:48 (keyboard cat), app.js:32 + mongoose-db.js:21 (URI logged); app.js:43 [Hardcoded Session Secret keyboard cat]; app.js:83 [Hardcoded SECRET_TOKEN Logged to Console]; views/admin.ejs:17 [Reflected XSS via redirectPage in admin.ejs]; mongoose-db.js:52 [Hardcoded Plaintext Mongo Admin Password]; routes/index.js:317 [Weak Random Admin Password in chat users]; routes/index.js:332 [Unauthenticated Chat History Disclosure in chat.get]; mongoose-db.js:43 [MongoDB Connection String Disclosure in Logs] |
| T4 | Attacker stores scripts in todos or crafts redirect links to steal sessions in victims browsers | remote_unauth | HTTP GET / todo list XSS sink, HTTP GET /login redirectPage reflector, HTTP POST /create todo | Todo items in MongoDB (user-controlled content) | high | almost_certain | unmitigated | marked configured with sanitize:true and exposed as app.locals.marked; save_account_details validates email/phone/ascii | views/index.ejs:20 (<%- marked %> unescaped, marked 0.3.5 XSS), views/admin.ejs:14 (<%- redirectPage %> reflector), routes/index.js:152 (Location echoes base64 content) |
| T5 | Attacker traverses archive entries, static paths or template layout to read and overwrite server files | remote_unauth | HTTP POST /import file upload, Static GET /public/*, HTTP POST /account_details, HTTP GET /about_new dust render | Filesystem contents (extracted zips, backup.txt, package.json, views) | high | almost_certain | unmitigated | import checks uploaded bytes with file-type before zip-vs-text branch | routes/index.js:232 (AdmZip.extractAllTo /tmp + backup.txt read), app.js:71 (st 0.2.4 traversal), routes/index.js:82 (hbs layout LFI); routes/index.js:257 [Zip-Slip Arbitrary File Overwrite in import]; routes/index.js:107 [Template Layout Control via save_account_details]; views/layout.ejs:7 [Insecure HTTP Script Include in layout.ejs] |
| T6 | Attacker poisons dependencies, base image or CI runners to backdoor the app and steal CI secrets | supply_chain | Container build and runtime config, CI workflows and dependency supply chain, Env/config CloudFoundry/Heroku/Docker | Source-code and supply-chain integrity (dependencies, image, CI) | high | possible | partially_mitigated | CI runs CodeQL javascript analysis and Snyk code/test scans on push/PR | Dockerfile:1 (node:18.13.0 root, EXPOSE 9229), docker-compose.yml:1 (MYSQL_ROOT_PASSWORD=root, exposed DB ports), package.json:18 (st, mongoose, marked, lodash vuln pins), .github/workflows/snyk-code.yml:1 |
| T7 | Attacker exhausts CPU, memory or disk with zip bombs, ReDoS strings and merge recursion to deny service | remote_unauth | HTTP POST /create todo, HTTP POST /import file upload, HTTP PUT /chat and GET/DELETE /chat, HTTP POST /users TypeORM create | Service availability (Mongo/MySQL/Node, ReDoS-sensitive parsers) | medium | possible | unmitigated | none |  |
| T8 | Security compromise via NoSQL Operator Injection in loginHandler password | remote_unauth | routes/index.js | application data and system state | high | almost_certain | unmitigated | none | routes/index.js:39 [NoSQL Operator Injection in loginHandler password]; routes/index.js:61 [Open Redirect in adminLoginSuccess via redirectPage] |
| T9 | Security compromise via Prototype Pollution in chat.add via lodash merge | remote_unauth | routes/index.js | application data and system state | high | almost_certain | unmitigated | none | routes/index.js:347 [Prototype Pollution in chat.add via lodash merge]; routes/index.js:359 [Cross-Unit Prototype-Pollution Privilege Escalation (PUT /chat to DELETE /chat and /users Query Hijack)] |
| T10 | Security compromise via Hardcoded MySQL root Credentials | remote_unauth | routes/index.js, typeorm-db.js | application data and system state | high | almost_certain | unmitigated | none | typeorm-db.js:12 [Hardcoded MySQL root Credentials]; routes/index.js:315 [Hardcoded Chat Credential Enables Authenticated Prototype-Pollution Entry] |
| T11 | Unauthorized access via missing authorization checks | remote_auth | routes/index.js, routes/users.js | application data and system state | high | almost_certain | unmitigated | none | routes/index.js:191 [Missing Authorization in destroy allows arbitrary deletion]; routes/index.js:221 [Missing Authorization in update allows arbitrary overwrite]; routes/users.js:16 [Unauthenticated User Enumeration in GET /users]; routes/index.js:152 [Missing Authorization in create allows anonymous todo creation] |
| T12 | Security compromise via Unbounded Zip Decompression in import enables zip-bomb DoS | remote_unauth | app.js, routes/index.js | application data and system state | medium | almost_certain | unmitigated | none | routes/index.js:255 [Unbounded Zip Decompression in import enables zip-bomb DoS]; app.js:49 [Unbounded File Upload Size in express-fileupload]; routes/index.js:279 [Attacker-Controlled Moment Locale in import] |
| T13 | Security compromise via Verbose Error Disclosure via development errorHandler | remote_unauth | app.js | application data and system state | medium | almost_certain | unmitigated | none | app.js:80 [Verbose Error Disclosure via development errorHandler] |
| T14 | Security compromise via Insecure Session Cookie Flags | remote_unauth | app.js, routes/index.js | application data and system state | medium | almost_certain | unmitigated | none | app.js:45 [Insecure Session Cookie Flags]; routes/index.js:285 [Stored XSS via import CSV content persistence] |
| T15 | Privilege escalation or unauthorized state tampering via mass assignment | remote_auth | routes/users.js | application data and system state | high | almost_certain | unmitigated | none | routes/users.js:36 [Mass Assignment Role Escalation in POST /users] |
| T16 | Security compromise via Cloud Environment Disclosure in Logs | remote_unauth | mongoose-db.js, typeorm-db.js | application data and system state | high | almost_certain | unmitigated | none | mongoose-db.js:21 [Cloud Environment Disclosure in Logs]; mongoose-db.js:49 [User Password Disclosure via console.log(users)]; typeorm-db.js:15 [Verbose SQL Logging Leaks PII in TypeORM] |
| T17 | Arbitrary code execution via dynamic code evaluation | remote_unauth | routes/index.js | application data and system state | critical | almost_certain | unmitigated | none | routes/index.js:300 [Dust Template Injection via device in about_new]; routes/index.js:203 [Missing Authorization in edit exposes all todos]; routes/index.js:241 [Missing Authorization in import allows anonymous file upload] |
| T18 | Unauthorized state change via cross-site request forgery (CSRF) | remote_unauth | app.js | application data and system state | medium | almost_certain | unmitigated | none | app.js:61 [CSRF via State-Changing GET /destroy/:id route]; app.js:42 [Missing CSRF, Security Headers, Rate Limiting and Hardened Cookies] |
| T19 | Security compromise via Plaintext Password Storage in Mongoose User Schema | remote_unauth | mongoose-db.js | application data and system state | high | almost_certain | unmitigated | none | mongoose-db.js:14 [Plaintext Password Storage in Mongoose User Schema] |
| T20 | Horizontal privilege escalation via Insecure Direct Object References (IDOR) | remote_auth | app.js | application data and system state | high | almost_certain | unmitigated | none | app.js:61 [Missing Authorization and IDOR on Todo lifecycle routes (create/destroy/edit/update/import)] |
| T21 | Audit log tampering or log injection via unneutralized log input | remote_unauth | routes/index.js | application data and system state | medium | almost_certain | unmitigated | none | routes/index.js:271 [Log Injection via Unsanitized CSV Field in POST /import] |
| T22 | Internal service access and cloud metadata exposure via Server-Side Request Forgery (SSRF) | remote_unauth | routes/index.js | application data and system state | high | almost_certain | unmitigated | none | routes/index.js:161 [Server-Side Request Forgery via ImageMagick identify URL fetch in POST /create] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Remote debugging or stack-trace disclosure via exposed 9229/errorhandler | Node debugger exposure on 9229 and verbose errorhandler only matter if deployment exposes those ports/mode; owner confirms demo stays on localhost and errorhandler stays development-gated, so parked below code-injection and auth failures. |
| Log forgery and repudiation via unsanitized console.log of login/import inputs | Console.log credential/log-injection weakens forensics but does not by itself yield RCE, takeover or data theft; ranked below direct injection, auth bypass and secret disclosure. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is this intentionally-vulnerable Goof demo ever exposed beyond localhost:3001, and is Node debugger port 9229 firewalled?
- What upstream controls (TLS, WAF, auth proxy, size limits on body/fileUpload) sit in front of bodyParser/fileUpload and exec/AdmZip paths?
- Are hardcoded credentials (admin@snyk.io/SuperSecretPassword, MySQL root/root, keyboard cat, SECRET_TOKEN) rotated or is this purely a local demo seed?
- What MongoDB/MySQL authentication, network ACLs, and persistence apply in CloudFoundry/Heroku/Docker targets using MONGOLAB_URI/cfenv?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-nodejs-goof
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-nodejs-goof/signals/prefilter.txt (40 entries)
  - secrets: .cerberus/realvuln-nodejs-goof/signals/secrets.json (1 entries)
  - iac: .cerberus/realvuln-nodejs-goof/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-nodejs-goof/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-nodejs-goof/signals/routes.txt (14 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Replace all shell/template string building with safe APIs: execFile without shell, allowlisted template names, no user-controlled layout. | T1,T5 | partial | M |
| Enforce authentication and ownership authorization on every state-changing and data-fetching route and use parameterized ORM/NoSQL queries. | T2,T4 | partial | M |
| Encode all template output by default, sanitize markdown with maintained sanitizer, validate redirect allowlist. | T3 | partial | M |
| Remove hardcoded secrets from source/seed, load from vault/env, rotate session secret and DB passwords, use CSPRNG. | T2,T4 | partial | M |
| Harden file handling: validate zip entries against traversal, cap size/count, extract to isolated temp dir, upgrade st/parsers. | T5,T7 | partial | M |
| Pin and continuously update dependencies/images, run as non-root, drop debugger port, lock CI permissions and secrets. | T6 | partial | M |
| Impose global size/timeout/rate limits and ReDoS-safe parsers to bound CPU/memory/disk exhaustion. | T7 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-nodejs-goof).
Confirmed primary claims: 47.

By class: CWE-798 x4, CWE-862 x4, CWE-532 x4, CWE-94 x4, CWE-400 x3, CWE-943 x2, CWE-1321 x2, CWE-79 x2, CWE-256 x2, CWE-614 x2, CWE-352 x2, CWE-306 x2, CWE-287 x2, CWE-78 x1, CWE-22 x1

Affected paths: routes/index.js x25, app.js x10, mongoose-db.js x5, typeorm-db.js x2, routes/users.js x2, views/admin.ejs x1, views/index.ejs x1, views/layout.ejs x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-117 x1, CWE-1321 x2, CWE-200 x1, CWE-209 x1, CWE-22 x1, CWE-256 x2, CWE-287 x2, CWE-306 x2, CWE-338 x1, CWE-352 x2, CWE-384 x1, CWE-400 x3, CWE-476 x1, CWE-532 x4, CWE-614 x2, CWE-639 x1, CWE-78 x1, CWE-79 x2, CWE-798 x4, CWE-829 x1, CWE-862 x4, CWE-915 x1, CWE-918 x1, CWE-94 x4, CWE-943 x2

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-338 x2 at utils.js — return Math.floor( Math.random() * ( max - min + 1 )) + min; | validator: utils.js:3-4 defines ran_no via Math.random but no security caller: no utils. use in routes/ (only require at routes/index.js:
- CWE-532 x2 at app.js, routes/users.js — console.log(results) | validator: routes/users.js:20 console.log(results) logs rows that are already returned unauthenticated via routes/users.js:22 res.json(results); logged fields name/address/role 
- CWE-117 x2 at routes/index.js — console.log(`User logged in: ${username}`) | validator: routes/index.js:42 validator.isEmail(req.body.username) gates login before routes/index.js:58 console.log(`User logged in: ${username}`), reject
- CWE-200 x1 at Dockerfile — EXPOSE 9229 | validator: Dockerfile:12 EXPOSE 9229 and docker-compose.yml:10 9229:9229 mapping are Dockerfile/container run config, explicitly out of scope per exclusion rules | refute: exclusion_rule
- CWE-798 x1 at docker-compose.yml — MYSQL_ROOT_PASSWORD: root | validator: docker-compose.yml:24 MYSQL_ROOT_PASSWORD: root is container run config, explicitly out of scope per infrastructure exclusion | refute: exclusion_rule | consensu
- CWE-650 x1 at app.js — app.use(methodOverride()); | validator: app.js:41 app.use(methodOverride()) allows verb tunneling but auth is session-based via routes/index.js:117 isLoggedIn (req.session.loggedIn===1), not method-sp
- CWE-391 x1 at routes/index.js — } catch (e) { | validator: routes/index.js:191 Todo.findById to routes/index.js:198 empty catch(e){} only swallows single-request error with no response; server stays up, no secret/auth boundary cross
- CWE-400 x1 at routes/index.js — item += ' [' + d.format(format) + ']'; | validator: routes/index.js:274 format from CSV to routes/index.js:282 d.format(format) only controls display formatting with no code exec or ReDoS; attacker al
- CWE-829 x1 at Dockerfile — FROM node:18.13.0 | validator: Dockerfile:2 FROM node:18.13.0 is build/infra config out of scope per exclusion rules | refute: exclusion_rule | consensus: 1/1 fp
- CWE-704 x1 at typeorm-db.js — synchronize: true, | validator: typeorm-db.js:14 synchronize:true is operational schema flag with no attacker-controlled inflow; no auth/dataflow boundary crossed | refute: not_a_vulnerability | conse
- CWE-755 x1 at routes/users.js — next(); | validator: routes/users.js:41-43 catch calls next() without err falls to Express finalhandler 404, not hang; no security impact | refute: misread_code | consensus: 1/1 fp
