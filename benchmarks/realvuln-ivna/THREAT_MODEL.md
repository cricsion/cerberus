# Threat Model: realvuln-ivna

## 1. System context

ivna is an intentionally vulnerable Node.js task manager and API training target (Express + Mongoose + Handlebars) presenting task/user CRUD, cookie JWT sessions, and static HTML/JS clients. Users sign up, log in, manage tasks and profiles via v2 authenticated APIs, views, and intentionally retained unauthenticated v1 legacy APIs. It runs as two containers (ivna app + mongo) for local CTF/API-testing use, with no evidence of upstream WAF, TLS, rate-limiting, or production hardening.

Repo: realvuln-ivna. Threat model for realvuln-ivna | stack: unknown stack | entry points: ~10 routes | prefilter signal classes: hardcoded-secret, js-exec, js-xss, log-inject, plaintext-creds | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-exec, js-xss, log-inject, plaintext-creds.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User account records (name, email, bcrypt-checked password, age, tokens[]) |  | critical |
| Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie |  | critical |
| JWT signing secret literal 'hardsecret' (auth integrity root) |  | critical |
| MongoDB database 'task-manager' / 'task-manager-api' backend datastore |  | critical |
| Task records + owner link (User._id) in MongoDB |  | high |
| Node/Express application process + container availability (port 8000) |  | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP POST /api/v2/users (signup) | Unauthenticated JSON/form body -> new User(req.body) -> save + generateAuthToken + Set-Cookie auth_token + redirect /dashboard; file: src/routers/user.js:16 [refs: `src/routers/user.js:16`] | untrusted network/client -> application + MongoDB | User account records (name, email, bcrypt-checked password, age, tokens[]), Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie |
| HTTP POST /dashboard (login) | Unauthenticated email/password body -> User.findByCredentials -> JWT + cookie + redirect; failure redirects with error query; file: src/routers/user.js:32 [refs: `src/routers/user.js:32`] | untrusted network/client -> authentication logic | User account records (name, email, bcrypt-checked password, age, tokens[]), Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie |
| HTTP GET /api/v2/user?name= (eval sink, no auth) | Query string req.query.name passed directly to eval() and reflected in response; file: src/routers/user.js:213-216 [refs: `src/routers/user.js:213`] | untrusted URL query -> JS engine (code execution) | Node/Express application process + container availability (port 8000) |
| HTTP GET /contact?url= (SSRF + open redirect, no auth) | Query string ?url= parsed via url.parse(req.url) then needle.get(query.url) server-side fetch, then redirect to attacker URL; file: src/routers/user.js:189-211 [refs: `src/routers/user.js:189`] | untrusted URL query -> server-side HTTP client + redirect | Node/Express application process + container availability (port 8000), MongoDB database 'task-manager' / 'task-manager-api' backend datastore |
| HTTP POST /api/v2/profile (template render) | Authenticated JSON body req.body.profile passed as template context to res.render('profile', profile); file: src/routers/user.js:124-128 [refs: `src/routers/user.js:124`] | authenticated client JSON -> Handlebars template engine | Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie, User account records (name, email, bcrypt-checked password, age, tokens[]) |
| HTTP POST /api/v2/tasks (create task, auth) | Authenticated CRUD with owner binding; POST body spread into Task({...req.body, owner}) ; file: src/routers/task.js:7 [refs: `src/routers/task.js:7`] | authenticated client JSON -> MongoDB via Mongoose | Task records + owner link (User._id), MongoDB database 'task-manager' / 'task-manager-api' backend datastore |
| HTTP GET/PATCH/DELETE /api/v2/tasks[/:id] (auth, owner-scoped) | Authenticated reads/updates/deletes scoped by { _id, owner }; PATCH allowlists description/completed; files: src/routers/task.js:21,30,46,70 [refs: `src/routers/task.js:21`, `src/routers/task.js:30`, `src/routers/task.js:46`, `src/routers/task.js:70`] | authenticated client -> owner authorization check -> MongoDB | Task records + owner link (User._id) |
| Legacy HTTP /api/v1/tasks + /api/v1/users/:name/:id (unauthenticated / IDOR) | No-auth list-all and BOLA update/delete by arbitrary :id (findById / findByIdAndDelete, ignoring req.user); files: src/routers/task.js:86,95 + src/routers/user.js:240,281,306 [refs: `src/routers/task.js:86`, `src/routers/task.js:95`, `src/routers/user.js:240`, `src/routers/user.js:281`, `src/routers/user.js:306`] | untrusted network/client -> legacy API bypassing owner checks | Task records + owner link (User._id), User account records (name, email, bcrypt-checked password, age, tokens[]), MongoDB database 'task-manager' / 'task-manager-api' backend datastore |
| HTTP PATCH/DELETE /api/v2/users/me + GET /logout + POST /users/logoutAll (auth) | Authenticated self update/delete via req.body keys applied to req.user (allowlisted) + token wipe logout; files: src/routers/user.js:92,104,137,156 [refs: `src/routers/user.js:92`, `src/routers/user.js:104`, `src/routers/user.js:137`, `src/routers/user.js:156`] | authenticated client -> own account/session state | User account records (name, email, bcrypt-checked password, age, tokens[]), Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie |
| HTTP static + Handlebars views (GET /api/v2/profile, /settings, /dashboard) | Authenticated profile/settings/dashboard hbs renders + static dirs public/ and express.static; files: src/index.js:22-34, src/routers/user.js:117,131,166 [refs: `src/index.js:22`, `src/index.js:29`, `src/routers/user.js:117`, `src/routers/user.js:131`, `src/routers/user.js:166`] | untrusted HTTP -> static file/template rendering | User account records (name, email, bcrypt-checked password, age, tokens[]), Node/Express application process + container availability (port 8000) |
| Cookie input auth_token (session) | Cookie auth_token read in middleware and verified; no Authorization header check server-side; file: src/middleware/auth.js:7 [refs: `src/middleware/auth.js:7`, `src/index.js:34`] | untrusted cookie -> JWT verify + DB session lookup | Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie |
| Env/config input MONGO_URI + DB name | MONGO_URI/DB_NAME/PORT from compose environment; mongoose.connect('mongodb://mongo:27017/task-manager-api'); file: src/db/mongoose.js:3, docker-compose.yml:14-18 [refs: `src/db/mongoose.js:3`, `docker-compose.yml:14`, `mongodb.js:10`] | deployment environment/config -> DB connection | MongoDB database 'task-manager' / 'task-manager-api' backend datastore |
| Container build/runtime (Dockerfile + compose) | FROM node:12.1.0, npm ci, COPY ., EXPOSE 8000, CMD npm start (no USER, runs as root); mongo:latest with host-mapped 27017:27017 no auth; files: Dockerfile:1-11, docker-compose.yml:1-22 [refs: `Dockerfile:1`, `docker-compose.yml:1`] | untrusted base image / host network -> container runtime | Node/Express application process + container availability (port 8000), MongoDB database 'task-manager' / 'task-manager-api' backend datastore |
| Supply chain: package.json dependencies + lockfile | Direct npm deps incl. node-serialize 0.0.4, needle, jsonwebtoken, mongoose, hbs/handlebars, validator; lockfile present; file: package.json:12-26 [refs: `package.json:12`] | third-party registry/code -> application runtime | Node/Express application process + container availability (port 8000), Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie |
| HTTP request handlers (10 routes detected) | Web and REST API endpoints (~10 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~10 framework routes:*

- `POST /api/v2/tasks` (`src/routers/task.js:7`)
- `GET /api/v2/tasks/:id` (`src/routers/task.js:30`)
- `PATCH /api/v2/tasks/:id` (`src/routers/task.js:46`)
- `DELETE /api/v2/tasks/:id` (`src/routers/task.js:70`)
- `PATCH /api/v1/tasks/:id` (`src/routers/task.js:95`)
- `POST /api/v2/users` (`src/routers/user.js:16`)
- `POST /dashboard` (`src/routers/user.js:32`)
- `GET /api/v1/users/:name` (`src/routers/user.js:240`)
- `PATCH /api/v1/users/:id` (`src/routers/user.js:281`)
- `DELETE /api/v1/users/:id` (`src/routers/user.js:306`)

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker bypasses owner checks via legacy APIs to read, modify, or delete any task or user. | remote_unauth | Legacy HTTP /api/v1/tasks + /api/v1/users/:name/:id (unauthenticated / IDOR); HTTP GET/PATCH/DELETE /api/v2/tasks[/:id] (auth, owner-scoped); HTTP POST /api/v2/tasks (create task, auth) | Task records + owner link (User._id) in MongoDB | critical | almost_certain | unmitigated | Owner-scoped task queries on /api/v2 (Task.findOne({_id, owner}) in src/routers/task.js:33,52,72) — bypassed by legacy routes with none | src/routers/task.js:86,95 findById without owner; src/routers/user.js:240,281,306 unauthenticated findById/updates; src/routers/user.js:291 [BOLA arbitrary user update via v1 patch]; src/routers/user.js:308 [BOLA arbitrary user deletion via v1 delete]; src/routers/task.js:105 [BOLA arbitrary task modification via v1 patch]; src/routers/task.js:88 [Unauthenticated bulk task disclosure via v1 list] |
| T2 | Attacker executes arbitrary server-side JavaScript via code-injection sinks to seize the process. | remote_unauth | HTTP GET /api/v2/user?name= (eval sink, no auth); HTTP POST /api/v2/profile (template render); Supply chain: package.json dependencies + lockfile | Node/Express application process + container availability (port 8000) | critical | likely | unmitigated | none | src/routers/user.js:213 eval(req.query.name); src/routers/user.js:124 res.render('profile', profile) with attacker JSON |
| T3 | Attacker forges or reuses JWT sessions to impersonate any user and take over accounts. | remote_unauth | HTTP POST /api/v2/users (signup); HTTP POST /dashboard (login); Cookie input auth_token (session); HTTP PATCH/DELETE /api/v2/users/me + GET /logout + POST /users/logoutAll (auth) | Session/auth state: JWTs signed with 'hardsecret' + stored tokens[] + auth_token cookie | critical | almost_certain | unmitigated | auth middleware (src/middleware/auth.js:5-22) requires auth_token cookie, jwt.verify with 'hardsecret', DB lookup User.findOne({_id, 'tokens.token'}) | src/models/user.js: hardsecret literal; src/middleware/auth.js:7 jwt.verify; src/routers/user.js:16,32 token issuance; src/routers/user.js:22 [Insecure session cookie missing HttpOnly/Secure/SameSite on signup]; src/routers/user.js:36 [Insecure session cookie missing flags on login]; src/models/user.js:71 [JWT without expiration enables indefinite sessions] |
| T4 | Attacker exploits exposed database, root container, or vulnerable dependencies to compromise the host or exhaust availability. | adjacent_network | Env/config input MONGO_URI + DB name; Container build/runtime (Dockerfile + compose); Supply chain: package.json dependencies + lockfile | MongoDB database 'task-manager' / 'task-manager-api' backend datastore | critical | possible | unmitigated | none |  |
| T5 | Attacker forces the server to fetch internal URLs and redirect victims to steal data or probe the network. | remote_unauth | HTTP GET /contact?url= (SSRF + open redirect, no auth) | MongoDB database 'task-manager' / 'task-manager-api' backend datastore | critical | almost_certain | unmitigated | none | src/routers/user.js:189-211 needle.get(query.url) + redirect to attacker URL; src/routers/user.js:197 [Open redirect to attacker-controlled URL in contact handler] |
| T6 | Attacker injects scripts stored in user/task fields that execute in victims' browsers to steal sessions. | remote_unauth | HTTP static + Handlebars views (GET /api/v2/profile, /settings, /dashboard); HTTP POST /api/v2/profile (template render); HTTP POST /dashboard (login); HTTP POST /api/v2/users (signup) | User account records (name, email, bcrypt-checked password, age, tokens[]) | high | possible | unmitigated | Client-side only stripHTML/sanitizeHTML helpers (public/js/client-util.js:26-63) — not server-side control; Input validation in Mongoose schema (validator.isEmail, password rules) | src/routers/user.js:117,131,166 hbs renders; public/js/client-util.js:26 sanitizer unused server-side |
| T7 | Attacker tampers with persisted records via mass-assignment or NoSQL operator injection to escalate privilege. | remote_unauth | HTTP POST /api/v2/users (signup); HTTP POST /api/v2/tasks (create task, auth); HTTP GET/PATCH/DELETE /api/v2/tasks[/:id] (auth, owner-scoped); HTTP PATCH/DELETE /api/v2/users/me + GET /logout + POST /users/logoutAll (auth) | User account records (name, email, bcrypt-checked password, age, tokens[]) | high | almost_certain | unmitigated | User.toJSON strips password and tokens (src/models/user.js:60-68); PATCH allowlist (src/routers/task.js:48-53, src/routers/user.js:138-143) — bypassed by direct spread and legacy | src/routers/task.js:7 Task({...req.body, owner}); src/routers/user.js:16 new User(req.body); src/routers/user.js:92 req.body key assignment; src/routers/user.js:17 [Signup mass-assignment allows arbitrary User field injection] |
| T8 | Security compromise via Unauthenticated remote code execution via eval | remote_unauth | src/routers/user.js | application data and system state | critical | almost_certain | unmitigated | none | src/routers/user.js:215 [Unauthenticated remote code execution via eval] |
| T9 | Internal service access and cloud metadata exposure via Server-Side Request Forgery (SSRF) | remote_unauth | src/routers/user.js | application data and system state | high | almost_certain | unmitigated | none | src/routers/user.js:194 [Unauthenticated SSRF via contact url parameter] |
| T10 | Security compromise via Signup error handler discloses internal error details | remote_unauth | src/routers/task.js, src/routers/user.js | application data and system state | medium | almost_certain | unmitigated | none | src/routers/user.js:26 [Signup error handler discloses internal error details]; src/routers/user.js:152 [Error disclosure in PATCH users me]; src/routers/user.js:302 [Error disclosure in PATCH v1 users id]; src/routers/task.js:17 [Error disclosure in POST tasks]; src/routers/task.js:66 [Error disclosure in PATCH v2 tasks id]; src/routers/task.js:116 [Error disclosure in PATCH v1 tasks id] |
| T11 | Information disclosure of sensitive application or configuration data | remote_unauth | src/routers/user.js | application data and system state | high | almost_certain | unmitigated | none | src/routers/user.js:250 [Unauthenticated user disclosure and enumeration via v1 name lookup]; src/routers/user.js:244 [Unauthenticated user disclosure via v1 name lookup] |
| T12 | Security compromise via Missing authentication on v2 user endpoint | remote_unauth | src/routers/user.js | application data and system state | critical | almost_certain | unmitigated | none | src/routers/user.js:213 [Missing authentication on v2 user endpoint] |
| T13 | Security compromise via Missing password hashing stores plaintext credentials | remote_unauth | src/models/user.js | application data and system state | high | almost_certain | unmitigated | none | src/models/user.js:86 [Missing password hashing stores plaintext credentials] |
| T14 | Security compromise via Hardcoded JWT verify secret in auth middleware | remote_unauth | src/middleware/auth.js, src/models/user.js | application data and system state | critical | almost_certain | unmitigated | none | src/middleware/auth.js:8 [Hardcoded JWT verify secret in auth middleware]; src/models/user.js:71 [Hardcoded JWT signing secret enables token forgery] |
| T15 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | public/contact.html, public/src/profile-app.js | application data and system state | high | almost_certain | unmitigated | none | public/contact.html:190 [DOM XSS via contact name query reflection]; public/src/profile-app.js:15 [Stored XSS via profile name innerHTML rendering] |
| T16 | Unauthorized state change via cross-site request forgery (CSRF) | remote_unauth | src/routers/user.js | application data and system state | medium | almost_certain | unmitigated | none | src/routers/user.js:92 [State-changing logout via GET enables CSRF] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Remote code execution via node-serialize deserialization | node-serialize 0.0.4 is listed as dependency but no unserialize() call was found in files read; no reachable deserialization sink confirmed. Parked pending proof of reachability rather than merged as RCE. |
| Log forgery obscuring audit trail | Log-injection regex fired but no security-relevant logging/audit trail was found to corrupt; repudiation risk is already covered by missing audit controls. Parked as low impact. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is this deployment ever network-reachable beyond localhost:8000, and who is the intended user (CTF learner vs hosted demo)?
- What upstream controls exist (WAF, TLS terminator, rate limits, size caps) — none found in src/index.js or compose?
- Is MongoDB authentication / network policy intended? compose maps 27017:27017 with no credentials found.
- Is node-serialize deserialization reachable (imported in src/routers/user.js:9-13 but no unserialize call found) — dead code or hidden route?
- Should legacy /api/v1 routes be removed, and what is the intended authorization model?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-ivna
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-ivna/signals/prefilter.txt (15 entries)
  - secrets: .cerberus/realvuln-ivna/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-ivna/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-ivna/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-ivna/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-ivna/signals/routes.txt (10 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Remove hardcoded JWT secret; require strong secret from environment and rotate existing tokens | T3 | yes | M |
| Remove or authenticate/authorize legacy v1 routes; enforce owner-scoped queries on every object access | T1 | yes | M |
| Eliminate eval() and untrusted template contexts; use safe parsers and sandboxed rendering | T2 | yes | M |
| Validate and allowlist outbound fetch targets; block cloud-metadata/internal addresses and attacker-controlled redirects | T5 | partial | M |
| Encode all template output server-side and enforce Content-Security-Policy; never rely on client-side sanitizers | T4 | partial | M |
| Enforce strict allowlisted schemas and parameterized Mongo queries; reject $ operators and extra keys | T7 | partial | M |
| Harden deployment: non-root user, pinned minimal base, no exposed DB, auth + resource limits | T6 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-ivna).
Confirmed primary claims: 27.

By class: CWE-209 x6, CWE-639 x3, CWE-614 x2, CWE-200 x2, CWE-256 x2, CWE-798 x2, CWE-79 x2, CWE-95 x1, CWE-915 x1, CWE-918 x1, CWE-601 x1, CWE-306 x1, CWE-352 x1, CWE-862 x1, CWE-613 x1

Affected paths: src/routers/user.js x16, src/routers/task.js x5, src/models/user.js x3, src/middleware/auth.js x1, public/contact.html x1, public/src/profile-app.js x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-200 x2, CWE-209 x6, CWE-256 x2, CWE-306 x1, CWE-352 x1, CWE-601 x1, CWE-613 x1, CWE-614 x2, CWE-639 x3, CWE-79 x2, CWE-798 x2, CWE-862 x1, CWE-915 x1, CWE-918 x1, CWE-95 x1

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x4 at public/js/app.js, public/js/client-app.js, public/src/profile-app.js, src/routers/user.js — res.send('Welcome name ' + eval(req.query.name)); | validator: Same sink res.send+eval at src/routers/user.js:215 as unit-public-10; XSS impact subsumed by RCE, single fix | refute: duplicate | consen
- CWE-94 x2 at src/routers/user.js — res.render('profile', profile) | validator: Hardcoded template name res.render('profile', profile) at src/routers/user.js:128; attacker controls only context values, Handlebars does not evaluate conte
- CWE-798 x2 at mongodb.js, src/db/mongoose.js — const connectionURL = 'mongodb://mongo:27017' | validator: mongodb.js:11 hardcoded URL in standalone script never required; src/index.js:3 uses src/db/mongoose.js:3, no import of mongodb.js | refute: 
- CWE-117 x2 at src/routers/user.js — console.log(query.url) | validator: src/routers/user.js:192 console.log(query.url) is debug stdout with no audit/security-log consumer or principal boundary | refute: not_a_vulnerability | consensus: 
- CWE-1104 x2 at Dockerfile, src/routers/user.js — var serialize = require('node-serialize'); //deser | validator: src/routers/user.js:11 only requires node-serialize; no unserialize() call in src/; package.json:21 pin is SCA-only with no reachable de
- CWE-943 x2 at src/models/user.js, src/routers/user.js — const user = await User.findByCredentials(req.body.email, req.body.password) | validator: src/routers/user.js:34 email passed to findByCredentials but src/models/user.js:80 findOne({email}) followed b
- CWE-693 x1 at src/index.js — app.use(express.json()) | validator: src/index.js:24-36 shows no helmet/rate-limit but absence alone demonstrates no tainted sink or principal boundary crossing | refute: not_a_vulnerability | consens
- CWE-85 x1 at public/js/client-util.js — .replace(/<[^>]+>/ig, '') | validator: public/js/client-util.js:23-42 stripHTML is browser-only helper used at public/js/client-app.js:51,274; server stores raw description at src/routers/task.js:7-17
- CWE-287 x1 at src/middleware/auth.js — const user = await User.findOne({ _id: decoded._id, 'tokens.token': token }) | validator: src/middleware/auth.js:7-9 enforces jwt.verify + User.findOne tokens.token DB lookup; revocation via tokens=[]
- CWE-400 x1 at src/index.js — app.use(express.json()) | validator: src/index.js:29,34 express.json() uses framework default 100kb limit, not unbounded; no custom large limit | refute: misread_code | consensus: 1/1 fp
- CWE-614 x1 at public/js/client-util.js — document.cookie = name + "=" + encodeURIComponent(value) + expires + '; Path=' + path + '; SameSite=' + sameSite + (secure ? ' Secure' : '') | validator: public/js/client-util.js:72,85 document.cookie
- CWE-306 x1 at docker-compose.yml — ports: - 27017:27017 | validator: docker-compose.yml:9-11 ports 27017:27017 mapping is container-run config; infra/build configs are out of scope per exclusion rules | refute: exclusion_rule | consens
- CWE-915 x1 at src/routers/task.js — const task = new Task({ | validator: src/routers/task.js:7-11 new Task({...req.body, owner:req.user._id}) owner forced after spread overwrites attacker owner; src/models/task.js:4-18 strict schema onl
