# Threat Model: realvuln-vuln-node-express

## 1. System context

This is Vulnerable Node Express (nodeexpressvulny) — an intentionally vulnerable Express 4 + SQLite + Pug demo explicitly maintained as a target for security-scanner testing (StackHawk/HawkScan). README documents working SQL Injection and Cross-Site Scripting via the search box with example payloads and warns it is for testing purposes only. Users are scanner developers and testers who run it locally via npm install plus node bootstrapdb.js plus npm start, or via Docker/docker-compose on port 3000, and drive it with CircleCI, Azure Pipelines, and stackhawk.yml DAST wiring.

Repo: realvuln-vuln-node-express. Threat model for realvuln-vuln-node-express | stack: unknown stack | entry points: ~3 routes | prefilter signal classes: hardcoded-secret, debug-exposure, log-inject | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, debug-exposure, log-inject.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| user credentials (username/password rows in `user` table, plaintext incl. admin) | SQLite user table with plaintext passwords including admin account seeded by bootstrap script | critical |
| sqlite database file (db/vulny.db containing user + item tables) | File-backed SQLite database containing credentials and catalog, opened per-request | high |
| item catalog data (id/name/description rows) | Searchable item inventory returned as HTML and JSON | low |
| application process integrity and availability (Node/Express server) | Express 4 server process, container filesystem and runtime | medium |
| HTTP cookie and request state (cookieParser / Express req/res) | Session cookies and request state subject to theft via XSS | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP route GET / | GET / renders index.pug with static title; untrusted HTTP request line/headers/cookies reach Express handler and view render (app.js:29, routes/index.js:5, views/index.pug:5) [refs: `app.js:29`, `routes/index.js:5`, `views/index.pug:5`] | untrusted network/client -> application logic + template render | application process integrity and availability, HTTP cookie and request state |
| HTTP routes GET+POST /search (form body searchText) | GET /search renders search form; POST /search takes body field searchText and passes verbatim to searchService.searchByName, whose string-concatenated SQL result and unescaped searchText flow to searchResult.pug h1!= (app.js:30, routes/search.js:7, routes/search.js:13, service/search.js:6, views/search.pug:4, views/searchResult.pug:4) [refs: `app.js:30`, `routes/search.js:7`, `routes/search.js:13`, `service/search.js:6`, `views/search.pug:4`, `views/searchResult.pug:4`] | untrusted network/client form input -> SQL query + HTML render | user credentials (username/password rows in `user` table, plaintext incl. admin), sqlite database file (db/vulny.db containing user + item tables), item catalog data, application process integrity and availability |
| HTTP route GET /api/search (query searchText) | GET /api/search takes query param searchText (default ''), console.log(req.query) plus string concat, calls same searchByName sink and returns rows as JSON; err object returned directly as JSON (app.js:31, routes/api.js:5, service/search.js:6) [refs: `app.js:31`, `routes/api.js:5`, `service/search.js:6`] | untrusted network/client query string -> SQL query + JSON response + server log | user credentials (username/password rows in `user` table, plaintext incl. admin), sqlite database file (db/vulny.db containing user + item tables), item catalog data, application process integrity and availability |
| Network listener + PORT env (bin/www) | Node http server listens on all interfaces on PORT env (default 3000); normalizePort accepts numeric port or named pipe string from environment (bin/www:13, bin/www:29) [refs: `bin/www:13`, `bin/www:29`] | container/host network + process environment -> Node http server | application process integrity and availability |
| SQLite file open + seed script (db/vulny.db) | SQLite file open of ./db/vulny.db at service start and in bootstrap script; bootstrapdb.js creates item/user tables and seeds plaintext passwords; service/search.js reopens same path per require (service/search.js:2, bootstrapdb.js:2, bootstrapdb.js:6, bootstrapdb.js:30) [refs: `service/search.js:2`, `bootstrapdb.js:2`, `bootstrapdb.js:6`, `bootstrapdb.js:30`] | untrusted file content / prior DB state -> process memory + query results | sqlite database file (db/vulny.db containing user + item tables), user credentials (username/password rows in `user` table, plaintext incl. admin), item catalog data |
| Supply chain: Dockerfile + package.json/package-lock.json | Container/dependency supply chain: base image node:14.16.1-buster, COPY . ., RUN npm install, pinned Express 4.16.1-era deps in package.json plus lockfile; no USER pinning (Dockerfile:1, Dockerfile:4, Dockerfile:5, package.json:10, docker-compose.yml:6) [refs: `Dockerfile:1`, `Dockerfile:4`, `Dockerfile:5`, `package.json:10`, `docker-compose.yml:6`] | untrusted base image / registry / npm packages -> container filesystem + runtime | application process integrity and availability |
| CI/CD + DAST config (.circleci, azure-pipelines, stackhawk.yml) | CI/CD and scan wiring: CircleCI machine job curls api.stackhawk.com and download.stackhawk.com then runs npm install/start and hawk scan with HAWK_API_KEY; Azure self-hosted Windows agent docker-runs image and runs HawkScan tasks with hawk_api_key; stackhawk.yml points scanner at http://localhost:3000 with APP_ID from env (.circleci/config.yml:11, .circleci/config.yml:14, azure-pipelines.yml:17, azure-pipelines.yml:27, stackhawk.yml:5) [refs: `.circleci/config.yml:11`, `.circleci/config.yml:14`, `azure-pipelines.yml:17`, `azure-pipelines.yml:27`, `stackhawk.yml:5`] | untrusted CI script source / download server / pipeline secrets -> build agent + deployed container | application process integrity and availability, sqlite database file (db/vulny.db containing user + item tables) |
| HTTP request handlers (3 routes detected) | Web and REST API endpoints (~3 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~3 framework routes:*

- `USE /` (`app.js:29`)
- `USE /search` (`app.js:30`)
- `USE /api` (`app.js:31`)

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker injects SQL via searchText to read or bypass the user table and exfiltrate plaintext credentials | remote_unauth | HTTP routes GET+POST /search (form body searchText), HTTP route GET /api/search (query searchText) | user credentials (username/password rows in `user` table, plaintext incl. admin) | critical | almost_certain | unmitigated | none — API deletes reflected searchText before res.json but does not sanitize DB sink | routes/search.js:13, service/search.js:6, routes/api.js:5, README.md: SQLi payload docs |
| T2 | Attacker reuses hardcoded plaintext seed passwords or readable sqlite file to impersonate users including admin | remote_unauth | SQLite file open + seed script (db/vulny.db) | user credentials (username/password rows in `user` table, plaintext incl. admin) | critical | almost_certain | unmitigated | none | bootstrapdb.js:6, bootstrapdb.js:30, service/search.js:2; bootstrapdb.js:43 [Hardcoded seed credentials including admin password]; bootstrapdb.js:34 [Plaintext password storage without hashing] |
| T3 | Attacker injects script via searchText that renders unescaped and executes in victims browsers to steal cookies and sessions | remote_unauth | HTTP routes GET+POST /search (form body searchText) | HTTP cookie and request state (cookieParser / Express req/res) | high | almost_certain | unmitigated | none | routes/search.js:13, views/searchResult.pug:4 (h1!= unescaped searchText), README.md: XSS docs; routes/search.js:17 [Reflected XSS render via POST /search searchResult]; service/search.js:9 [Sensitive SQL errors and DB rows logged to stdout in shared search service] |
| T4 | Attacker abusing curl-piped HawkScan install or leaked Hawk API keys compromises build agents and resulting images | supply_chain | CI/CD + DAST config (.circleci, azure-pipelines, stackhawk.yml) | application process integrity and availability (Node/Express server) | high | possible | unmitigated | none |  |
| T5 | Attacker probes debug/error output and stack traces to fingerprint internals and plan further exploitation | remote_unauth | HTTP route GET /api/search (query searchText), Network listener + PORT env (bin/www) | application process integrity and availability (Node/Express server) | medium | likely | partially_mitigated | Error-detail gating: stack only in development (app.js); otherwise partial | routes/api.js:5 (err returned as JSON), bin/www + DEBUG=myapp:* wiring |
| T6 | Attacker exhausts unauthenticated routes and SQLite-per-request handling to deny service to legitimate scanners | remote_unauth | HTTP route GET /, Network listener + PORT env (bin/www), HTTP routes GET+POST /search (form body searchText), HTTP route GET /api/search (query searchText) | application process integrity and availability (Node/Express server) | critical | almost_certain | unmitigated | none | service/search.js:6 [test]; service/search.js:4 [Intrinsic SQL concatenation sink in searchByName]; routes/search.js:11 [SQL Injection entry via POST /search searchText]; routes/api.js:7 [SQL Injection entry via GET /api/search query searchText]; routes/api.js:11 [Verbose SQLite error disclosure in GET /api/search] |
| T7 | Attacker injects CRLF/control characters into logged query to forge log entries and erase attribution | remote_unauth | HTTP route GET /api/search (query searchText) | application process integrity and availability (Node/Express server) | medium | possible | unmitigated | none | routes/api.js:5 console.log(req.query) |
| T8 | Audit log tampering or log injection via unneutralized log input | remote_unauth | routes/api.js | application data and system state | medium | almost_certain | unmitigated | none | routes/api.js:8 [Log injection via unsanitized req.query logging] |
| T9 | Security compromise via Missing security headers and CSP baseline amplifies XSS | remote_unauth | app.js | application data and system state | medium | almost_certain | unmitigated | none | app.js:23 [Missing security headers and CSP baseline amplifies XSS] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Authentication bypass / session hijacking via broken auth logic | No authentication, session, or authorization logic exists to spoof or bypass beyond trivial unauthenticated access already modeled; no IDOR/authz cluster to close. |
| Cryptographic failure / weak randomness | No cryptographic operations, tokens, or secrets management in tree beyond seeded plaintext passwords and HawkScan keys already modeled; no crypto-failure cluster. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is there any published security scope/policy or intended deploy network (localhost test only vs. reachable)? No SECURITY.md found — owner to confirm.
- What upstream controls exist, if any (WAF, auth proxy, rate limits, input size caps, helmet/CSP, secrets manager)? None found in code — owner to confirm.
- Are seeded plaintext passwords (admin:S3cr37P@$$w0rD! in bootstrapdb.js) fixture-only, and is db/vulny.db committed/deployed or rebuilt via node bootstrapdb.js?
- Is HAWK_API_KEY / hawk_api_key and APP_ID rotation managed outside this tree; who owns the self-hosted Azure agent pool?
- Base image node:14.16.1-buster is EOL and Dockerfile runs as root with DEBUG=myapp:* — is this intentional vuln-target-only and never reused for production?
- Dependency vulnerability state (Express 4.16.1, pug 2.x, sqlite 3.x, debug 2.6.9) not audited here — owner to confirm scan results.

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-vuln-node-express
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-vuln-node-express/signals/prefilter.txt (16 entries)
  - secrets: .cerberus/realvuln-vuln-node-express/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-vuln-node-express/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-vuln-node-express/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-vuln-node-express/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-vuln-node-express/signals/routes.txt (3 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Use parameterized queries / prepared statements for all SQLite access and never concatenate user input into SQL | T1 | yes | M |
| Auto-escape all template output and enable Content-Security-Policy plus input validation on reflected fields | T3 | yes | M |
| Eliminate hardcoded plaintext credentials, hash passwords with bcrypt/scrypt, and keep seed DB out of the image | T2 | yes | M |
| Return generic error messages to clients, disable DEBUG in production, and sanitize logs with structured logging | T5,T7 | partial | M |
| Rebuild on supported base image, run as non-root USER, pin/audit dependencies, and add healthcheck and resource limits | T6 | partial | M |
| Bind to localhost by default, require auth/rate-limiting/reverse-proxy, and pin CI downloads with secret rotation | T4,T6 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-vuln-node-express).
Confirmed primary claims: 13.

By class: CWE-89 x4, CWE-79 x2, CWE-256 x2, CWE-798 x1, CWE-209 x1, CWE-117 x1, CWE-532 x1, CWE-693 x1

Affected paths: service/search.js x3, routes/api.js x3, bootstrapdb.js x3, routes/search.js x2, views/searchResult.pug x1, app.js x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-117 x1, CWE-209 x1, CWE-256 x2, CWE-532 x1, CWE-693 x1, CWE-79 x2, CWE-798 x1, CWE-89 x4

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-400 x7 at app.js, docker-compose.yml, routes/api.js, service/search.js, stackhawk.yml — app.use(logger('dev')); app.use(express.json()); app.use(express.urlencoded({ extended: false })); | validator: app.js:24-25 express.json()/urlencoded() on Express ~4.16.1 (package.json:13) default to
- CWE-829 x5 at Dockerfile, azure-pipelines.yml — docker run --rm --publish 3000:3000 --detach --name nodeexpressvulny stackhawk/nodeexpressvulny | validator: azure-pipelines.yml:17 docker run stackhawk/nodeexpressvulny and azure-pipelines.yml:12 sel
- CWE-494 x2 at .circleci/config.yml — - run: curl -v https://download.stackhawk.com/hawk/cli/hawk-"${HAWK_VERSION}".zip -o hawk.zip - run: unzip hawk.zip | validator: .circleci/config.yml:15 curl https://download.stackhawk.com/hawk/cli/ha
- CWE-209 x2 at app.js — res.locals.error = req.app.get('env') === 'development' ? err : {}; | validator: app.js:42 res.locals.error = req.app.get('env')==='development' ? err : {} neutralizes stack in production; views/error
- CWE-668 x2 at bin/www, docker-compose.yml — server.listen(port); | validator: bin/www:28 server.listen(port) without host is standard Express bind; service intentionally exposes 3000 per Dockerfile:6 EXPOSE 3000 and docker-compose.yml:6 | refut
- CWE-532 x2 at .circleci/config.yml, service/search.js — - run: hawk --api-key="${HAWK_API_KEY}" scan --env CIRCLE_SHA1="$CIRCLE_SHA1" --env CIRCLE_BRANCH="$CIRCLE_BRANCH" --debug stackhawk.yml | validator: .circleci/config.yml:19 passes ${HAWK_API_KEY} as 
- CWE-319 x2 at bin/www, stackhawk.yml — env: Development host: http://localhost:3000 | validator: stackhawk.yml:4 host http://localhost:3000 is loopback-only scanner target; no remote eavesdropper boundary crossed | refute: not_a_vulnerabil
- CWE-862 x2 at app.js, routes/api.js — router.get('/search', function (req, res, next) { | validator: routes/api.js:5 GET /search is intentionally public catalog query mounted at app.js:31 with no auth model anywhere in repo; no auth-prote
- CWE-352 x2 at routes/search.js — router.post('/', function (req, res, next) { | validator: routes/search.js:10 POST / only calls service/search.js:6 db.all SELECT (read-only) and has no session/auth (app.js:26 only cookieParser, no s
- CWE-248 x2 at bin/www — throw error; | validator: bin/www:56-58 onError handles server 'error' startup event only (syscall!=='listen'), not per-request input; remote attacker cannot trigger via routes | refute: not_reachable
- CWE-732 x2 at bootstrapdb.js, service/search.js — const db = new sqlite3.Database('./db/vulny.db'); | validator: bootstrapdb.js:2 default-mode DB create runs in single-user root container (Dockerfile:1-5 no USER); no multi-user boundary crossed — rea
- CWE-1104 x1 at Dockerfile — FROM node:14.16.1-buster | validator: Dockerfile:1 FROM node:14.16.1-buster and Dockerfile:1-8 no USER; infrastructure/build config out of scope per exclusion rules | refute: exclusion_rule | consensu
- CWE-693 x1 at app.js — var app = express(); | validator: app.js:12 var app=express() lacks helmet/CSP but no tainted sink or boundary crossing demonstrated; absence of hardening baseline alone is not exploitable | refute: n
- CWE-215 x1 at Dockerfile — ENV DEBUG=myapp:* | validator: Dockerfile:6 ENV DEBUG=myapp:* ; Dockerfile build config out of scope per exclusion rules | refute: exclusion_rule | consensus: 1/1 fp
- CWE-614 x1 at app.js — app.use(cookieParser()); | validator: app.js:26 app.use(cookieParser()) without secret but repo has no res.cookie/req.cookies usage (no Set-Cookie flow); no cookie boundary crossed | refute: not_a_vul
