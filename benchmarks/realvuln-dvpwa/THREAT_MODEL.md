# Threat Model: realvuln-dvpwa

## 1. System context

DVPWA (Damn Vulnerable Python Web Application) is an intentionally vulnerable school grading training app inspired by DVWA, implementing students, courses, marks, course reviews and login/logout to demonstrate web vulnerabilities. It is used by students/trainees in a lab following a 2017 presentation, with no real users or real data by design. It runs either via docker-compose (app + postgres + redis) or natively with local postgres/redis, and must be treated as lab-only and never exposed to untrusted networks or loaded with real credentials.

Repo: realvuln-dvpwa. Threat model for realvuln-dvpwa | stack: unknown stack | entry points: ~0 routes | prefilter signal classes: sqli-cursor, jinja-render, md5-sha1, js-exec, js-xss, log-inject, weak-random, plaintext-creds, docker-add, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): sqli-cursor, jinja-render, md5-sha1, js-exec, js-xss, log-inject, weak-random, plaintext-creds, docker-add, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.rst.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User accounts, password hashes (MD5) and session identity | Login users, MD5 password hashes from fixtures, session user_id identity | high |
| Academic data: students, courses, marks, course_reviews in PostgreSQL | Students, courses, grades/marks and course reviews taught in demo school site | medium |
| PostgreSQL database (sqli) confidentiality/integrity/availability | Backend sqli database holding all app tables | high |
| Redis session store and active login sessions | Server-side sessions backing authentication | high |
| Deployment secrets: DB password in config/dev.yaml and fixture credentials | Cleartext db password and weak fixture passwords | medium |
| Server process integrity (Jinja2 render context + Python app) | aiohttp Python process and Jinja2 rendering context | high |
| Service availability (aiohttp on 0.0.0.0:8080 + postgres + redis) | Web service and backing stores availability | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP GET/POST / login | Unauthenticated form username/password via request.post(); looks up User.get_by_username and MD5 check, sets session[user_id]; last_visited also read/written to Redis session [refs: `sqli/routes.py:6`, `sqli/views.py:20`] | unauthenticated network client → aiohttp handler + DB + session store | User accounts, password hashes (MD5) and session identity, Redis session store and active login sessions, PostgreSQL database (sqli) confidentiality/integrity/availability |
| HTTP GET/POST /students/ create+list students | POST name passed unvalidated to Student.create which string-interpolates into INSERT; GET lists all students [refs: `sqli/routes.py:9`, `sqli/views.py:50`, `sqli/dao/student.py:36`] | unauthenticated network client → SQL query string | Academic data: students, courses, marks, course_reviews in PostgreSQL, PostgreSQL database (sqli) confidentiality/integrity/availability, Server process integrity (Jinja2 render context + Python app) |
| HTTP GET /students/{id} view student | Path param id cast to int, used in parameterized Student.get / Mark.get_for_student; rendered with selective /e [refs: `sqli/routes.py:11`, `sqli/views.py:62`] | network path param → DB lookup → Jinja render | Academic data: students, courses, marks, course_reviews in PostgreSQL, Server process integrity (Jinja2 render context + Python app) |
| HTTP GET/POST /courses/ create+list courses | POST title/description passed to Course.create (parameterized); no server-side authz check — admin-only UI gate only [refs: `sqli/routes.py:13`, `sqli/views.py:81`, `sqli/dao/course.py:38`] | unauthenticated network client → DB insert (authz bypass: UI-only admin check) | Academic data: students, courses, marks, course_reviews in PostgreSQL, PostgreSQL database (sqli) confidentiality/integrity/availability |
| HTTP GET /courses/{id} view course + reviews | Path course_id to Course.get + Review.get_for_course; review_text rendered unescaped enabling stored XSS; evaluate aside form posts here [refs: `sqli/routes.py:15`, `sqli/views.py:94`, `sqli/templates/course.jinja2:23`] | stored DB review_text → Jinja engine (autoescape=False) → victim browser | Academic data: students, courses, marks, course_reviews in PostgreSQL, Server process integrity (Jinja2 render context + Python app), Redis session store and active login sessions |
| HTTP GET/POST /courses/{course_id}/review submit review | POST review_text (only presence-checked) to Review.create parameterized INSERT; no auth required; later rendered unescaped [refs: `sqli/routes.py:21`, `sqli/views.py:113`, `sqli/dao/review.py:28`] | unauthenticated network form input → DB row → stored-XSS sink | Academic data: students, courses, marks, course_reviews in PostgreSQL, Server process integrity (Jinja2 render context + Python app) |
| HTTP POST /students/{student_id}/evaluate/{course_id} grade student | Path student_id/course_id + POST points validated 0-5 via EVALUATE_SCHEMA then Mark.create parameterized INSERT; no authn/authz check [refs: `sqli/routes.py:17`, `sqli/views.py:142`, `sqli/schema/forms.py:3`] | unauthenticated network client → grade integrity (missing authorization) | Academic data: students, courses, marks, course_reviews in PostgreSQL, PostgreSQL database (sqli) confidentiality/integrity/availability |
| HTTP POST /logout/ | Authenticated-only route via @authorize(); pops user_id from Redis session and redirects [refs: `sqli/routes.py:28`, `sqli/views.py:156`, `sqli/utils/auth.py:5`] | authenticated session → session destruction | Redis session store and active login sessions, User accounts, password hashes (MD5) and session identity |
| HTTP GET /static/* static files | Unauthenticated static file serving from sqli/static/ [refs: `sqli/routes.py:29`] | network client → filesystem read (path traversal bounded by aiohttp static handler) | Service availability (aiohttp on 0.0.0.0:8080 + postgres + redis) |
| CLI argv + YAML config file | CLI argv parsed with trafaret-config standard_argparse_options default ./config/dev.yaml; YAML config supplies DB/redis/app host/ports/passwords; aiohttp debug=True + 0.0.0.0 bind [refs: `run.py:13`, `sqli/app.py:15`, `config/dev.yaml:1`, `sqli/schema/config.py:3`] | local operator/config file + process argv → app config + DSN construction (sqli/services/db.py:10) | Deployment secrets: DB password in config/dev.yaml and fixture credentials, Service availability (aiohttp on 0.0.0.0:8080 + postgres + redis) |
| Infra data stores: postgres + redis connections | Redis session backend with no password/TLS; cookie httponly=False; Postgres DSN built by string format from config [refs: `sqli/services/db.py:10`, `sqli/services/redis.py:10`, `sqli/middlewares.py:15`, `docker-compose.yml:3`] | app process → plaintext LAN connections to postgres:5432 / redis:6379 | PostgreSQL database (sqli) confidentiality/integrity/availability, Redis session store and active login sessions, Deployment secrets: DB password in config/dev.yaml and fixture credentials |
| Supply chain + container build/runtime | Build-time remote code fetch (wget raw.githubusercontent.com wait-for), pinned 2018-era vulnerable pins (aiohttp 3.5.3, jinja2 2.10, pyyaml 3.13), DB image copies migrations/, compose publishes 5432/8080 with default creds [refs: `Dockerfile.app:3`, `requirements.txt:1`, `Dockerfile.db:1`, `docker-compose.yml:1`] | external registry/network + lockfile contents → container filesystem and runtime | Server process integrity (Jinja2 render context + Python app), Deployment secrets: DB password in config/dev.yaml and fixture credentials, Service availability (aiohttp on 0.0.0.0:8080 + postgres + redis) |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker injects SQL via student creation to read, modify, or destroy database contents | remote_unauth | HTTP GET/POST /students/ create+list students, HTTP GET /students/{id} view student | PostgreSQL database (sqli) confidentiality/integrity/availability | critical | almost_certain | unmitigated | Partial parameterized queries elsewhere (User/Course/Review/Mark DAOs); no validation on student name path | sqli/dao/student.py:41 [SQL injection in Student.create]; sqli/views.py:57 [Missing authorization on student creation]; sqli/views.py:54 [Missing authentication on POST /students/ allows unauthenticated student creation] |
| T2 | Attacker cracks weak MD5 password hashes and forges or hijacks login sessions via CSRF and stealable cookies | remote_unauth | HTTP GET/POST / login, HTTP POST /logout/, Infra data stores: postgres + redis connections | User accounts, password hashes (MD5) and session identity | high | almost_certain | unmitigated | Redis-backed server-side sessions with httponly=False; CSRF enforcement commented out | sqli/app.py:27 [CSRF middleware disabled]; sqli/middlewares.py:20 [Session cookie without HttpOnly flag]; sqli/views.py:42 [Session fixation on login]; sqli/dao/user.py:40 [Unsalted fast MD5 password hashing with weak fixture passwords] |
| T3 | Attacker invokes grade, course, and student mutations without authentication to forge academic records | remote_unauth | HTTP GET/POST /courses/ create+list courses, HTTP POST /students/{student_id}/evaluate/{course_id} grade student, HTTP GET/POST /students/ create+list students | Academic data: students, courses, marks, course_reviews in PostgreSQL | high | almost_certain | unmitigated | authorize() gate on logout only; no server-side authz on students/courses create or evaluate | sqli/templates/course.jinja2:49 [Stored XSS via student name in evaluate sidebar]; sqli/templates/student.jinja2:19 [Stored XSS via course fields on student page]; sqli/views.py:129 [Missing authentication on POST /courses/{course_id}/review]; sqli/views.py:135 [Missing authorization on POST /students/{student_id}/evaluate/{course_id} allows unauthenticated grade forgery] |
| T4 | Attacker plants stored cross-site script via course review to hijack victim sessions | remote_unauth | HTTP GET/POST /courses/{course_id}/review submit review, HTTP GET /courses/{id} view course + reviews | Redis session store and active login sessions | high | almost_certain | unmitigated | Selective Jinja /e escaping on some variables despite global autoescape=False; CSRF token generator exists but enforcement disabled | sqli/templates/course.jinja2:22 [Stored XSS via course review_text]; sqli/templates/course.jinja2:14 [Stored XSS via course title/description]; sqli/templates/course.jinja2:9 [Stored XSS via course title in breadcrumb]; sqli/templates/review.jinja2:32 [Stored XSS via course title on review page (card title)] |
| T5 | Attacker compromises build-time fetch or pinned vulnerable dependency to execute code in the container | supply_chain | Supply chain + container build/runtime | Server process integrity (Jinja2 render context + Python app) | high | possible | unmitigated | none |  |
| T6 | Attacker on the network or with config access reads cleartext secrets and intercepts plaintext database and session traffic | adjacent_network | CLI argv + YAML config file, Infra data stores: postgres + redis connections | Deployment secrets: DB password in config/dev.yaml and fixture credentials | high | almost_certain | unmitigated | none | config/dev.yaml:1 [Hardcoded database credentials in config/dev.yaml] |
| T7 | Attacker floods unauthenticated endpoints or static serving to exhaust resources and acts without attributable logs | remote_unauth | HTTP GET /static/* static files, HTTP GET/POST /students/ create+list students, HTTP GET/POST /courses/ create+list courses | Service availability (aiohttp on 0.0.0.0:8080 + postgres + redis) | medium | possible | unmitigated | Centralized error-page middleware; no rate limits, size caps, or audit logging found |  |
| T8 | Database compromise and sensitive data exfiltration via SQL injection | remote_unauth | sqli/app.py | application data and system state | critical | almost_certain | unmitigated | none | sqli/app.py:33 [Global Jinja2 autoescape disabled] |
| T9 | Security compromise via Unsalted MD5 password hashing | remote_unauth | sqli/dao/user.py | application data and system state | high | almost_certain | unmitigated | none | sqli/dao/user.py:40 [Unsalted MD5 password hashing] |
| T10 | Unauthorized access via missing authorization checks | remote_auth | sqli/views.py | application data and system state | high | almost_certain | unmitigated | none | sqli/views.py:89 [Missing authorization on course creation]; sqli/views.py:151 [Missing authorization on grade evaluation]; sqli/views.py:129 [Missing authentication on review submission]; sqli/views.py:84 [Missing authorization on POST /courses/ allows unauthenticated course creation] |
| T11 | Security compromise via aiohttp debug mode enabled | remote_unauth | sqli/app.py | application data and system state | medium | almost_certain | unmitigated | none | sqli/app.py:23 [aiohttp debug mode enabled] |
| T12 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | sqli/templates/course.jinja2, sqli/templates/courses.jinja2, sqli/templates/evaluate.jinja2 | application data and system state | high | almost_certain | unmitigated | none | sqli/templates/courses.jinja2:17 [Stored XSS in courses list]; sqli/templates/students.jinja2:16 [Stored XSS via student name list]; sqli/templates/evaluate.jinja2:25 [XSS via student name on evaluate error page]; sqli/templates/course.jinja2 [template reflection surface]; sqli/templates/courses.jinja2 [template reflection surface]; sqli/templates/review.jinja2 [template reflection surface]; sqli/templates/students.jinja2 [template reflection surface] |
| T13 | Security compromise via Internal error details disclosed in 50x page | remote_unauth | sqli/middlewares.py, sqli/templates/errors/50x.jinja2 | application data and system state | medium | almost_certain | unmitigated | none | sqli/templates/errors/50x.jinja2:6 [Internal error details disclosed in 50x page]; sqli/middlewares.py:51 [Error middleware only handles HTTPException, leaking debug tracebacks] |
| T14 | Security compromise via No rate-limiting or lockout on login enables brute-force | remote_unauth | sqli/views.py | application data and system state | high | almost_certain | unmitigated | none | sqli/views.py:40 [No rate-limiting or lockout on login enables brute-force]; sqli/views.py:33 [No rate-limiting or lockout on login enables credential brute-force] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Remote code execution via server-side template injection | No user-controlled template path or template-editing feature found; autoescape=False enables stored/reflected XSS (covered) but not server-side template injection to RCE without an additional template-upload primitive. |
| Path traversal via static file serving escaping sqli/static/ | Static handler delegates to aiohttp static file handling which bounds traversal; no custom path join or symlink logic found, so lower priority than intentional SQLi/XSS/authz flaws. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is this deployment ever network-reachable beyond lab use? README presents it as intentionally vulnerable demo on localhost:8080 — confirm it must never be exposed or loaded with real data.
- What bounds the exposed ports (5432 postgres, 8080 app, redis) — host firewall, compose override, or auth? No TLS, no Redis password, and default db password postgres found in config.
- Workload identity: no USER in Dockerfile.app, no serviceAccount/IAM (plain compose) — app likely runs as root; is that accepted for a lab image, and what reaches the Docker socket/host?
- Credentials surviving teardown: fixture MD5 hashes of weak passwords (superadmin/superadmin, password, spidey) committed in migrations — are these lab-only and rotated anywhere reused?
- Upstream controls: no WAF, size caps, rate limits, or security headers found in code — is any gateway expected to add them, or intentionally absent for training?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-dvpwa
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-dvpwa/signals/prefilter.txt (81 entries)
  - secrets: .cerberus/realvuln-dvpwa/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-dvpwa/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-dvpwa/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-dvpwa/signals/codegraph-index.txt (1 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Use parameterized queries everywhere and forbid string-interpolated SQL | T1 | yes | M |
| Enable Jinja2 autoescape by default and encode all DB-sourced output | T4 | yes | M |
| Enforce server-side authentication and role-based authorization on every state-changing handler | T2,T3 | yes | M |
| Store only salted slow hashes, issue Secure/HttpOnly/SameSite session cookies over TLS, and enable CSRF enforcement | T2,T3 | partial | M |
| Pin and scan dependencies, verify build fetches, run as non-root with secrets from vault not repo | T5 | partial | M |
| Bind to localhost, disable debug, require passwords/TLS for postgres/redis, and firewall published ports | T6 | partial | M |
| Add rate limits, request size caps, and append-only audit logging for auth and data mutations | T7 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-dvpwa).
Confirmed primary claims: 34.

By class: CWE-79 x13, CWE-862 x6, CWE-89 x2, CWE-209 x2, CWE-307 x2, CWE-306 x2, CWE-352 x1, CWE-328 x1, CWE-489 x1, CWE-1004 x1, CWE-384 x1, CWE-327 x1, CWE-798 x1

Affected paths: sqli/views.py x11, sqli/templates/course.jinja2 x5, sqli/app.py x3, sqli/dao/user.py x2, sqli/middlewares.py x2, sqli/templates/courses.jinja2 x2, sqli/templates/students.jinja2 x2, sqli/templates/review.jinja2 x2, sqli/dao/student.py x1, sqli/templates/errors/50x.jinja2 x1, sqli/templates/student.jinja2 x1, sqli/templates/evaluate.jinja2 x1, config/dev.yaml x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-1004 x1, CWE-209 x2, CWE-306 x2, CWE-307 x2, CWE-327 x1, CWE-328 x1, CWE-352 x1, CWE-384 x1, CWE-489 x1, CWE-79 x13, CWE-798 x1, CWE-862 x6, CWE-89 x2

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x5 at sqli/templates/base.jinja2, sqli/templates/index.jinja2 — <span class="">{{ auth_user.first_name }} {{ auth_user.middle_name or '' }} {{ auth_user.last_name }}</span> | validator: sqli/templates/base.jinja2:39 auth_user names come from users table written on
- CWE-20 x3 at sqli/utils/auth.py, sqli/views.py — user_id = session.get('user_id') | validator: sqli/utils/auth.py:29-31 server-side session user_id passed to parameterized sqli/dao/user.py:26-29 WHERE id=%s; no injection and None safely returns None
- CWE-319 x2 at sqli/services/db.py, sqli/services/redis.py — redis = await aioredis.create_pool((conf['host'], conf['port']), | validator: sqli/services/redis.py:12 create_pool without password/TLS but docker-compose.yml:12-15 redis service publishes no ports (
- CWE-732 x1 at config/dev.yaml — host: 0.0.0.0 | validator: config/dev.yaml:14 wildcard host consumed at run.py:17 is deployment/container config out of scope | refute: exclusion_rule | consensus: 1/1 fp
- CWE-1104 x1 at Dockerfile.db — FROM postgres:9.6.15-alpine | validator: Dockerfile.db:1 postgres:9.6.15-alpine pin is Dockerfile/dependency-pin out of scope | refute: exclusion_rule | consensus: 1/1 fp
- CWE-250 x1 at Dockerfile.app — ADD ./run.py /app | validator: Dockerfile.app:1-20 has no USER directive; ADD at Dockerfile.app:18 is container build config out of scope | refute: exclusion_rule | consensus: 1/1 fp
- CWE-532 x1 at run.py — logging.basicConfig(level=logging.DEBUG) | validator: run.py:11 sets DEBUG level but no source shows passwords/queries/secrets written to logs; no boundary crossed | refute: not_a_vulnerability | cons
- CWE-754 x1 at sqli/templates/review.jinja2 — <span>{{ fieldname }}: {{ error }}</span> | validator: sqli/templates/review.jinja2:25-26 display typo hides message but sqli/views.py:115-122 still blocks Review.create; non-security UI gap | refute:
- CWE-798 x1 at config/dev.yaml — password: postgres | validator: config/dev.yaml:3 password postgres is dev-only default documented for local docker; no remote secret disclosure by code itself | refute: not_a_vulnerability | consensu
- CWE-758 x1 at sqli/dao/course.py — await cur.execute(q, **params) | validator: sqli/dao/course.py:31-37 execute(q,**params) buggy but callers sqli/views.py:62-94 call Course.get_many(conn) without limit/offset; no attacker inflow, only
- CWE-613 x1 at sqli/views.py — session.pop('user_id', None) | validator: sqli/views.py:158-159 session.pop(user_id) removes auth; sqli/utils/auth.py:27-31 get_auth_user then returns None, old cookie yields unauthenticated session |
- CWE-494 x1 at Dockerfile.app — && wget -O /usr/bin/wait-for https://raw.githubusercontent.com/eficode/wait-for/master/wait-for | validator: Dockerfile.app:4 wget wait-for is Dockerfile build fetch; Dockerfiles explicitly out of sco
- CWE-200 x1 at docker-compose.yml — - 5432:5432 | validator: docker-compose.yml:9 5432:5432 publish is container run config; container run configs explicitly out of scope per exclusion rules | refute: exclusion_rule | consensus: 1/1 fp
