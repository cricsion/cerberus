# Threat Model: realvuln-flask-xss

## 1. System context

Flask XSS is an intentionally vulnerable Flask training sandbox companion to Web Application Hacker's Handbook Ch.12. It demonstrates reflected, cookie-based, and stored XSS with a hackable admin user and a toggleable X-XSS-Protection header. Local learners clone the repo, pip install requirements, run manage.py add_admin (default admin/admin) and runserver on localhost:5000 backed by SQLite at /tmp/test.db with DEBUG=True and a hardcoded SECRET_KEY. Every sink uses Jinja `| safe` by design with no output encoding, no password hashing, no CSRF tokens, and no secure cookie flags.

Repo: realvuln-flask-xss. Threat model for realvuln-flask-xss | stack: unknown stack | entry points: ~10 routes | prefilter signal classes: hardcoded-secret, sqli-cursor, jinja-render, cookie-flags, tpl-xss, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, sqli-cursor, jinja-render, cookie-flags, tpl-xss, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User credentials (username, plaintext password, email in User table) | User table stores plaintext passwords and emails queried and updated by login and account flows | high |
| Login session & Flask SECRET_KEY ('Keep it secret, keep it safe') | Hardcoded SECRET_KEY signing Flask-Login sessions; session cookie is auth token | critical |
| Feedback Messages store (message, from_user, acknowledged flag) | Persistent attacker-controlled messages rendered to admin and via API | medium |
| Admin capability (admin user, /admin panel, Messages acknowledge workflow) | Default admin/admin account plus admin-only views and acknowledge actions | high |
| Application integrity & availability (SQLite at /tmp/test.db, DEBUG app) | Single-file SQLite DB and DEBUG=True dev server; process integrity and availability | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| GET /sandbox/unsafe_params (?name=) | Query param ?name= read via request.args and rendered with {{ name / safe }}; reflected XSS demo [refs: `app/blueprints/sandboxes/views.py:6`, `app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:5`] | untrusted network query param → server template HTML/JS execution | Application integrity & availability (SQLite at /tmp/test.db, DEBUG app), Login session & Flask SECRET_KEY ('Keep it secret, keep it safe') |
| GET/POST /sandbox/unsafe_cookies (cookie + form name) | Cookie `name` via request.cookies plus POST form field `name`; value re-rendered with / safe and persisted via response.set_cookie without flags [refs: `app/blueprints/sandboxes/views.py:20`, `app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html:5`] | untrusted cookie/form input → response HTML + Set-Cookie | Login session & Flask SECRET_KEY ('Keep it secret, keep it safe'), Application integrity & availability (SQLite at /tmp/test.db, DEBUG app) |
| POST /auth/login (username, password) | Form username/password looked up via User.query.filter_by and compared as plaintext; on success login_user + redirect [refs: `app/blueprints/login/views.py:9`] | untrusted network form input → auth/session decision + DB read | User credentials (username, plaintext password, email in User table), Login session & Flask SECRET_KEY ('Keep it secret, keep it safe'), Admin capability (admin user, /admin panel, Messages acknowledge workflow) |
| GET/POST /auth/logout | Terminates Flask-Login session and redirects to index; reachable anonymously [refs: `app/blueprints/login/views.py:27`] | authenticated session → anonymous session | Login session & Flask SECRET_KEY ('Keep it secret, keep it safe') |
| GET /account_area/ (authenticated) | Authenticated-only account page rendering g.user.username/email and reflecting error string; base template renders username with / safe [refs: `app/blueprints/account_area/views.py:9`, `app/templates/_base.html:54`] | authenticated request → DB-backed user record rendered to HTML | User credentials (username, plaintext password, email in User table), Login session & Flask SECRET_KEY ('Keep it secret, keep it safe') |
| POST /account_area/change_password | Form fields current-password/new-password/confirm-password; plaintext comparison then User.query.update password + commit; no CSRF, no hashing [refs: `app/blueprints/account_area/views.py:15`] | authenticated form input → credential store write | User credentials (username, plaintext password, email in User table) |
| POST /account_area/change_email | Form field email written directly via User.query.update email + commit; no validation beyond non-empty [refs: `app/blueprints/account_area/views.py:41`] | authenticated form input → user record write | User credentials (username, plaintext password, email in User table) |
| POST /account_area/send_feedback (feedback) | Form field feedback stored as Message(message, from_user=current_user.username); later rendered with / safe in admin view = stored XSS source [refs: `app/blueprints/account_area/views.py:61`, `app/templates/admin/message.html:31`] | authenticated form input → persistent message store → admin browser | Feedback Messages store (message, from_user, acknowledged flag), Admin capability (admin user, /admin panel, Messages acknowledge workflow) |
| GET /toggle_xss_protection/?next= (open redirect + header toggle) | Flips session xss_protection_enabled and redirects to attacker-controllable ?next (defaults to index); controls after_request X-XSS-Protection: 0 header [refs: `app/blueprints/xss_protection/views.py:6`, `app/flask_xss.py:50`] | untrusted query param → session state + 302 Location header | Login session & Flask SECRET_KEY ('Keep it secret, keep it safe'), Application integrity & availability (SQLite at /tmp/test.db, DEBUG app) |
| API /api/v1/messages (Flask-Classy MessagesView) | JSON body {message, from_user} via request.get_json() stored as Message without auth; JSON list/read/delete/acknowledge gated by admin_required; serialize includes all fields [refs: `app/blueprints/api/views.py:14`, `app/blueprints/api/views.py:39`, `app/blueprints/api/views.py:57`] | untrusted JSON/URL id → DB + JSON response; admin-only vs unauthenticated POST split | Feedback Messages store (message, from_user, acknowledged flag), Admin capability (admin user, /admin panel, Messages acknowledge workflow) |
| GET /admin/messages (MessagesView) + /admin User ModelView | Admin-only HTML/JS view over unacknowledged Messages rendering from_user/message/date with / safe plus AJAX POST to acknowledge endpoint; backed by AdminOnlyMixin [refs: `app/blueprints/admin/views.py:18`, `app/templates/admin/message.html:31`] | persistent attacker message → admin browser JS execution | Feedback Messages store (message, from_user, acknowledged flag), Admin capability (admin user, /admin panel, Messages acknowledge workflow), User credentials (username, plaintext password, email in User table) |
| GET / (index) + manage.py add_admin + supply chain (requirements/setup/CDN) | Index enumerates sandbox routes and renders; management command creates/overwrites admin/admin with default password; pip/CDN supply chain [refs: `app/flask_xss.py:60`, `manage.py:11`, `requirements.txt:1`, `setup.py:3`, `app/templates/_base.html:7`] | local operator/packaging/CDN inputs → deployed app identity and client execution | Admin capability (admin user, /admin panel, Messages acknowledge workflow), Application integrity & availability (SQLite at /tmp/test.db, DEBUG app) |
| HTTP request handlers (10 routes detected) | Web and REST API endpoints (~10 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |

### Key Detected Endpoints
*Detected ~10 framework routes:*

- `GET /` (`app/blueprints/account_area/views.py:9`)
- `POST /change_password` (`app/blueprints/account_area/views.py:15`)
- `POST /change_email` (`app/blueprints/account_area/views.py:41`)
- `POST /send_feedback` (`app/blueprints/account_area/views.py:61`)
- `POST /login` (`app/blueprints/login/views.py:9`)
- `POST /logout` (`app/blueprints/login/views.py:27`)
- `GET /unsafe_params` (`app/blueprints/sandboxes/views.py:6`)
- `GET /unsafe_cookies` (`app/blueprints/sandboxes/views.py:20`)
- *(and ~2 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker authenticates as admin or forges sessions using default admin/admin credentials, plaintext password comparison, and hardcoded SECRET_KEY | remote_unauth | POST /auth/login (username, password), GET /account_area/ (authenticated), GET /admin/messages (MessagesView) + /admin User ModelView, GET / (index) + manage.py add_admin + supply chain (requirements/setup/CDN) | User credentials (username, plaintext password, email in User table), Login session & Flask SECRET_KEY ('Keep it secret, keep it safe'), Admin capability (admin user, /admin panel, Messages acknowledge workflow) | critical | almost_certain | unmitigated | Flask-Login LoginManager with user_loader; no hashing or secret randomness found | app/blueprints/login/views.py:9, manage.py:11, app/flask_xss.py:SECRET_KEY; app/flask_xss.py:23 [Hardcoded Flask SECRET_KEY enables session forgery]; app/blueprints/login/views.py:17 [Plaintext password comparison in login]; app/blueprints/account_area/views.py:34 [Plaintext password storage in change_password]; manage.py:14 [Default admin credential in manage] |
| T2 | Attacker injects script via reflected, cookie, or stored inputs that executes in victim and admin browsers and hijacks sessions | remote_unauth | GET /sandbox/unsafe_params (?name=), GET/POST /sandbox/unsafe_cookies (cookie + form name), POST /account_area/send_feedback (feedback), API /api/v1/messages (Flask-Classy MessagesView), GET /admin/messages (MessagesView) + /admin User ModelView, GET /account_area/ (authenticated) | Login session & Flask SECRET_KEY ('Keep it secret, keep it safe'), Admin capability (admin user, /admin panel, Messages acknowledge workflow) | critical | almost_certain | unmitigated | none — every sink uses `/ safe` by design; X-XSS-Protection toggle defaults off and is attacker-flippable | app/blueprints/sandboxes/views.py:6, app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:5, app/blueprints/sandboxes/views.py:20, app/blueprints/account_area/views.py:61, app/templates/admin/message.html:31; app/blueprints/sandboxes/views.py:36 [Reflected cookie XSS in unsafe_cookies handler] |
| T3 | Attacker creates unauthenticated stored messages and invokes admin-gated read/delete/acknowledge paths via IDOR or missing ownership checks | remote_unauth | API /api/v1/messages (Flask-Classy MessagesView), GET /admin/messages (MessagesView) + /admin User ModelView | Feedback Messages store (message, from_user, acknowledged flag), Admin capability (admin user, /admin panel, Messages acknowledge workflow) | high | almost_certain | unmitigated | admin_required decorator + AdminOnlyMixin.is_accessible; unauthenticated POST to MessagesView still permitted | app/blueprints/api/views.py:14, app/blueprints/api/views.py:39, app/blueprints/api/views.py:57, app/blueprints/decorators.py; app/templates/admin/message.html:29 [Stored XSS via from_user safe]; app/templates/admin/message.html:30 [Stored XSS via message safe] |
| T4 | Attacker forces authenticated victims to change passwords, emails, or feedback via cross-site requests that lack CSRF tokens | remote_unauth | POST /account_area/change_password, POST /account_area/change_email, POST /account_area/send_feedback (feedback), GET/POST /auth/logout, API /api/v1/messages (Flask-Classy MessagesView), GET /admin/messages (MessagesView) + /admin User ModelView | User credentials (username, plaintext password, email in User table), Feedback Messages store (message, from_user, acknowledged flag) | high | almost_certain | unmitigated | login_required on /account_area/* only; no CSRF tokens found | app/blueprints/login/views.py:28 [Logout CSRF via GET-accessible logout]; app/blueprints/login/views.py:9 [Login CSRF on POST auth login]; app/blueprints/api/views.py:61 [CSRF blind update in acknowledge_message]; app/blueprints/account_area/views.py:41 [Missing CSRF on change_email enables email hijack]; app/blueprints/account_area/views.py:61 [Missing CSRF on send_feedback enables forced stored XSS]; app/blueprints/xss_protection/views.py:6 [CSRF-able session-state toggle via unauthenticated GET] |
| T5 | Attacker steals or forges login sessions by reading session cookies missing HttpOnly/Secure/SameSite or signing cookies with known SECRET_KEY | remote_unauth | GET/POST /sandbox/unsafe_cookies (cookie + form name), POST /auth/login (username, password), GET/POST /auth/logout, GET /account_area/ (authenticated), GET /toggle_xss_protection/?next= (open redirect + header toggle) | Login session & Flask SECRET_KEY ('Keep it secret, keep it safe') | high | almost_certain | unmitigated | none — set_cookie without flags observed; after_request header toggle is attacker-controlled | app/blueprints/sandboxes/views.py:20, app/flask_xss.py:50, app/blueprints/xss_protection/views.py:6; app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html:6 [Reflected XSS sink in unsafe_cookies template]; app/blueprints/sandboxes/views.py:38 [Insecure cookie flags on unsafe_cookies Set-Cookie]; app/blueprints/login/views.py:9 [Missing rate limiting on login enables brute force]; app/flask_xss.py:22 [Session cookie missing Secure/SameSite flags] |
| T6 | Attacker tampers with DEBUG error pages, world-writable SQLite file, or pip/CDN dependencies to backdoor the app or deny service | local_user | GET / (index) + manage.py add_admin + supply chain (requirements/setup/CDN) | Application integrity & availability (SQLite at /tmp/test.db, DEBUG app), Admin capability (admin user, /admin panel, Messages acknowledge workflow) | high | almost_certain | unmitigated | none — DEBUG=True, sqlite:////tmp/test.db, unpinned requirements/CDN includes observed | app/flask_xss.py:60, manage.py:11, requirements.txt:1, setup.py:3, app/templates/_base.html:7; app/flask_xss.py:24 [World-writable SQLite path in tmp] |
| T7 | Attacker redirects victims to malicious sites via unbounded ?next and downgrades browser XSS defenses via session toggle | remote_unauth | GET /toggle_xss_protection/?next= (open redirect + header toggle), GET /sandbox/unsafe_params (?name=), GET/POST /sandbox/unsafe_cookies (cookie + form name) | Login session & Flask SECRET_KEY ('Keep it secret, keep it safe'), Application integrity & availability (SQLite at /tmp/test.db, DEBUG app) | high | almost_certain | unmitigated | none | app/blueprints/xss_protection/views.py:6, app/flask_xss.py:50; app/blueprints/account_area/views.py:75 [Stored XSS source in send_feedback]; app/blueprints/xss_protection/views.py:12 [Open redirect in xss_protection index]; app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:6 [Reflected XSS sink in unsafe_params template]; app/templates/_base.html:67 [Unquoted attribute XSS via g.path] |
| T8 | Security compromise via Reflected XSS in unsafe_params view | remote_unauth | app/blueprints/sandboxes/views.py | application data and system state | critical | almost_certain | unmitigated | none | app/blueprints/sandboxes/views.py:13 [Reflected XSS in unsafe_params view] |
| T9 | Security compromise via DEBUG True enabled | remote_unauth | app/flask_xss.py | application data and system state | medium | almost_certain | unmitigated | none | app/flask_xss.py:26 [DEBUG True enabled] |
| T10 | Unauthorized access via missing authorization checks | remote_auth | app/blueprints/api/views.py | application data and system state | high | almost_certain | unmitigated | none | app/blueprints/api/views.py:43 [Missing authentication on API MessagesView.post] |
| T11 | Security compromise via Missing Content-Security-Policy and clickjacking/sniffing headers | remote_unauth | app/flask_xss.py | application data and system state | medium | almost_certain | unmitigated | none | app/flask_xss.py:71 [Missing Content-Security-Policy and clickjacking/sniffing headers] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Remote code execution via memory corruption or unsafe deserialization | No native code, file parsers, deserialization, eval/exec, or upload handlers observed in tree; class not applicable to this Python template app. |
| Database replication lag or backup disclosure | Single-node SQLite at /tmp/test.db with no replication or backup workflow in scope; availability loss is re-install, not data-loss event. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is SECRET_KEY/SQLALCHEMY_DATABASE_URI/DEBUG=True overridden in production or is the hardcoded 'Keep it secret, keep it safe' + sqlite:////tmp/test.db + DEBUG the deployed config?
- Are Secure/HttpOnly/SameSite cookie flags, CSRF tokens, and password hashing intentionally absent (demo) or expected compensating controls upstream (WAF, reverse proxy)?
- Is UsersView in app/blueprints/api/views.py intentionally unregistered (only MessagesView.register(api) at line 103) or dead vulnerable code awaiting wiring?
- No Dockerfile, Terraform, K8s manifests, or CI workflows found in tree; what identity does the workload run as in deployment and are there ad-hoc IAM/grants outside this repo?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-flask-xss
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-flask-xss/signals/prefilter.txt (30 entries)
  - secrets: .cerberus/realvuln-flask-xss/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-flask-xss/signals/sca.json (1 entries)
  - iac: .cerberus/realvuln-flask-xss/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-flask-xss/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-flask-xss/signals/routes.txt (10 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Enable autoescape everywhere and remove all `/ safe` on user-controlled variables; return Content-Security-Policy and validate on input | T2 | yes | M |
| Hash passwords with bcrypt/argon2, enforce unique secrets via env, rotate SECRET_KEY and require strong add_admin passwords | T1 | yes | M |
| Set Secure/HttpOnly/SameSite=Lax on all cookies, enforce SECRET_KEY from env, and pin session lifetime | T5 | partial | M |
| Require per-session CSRF tokens on all state-changing POSTs and SameSite cookies plus Origin check | T4 | yes | M |
| Enforce server-side authorization on every API/admin action and require auth for message creation with ownership checks | T3 | yes | M |
| Allowlist redirect targets for ?next and remove attacker-controlled X-XSS-Protection toggle; send fixed security headers | T7 | yes | M |
| Harden deployment: DEBUG=False, SQLite outside /tmp with file perms, pin dependencies with hashes, add audit logging | T6 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-flask-xss).
Confirmed primary claims: 26.

By class: CWE-79 x6, CWE-352 x6, CWE-798 x4, CWE-256 x2, CWE-614 x2, CWE-601 x1, CWE-489 x1, CWE-668 x1, CWE-862 x1, CWE-307 x1, CWE-693 x1

Affected paths: app/flask_xss.py x5, app/blueprints/login/views.py x4, app/blueprints/account_area/views.py x4, app/blueprints/sandboxes/views.py x3, app/blueprints/xss_protection/views.py x2, app/templates/admin/message.html x2, app/blueprints/api/views.py x2, app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html x1, app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html x1, manage.py x1, app/templates/_base.html x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-256 x2, CWE-307 x1, CWE-352 x6, CWE-489 x1, CWE-601 x1, CWE-614 x2, CWE-668 x1, CWE-693 x1, CWE-79 x6, CWE-798 x4, CWE-862 x1

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x4 at app/templates/_base.html, app/templates/components/forms.html — You are logged in as a regular user | validator: app/templates/_base.html:54 |safe sink reachable but username has no network writer: no signup, account_area/views.py only email/password/feedback, Use
- CWE-200 x2 at app/blueprints/api/views.py, app/models/models.py — password self.password | validator: app/blueprints/api/views.py:103 only MessagesView.register(api); UsersView (sole user.serialize consumer at :72) is never registered so User.serialize password at m
- CWE-352 x1 at app/blueprints/account_area/views.py — @account_area.route('/change_password', methods=['POST']) | validator: app/blueprints/account_area/views.py:19-27 requires current_password match (current_user.password == current_password) before upd
- CWE-693 x1 at app/flask_xss.py — response.headers['X-XSS-Protection'] = 0 | validator: app/flask_xss.py:69-75 sets X-XSS-Protection:0 when session flag False (default); deprecated auditor header where 0 is recommended secure default,
- CWE-480 x1 at app/templates/admin/message.html — if (data.status assignment success) | validator: app/templates/admin/message.html:42 if (data.status = "success") assignment always truthy causes reload logic bug only; no auth/data/execution boundary
- CWE-20 x1 at app/blueprints/account_area/views.py — User.query.filter_by(id=current_user.id).update({ | validator: app/blueprints/account_area/views.py:41-55 email update is self-only via current_user.id + @login_required; render at account_area.html:1
- CWE-252 x1 at app/blueprints/api/views.py — message = Message.query.filter_by(id=id).first().serialize | validator: app/blueprints/api/views.py:23-25 MessagesView.get has @admin_required so only admin reaches Message.query.filter_by(id=id).firs
- CWE-697 x1 at app/blueprints/decorators.py — def is_owning_user(user, id): | validator: app/blueprints/decorators.py:10-11 user.id (int) == id (URL string from api/views.py:24,60 with no <int:> converter) always False fail-closed; denies owners,
- CWE-863 x1 at app/blueprints/decorators.py — def is_admin_user(user): | validator: app/blueprints/decorators.py:6-7 is_admin_user ignores param for current_user.is_admin but all callers pass current_user (decorators.py:14 wrapper, :21 is_admin_o
- CWE-287 x1 at app/models/models.py — return self.username == 'admin' | validator: app/models/models.py:20-21 username=='admin' privilege has no network-reachable writer for attacker-chosen username: no signup/username-update, UsersView d
- CWE-676 x1 at app/flask_xss.py — app.jinja_env.globals.update( | validator: Globals at app/flask_xss.py:31-34 are only hasattr/enumerate/len; templates are static files via render_template with literal names, no user-controlled templ
