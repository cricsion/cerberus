# Threat Model: realvuln-threatbyte

## 1. System context

ThreatByte is a deliberately vulnerable Flask file-storing/sharing learning app: users sign up, log in/out, view a dashboard of uploaded files, upload/download files, and manage profiles through web views (server/routes.py plus client/templates) backed by SQLite (db/initialize_db.py) and through a Flask-RESTX JSON API (server/api/v1/api_v1.py with Swagger at /api/docs). README explicitly lists in-scope weakness classes including weak crypto, weak sessions, BOLA/BOPA/BFLA, CSRF, path traversal, SQLi, reflected/stored/DOM XSS, unrestricted upload and SSRF. It runs as a Flask dev server with DEBUG=True locally or as a root container from Dockerfile, with only detective CI scans (OpenGrep, Trivy, KICS, ZAP) and no authentication gateway, rate limiting, or CSRF/security-header controls found in code.

Repo: realvuln-threatbyte. Threat model for realvuln-threatbyte | stack: unknown stack | entry points: ~20 routes | prefilter signal classes: sqli-cursor, jinja-render, ssrf-requests, jwt-decode-verify-false, md5-sha1, path-open-join, tpl-xss, debug-exposure, open-redirect, toctou-hint, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): sqli-cursor, jinja-render, ssrf-requests, jwt-decode-verify-false, md5-sha1, path-open-join, tpl-xss, debug-exposure, open-redirect, toctou-hint, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at) | Central user store queried by web and API views | critical |
| User password hashes and low-entropy dummy passwords (MD5 of 'password', 'password123') | Weak hashes enabling offline cracking and credential recovery | critical |
| Flask SECRET_KEY 'just_another_secret' and JWT/session signing key | Hardcoded signing key enabling session and token forgery | critical |
| Flask session cookies (session_token, username/user_id) and API JWT bearer tokens (24h expiry) | Bearer session state for web and API | high |
| User-uploaded files in server/uploads and profile pictures in server/uploads/profile_pictures | User content stored then served back to browsers | high |
| SQLite database file db/database.db (all users + file ownership mapping) | Whole application database file | high |
| Source-code and container-image integrity (Flask app, templates, Dockerfile, CI workflows) | Code and image executed as root container / dev server | medium |
| Service availability of Flask dev server (debug mode) on port 5000 | Single-process dev server serving all views | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP GET / and /index | GET / and /index render static landing page; no input. Crosses network->Flask view (server/__init__.py registers routes). server/routes.py:15, server/__init__.py:16 [refs: `server/routes.py:15`, `server/__init__.py:16`] | untrusted network/client -> Flask application logic | Service availability of Flask dev server (debug mode) on port 5000, Source-code and container-image integrity (Flask app, templates, Dockerfile, CI workflows) |
| HTTP POST /login (web form) | POST username/password form fields; parameterized SELECT then MD5 compare, sets session username/user_id. Crosses form input->DB auth + session. server/routes.py:21 [refs: `server/routes.py:21`] | untrusted network/client -> application logic + session state | User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at), User password hashes and low-entropy dummy passwords (MD5 of 'password', 'password123'), Flask session cookies (session_token, username/user_id) and API JWT bearer tokens (24h expiry) |
| HTTP POST /signup (web form) | POST username/email/country/password/confirm_password; MD5 custom_hash then INSERT; auto-login via session. Crosses form input->DB write. server/routes.py:65 [refs: `server/routes.py:65`] | untrusted network/client -> application logic + database | User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at), Flask session cookies (session_token, username/user_id) and API JWT bearer tokens (24h expiry) |
| HTTP GET /dashboard ?search= | GET ?search= interpolated into f-string SQL LIKE query (sqli-cursor); files list rendered with search_query/safe. Crosses query string->SQL + template. server/routes.py:121 [refs: `server/routes.py:121`] | untrusted query string -> SQL engine + Jinja template engine | User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at), SQLite database file db/database.db (all users + file ownership mapping), User-uploaded files in server/uploads and profile pictures in server/uploads/profile_pictures |
| HTTP GET /profile and /edit_profile | GET /profile and /edit_profile read session user_id then SELECT *; country rendered with /safe, role/permissions disclosed. Crosses session->DB->template. server/routes.py:156 [refs: `server/routes.py:156`] | session state -> database -> template engine | User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at) |
| HTTP POST /update_profile (multipart form) | POST username/email/country/role/permissions/team + profile_picture file; role/permissions taken from form if present (mass-assignment/BOPA); picture saved as <incremental-id>.png. Crosses form+file->DB+filesystem. server/routes.py:170 [refs: `server/routes.py:170`] | untrusted form fields + file upload -> database + filesystem | User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at), User-uploaded files in server/uploads and profile pictures in server/uploads/profile_pictures |
| HTTP POST /upload file upload | POST multipart file with attacker-chosen file.filename joined to UPLOAD_FOLDER and saved, then INSERT into files table; no type/size/extension check. Crosses file bytes+filename->filesystem+DB. server/routes.py:248 [refs: `server/routes.py:248`] | untrusted file bytes + filename -> filesystem + database | User-uploaded files in server/uploads and profile pictures in server/uploads/profile_pictures, Service availability of Flask dev server (debug mode) on port 5000, Source-code and container-image integrity (Flask app, templates, Dockerfile, CI workflows) |
| HTTP GET /uploads/<filename> and /download/<filename> | GET <filename> with send_from_directory after ownership SELECT; filename path component reaches filesystem join. Crosses URL path->DB check->file read. server/routes.py:283, server/routes.py:312 [refs: `server/routes.py:283`, `server/routes.py:312`] | untrusted URL path -> filesystem read | User-uploaded files in server/uploads and profile pictures in server/uploads/profile_pictures, SQLite database file db/database.db (all users + file ownership mapping) |
| HTTP REST API /api/v1/* including update_picture picture_url | RESTX JSON API login/profile/update/delete-user/update_picture endpoints; JWT bearer via token_required (commented out on some routes) and picture_url fetched via requests. Crosses JSON/body+headers->DB+egress. server/api/v1/api_v1.py:103, server/api/v1/api_v1.py:146, server/api/v1/api_v1.py:172, server/api/v1/api_v1.py:215, server/api/v1/api_v1.py:240 [refs: `server/api/v1/api_v1.py:103`, `server/api/v1/api_v1.py:146`, `server/api/v1/api_v1.py:215`, `server/api/v1/api_v1.py:240`] | untrusted network/client -> API logic + JWT/session verification + server-side egress | User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at), Flask SECRET_KEY 'just_another_secret' and JWT/session signing key, Flask session cookies (session_token, username/user_id) and API JWT bearer tokens (24h expiry) |
| HTTP request handlers (20 routes detected) | Web and REST API endpoints (~20 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~20 framework routes:*

- `GET /login` (`server/api/v1/api_v1.py:103`)
- `GET /profile` (`server/api/v1/api_v1.py:146`)
- `GET /update-profile` (`server/api/v1/api_v1.py:172`)
- `GET /delete-user/<int:user_id>` (`server/api/v1/api_v1.py:215`)
- `GET /update_picture` (`server/api/v1/api_v1.py:240`)
- `GET /` (`server/routes.py:15`)
- `GET /index` (`server/routes.py:16`)
- `GET /signup` (`server/routes.py:65`)
- `GET /dashboard` (`server/routes.py:121`)
- `GET /edit_profile` (`server/routes.py:156`)
- `POST /update_profile` (`server/routes.py:170`)
- `GET /upload` (`server/routes.py:248`)
- `GET /uploads/<filename>` (`server/routes.py:283`)
- `GET /uploads/profile_pictures/<filename>` (`server/routes.py:307`)
- `GET /download/<filename>` (`server/routes.py:312`)
- *(and ~5 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker forges sessions or JWTs and brute-forces weak MD5 credentials to take over accounts | remote_unauth | HTTP POST /login (web form), HTTP POST /signup (web form), HTTP REST API /api/v1/* including update_picture picture_url | Flask SECRET_KEY 'just_another_secret' and JWT/session signing key, Flask session cookies and API JWT bearer tokens, User password hashes (MD5) | critical | almost_certain | unmitigated | Session login gate 'if username in session' on web routes; JWT helper token_required defined but commented out on UserProfile/UserDelete routes | server/api/v1/api_v1.py:182 [Sensitive session data logged via print(session) in UserProfileUpdate]; server/api/v1/api_v1.py:114 [No brute-force protection in API UserLogin.post()]; server/routes.py:51 [No brute-force protection in login()] |
| T2 | Attacker injects SQL through dashboard search to dump or modify the SQLite user and file tables | remote_unauth | HTTP GET /dashboard ?search= | User account records in SQLite users table (username, email, MD5 password hash, country, role, permissions, team, profile_picture id, last_login, created_at), SQLite database file db/database.db | critical | almost_certain | unmitigated | Parameterized SQLite queries (?) used on most login/signup/profile lookups — not applied on dashboard search f-string | server/routes.py:137 [SQL Injection in dashboard() via search parameter]; client/templates/dashboard.html:64 [Reflected XSS via safe filter in dashboard.html] |
| T3 | Attacker uploads malicious files and traverses filenames to execute content or exhaust disk | remote_auth | HTTP POST /upload file upload, HTTP POST /update_profile (multipart form), HTTP GET /uploads/<filename> and /download/<filename> | User-uploaded files in server/uploads and profile pictures, Service availability of Flask dev server, Source-code and container-image integrity | critical | almost_certain | unmitigated | Empty-filename rejection only; no type/size/extension check; attacker filename joined to UPLOAD_FOLDER | server/routes.py:262 [Unrestricted file upload with path traversal in upload_file()]; server/routes.py:248 [Missing CSRF protection in upload_file()] |
| T4 | Authenticated user escalates privilege via mass-assignment or IDOR/BOLA to modify other users and access their files | remote_auth | HTTP POST /update_profile (multipart form), HTTP REST API /api/v1/* including update_picture picture_url, HTTP GET /uploads/<filename> and /download/<filename> | User account records in SQLite users table, Flask session cookies and API JWT bearer tokens | high | almost_certain | unmitigated | API UserProfileUpdate scope check (403 if body user_id != session user_id; sensitive_updates only when role==admin); per-file ownership SELECT before send_from_directory | server/api/v1/api_v1.py:164 [BOLA unauthenticated profile disclosure in UserProfile.get()]; server/routes.py:190 [Mass-assignment privilege escalation in update_profile()]; server/api/v1/api_v1.py:201 [Cross-unit privilege escalation: web mass-assignment persists admin role that bypasses API sensitive-update gate] |
| T5 | Attacker abuses SSRF picture fetch, open redirect, and debug-mode exposure to probe internal network and disclose runtime secrets | remote_unauth | HTTP REST API /api/v1/* including update_picture picture_url, HTTP GET / and /index | Service availability of Flask dev server, Source-code and container-image integrity, User account records | high | almost_certain | unmitigated | Content-Type allowlist check for image/jpeg/image/png before saving SSRF-fetched picture only; detective-only CI (OpenGrep, Trivy, KICS, ZAP); no egress allowlist, no redirect validation, DEBUG=True | server/api/v1/api_v1.py:254 [SSRF in ProfilePicture.post() via picture_url]; server/config.py:5 [Debug mode enabled in Config] |
| T6 | Attacker injects stored or reflected script via profile/search fields rendered with /safe to hijack sessions | remote_unauth | HTTP GET /dashboard ?search=, HTTP GET /profile and /edit_profile, HTTP POST /update_profile (multipart form) | Flask session cookies and API JWT bearer tokens, User-uploaded files served back to browsers | high | almost_certain | unmitigated | none | server/routes.py:308 [Missing authentication on profile_pictures() file serve]; client/templates/profile.html:41 [Stored XSS via safe filter in profile.html]; server/api/v1/api_v1.py:182 [Missing CSRF protection on session-authenticated POST /api/v1/update-profile] |
| T7 | Security compromise via Broken password hashing in custom_hash() uses unsalted MD5 | remote_unauth | server/routes.py | application data and system state | high | almost_certain | unmitigated | none | server/routes.py:393 [Broken password hashing in custom_hash() uses unsalted MD5]; server/routes.py:93 [Weak password storage in signup()] |
| T8 | Security compromise via Broken function-level authorization in UserDelete.delete() | remote_unauth | server/api/v1/api_v1.py | application data and system state | critical | almost_certain | unmitigated | none | server/api/v1/api_v1.py:232 [Broken function-level authorization in UserDelete.delete()] |
| T9 | Security compromise via Hardcoded Flask/JWT secret in Config | remote_unauth | server/api/v1/api_v1.py, server/config.py | application data and system state | critical | almost_certain | unmitigated | none | server/config.py:7 [Hardcoded Flask/JWT secret in Config]; server/api/v1/api_v1.py:130 [Weak JWT issuance with hardcoded secret in UserLogin.post()] |
| T10 | Security compromise via Flask debug server execution in run.py | remote_unauth | run.py | application data and system state | medium | almost_certain | unmitigated | none | run.py:10 [Flask debug server execution in run.py] |
| T11 | Unauthorized access via missing authorization checks | remote_auth | server/api/v1/api_v1.py | application data and system state | high | almost_certain | unmitigated | none | server/api/v1/api_v1.py:243 [Missing authentication in ProfilePicture.post() allows arbitrary picture overwrite] |
| T12 | Unauthorized state change via cross-site request forgery (CSRF) | remote_unauth | server/routes.py | application data and system state | high | almost_certain | unmitigated | none | server/routes.py:170 [Missing CSRF protection in update_profile()]; server/routes.py:340 [Missing CSRF protection in delete_file()]; server/routes.py:386 [Logout CSRF: state-changing GET /logout with no CSRF token] |
| T13 | Security compromise via Insecure session cookie configuration in run.py | remote_unauth | run.py, server/config.py | application data and system state | medium | almost_certain | unmitigated | none | run.py:8 [Insecure session cookie configuration in run.py]; server/config.py:4 [Missing Secure and SameSite cookie flags in Config]; server/config.py:6 [HttpOnly disabled for session cookie in Config] |
| T14 | Security compromise via Missing upload size limit and security headers in app factory | remote_unauth | server/__init__.py | application data and system state | medium | almost_certain | unmitigated | none | server/__init__.py:7 [Missing upload size limit and security headers in app factory] |
| T15 | Security compromise via Unrestricted remote file write in ProfilePicture.post() | remote_unauth | server/api/v1/api_v1.py | application data and system state | high | almost_certain | unmitigated | none | server/api/v1/api_v1.py:284 [Unrestricted remote file write in ProfilePicture.post()] |
| T16 | Security compromise via Internal error disclosure in ProfilePicture.post() | remote_unauth | server/api/v1/api_v1.py | application data and system state | medium | almost_certain | unmitigated | none | server/api/v1/api_v1.py:298 [Internal error disclosure in ProfilePicture.post()] |
| T17 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | client/templates/dashboard.html | application data and system state | medium | almost_certain | unmitigated | none | client/templates/dashboard.html [template reflection surface] |
| T18 | Security compromise via Missing-field 500 DoS and error echo in POST /api/v1/update_picture | remote_unauth | server/api/v1/api_v1.py | application data and system state | medium | almost_certain | unmitigated | none | server/api/v1/api_v1.py:248 [Missing-field 500 DoS and error echo in POST /api/v1/update_picture] |
| T19 | Security compromise via User enumeration oracle on /signup with no anti-automation | remote_unauth | server/routes.py | application data and system state | medium | almost_certain | unmitigated | none | server/routes.py:101 [User enumeration oracle on /signup with no anti-automation] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Remote code execution via deserialization or template-engine code execution outside Jinja variable interpolation | No attacker-controlled deserialization, native-code parser, or eval/exec sink found in tree; DoS via large uploads/DB growth already covers availability loss. |
| Supply-chain compromise via malicious base image or PyPI dependency update | No vendored dependency versions or lockfile vulns confirmed in-repo and no SECURITY.md policy; covered detectively by Trivy SCA until owner confirms production image pinning. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is this deployment network-reachable and by whom? README shows localhost:5000 and 0.0.0.0 in container; owner to confirm production exposure.
- Who supplies inputs to SSRF picture_url and upload filenames, and are there upstream WAF/egress/size limits? None found in code.
- Which controls sit upstream (auth gateway, rate limiting for brute force, CSRF tokens)? No brute-force protection, CSRF tokens, or security headers found in code.
- Do dummy MD5 passwords/seeds appear in production DB, or are they test-only fixtures? Owner to confirm.
- What identity does the container/CI runner use and what can it reach? No USER, IAM, or secrets-mount config found in tree; ad-hoc runner/IAM grants unknown.
- What bounds automated CI merge/write paths (path allowlists, reviewers)? Workflows trigger on push/PR to main with no environment approvals found.

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-threatbyte
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-threatbyte/signals/prefilter.txt (111 entries)
  - secrets: .cerberus/realvuln-threatbyte/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-threatbyte/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-threatbyte/signals/iac.json (2 entries)
  - codegraph-index: .cerberus/realvuln-threatbyte/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-threatbyte/signals/routes.txt (20 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Enforce parameterized queries everywhere and least-privilege DB access; remove f-string SQL | T2 | partial | M |
| Autoescape by default, remove /safe on user data, encode on output and set Content-Security-Policy | T1 | partial | M |
| Replace MD5 with bcrypt/argon2, require strong random SECRET_KEY from env/vault, verify JWT signatures and expiry, add rate-limiting, secure cookie flags and CSRF tokens | T4 | partial | M |
| Enforce server-side authorization on every object/action: allowlist updatable fields, deny role/permission self-update, check ownership on all file and user IDs | T3 | partial | M |
| Validate uploads by allowlist type/size, randomize stored names outside webroot, block traversal and serve with safe disposition | T6 | partial | M |
| Deny server-side egress by default: allowlist picture_url hosts, validate redirect targets, disable DEBUG in production and run as non-root with resource limits | T5 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-threatbyte).
Confirmed primary claims: 36.

By class: CWE-352 x5, CWE-285 x3, CWE-614 x3, CWE-79 x3, CWE-327 x2, CWE-434 x2, CWE-798 x2, CWE-862 x2, CWE-215 x2, CWE-307 x2, CWE-89 x1, CWE-639 x1, CWE-918 x1, CWE-532 x1, CWE-693 x1

Affected paths: server/routes.py x13, server/api/v1/api_v1.py x13, server/config.py x4, run.py x2, client/templates/dashboard.html x2, server/__init__.py x1, client/templates/profile.html x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-20 x1, CWE-204 x1, CWE-209 x1, CWE-215 x2, CWE-285 x3, CWE-307 x2, CWE-327 x2, CWE-352 x5, CWE-384 x1, CWE-400 x1, CWE-434 x2, CWE-532 x1, CWE-614 x3, CWE-639 x1, CWE-693 x1, CWE-79 x3, CWE-798 x2, CWE-862 x2, CWE-89 x1, CWE-918 x1

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x8 at client/templates/dashboard.html, client/templates/edit_profile.html, client/templates/login.html, client/templates/signup.html, client/templates/upload.html — $commentList.append('<li>' + comment + '</li>'); | validator: client/templates/dashboard.html:119 comment from local .val() input; client/templates/dashboard.html:123 $commentList.append('<li>'+commen
- CWE-252 x4 at server/routes.py — user_id = user['id'] | validator: server/routes.py:132-134 dashboard None-deref on stale session returns per-request 500 only; server not taken down, no cross-principal impact | refute: not_a_vulnerab
- CWE-22 x3 at server/routes.py — os.remove(file_path) | validator: server/routes.py:342 file_path=os.path.join(UPLOAD_FOLDER,filename) but server/routes.py:353-358 requires SELECT * FROM files WHERE filename=? AND user_id=? for calle
- CWE-327 x1 at db/create_dummy_data.py — return hashlib.md5(password.encode()).hexdigest() | validator: db/create_dummy_data.py:8 MD5 sink only called by db/create_dummy_data.py:16 insert_dummy_users guarded by db/create_dummy_data.py:37 if 
- CWE-434 x1 at server/routes.py — file.save(os.path.join(PROFILE_PICTURES_UPLOAD_FOLDER, filename)) | validator: server/routes.py:216 filename = str(profile_picture_id)+'.png' server-generates numeric name before server/routes.py:217 
- CWE-798 x1 at db/create_dummy_data.py — ('john_doe', 'john@example.com', hash_password('super-secret'), 'USA', 'admin', 'all', 'Team A', now, now), | validator: db/create_dummy_data.py:20-27 hardcoded seed rows only inserted by db/create_du
- CWE-20 x1 at server/routes.py — new_username = request.form['username'] or current_user['username'] | validator: server/routes.py:184 request.form['username'] failure is per-request 400 via Werkzeug BadRequest, server stays up; no c
- CWE-601 x1 at server/routes.py — return redirect(request.url) | validator: server/routes.py:256 redirect(request.url) is self-URL redirect; Host is browser-controlled so victim keeps victim Host, no attacker-chosen path at :253-256 |
- CWE-89 x1 at server/api/v1/api_v1.py — update_query = "UPDATE users SET " + ", ".join([f"{key} = ?" for key in updates.keys()]) + " WHERE id = ?" | validator: server/api/v1/api_v1.py:190-193 updates filtered to allowlist ['email','country'
- CWE-287 x1 at server/api/v1/api_v1.py — token = request.headers['Authorization'].split(" ")[1] # Assumes Bearer Token | validator: server/api/v1/api_v1.py:88 split(' ')[1] on malformed header raises IndexError; server/api/v1/api_v1.py:94 jw
