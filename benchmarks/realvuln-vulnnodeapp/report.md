# Cerberus Report

**Findings:** 20 actionable — 1 critical, 2 high, 16 medium, 1 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 1 duplicate — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 1 | 0 / 1 (0%) | 1 |
| HIGH | 2 | 0 / 2 (0%) | 2 |
| MEDIUM | 16 | 0 / 16 (0%) | 16 |
| LOW | 1 | 0 / 1 (0%) | 1 |
| **TOTAL** | **20** | **0 / 20 (0%)** | **20** |

## Table of Contents

- [Confirmed (20)](#confirmed)
  - [CRITICAL: Cross-unit SQL injection authentication bypass in login flow (`models/usersModel.js:15`)](#finding-1)
  - [HIGH: Plaintext password storage and comparison without hashing (`models/usersModel.js:56`)](#finding-2)
  - [HIGH: Hardcoded session secret with insecure cookie flags (`app.js:25`)](#finding-3)
  - [MEDIUM: SQL Injection in UsersModel.findUserById (`models/usersModel.js:7`)](#finding-4)
  - [MEDIUM: Cross-unit OS command injection in ping feature (`utils/utility.js:63`)](#finding-5)
  - [MEDIUM: Cross-unit insecure deserialization RCE via user cookie (`utils/utility.js:140`)](#finding-6)
  - [MEDIUM: Insecure password change allows arbitrary account takeover via client-supplied id (`routes/users/user.js:122`)](#finding-7)
  - [MEDIUM: Cross-unit stored XSS via registration persisted to dashboard header (`views/body-header.ejs:34`)](#finding-8)
  - [MEDIUM: Cross-unit stored reflected XSS via unescaped EJS output (`controllers/usersController.js:58`)](#finding-9)
  - [MEDIUM: Missing CSRF protection on state-changing POST endpoints (`routes/users/index.js:16`)](#finding-10)
  - [MEDIUM: Missing authorization (IDOR) on error-based-sqli profile read/update (`routes/users/index.js:16`)](#finding-11)
  - [MEDIUM: Missing authorization IDOR on profile and password endpoints (`routes/users/index.js:40`)](#finding-12)
  - [MEDIUM: Cross-unit path traversal arbitrary file read (`utils/utility.js:81`)](#finding-13)
  - [MEDIUM: Cross-unit XXE with external entity expansion (`utils/utility.js:127`)](#finding-14)
  - [MEDIUM: Missing rate limiting / brute-force protection on login and registration (`routes/users/index.js:8`)](#finding-15)
  - [MEDIUM: Cross-unit regex injection ReDoS in log search (`utils/utility.js:94`)](#finding-16)
  - [MEDIUM: DOM-based XSS via default parameter (`views/body-header.ejs:16`)](#finding-17)
  - [MEDIUM: Insufficient session expiration: logout does not invalidate server session (`views/body-header.ejs:64`)](#finding-18)
  - [MEDIUM: Hardcoded default database credentials in application config (`config/config.js:5`)](#finding-19)
  - [LOW: Sensitive information exposure via raw database error responses (`routes/users/user.js:36`)](#finding-20)

<a id="confirmed"></a>
## Confirmed (20)

<a id="finding-1"></a>
### CRITICAL Cross-unit SQL injection authentication bypass in login flow
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.98
- Location: `models/usersModel.js:15-15`
- Vulnerable code (`models/usersModel.js`):
```javascript
let query = "SELECT * FROM users WHERE email ='" + parameter[0] + "' AND password = '" + parameter[1] + "'";
```
- Taint Flow:
  - **Source**: `req.body.username / req.body.password login input`
  - **Path**:
    - `routes/users/index.js:8 POST / authenticate`
    - `utils/passportLocalStrategy.js:20 username/password`
    - `controllers/usersController.js:30 authenticateUser`
    - `models/usersModel.js:15 executeQuery`
  - **Sink**: `raw SQL query execution via executeQuery`
- Evidence: POST / login (routes/users/index.js:8) -> passport LocalStrategy (utils/passportLocalStrategy.js:20 credentials from req.body) -> UsersController.authenticateUser (controllers/usersController.js:30) -> UsersModel.authenticateUser sink at models/usersModel.js:15 with string-concatenated email/password into SELECT; bypass with ' OR '1'='1
  - Validation: routes/users/index.js:8 unauth POST / -> utils/passportLocalStrategy.js:20 credentials from req input -> controllers/usersController.js:30 authenticateUser -> models/usersModel.js:15 string-concatenated SELECT email/password via executeQuery
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:8 unauth POST / -> utils/passportLocalStrategy.js:20 credentials from req input -> controllers/usersController.js:30 authenticateUser -> models/usersModel.js:15 string-concatenated SELECT email/password via executeQuery | consensus: 1/1 confirmed | triage: Unauthenticated login SQLi bypass zero preconditions
- Patch:
  - **Summary**: Use parameterized query (executeQueryWithParam with ? placeholders) for email/password lookup; bypass with ' OR '1'='1 confirms sink.

<a id="finding-2"></a>
### HIGH Plaintext password storage and comparison without hashing
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `models/usersModel.js:56-56`
- Vulnerable code (`models/usersModel.js`):
```javascript
executeQueryWithParam(query, [user.fullname, user.username, user.email, user.phone, user.password]).then(() => {
```
- Taint Flow:
  - **Source**: `unauthenticated POST /register req.body.password`
  - **Path**:
    - `routes/users/index.js:12 POST /register`
    - `routes/users/user.js:68 usersController.registerUser(req.body)`
    - `controllers/usersController.js:77 registerUser(user)`
    - `models/usersModel.js:56 insert user.password`
  - **Sink**: `SQL INSERT of plaintext password (models/usersModel.js:56)`
- Evidence: POST /register (routes/users/index.js:12) -> user.registerUser (routes/users/user.js:68 req.body) -> UsersController.registerUser -> UsersModel.registerUser inserts user.password directly; no call to generateHash anywhere (utils/sha512.js defines generateHash but grep shows zero call sites; passportLocalStrategy.js imports sha512 but never uses it) and login compares plaintext (models/usersModel.js:15)
  - Validation: routes/users/index.js:12 POST /register -> routes/users/user.js:68 registerUser(req.body) -> controllers/usersController.js:73-77 no hash -> models/usersModel.js:56 executeQueryWithParam plaintext password; utils/sha512.js:3 generateHash never called and login models/usersModel.js:15 compares plaintext
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:12 POST /register -> routes/users/user.js:68 registerUser(req.body) -> controllers/usersController.js:73-77 no hash -> models/usersModel.js:56 executeQueryWithParam plaintext password; utils/sha512.js:3 generateHash never called and login models/usersModel.js:15 compares plaintext | consensus: 1/1 confirmed | triage: Unauthenticated register stores plaintext passwords
- Patch:
  - **Summary**: Hash passwords with bcrypt/scrypt on register and compare hashes on login; migrate existing plaintext column.

<a id="finding-3"></a>
### HIGH Hardcoded session secret with insecure cookie flags
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.9
- Location: `app.js:25-28`
- Vulnerable code (`app.js`):
```javascript
secret is set to default committed value;
```
- Taint Flow:
  - **Source**: `committed source secret`
  - **Path**:
    - `app.js:25 hardcoded secret committed`
    - `app.js:28 cookie flags`
  - **Sink**: `signed session plus readable cookie`
- Evidence: Session secret committed in source with httpOnly false secure false plus unsigned base64 user cookie
  - Validation: app.js:25 secret:'secrettobechanged' committed in repo + app.js:28 cookie:{httpOnly:false,secure:false} allows JS theft; user cookie routes/users/user.js:239-244 unsigned base64
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:25 secret:'secrettobechanged' committed in repo + app.js:28 cookie:{httpOnly:false,secure:false} allows JS theft; user cookie routes/users/user.js:239-244 unsigned base64 | consensus: 1/1 confirmed | triage: Committed session secret enables forgery
- Patch:
  - **Summary**: Load session secret from env/secret manager, set cookie httpOnly:true secure:true sameSite, and sign/encrypt user cookie.

<a id="finding-4"></a>
### MEDIUM SQL Injection in UsersModel.findUserById
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-89 | confidence: 0.95
- Location: `models/usersModel.js:7-7`
- Vulnerable code (`models/usersModel.js`):
```javascript
let query = "SELECT * FROM users WHERE id =" + parameter[0];
```
- Taint Flow:
  - **Source**: `req.query.id`
  - **Path**:
    - `routes/users/user.js:28 req.query.id`
    - `models/usersModel.js:7 executeQuery`
  - **Sink**: `executeQuery concatenated SELECT`
- Evidence: let query = "SELECT * FROM users WHERE id =" + parameter[0];
  - Validation: models/usersModel.js:7 concatenates parameter[0] into SELECT and calls executeQuery; routes/users/user.js:28 getUser(req.query.id) -> controllers/usersController.js:15 findUserById -> utils/mysqlConnectionPool.js:28 pool.query(raw string) with no sanitization on this path
  - Alternatives considered: test | select like query concat
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: models/usersModel.js:7 concatenates parameter[0] into SELECT and calls executeQuery; routes/users/user.js:28 getUser(req.query.id) -> controllers/usersController.js:15 findUserById -> utils/mysqlConnectionPool.js:28 pool.query(raw string) with no sanitization on this path | consensus: 1/1 confirmed | triage: Primary authenticated SQLi sink at usersModel.js:7
- Patch:
  - **Summary**: Use executeQueryWithParam with ? placeholder for id and validate/coerce id to integer before query
  - +1 duplicate(s): `models/usersModel.js:7`

<a id="finding-5"></a>
### MEDIUM Cross-unit OS command injection in ping feature
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-78 | confidence: 0.95
- Location: `utils/utility.js:63-63`
- Vulnerable code (`utils/utility.js`):
```javascript
let command = ping minus c 3 plus ip;
```
- Taint Flow:
  - **Source**: `authenticated req.body.ip`
  - **Path**:
    - `routes/users/index.js:50 POST command-injection`
    - `routes/users/user.js:135 req.body.ip`
  - **Sink**: `child_process exec of attacker shell string`
- Evidence: POST command-injection req.body.ip to pingMe to shell string plus exec in utility
  - Validation: routes/users/index.js:50 POST /command-injection -> routes/users/user.js:134 req.body.ip -> controllers/usersController.js:130 pingMe(ip) -> utils/utility.js:63 'ping -c 3 '+ip -> utils/utility.js:66 exec(command) with no validation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:50 POST /command-injection -> routes/users/user.js:134 req.body.ip -> controllers/usersController.js:130 pingMe(ip) -> utils/utility.js:63 'ping -c 3 '+ip -> utils/utility.js:66 exec(command) with no validation | consensus: 1/1 confirmed | triage: Authenticated ip to exec ping command injection
- Patch:
  - **Summary**: Replace exec(string) with execFile('ping',['-c','3',ip]) plus strict IP/host allowlist validation; never concatenate user input into shell.

<a id="finding-6"></a>
### MEDIUM Cross-unit insecure deserialization RCE via user cookie
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-502 | confidence: 0.95
- Location: `utils/utility.js:140-140`
- Vulnerable code (`utils/utility.js`):
```javascript
var obj = serialize.unserialize(str);
```
- Taint Flow:
  - **Source**: `authenticated Cookie user base64`
  - **Path**:
    - `routes/users/index.js:62 GET deserialization cookie`
    - `controllers/usersController.js:205 cookies.user`
  - **Sink**: `node-serialize unserialize evaluation`
- Evidence: GET deserialization Cookie user to getDeserializeData to base64 decode plus node-serialize unserialize with RCE gadget in comments
  - Validation: routes/users/index.js:62 GET /deserialization (auth) -> routes/users/user.js:177 deserialization(req.cookies) -> controllers/usersController.js:205 getDeserializeData(cookies.user) -> utils/utility.js:139-140 base64 decode + serialize.unserialize(str) using node-serialize@0.0.4 (package.json:21)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:62 GET /deserialization (auth) -> routes/users/user.js:177 deserialization(req.cookies) -> controllers/usersController.js:205 getDeserializeData(cookies.user) -> utils/utility.js:139-140 base64 decode + serialize.unserialize(str) using node-serialize@0.0.4 (package.json:21) | consensus: 1/1 confirmed | triage: Authenticated cookie to node-serialize unserialize RCE
- Patch:
  - **Summary**: Remove node-serialize; use JSON.parse on signed httpOnly cookies (cookieParser signed) and never unserialize client-controlled data.

<a id="finding-7"></a>
### MEDIUM Insecure password change allows arbitrary account takeover via client-supplied id
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-639 | confidence: 0.92
- Location: `routes/users/user.js:122-122`
- Vulnerable code (`routes/users/user.js`):
```javascript
usersController.changePassword(req.body.password, req.body.id)
```
- Taint Flow:
  - **Source**: `authenticated POST req.body.id + req.body.password`
  - **Path**:
    - `routes/users/index.js:46 POST /change-password`
    - `routes/users/user.js:122 req.body.id`
    - `controllers/usersController.js:changePassword -> models/usersModel.js:70`
  - **Sink**: `UPDATE users SET password WHERE id=attacker-controlled id`
- Evidence: POST /change-password route (routes/users/index.js:46) calls handler that trusts client id: routes/users/user.js:122 usersController.changePassword(req.body.password, req.body.id); form supplies id via hidden field views/change-password.ejs:51 value="<%= id %>"; model executes update users set password=? where id=? (models/usersModel.js:70) with attacker id, no check req.body.id == req.user.id and no current-password verification. Distinct from prior IDOR at /idor (index.js:40-42).
  - Validation: routes/users/index.js:46 POST /change-password -> routes/users/user.js:122 changePassword(req.body.password,req.body.id) attacker id -> controllers/usersController.js:114 models/usersModel.js:70 UPDATE password WHERE id=?; form views/change-password.ejs:51 hidden id tamperable, no req.user.id match or old-password check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:46 POST /change-password -> routes/users/user.js:122 changePassword(req.body.password,req.body.id) attacker id -> controllers/usersController.js:114 models/usersModel.js:70 UPDATE password WHERE id=?; form views/change-password.ejs:51 hidden id tamperable, no req.user.id match or old-password check | consensus: 1/1 confirmed | triage: Distinct /change-password takeover via req.body.id
- Patch:
  - **Summary**: Ignore client id; use req.user.id from session and require current-password verification before update.

<a id="finding-8"></a>
### MEDIUM Cross-unit stored XSS via registration persisted to dashboard header
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.92
- Location: `views/body-header.ejs:34-34`
- Vulnerable code (`views/body-header.ejs`):
```ejs
<span class="hidden-xs"><%- fullName %></span>
```
- Taint Flow:
  - **Source**: `req.body.fullname / username at registration`
  - **Path**:
    - `routes/users/index.js:12 POST /register req.body.fullname`
    - `controllers/usersController.js:74 registerUser`
    - `models/usersModel.js:56 addUser insert`
    - `views/body-header.ejs:34 <%- fullName %>`
  - **Sink**: `unescaped EJS output of stored fullname`
- Evidence: POST /register (routes/users/index.js:12) -> routes/users/user.js:68 registerUser(req.body) -> controllers/usersController.js:73-74 no sanitization -> models/usersModel.js:56 insert fullname/username verbatim; on login req.user.fullname rendered unescaped at views/body-header.ejs:34 and :42 and views/navigation.ejs:17 via <%- fullName %>; distinct sink from prior controller:58 search-result XSS
  - Validation: routes/users/index.js:12 POST /register req.body.fullname -> controllers/usersController.js:73 no sanitization -> models/usersModel.js:56 verbatim insert -> views/body-header.ejs:34 <%- fullName %> and :42 plus views/navigation.ejs:17 <%- fullName %> unescaped on every page
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:12 POST /register req.body.fullname -> controllers/usersController.js:73 no sanitization -> models/usersModel.js:56 verbatim insert -> views/body-header.ejs:34 <%- fullName %> and :42 plus views/navigation.ejs:17 <%- fullName %> unescaped on every page | consensus: 1/1 confirmed | triage: Unauth register fullname to unescaped header XSS
- Patch:
  - **Summary**: Encode with <%= fullName %> (escaped) and sanitize/validate fullname/username on registration.

<a id="finding-9"></a>
### MEDIUM Cross-unit stored reflected XSS via unescaped EJS output
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `controllers/usersController.js:58-58`
- Vulnerable code (`controllers/usersController.js`):
```javascript
htmlResponse = generateSearchUserResponse(user);
```
- Taint Flow:
  - **Source**: `request username and stored profile fields`
  - **Path**:
    - `routes/users/user.js:54 req.body.username`
    - `controllers/usersController.js:58 generate response`
  - **Sink**: `EJS unescaped output of attacker HTML`
- Evidence: Controller builds htmlResponse from DB rows rendered via unescaped EJS output in blind-sqli command-injection deserialization plus layout fullName
  - Validation: routes/users/user.js:54 searchUser(req.body.username) -> controllers/usersController.js:58/94 generateSearchUserResponse -> controllers/usersController.js:232-235 weak case-sensitive blacklist only -> views/blind-sqli.ejs:65 <%- htmlResponse %> unescaped renders stored rows
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/user.js:54 searchUser(req.body.username) -> controllers/usersController.js:58/94 generateSearchUserResponse -> controllers/usersController.js:232-235 weak case-sensitive blacklist only -> views/blind-sqli.ejs:65 <%- htmlResponse %> unescaped renders stored rows | consensus: 1/1 confirmed | triage: Stored search results rendered via unescaped EJS
- Patch:
  - **Summary**: Escape output with <%= %> / encoder and validate stored fields on input; replace blacklist with contextual output encoding.

<a id="finding-10"></a>
### MEDIUM Missing CSRF protection on state-changing POST endpoints
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `routes/users/index.js:16-16`
- Vulnerable code (`routes/users/index.js`):
```javascript
router.post('/update-profile', userSession.isAuthenticated, user.updateProfile);
```
- Taint Flow:
  - **Source**: `cookie-authenticated cross-site request`
  - **Path**:
    - `cross-site POST /update-profile`
    - `routes/users/user.js:41 updateUserById(req.body, req.query.id)`
  - **Sink**: `authenticated UPDATE without CSRF verification`
- Evidence: State-changing POST routes/users/index.js:16 POST /update-profile (also 20,26,34,38,42,46,50,56,60) perform updates/inserts with no CSRF token; app.js has no csurf/csrf middleware (only cookieParser, session, passport) and no view emits a CSRF token; handler routes/users/user.js:41 updateUserById(req.body, req.query.id) executes UPDATE on cross-site POST.
  - Validation: routes/users/index.js:16 POST /update-profile (also :8,:12,:26,:34,:38,:42,:46,:50,:56,:60) guarded only by userSession.isAuthenticated (utils/userSession.js:2); app.js:1-60 has no csurf import/middleware and no token check; session cookie auth makes cross-site POST authenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:16 POST /update-profile (also :8,:12,:26,:34,:38,:42,:46,:50,:56,:60) guarded only by userSession.isAuthenticated (utils/userSession.js:2); app.js:1-60 has no csurf import/middleware and no token check; session cookie auth makes cross-site POST authenticated | consensus: 1/1 confirmed | triage: State-changing POSTs lack CSRF token
- Patch:
  - **Summary**: Add csurf/crsf middleware in app.js and require/verify token on all state-changing POST routes and emit token in views

<a id="finding-11"></a>
### MEDIUM Missing authorization (IDOR) on error-based-sqli profile read/update
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-639 | confidence: 0.9
- Location: `routes/users/index.js:16-16`
- Vulnerable code (`routes/users/index.js`):
```javascript
router.post('/update-profile', userSession.isAuthenticated, user.updateProfile);
```
- Taint Flow:
  - **Source**: `req.query.id attacker-controlled identifier`
  - **Path**:
    - `routes/users/index.js:16 POST /update-profile?id=attacker-chosen`
    - `routes/users/user.js:41 updateUserById(req.body, req.query.id)`
  - **Sink**: `arbitrary user record update`
- Evidence: Authenticated endpoints routes/users/index.js:14 GET /error-based-sqli and :16 POST /update-profile only check isAuthenticated, handlers routes/users/user.js:28 getUser(req.query.id) and :41 updateUserById(req.body, req.query.id) use client-supplied id with no req.user.id ownership check; distinct from prior /idor (40-42) finding
  - Validation: routes/users/index.js:14 GET /error-based-sqli + :16 POST /update-profile only isAuthenticated -> routes/users/user.js:28 getUser(req.query.id) and :41 updateUserById(req.body,req.query.id) use attacker id with no ownership check, distinct from /idor routes
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:14 GET /error-based-sqli + :16 POST /update-profile only isAuthenticated -> routes/users/user.js:28 getUser(req.query.id) and :41 updateUserById(req.body,req.query.id) use attacker id with no ownership check, distinct from /idor routes | consensus: 1/1 confirmed | triage: Distinct route /update-profile IDOR via req.query.id
- Patch:
  - **Summary**: Require req.query.id==req.user.id (or admin role) on error-based-sqli read and update-profile write.

<a id="finding-12"></a>
### MEDIUM Missing authorization IDOR on profile and password endpoints
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-639 | confidence: 0.9
- Location: `routes/users/index.js:40-42`
- Vulnerable code (`routes/users/index.js`):
```javascript
router.get idor userSession.isAuthenticated user.idorViewProfile;
```
- Taint Flow:
  - **Source**: `authenticated req.query.id and req.body.id`
  - **Path**:
    - `routes/users/index.js:40 GET idor victim id`
    - `routes/users/user.js:204 getUser req.query.id`
  - **Sink**: `read update of arbitrary user object`
- Evidence: Profile read update and password change use req.query.id and req.body.id with only isAuthenticated and no ownership check
  - Validation: routes/users/index.js:40-42 GET/POST /idor with only userSession.isAuthenticated -> routes/users/user.js:205 getUser(req.query.id) and :218 updateUserById(req.body,req.query.id) with no req.user.id ownership check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:40-42 GET/POST /idor with only userSession.isAuthenticated -> routes/users/user.js:205 getUser(req.query.id) and :218 updateUserById(req.body,req.query.id) with no req.user.id ownership check | consensus: 1/1 confirmed | triage: Distinct /idor read/update IDOR via req.query.id
- Patch:
  - **Summary**: Enforce req.query.id==req.user.id (or role check) on both idor view and update handlers; reject cross-user ids.

<a id="finding-13"></a>
### MEDIUM Cross-unit path traversal arbitrary file read
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-22 | confidence: 0.9
- Location: `utils/utility.js:81-81`
- Vulnerable code (`utils/utility.js`):
```javascript
fs.readFile(filePath, encoding utf-8, function(err,data);
```
- Taint Flow:
  - **Source**: `authenticated req.query.filename`
  - **Path**:
    - `routes/users/index.js:52 GET file retrieval`
    - `routes/users/user.js:144 req.query.filename`
  - **Sink**: `fs.readFile of attacker path`
- Evidence: GET arbitrary-file-retrieval req.query.filename to readDosAndDonts to path join plus readFile with unescaped render
  - Validation: routes/users/index.js:52 GET /arbitrary-file-retrieval -> routes/users/user.js:144 req.query.filename -> controllers/usersController.js:146 readDosAndDonts -> utils/utility.js:80 path.join(__dirname,filename) + utils/utility.js:81 fs.readFile with no normalization/allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:52 GET /arbitrary-file-retrieval -> routes/users/user.js:144 req.query.filename -> controllers/usersController.js:146 readDosAndDonts -> utils/utility.js:80 path.join(__dirname,filename) + utils/utility.js:81 fs.readFile with no normalization/allowlist | consensus: 1/1 confirmed | triage: Authenticated arbitrary file read via filename to readFile
- Patch:
  - **Summary**: Canonicalize with path.normalize/resolve, enforce containment under intended dir and allowlist filenames; reject ../ and absolute paths.

<a id="finding-14"></a>
### MEDIUM Cross-unit XXE with external entity expansion
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-611 | confidence: 0.9
- Location: `utils/utility.js:127-127`
- Vulnerable code (`utils/utility.js`):
```javascript
var doc = libxml.parseXmlString(xmlInput, parserOptions);
```
- Taint Flow:
  - **Source**: `authenticated req.body.search XML`
  - **Path**:
    - `routes/users/index.js:60 POST xxe`
    - `routes/users/user.js:170 req.body.search`
  - **Sink**: `libxmljs parse with entity expansion`
- Evidence: POST xxe req.body.search to parseXML to libxmljs with noent true allowing external entities then chained to SQL
  - Validation: routes/users/index.js:60 POST /xxe -> routes/users/user.js:168 xxe(req.body.search) -> controllers/usersController.js:179 parseXML -> utils/utility.js:120-127 libxmljs parseXmlString with noent:true enabling external-entity expansion
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:60 POST /xxe -> routes/users/user.js:168 xxe(req.body.search) -> controllers/usersController.js:179 parseXML -> utils/utility.js:120-127 libxmljs parseXmlString with noent:true enabling external-entity expansion | consensus: 1/1 confirmed | triage: Authenticated XML to libxmljs noent expansion
- Patch:
  - **Summary**: Set noent:false, nonet:true and disable external entity/DTD loading; reject DOCTYPE if not needed.

<a id="finding-15"></a>
### MEDIUM Missing rate limiting / brute-force protection on login and registration
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-307 | confidence: 0.85
- Location: `routes/users/index.js:8-8`
- Vulnerable code (`routes/users/index.js`):
```javascript
router.post('/', user.authenticate);
```
- Taint Flow:
  - **Source**: `network attacker repeated login requests`
  - **Path**:
    - `routes/users/index.js:8 POST / login unlimited attempts`
  - **Sink**: `authentication verification without throttling`
- Evidence: Public auth endpoints routes/users/index.js:8 POST / (login) and :12 POST /register have only isAuthenticated-free access with no rate-limit, throttle, lockout, or CAPTCHA; app.js has no express-rate-limit middleware; enables unlimited credential stuffing and mass account creation
  - Validation: routes/users/index.js:8 POST / login and :12 POST /register allow unlimited attempts with only isAuthenticated-free access; app.js:1-60 registers no express-rate-limit/throttle/lockout; routes/users/user.js:6 passport.authenticate has no counter
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:8 POST / login and :12 POST /register allow unlimited attempts with only isAuthenticated-free access; app.js:1-60 registers no express-rate-limit/throttle/lockout; routes/users/user.js:6 passport.authenticate has no counter | consensus: 1/1 confirmed | triage: Unlimited login/register attempts enable stuffing
- Patch:
  - **Summary**: Add express-rate-limit on auth routes plus account lockout/CAPTCHA and fail-closed throttling

<a id="finding-16"></a>
### MEDIUM Cross-unit regex injection ReDoS in log search
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-1333 | confidence: 0.85
- Location: `utils/utility.js:94-94`
- Vulnerable code (`utils/utility.js`):
```javascript
let rgx = new RegExp search pattern concat;
```
- Taint Flow:
  - **Source**: `authenticated req.body.search`
  - **Path**:
    - `routes/users/index.js:56 POST regex-injection`
    - `routes/users/user.js:159 req.body.search`
  - **Sink**: `new RegExp with attacker pattern`
- Evidence: POST regex-injection req.body.search to searchLogs to new RegExp concatenation with reflected output
  - Validation: routes/users/index.js:56 POST /regex-injection -> routes/users/user.js:157 regExInjection(req.body.search) -> controllers/usersController.js:163 searchLogs -> utils/utility.js:94 new RegExp('(public\\[\\d+\\] +.*'+search+'.*)') concatenates attacker pattern with no escaping
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:56 POST /regex-injection -> routes/users/user.js:157 regExInjection(req.body.search) -> controllers/usersController.js:163 searchLogs -> utils/utility.js:94 new RegExp('(public\\[\\d+\\] +.*'+search+'.*)') concatenates attacker pattern with no escaping | consensus: 1/1 confirmed | triage: Authenticated ReDoS via unescaped RegExp concat
- Patch:
  - **Summary**: Escape search with RegExp.escape / fixed-string match (includes/indexOf) and add timeout/input-length limits.

<a id="finding-17"></a>
### MEDIUM DOM-based XSS via default parameter
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.85
- Location: `views/body-header.ejs:16-16`
- Vulnerable code (`views/body-header.ejs`):
```ejs
var lang = getUrlVars default;
```
- Taint Flow:
  - **Source**: `URL query parameter default`
  - **Path**:
    - `URL default attacker value`
    - `views/body-header.ejs:16 getUrlVars default`
  - **Sink**: `document write of URL string`
- Evidence: Layout reads default query param via getUrlVars and injects via document.write without encoding on every authenticated page
  - Validation: views/header.ejs:18 getUrlVars parses location.href -> views/body-header.ejs:15 var lang=getUrlVars()['default'] -> views/body-header.ejs:19-21 document.write(decodeURIComponent(lang)) with no encoding on every authenticated page
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: views/header.ejs:18 getUrlVars parses location.href -> views/body-header.ejs:15 var lang=getUrlVars()['default'] -> views/body-header.ejs:19-21 document.write(decodeURIComponent(lang)) with no encoding on every authenticated page | consensus: 1/1 confirmed | triage: URL default param to document.write DOM XSS
- Patch:
  - **Summary**: Remove document.write; render via textContent/DOM APIs and treat default param as opaque text, never as HTML.

<a id="finding-18"></a>
### MEDIUM Insufficient session expiration: logout does not invalidate server session
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-613 | confidence: 0.85
- Location: `views/body-header.ejs:64-64`
- Vulnerable code (`views/body-header.ejs`):
```ejs
document.cookie = "connect.sid=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
```
- Taint Flow:
  - **Source**: `authenticated session identifier`
  - **Path**:
    - `routes/users/user.js:13 login without regenerate`
    - `views/body-header.ejs:64 client-only cookie clear`
  - **Sink**: `server session never invalidated`
- Evidence: No server-side logout route exists in routes/users/index.js; logout is client-only JS in views/body-header.ejs:62-65 that only expires connect.sid cookie, never calls req.logout/req.logOut or session.destroy. Login in routes/users/user.js:13 req.logIn without session.regenerate enables fixation; stolen/fixed sid stays valid after victim logout.
  - Validation: routes/users/index.js:1-67 defines no /logout route; views/body-header.ejs:64 logout only expires connect.sid client-side; no session.destroy/req.logout in repo; routes/users/user.js:13 req.logIn without session.regenerate
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/index.js:1-67 defines no /logout route; views/body-header.ejs:64 logout only expires connect.sid client-side; no session.destroy/req.logout in repo; routes/users/user.js:13 req.logIn without session.regenerate | consensus: 1/1 confirmed | triage: Client-only logout leaves server session valid
- Patch:
  - **Summary**: Add server-side POST /logout calling req.logout/session.destroy and clearing cookie; regenerate session on login

<a id="finding-19"></a>
### MEDIUM Hardcoded default database credentials in application config
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-798 | confidence: 0.8
- Location: `config/config.js:5-5`
- Vulnerable code (`config/config.js`):
```javascript
DATABASE_PASS: process.env.DATABASE_PASS?process.env.DATABASE_PASS:***,
```
- Taint Flow:
  - **Source**: `hardcoded fallback in source`
  - **Path**:
    - `config/config.js:5 default credential definition`
    - `utils/mysqlConnectionPool.js:9 pool creation`
  - **Sink**: `database authentication with default password`
- Evidence: Application config config/config.js:2-5 defines default database credentials (DATABASE_HOST, DATABASE_NAME, DATABASE_USER, DATABASE_PASS=***) used by utils/mysqlConnectionPool.js when env vars absent; distinct from prior session-secret finding at app.js:25-28
  - Validation: config/config.js:5 DATABASE_PASS fallback to 'pass' (plus :2-4 host/user/name defaults) consumed by utils/mysqlConnectionPool.js:5-11 pool creation when env vars absent
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: config/config.js:5 DATABASE_PASS fallback to 'pass' (plus :2-4 host/user/name defaults) consumed by utils/mysqlConnectionPool.js:5-11 pool creation when env vars absent | consensus: 1/1 confirmed | triage: Default DB creds separate file from session secret
- Patch:
  - **Summary**: Remove hardcoded fallbacks; require env vars and fail closed if absent, rotate any deployed default password

<a id="finding-20"></a>
### LOW Sensitive information exposure via raw database error responses
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.9
- Location: `routes/users/user.js:36-36`
- Vulnerable code (`routes/users/user.js`):
```javascript
return res.send(err);
```
- Taint Flow:
  - **Source**: `DB error induced by attacker input req.query.id`
  - **Path**:
    - `routes/users/user.js:28 getUser(req.query.id)`
    - `models/usersModel.js:7 string-concatenated SQL`
    - `routes/users/user.js:36 res.send(err)`
  - **Sink**: `raw database error sent to HTTP response`
- Evidence: routes/users/user.js:36 return res.send(err) in errorBasedSqli catch forwards raw DB/driver error to client; same pattern at :45 updateProfile, :213 idorUpdateProfile, :222 idorViewProfile fallback. Leaks SQL syntax, table/column names aiding injection.
  - Validation: routes/users/user.js:36 return res.send(err) forwards DB driver error from models/usersModel.js:7 via utils/mysqlConnectionPool.js:27 reject(err); same pattern at routes/users/user.js:45,213,222 and :xxe res.send(err)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users/user.js:36 return res.send(err) forwards DB driver error from models/usersModel.js:7 via utils/mysqlConnectionPool.js:27 reject(err); same pattern at routes/users/user.js:45,213,222 and :xxe res.send(err) | consensus: 1/1 confirmed | triage: Raw DB errors forwarded to client aiding injection
- Patch:
  - **Summary**: Log err server-side and return generic error message/status instead of res.send(err)
