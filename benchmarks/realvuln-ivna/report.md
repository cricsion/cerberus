# Cerberus Report

**Findings:** 27 actionable — 6 critical, 9 high, 2 medium, 10 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 20 false positives and 11 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 6 | 0 / 6 (0%) | 6 |
| HIGH | 9 | 0 / 9 (0%) | 9 |
| MEDIUM | 2 | 0 / 2 (0%) | 2 |
| LOW | 10 | 0 / 10 (0%) | 10 |
| **TOTAL** | **27** | **0 / 27 (0%)** | **27** |

## Table of Contents

- [Confirmed (27)](#confirmed)
  - [CRITICAL: Hardcoded JWT signing secret enables token forgery (`src/models/user.js:71`)](#finding-1)
  - [CRITICAL: Unauthenticated remote code execution via eval (`src/routers/user.js:215`)](#finding-2)
  - [CRITICAL: Hardcoded JWT verify secret in auth middleware (`src/middleware/auth.js:8`)](#finding-3)
  - [CRITICAL: Missing authentication on v2 user endpoint (`src/routers/user.js:213`)](#finding-4)
  - [CRITICAL: BOLA arbitrary user update via v1 patch (`src/routers/user.js:291`)](#finding-5)
  - [CRITICAL: BOLA arbitrary user deletion via v1 delete (`src/routers/user.js:308`)](#finding-6)
  - [HIGH: Unauthenticated bulk task disclosure via v1 list (`src/routers/task.js:88`)](#finding-7)
  - [HIGH: Missing password hashing stores plaintext credentials (`src/models/user.js:86`)](#finding-8)
  - [HIGH: BOLA arbitrary task modification via v1 patch (`src/routers/task.js:105`)](#finding-9)
  - [HIGH: Signup mass-assignment with plaintext password storage (no hashing) (`src/routers/user.js:17`)](#finding-10)
  - [HIGH: Unauthenticated SSRF via contact url parameter (`src/routers/user.js:194`)](#finding-11)
  - [HIGH: Unauthenticated user disclosure via v1 name lookup (`src/routers/user.js:244`)](#finding-12)
  - [HIGH: DOM XSS via contact name query reflection (`public/contact.html:190`)](#finding-13)
  - [HIGH: Stored XSS via profile name innerHTML rendering (`public/src/profile-app.js:15`)](#finding-14)
  - [HIGH: Unauthenticated user disclosure and enumeration via v1 name lookup (`src/routers/user.js:250`)](#finding-15)
  - [MEDIUM: Open redirect to attacker-controlled URL in contact handler (`src/routers/user.js:197`)](#finding-16)
  - [MEDIUM: Signup mass-assignment allows arbitrary User field injection (`src/routers/user.js:17`)](#finding-17)
  - [LOW: Insecure session cookie missing HttpOnly/Secure/SameSite on signup (`src/routers/user.js:22`)](#finding-18)
  - [LOW: Insecure session cookie missing flags on login (`src/routers/user.js:36`)](#finding-19)
  - [LOW: JWT without expiration enables indefinite sessions (`src/models/user.js:71`)](#finding-20)
  - [LOW: Signup error handler discloses internal error details (`src/routers/user.js:26`)](#finding-21)
  - [LOW: Error disclosure in POST tasks (`src/routers/task.js:17`)](#finding-22)
  - [LOW: Error disclosure in PATCH v2 tasks id (`src/routers/task.js:66`)](#finding-23)
  - [LOW: Error disclosure in PATCH v1 tasks id (`src/routers/task.js:116`)](#finding-24)
  - [LOW: Error disclosure in PATCH users me (`src/routers/user.js:152`)](#finding-25)
  - [LOW: Error disclosure in PATCH v1 users id (`src/routers/user.js:302`)](#finding-26)
  - [LOW: State-changing logout via GET enables CSRF (`src/routers/user.js:92`)](#finding-27)

<a id="confirmed"></a>
## Confirmed (27)

<a id="finding-1"></a>
### CRITICAL Hardcoded JWT signing secret enables token forgery
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 1.0
- Location: `src/models/user.js:71-71`
- Vulnerable code (`src/models/user.js`):
```javascript
const token = jwt.sign({ _id: user._id.toString() }, '***')
```
- Taint Flow:
  - **Source**: `hardcoded application secret in source`
  - **Path**:
    - `src/models/user.js:71 jwt.sign with committed secret`
    - `src/middleware/auth.js:8 jwt.verify with same secret`
    - `src/middleware/auth.js:9 User.findOne session lookup`
  - **Sink**: `authentication bypass via token forgery`
- Evidence: JWT signing at src/models/user.js:71 uses hardcoded secret ***; verification at src/middleware/auth.js:8 uses same hardcoded secret *** enabling forgery
  - Validation: src/models/user.js:71 jwt.sign with literal 'hardsecret' and src/middleware/auth.js:8 jwt.verify with same literal; plantable via src/routers/user.js:17 new User(req.body) tokens mass-assignment
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/models/user.js:71 jwt.sign with literal 'hardsecret' and src/middleware/auth.js:8 jwt.verify with same literal; plantable via src/routers/user.js:17 new User(req.body) tokens mass-assignment | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Load JWT secret from environment (required, no fallback), rotate tokens, reject tokens not issued server-side
  - +1 duplicate(s): `src/models/user.js:71`

<a id="finding-2"></a>
### CRITICAL Unauthenticated remote code execution via eval
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-95 | confidence: 1.0
- Location: `src/routers/user.js:215-215`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.send('Welcome name ' + eval(req.query.name));
```
- Taint Flow:
  - **Source**: `req.query.name URL parameter`
  - **Path**:
    - `src/routers/user.js:215`
  - **Sink**: `eval() code execution`
- Evidence: res.send('Welcome name ' + eval(req.query.name));
  - Validation: Unauth eval of query at src/routers/user.js:213-215 with no sanitizer; mounted via src/index.js:35-36
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Unauth eval of query at src/routers/user.js:213-215 with no sanitizer; mounted via src/index.js:35-36 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove eval() at src/routers/user.js:215; treat req.query.name as string and encode on res.send
  - +1 duplicate(s): `src/routers/user.js:215`

<a id="finding-3"></a>
### CRITICAL Hardcoded JWT verify secret in auth middleware
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `src/middleware/auth.js:8-8`
- Vulnerable code (`src/middleware/auth.js`):
```javascript
const decoded = jwt.verify(token, 'hardsecret')
```
- Taint Flow:
  - **Source**: `literal 'hardsecret'`
  - **Path**:
    - `src/middleware/auth.js:8`
  - **Sink**: `jwt.verify hardcoded secret`
- Evidence: const decoded = jwt.verify(token, 'hardsecret')
  - Validation: src/middleware/auth.js:8 jwt.verify(token,'hardsecret') hardcoded; src/models/user.js:71 jwt.sign({_id},'hardsecret') same literal
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/middleware/auth.js:8 jwt.verify(token,'hardsecret') hardcoded; src/models/user.js:71 jwt.sign({_id},'hardsecret') same literal | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Read JWT secret from env (e.g., process.env.JWT_SECRET), require strong value at startup, rotate existing tokens.

<a id="finding-4"></a>
### CRITICAL Missing authentication on v2 user endpoint
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `src/routers/user.js:213-213`
- Vulnerable code (`src/routers/user.js`):
```javascript
router.get('/api/v2/user', function (req, res) {
```
- Taint Flow:
  - **Source**: `GET without auth`
  - **Path**:
    - `src/routers/user.js:213`
  - **Sink**: `unauthenticated handler`
- Evidence: router.get('/api/v2/user', function (req, res) {
  - Validation: src/routers/user.js:213 router.get('/api/v2/user') has no auth middleware and reaches eval(req.query.name) at src/routers/user.js:215 unauthenticated RCE
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/user.js:213 router.get('/api/v2/user') has no auth middleware and reaches eval(req.query.name) at src/routers/user.js:215 unauthenticated RCE | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove eval() and require auth middleware on /api/v2/user; return static/safe response.
  - +1 duplicate(s): `src/routers/user.js:22`

<a id="finding-5"></a>
### CRITICAL BOLA arbitrary user update via v1 patch
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `src/routers/user.js:291-291`
- Vulnerable code (`src/routers/user.js`):
```javascript
const user = await User.findById(req.params.id)
```
- Taint Flow:
  - **Source**: `req.params.id authenticated but unauthorized`
  - **Path**:
    - `src/routers/user.js:281`
    - `src/routers/user.js:291`
  - **Sink**: `User.findById arbitrary ID write`
- Evidence: const user = await User.findById(req.params.id)
  - Validation: auth-only PATCH src/routers/user.js:281 with unscoped User.findById(req.params.id) at src/routers/user.js:291 allows any-user overwrite
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: auth-only PATCH src/routers/user.js:281 with unscoped User.findById(req.params.id) at src/routers/user.js:291 allows any-user overwrite | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enforce owner check: only req.user._id may be updated; replace findById(id) with req.user at src/routers/user.js:291
  - +1 duplicate(s): `src/routers/user.js:291`

<a id="finding-6"></a>
### CRITICAL BOLA arbitrary user deletion via v1 delete
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `src/routers/user.js:308-308`
- Vulnerable code (`src/routers/user.js`):
```javascript
const user = await User.findByIdAndDelete(req.params.id)
```
- Taint Flow:
  - **Source**: `req.params.id`
  - **Path**:
    - `src/routers/user.js:306`
    - `src/routers/user.js:308`
  - **Sink**: `findByIdAndDelete arbitrary ID`
- Evidence: const user = await User.findByIdAndDelete(req.params.id)
  - Validation: auth-only DELETE src/routers/user.js:306 with User.findByIdAndDelete(req.params.id) at src/routers/user.js:308, no owner check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: auth-only DELETE src/routers/user.js:306 with User.findByIdAndDelete(req.params.id) at src/routers/user.js:308, no owner check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Restrict delete to self: delete req.user only instead of arbitrary id at src/routers/user.js:308
  - +1 duplicate(s): `src/routers/user.js:308`

<a id="finding-7"></a>
### HIGH Unauthenticated bulk task disclosure via v1 list
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 1.0
- Location: `src/routers/task.js:88-88`
- Vulnerable code (`src/routers/task.js`):
```javascript
const tasks = await Task.find({})
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP request`
  - **Path**:
    - `src/routers/task.js:86 unauthenticated entry`
    - `src/routers/task.js:88 Task.find({}) sink`
  - **Sink**: `bulk disclosure of all task records`
- Evidence: Route src/routers/task.js:86 GET /api/v1/tasks has no auth middleware; sink src/routers/task.js:88 Task.find({}) returns all tasks
  - Validation: src/routers/task.js:86 GET /api/v1/tasks has no auth middleware and src/routers/task.js:88 Task.find({}) returns every task
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/task.js:86 GET /api/v1/tasks has no auth middleware and src/routers/task.js:88 Task.find({}) returns every task | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require auth on /api/v1/tasks and scope query to owner, or remove legacy route
  - +1 duplicate(s): `src/routers/task.js:88`

<a id="finding-8"></a>
### HIGH Missing password hashing stores plaintext credentials
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `src/models/user.js:86-86`
- Vulnerable code (`src/models/user.js`):
```javascript
const user = new User(req.body) // saved with no bcrypt.hash; stored plaintext
```
- Taint Flow:
  - **Source**: `req.body.password via signup`
  - **Path**:
    - `src/routers/user.js:17`
    - `src/models/user.js:86`
  - **Sink**: `plaintext password persisted (no bcrypt.hash)`
- Evidence: const isMatch = await bcrypt.compare(password, user.password)
  - Validation: src/models/user.js:25 password field with no pre-save hash hook (only pre('remove')); grep bcrypt.hash returns no match; src/models/user.js:86 bcrypt.compare assumes hash never created; src/routers/user.js:17 new User(req.body) saves plaintext
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/models/user.js:25 password field with no pre-save hash hook (only pre('remove')); grep bcrypt.hash returns no match; src/models/user.js:86 bcrypt.compare assumes hash never created; src/routers/user.js:17 new User(req.body) saves plaintext | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Add userSchema.pre('save') hook to bcrypt.hash password when modified (e.g., 8+ rounds) before save.

<a id="finding-9"></a>
### HIGH BOLA arbitrary task modification via v1 patch
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `src/routers/task.js:105-105`
- Vulnerable code (`src/routers/task.js`):
```javascript
const task = await Task.findById(req.params.id)
```
- Taint Flow:
  - **Source**: `req.params.id`
  - **Path**:
    - `src/routers/task.js:95`
    - `src/routers/task.js:105`
  - **Sink**: `findById without owner`
- Evidence: const task = await Task.findById(req.params.id)
  - Validation: auth-only PATCH src/routers/task.js:95 with unscoped Task.findById(req.params.id) at src/routers/task.js:105, no owner check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: auth-only PATCH src/routers/task.js:95 with unscoped Task.findById(req.params.id) at src/routers/task.js:105, no owner check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Scope lookup to owner: Task.findOne({_id, owner:req.user._id}) at src/routers/task.js:105
  - +1 duplicate(s): `src/routers/task.js:105`

<a id="finding-10"></a>
### HIGH Signup mass-assignment with plaintext password storage (no hashing)
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `src/routers/user.js:17-17`
- Vulnerable code (`src/routers/user.js`):
```javascript
const user = new User(req.body)
```
- Taint Flow:
  - **Source**: `req.body.password (plus arbitrary User fields)`
  - **Path**:
    - `src/routers/user.js:17 new User(req.body)`
    - `src/models/user.js: save without hash`
    - `src/db/mongoose.js:3 Mongo persistence`
  - **Sink**: `plaintext password persisted in Mongo`
- Evidence: src/routers/user.js:17 new User(req.body) flows to user.save(); src/models/user.js has no pre-save bcrypt hash — only bcrypt.compare on login — so password persists as supplied
  - Validation: src/routers/user.js:17 new User(req.body) saves password directly; src/models/user.js has only pre(remove) hook and src/models/user.js:86 bcrypt.compare with no bcrypt.hash/pre-save hashing
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/user.js:17 new User(req.body) saves password directly; src/models/user.js has only pre(remove) hook and src/models/user.js:86 bcrypt.compare with no bcrypt.hash/pre-save hashing | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add pre-save hook hashing password with bcrypt and allowlist signup fields (name,email,password,age only)

<a id="finding-11"></a>
### HIGH Unauthenticated SSRF via contact url parameter
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/routers/user.js:194-194`
- Vulnerable code (`src/routers/user.js`):
```javascript
needle.get(query.url, { timeout: 3000 }, function(error, response1) {
```
- Taint Flow:
  - **Source**: `query.url URL query parameter`
  - **Path**:
    - `src/routers/user.js:191`
    - `src/routers/user.js:194`
  - **Sink**: `needle.get server-side fetch`
- Evidence: needle.get(query.url, { timeout: 3000 }, function(error, response1) {
  - Validation: Unauth needle.get(query.url) at src/routers/user.js:194 with query from url.parse(req.url) at src/routers/user.js:189-191, no allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Unauth needle.get(query.url) at src/routers/user.js:194 with query from url.parse(req.url) at src/routers/user.js:189-191, no allowlist | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Allowlist outbound hosts, block internal/metadata IPs, and reject attacker URLs at src/routers/user.js:189-197
  - +1 duplicate(s): `src/routers/user.js:194`

<a id="finding-12"></a>
### HIGH Unauthenticated user disclosure via v1 name lookup
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.95
- Location: `src/routers/user.js:244-244`
- Vulnerable code (`src/routers/user.js`):
```javascript
const user = await User.findOne({name: name})
```
- Taint Flow:
  - **Source**: `req.params.name unauthenticated`
  - **Path**:
    - `src/routers/user.js:240 :name entry unauthenticated`
    - `src/routers/user.js:244 findOne sink`
    - `src/routers/user.js:250 res.send(user) disclosure`
  - **Sink**: `full user document disclosure`
- Evidence: Route src/routers/user.js:240 GET /api/v1/users/:name has no auth; sink src/routers/user.js:244 User.findOne({name}) returns full user document including password hash and tokens via toJSON bypass? res.send(user)
  - Validation: src/routers/user.js:240 GET /api/v1/users/:name has no auth and src/routers/user.js:244 User.findOne({name}) plus src/routers/user.js:250 res.send(user) discloses user PII unauthenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/user.js:240 GET /api/v1/users/:name has no auth and src/routers/user.js:244 User.findOne({name}) plus src/routers/user.js:250 res.send(user) discloses user PII unauthenticated | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require auth and owner/self scope on user lookup or remove legacy route

<a id="finding-13"></a>
### HIGH DOM XSS via contact name query reflection
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `public/contact.html:190-190`
- Vulnerable code (`public/contact.html`):
```html
resultsEl.innerHTML = html; // html includes raw name
```
- Taint Flow:
  - **Source**: `location.search name parameter`
  - **Path**:
    - `public/contact.html:185`
    - `public/contact.html:190`
  - **Sink**: `innerHTML XSS sink`
- Evidence: resultsEl.innerHTML = html;
  - Validation: public/contact.html:185 html+='<p> Thank you for Contacting '+name attacker-controlled query param; public/contact.html:190 resultsEl.innerHTML=html unsanitized sink
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: public/contact.html:185 html+='<p> Thank you for Contacting '+name attacker-controlled query param; public/contact.html:190 resultsEl.innerHTML=html unsanitized sink | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Use textContent or encode name (encodeURIComponent/escape) before DOM insertion; avoid innerHTML with URL input.

<a id="finding-14"></a>
### HIGH Stored XSS via profile name innerHTML rendering
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `public/src/profile-app.js:15-15`
- Vulnerable code (`public/src/profile-app.js`):
```javascript
document.getElementById(dataId).innerHTML = `<strong>${dataName}</strong>: ${userData}`
```
- Taint Flow:
  - **Source**: `data.user.name from /api/v2/profile`
  - **Path**:
    - `public/src/profile-app.js:15`
  - **Sink**: `innerHTML stored XSS`
- Evidence: document.getElementById(dataId).innerHTML = '<strong>${dataName}</strong>: ${userData}'
  - Validation: public/src/profile-app.js:15 innerHTML with data.user.name from /api/v2/profile; src/models/user.js:7-12 name field has only trim/required, no validation/encoding; src/routers/user.js:138 allowlists name updates
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: public/src/profile-app.js:15 innerHTML with data.user.name from /api/v2/profile; src/models/user.js:7-12 name field has only trim/required, no validation/encoding; src/routers/user.js:138 allowlists name updates | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Render profile fields with textContent or server-side-escape name; validate/encode on display.

<a id="finding-15"></a>
### HIGH Unauthenticated user disclosure and enumeration via v1 name lookup
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.9
- Location: `src/routers/user.js:250-250`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.send(user)
```
- Taint Flow:
  - **Source**: `:name path parameter unauthenticated`
  - **Path**:
    - `src/routers/user.js:240`
    - `src/routers/user.js:250`
  - **Sink**: `res.send(user) disclosure`
- Evidence: res.send(user)
  - Validation: Unauth GET src/routers/user.js:240 with User.findOne({name}) and res.send(user) at src/routers/user.js:250 discloses email/age; toJSON at src/models/user.js:60-68 strips only password/tokens
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Unauth GET src/routers/user.js:240 with User.findOne({name}) and res.send(user) at src/routers/user.js:250 discloses email/age; toJSON at src/models/user.js:60-68 strips only password/tokens | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Require auth/owner check on GET /api/v1/users/:name at src/routers/user.js:240 and minimize returned fields

<a id="finding-16"></a>
### MEDIUM Open redirect to attacker-controlled URL in contact handler
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-601 | confidence: 0.9
- Location: `src/routers/user.js:197-197`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.redirect(query.url)
```
- Taint Flow:
  - **Source**: `query.url`
  - **Path**:
    - `src/routers/user.js:191`
    - `src/routers/user.js:197`
  - **Sink**: `res.redirect attacker URL`
- Evidence: res.redirect(query.url)
  - Validation: Unauth res.redirect(query.url) at src/routers/user.js:197 with query from url.parse at src/routers/user.js:189-191, no validation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Unauth res.redirect(query.url) at src/routers/user.js:197 with query from url.parse at src/routers/user.js:189-191, no validation | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Allowlist redirect targets and reject absolute attacker URLs at src/routers/user.js:197

<a id="finding-17"></a>
### MEDIUM Signup mass-assignment allows arbitrary User field injection
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-915 | confidence: 0.85
- Location: `src/routers/user.js:17-17`
- Vulnerable code (`src/routers/user.js`):
```javascript
const user = new User(req.body)
```
- Taint Flow:
  - **Source**: `req.body unauthenticated signup JSON`
  - **Path**:
    - `src/routers/user.js:17`
  - **Sink**: `new User(req.body) mass-assignment persistence`
- Evidence: const user = new User(req.body)
  - Validation: Unauth new User(req.body) at src/routers/user.js:16-17 with no allowlist; tokens[] injectable per src/models/user.js:44-49
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Unauth new User(req.body) at src/routers/user.js:16-17 with no allowlist; tokens[] injectable per src/models/user.js:44-49 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Allowlist signup fields (name,email,password,age) at src/routers/user.js:17; reject tokens and extra keys before new User()

<a id="finding-18"></a>
### LOW Insecure session cookie missing HttpOnly/Secure/SameSite on signup
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.95
- Location: `src/routers/user.js:22-22`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.cookie('auth_token', token)
```
- Taint Flow:
  - **Source**: `server-generated JWT session token`
  - **Path**:
    - `src/routers/user.js:22`
  - **Sink**: `Set-Cookie without Secure/HttpOnly/SameSite`
- Evidence: res.cookie('auth_token', token)
  - Validation: Set-Cookie without flags at src/routers/user.js:22; no HttpOnly/Secure/SameSite on auth_token
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Set-Cookie without flags at src/routers/user.js:22; no HttpOnly/Secure/SameSite on auth_token | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Add HttpOnly, Secure, SameSite=Strict/Lax to res.cookie at src/routers/user.js:22
  - +1 duplicate(s): `src/routers/user.js:22`

<a id="finding-19"></a>
### LOW Insecure session cookie missing flags on login
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.95
- Location: `src/routers/user.js:36-36`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.cookie('auth_token', token)
```
- Taint Flow:
  - **Source**: `JWT from generateAuthToken`
  - **Path**:
    - `src/routers/user.js:36`
  - **Sink**: `Set-Cookie without flags`
- Evidence: res.cookie('auth_token', token)
  - Validation: Set-Cookie without flags at src/routers/user.js:36 on login; no HttpOnly/Secure/SameSite
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Set-Cookie without flags at src/routers/user.js:36 on login; no HttpOnly/Secure/SameSite | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Add HttpOnly, Secure, SameSite to res.cookie at src/routers/user.js:36

<a id="finding-20"></a>
### LOW JWT without expiration enables indefinite sessions
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-613 | confidence: 0.9
- Location: `src/models/user.js:71-71`
- Vulnerable code (`src/models/user.js`):
```javascript
const token = jwt.sign({ _id: user._id.toString() }, '***')
```
- Taint Flow:
  - **Source**: `JWT payload without exp claim`
  - **Path**:
    - `src/models/user.js:71 token creation without expiry`
    - `src/middleware/auth.js:8 verification without expiry`
  - **Sink**: `indefinite session validity`
- Evidence: Token creation src/models/user.js:71 jwt.sign payload only {_id} with no expiresIn; verification src/middleware/auth.js:8 imposes no expiry, tokens persist until explicit logout wipe
  - Validation: src/models/user.js:71 jwt.sign({_id}) with no expiresIn and src/middleware/auth.js:8 jwt.verify with no expiry check, tokens valid until logout wipe
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/models/user.js:71 jwt.sign({_id}) with no expiresIn and src/middleware/auth.js:8 jwt.verify with no expiry check, tokens valid until logout wipe | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add short expiresIn to jwt.sign and enforce exp on verify with refresh/logout
  - +1 duplicate(s): `src/models/user.js:71`

<a id="finding-21"></a>
### LOW Signup error handler discloses internal error details
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.9
- Location: `src/routers/user.js:26-26`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.status(400).send(e)
```
- Taint Flow:
  - **Source**: `Mongoose validation exception from attacker input`
  - **Path**:
    - `src/routers/user.js:26`
  - **Sink**: `res.send(e) error disclosure`
- Evidence: res.status(400).send(e)
  - Validation: Mongoose error reflected via res.status(400).send(e) at src/routers/user.js:26 on unauth signup
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Mongoose error reflected via res.status(400).send(e) at src/routers/user.js:26 on unauth signup | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Return generic error message instead of e at src/routers/user.js:26; log details server-side

<a id="finding-22"></a>
### LOW Error disclosure in POST tasks
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `src/routers/task.js:17-17`
- Vulnerable code (`src/routers/task.js`):
```javascript
res.status(400).send(e)
```
- Taint Flow:
  - **Source**: `task JSON`
  - **Path**:
    - `src/routers/task.js:7`
    - `src/routers/task.js:17`
  - **Sink**: `res.send disclosure`
- Evidence: res.status(400).send(e)
  - Validation: src/routers/task.js:7-17 catch(e) does res.status(400).send(e) leaking Mongoose validation internals on task create
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/task.js:7-17 catch(e) does res.status(400).send(e) leaking Mongoose validation internals on task create | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace res.send(e) with generic error message and log details server-side.

<a id="finding-23"></a>
### LOW Error disclosure in PATCH v2 tasks id
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `src/routers/task.js:66-66`
- Vulnerable code (`src/routers/task.js`):
```javascript
res.status(400).send(e)
```
- Taint Flow:
  - **Source**: `PATCH body`
  - **Path**:
    - `src/routers/task.js:46`
    - `src/routers/task.js:66`
  - **Sink**: `res.send disclosure`
- Evidence: res.status(400).send(e)
  - Validation: src/routers/task.js:46-66 catch(e) does res.status(400).send(e) leaking Mongoose internals on v2 task PATCH
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/task.js:46-66 catch(e) does res.status(400).send(e) leaking Mongoose internals on v2 task PATCH | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace res.send(e) with generic error message and log details server-side.

<a id="finding-24"></a>
### LOW Error disclosure in PATCH v1 tasks id
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `src/routers/task.js:116-116`
- Vulnerable code (`src/routers/task.js`):
```javascript
res.status(400).send(e)
```
- Taint Flow:
  - **Source**: `v1 body`
  - **Path**:
    - `src/routers/task.js:95`
    - `src/routers/task.js:116`
  - **Sink**: `res.send disclosure`
- Evidence: res.status(400).send(e)
  - Validation: src/routers/task.js:95-116 catch(e) does res.status(400).send(e) leaking Mongoose internals on v1 task PATCH
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/task.js:95-116 catch(e) does res.status(400).send(e) leaking Mongoose internals on v1 task PATCH | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace res.send(e) with generic error message and log details server-side.
  - +1 duplicate(s): `src/routers/user.js:128`

<a id="finding-25"></a>
### LOW Error disclosure in PATCH users me
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `src/routers/user.js:152-152`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.status(400).send(e)
```
- Taint Flow:
  - **Source**: `Mongoose error`
  - **Path**:
    - `src/routers/user.js:147`
    - `src/routers/user.js:152`
  - **Sink**: `res.send disclosure`
- Evidence: res.status(400).send(e)
  - Validation: src/routers/user.js:147-152 catch(e) does res.status(400).send(e) leaking Mongoose internals to authenticated caller
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/user.js:147-152 catch(e) does res.status(400).send(e) leaking Mongoose internals to authenticated caller | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace res.send(e) with generic error message and log details server-side.

<a id="finding-26"></a>
### LOW Error disclosure in PATCH v1 users id
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `src/routers/user.js:302-302`
- Vulnerable code (`src/routers/user.js`):
```javascript
res.status(400).send(e)
```
- Taint Flow:
  - **Source**: `attacker body`
  - **Path**:
    - `src/routers/user.js:291`
    - `src/routers/user.js:302`
  - **Sink**: `res.send disclosure`
- Evidence: res.status(400).send(e)
  - Validation: src/routers/user.js:291-302 catch(e) does res.status(400).send(e) leaking Mongoose internals on v1 PATCH
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/user.js:291-302 catch(e) does res.status(400).send(e) leaking Mongoose internals on v1 PATCH | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace res.send(e) with generic error message and log details server-side.

<a id="finding-27"></a>
### LOW State-changing logout via GET enables CSRF
- CVSS: **2.2** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.8
- Location: `src/routers/user.js:92-92`
- Vulnerable code (`src/routers/user.js`):
```javascript
router.get('/logout', auth, async (req, res) => {
```
- Taint Flow:
  - **Source**: `cross-site GET with victim cookies`
  - **Path**:
    - `src/routers/user.js:92`
  - **Sink**: `req.user.tokens=[] state change on GET`
- Evidence: router.get('/logout', auth, async (req, res) => {
  - Validation: src/routers/user.js:92 router.get('/logout',auth) performs state change src/routers/user.js:93 req.user.tokens=[] via cookie auth readable cross-site; res.cookie without SameSite/HttpOnly
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/routers/user.js:92 router.get('/logout',auth) performs state change src/routers/user.js:93 req.user.tokens=[] via cookie auth readable cross-site; res.cookie without SameSite/HttpOnly | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Change logout to POST with CSRF token and set cookies SameSite=Lax/Strict, HttpOnly, Secure.
