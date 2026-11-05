# Cerberus Report

**Findings:** 40 actionable — 7 critical, 13 high, 8 medium, 12 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 28 false positives and 1 duplicate — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 7 | 0 / 7 (0%) | 7 |
| HIGH | 13 | 0 / 13 (0%) | 13 |
| MEDIUM | 8 | 0 / 8 (0%) | 8 |
| LOW | 12 | 0 / 12 (0%) | 12 |
| **TOTAL** | **40** | **0 / 40 (0%)** | **40** |

## Table of Contents

- [Confirmed (40)](#confirmed)
  - [CRITICAL: Hardcoded JWT signing secret 'hello' enables universal token forgery (`routers/index.js:10`)](#finding-1)
  - [CRITICAL: Authenticated node-serialize deserialization leads to RCE (`routers/index.js:727`)](#finding-2)
  - [CRITICAL: NoSQL operator injection in login findOne enables authentication bypass (`routers/index.js:148`)](#finding-3)
  - [CRITICAL: NoSQL injection and full user dump via query param (`routers/index.js:235`)](#finding-4)
  - [CRITICAL: NoSQL injection and user disclosure via username lookup (`routers/index.js:263`)](#finding-5)
  - [CRITICAL: Mass-assignment of admin flag plus plaintext password storage on signup (`routers/index.js:320`)](#finding-6)
  - [CRITICAL: Unauthenticated RCE via alg=none JWT forgery chaining into node-serialize shell sink (`routers/index.js:727`)](#finding-7)
  - [HIGH: DOM XSS via eval of URL id parameter (`home.html:249`)](#finding-8)
  - [HIGH: Unauthenticated SSRF with reflected content via needle fetch (`routers/index.js:696`)](#finding-9)
  - [HIGH: Reflected XSS via SSRF url in success branch (`routers/index.js:700`)](#finding-10)
  - [HIGH: Reflected XSS via SSRF url in error branch (`routers/index.js:706`)](#finding-11)
  - [HIGH: Sensitive SSRF and user-dump endpoints lack authentication (`routers/index.js:685`)](#finding-12)
  - [HIGH: Directory traversal via express-blinker static mount (`app.js:27`)](#finding-13)
  - [HIGH: Global multer middleware enables unauthenticated file persistence via any POST endpoint (`app.js:74`)](#finding-14)
  - [HIGH: Broken access control allows reading any user's posts (`routers/index.js:381`)](#finding-15)
  - [HIGH: Global-state post attribution enables cross-user forgery and stored XSS (`routers/index.js:436`)](#finding-16)
  - [HIGH: Password-reset user enumeration and Host-header poisonable reset link (`routers/index.js:546`)](#finding-17)
  - [HIGH: Password reset overwrites plaintext password without token invalidation or expiry (`routers/index.js:613`)](#finding-18)
  - [HIGH: Typeless password field disables casting and preserves operator injection (`models/user.js:11`)](#finding-19)
  - [HIGH: OAuth token exfiltration via wildcard postMessage (`public/redirect.html:31`)](#finding-20)
  - [MEDIUM: CSRF protection defined but never enforced on state-changing routes (`routers/index.js:33`)](#finding-21)
  - [MEDIUM: Password-reset token rotation no-op leaves old token valid (`routers/index.js:539`)](#finding-22)
  - [MEDIUM: Weak upload validation allows malicious file persistence in webroot (`app.js:61`)](#finding-23)
  - [MEDIUM: OAuth implicit flow with static state never validated enables login CSRF (`routers/index.js:79`)](#finding-24)
  - [MEDIUM: JWT verification without algorithm allowlist or expiry enables forgery (`routers/index.js:206`)](#finding-25)
  - [MEDIUM: Href attribute injection via poisonable reset link (`utils/sendemail.js:212`)](#finding-26)
  - [MEDIUM: Implicit global assignments enable cross-request state pollution and data leakage (`models/strict.js:5`)](#finding-27)
  - [MEDIUM: Unrestricted CORS allows cross-origin reads of sensitive data (`routers/index.js:46`)](#finding-28)
  - [LOW: Auth cookie in OAuth callback lacks HttpOnly/Secure/SameSite (`routers/index.js:99`)](#finding-29)
  - [LOW: Password-reset mailer references undefined res causing crash on success (`utils/sendemail.js:294`)](#finding-30)
  - [LOW: Hardcoded express-session secret with insecure cookie defaults (`app.js:92`)](#finding-31)
  - [LOW: Session JWT written to server logs in profile handler (`routers/index.js:54`)](#finding-32)
  - [LOW: Plaintext login password written to logs (`routers/index.js:138`)](#finding-33)
  - [LOW: Minted session JWT logged after login (`routers/index.js:166`)](#finding-34)
  - [LOW: Login Auth cookie lacks HttpOnly/Secure/SameSite and has no expiry (`routers/index.js:168`)](#finding-35)
  - [LOW: Null dereference and global pollution on missing upload file (`routers/index.js:438`)](#finding-36)
  - [LOW: Unchecked email dereference DoS in forgot handler (`routers/index.js:501`)](#finding-37)
  - [LOW: OAuth bearer token logged in auth callback (`routers/index.js:82`)](#finding-38)
  - [LOW: Logout clears cookie but does not invalidate JWT/server session (`routers/index.js:487`)](#finding-39)
  - [LOW: Password-reset first request never sends email (inverted Token branch) (`routers/index.js:529`)](#finding-40)

<a id="confirmed"></a>
## Confirmed (40)

<a id="finding-1"></a>
### CRITICAL Hardcoded JWT signing secret 'hello' enables universal token forgery
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 1.0
- Location: `routers/index.js:10-10`
- Vulnerable code (`routers/index.js`):
```javascript
const accessTokenSecret = 'hello';
```
- Taint Flow:
  - **Source**: `hardcoded literal in source`
  - **Sink**: `jwt.sign/jwt.verify HMAC key`
- Evidence: const accessTokenSecret = 'hello';
  - Validation: routers/index.js:10 hardcodes accessTokenSecret='hello' used as HMAC key in jwt.sign at routers/index.js:97,165 and jwt.verify at routers/index.js:206
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:10 hardcodes accessTokenSecret='hello' used as HMAC key in jwt.sign at routers/index.js:97,165 and jwt.verify at routers/index.js:206 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Load JWT secret from env (process.env.JWT_SECRET) with startup failure if missing, rotate secret, set short expiresIn and re-issue tokens.

<a id="finding-2"></a>
### CRITICAL Authenticated node-serialize deserialization leads to RCE
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 1.0
- Location: `routers/index.js:727-727`
- Vulnerable code (`routers/index.js`):
```javascript
const uns = serialize.unserialize(req.body)    // Insecure Deserailiazation => Remote Code Execution
```
- Taint Flow:
  - **Source**: `authenticated POST JSON body`
  - **Path**:
    - `routers/index.js:718 req.body`
    - `routers/index.js:727 unserialize`
  - **Sink**: `node-serialize unserialize code execution`
- Evidence: const uns = serialize.unserialize(req.body)    // Insecure Deserailiazation => Remote Code Execution
  - Validation: routers/index.js:718-727 POST /secret/shell passes req.body directly to serialize.unserialize with authenticateToken only; node-serialize@0.0.4 in package.json:27 allows _$$ND_FUNC$$_ RCE
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:718-727 POST /secret/shell passes req.body directly to serialize.unserialize with authenticateToken only; node-serialize@0.0.4 in package.json:27 allows _$$ND_FUNC$$_ RCE | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove node-serialize; use JSON.parse with schema validation and never unserialize untrusted input.

<a id="finding-3"></a>
### CRITICAL NoSQL operator injection in login findOne enables authentication bypass
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `routers/index.js:148-151`
- Vulnerable code (`routers/index.js`):
```javascript
userSchema.findOne({
        username: req.body.username,
        password:req.body.password
```
- Taint Flow:
  - **Source**: `POST /secret/login body username/password`
  - **Path**:
    - `routers/index.js:118 req.body.username/password`
    - `routers/index.js:148 findOne filter`
  - **Sink**: `Mongoose findOne query operator injection`
- Evidence: userSchema.findOne({ username: req.body.username, password:req.body.password
  - Validation: routers/index.js:148-151 userSchema.findOne({username:req.body.username,password:req.body.password}) with only notEmpty checks at routers/index.js:119-130; bodyParser.json at routers/index.js:47 allows object operators like {"$gt":""} to bypass auth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:148-151 userSchema.findOne({username:req.body.username,password:req.body.password}) with only notEmpty checks at routers/index.js:119-130; bodyParser.json at routers/index.js:47 allows object operators like {"$gt":""} to bypass auth | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enforce string types and reject keys starting with $/containing . before Mongoose query; use exact-match parameterized lookup plus password hash compare.

<a id="finding-4"></a>
### CRITICAL NoSQL injection and full user dump via query param
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `routers/index.js:235-239`
- Vulnerable code (`routers/index.js`):
```javascript
userSchema.findOne({
       username:req.query.user
```
- Taint Flow:
  - **Source**: `query param ?user=`
  - **Path**:
    - `routers/index.js:230 req.query.user`
    - `routers/index.js:235 findOne`
    - `routers/index.js:244 res.json(result)`
  - **Sink**: `findOne + res.json full user document`
- Evidence: userSchema.findOne({ username:req.query.user
  - Validation: routers/index.js:230-244 POST /secret/?user does userSchema.findOne({username:req.query.user}) with no validation then res.json(result) disclosing full user document including password/admin
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:230-244 POST /secret/?user does userSchema.findOne({username:req.query.user}) with no validation then res.json(result) disclosing full user document including password/admin | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Require authentication/authorization, validate user as string, reject operators, and never res.json full user document.

<a id="finding-5"></a>
### CRITICAL NoSQL injection and user disclosure via username lookup
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `routers/index.js:263-267`
- Vulnerable code (`routers/index.js`):
```javascript
userSchema.findOne({
     username:req.body.username
```
- Taint Flow:
  - **Source**: `POST body username`
  - **Path**:
    - `routers/index.js:259 req.body.username`
    - `routers/index.js:263 findOne`
    - `routers/index.js:271 res.json(result)`
  - **Sink**: `findOne + res.json full document`
- Evidence: userSchema.findOne({ username:req.body.username
  - Validation: routers/index.js:259-271 POST /secret/username does userSchema.findOne({username:req.body.username}) with no validation then res.json(result) disclosing full user document
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:259-271 POST /secret/username does userSchema.findOne({username:req.body.username}) with no validation then res.json(result) disclosing full user document | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Require auth, strictly validate username string, reject Mongo operators, and return minimal fields only.

<a id="finding-6"></a>
### CRITICAL Mass-assignment of admin flag plus plaintext password storage on signup
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-915 | confidence: 0.95
- Location: `routers/index.js:320-321`
- Vulnerable code (`routers/index.js`):
```javascript
admin:req.body.admin, // privilege escalation
```
- Taint Flow:
  - **Source**: `POST signup body admin`
  - **Path**:
    - `routers/index.js:292 req.body.admin`
    - `routers/index.js:320 new userSchema`
  - **Sink**: `user creation with attacker-controlled admin flag`
- Evidence: admin:req.body.admin, // privilege escalation
  - Validation: routers/index.js:292-321 unauthenticated signup builds new userSchema with admin:req.body.admin and password:req.body.password; models/user.js:5-21 stores password verbatim with no hash and no bcrypt in package.json
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:292-321 unauthenticated signup builds new userSchema with admin:req.body.admin and password:req.body.password; models/user.js:5-21 stores password verbatim with no hash and no bcrypt in package.json | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Whitelist signup fields (username/email/password only), force admin:false server-side, and hash passwords with bcrypt.

<a id="finding-7"></a>
### CRITICAL Unauthenticated RCE via alg=none JWT forgery chaining into node-serialize shell sink
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.95
- Location: `routers/index.js:727-728`
- Vulnerable code (`routers/index.js`):
```javascript
const uns = serialize.unserialize(req.body)
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP cookie Auth with forged alg=none JWT`
  - **Path**:
    - `unauth attacker mints alg=none Auth cookie -> routers/index.js:206`
    - `authenticateToken passes -> routers/index.js:718`
    - `req.body -> routers/index.js:727`
  - **Sink**: `node-serialize unserialize RCE`
- Evidence: routers/index.js:206 jwt.verify accepts alg=none (jwa none verifier returns true on empty signature) proven by direct node repro; routers/index.js:718 shell route gated only by authenticateToken; routers/index.js:727 unserialize sink
  - Validation: routers/index.js:197-211 authenticateToken calls jwt.verify(token,accessTokenSecret) with no algorithms allowlist; jsonwebtoken@0.4.0/jwa accepts alg=none with empty signature (proven: trailing-dot none token verifies); routers/index.js:718 shell gated only by authenticateToken; routers/index.js:727 serialize.unserialize(req.body) evals _$$ND_FUNC$$_ (node-serialize/lib/serialize.js eval)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:197-211 authenticateToken calls jwt.verify(token,accessTokenSecret) with no algorithms allowlist; jsonwebtoken@0.4.0/jwa accepts alg=none with empty signature (proven: trailing-dot none token verifies); routers/index.js:718 shell gated only by authenticateToken; routers/index.js:727 serialize.unserialize(req.body) evals _$$ND_FUNC$$_ (node-serialize/lib/serialize.js eval) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enforce algorithm allowlist in jwt.verify (e.g. {algorithms:['HS256']}), rotate hardcoded secret routers/index.js:10 to env secret with expiry, and replace node-serialize unserialize at routers/index.js:727 with JSON.parse plus schema validation.

<a id="finding-8"></a>
### HIGH DOM XSS via eval of URL id parameter
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-95 | confidence: 1.0
- Location: `home.html:249-250`
- Vulnerable code (`home.html`):
```html
eval(id);
```
- Taint Flow:
  - **Source**: `?id= query param`
  - **Path**:
    - `home.html:241 location.search`
    - `home.html:249 eval`
  - **Sink**: `eval attacker string`
- Evidence: eval(id);
  - Validation: home.html:241-250 reads params.get('id') from location.search and calls eval(id) with no sanitization; reachable via app.js:117 GET /home sendFile home.html
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: home.html:241-250 reads params.get('id') from location.search and calls eval(id) with no sanitization; reachable via app.js:117 GET /home sendFile home.html | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove eval(id); treat id as data (textContent/URL allowlist) and never execute URL input.

<a id="finding-9"></a>
### HIGH Unauthenticated SSRF with reflected content via needle fetch
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `routers/index.js:696-700`
- Vulnerable code (`routers/index.js`):
```javascript
needle.get(url, { timeout: 3000 }, function(error, response1) {
```
- Taint Flow:
  - **Source**: `query param url`
  - **Path**:
    - `routers/index.js:688 req.query url`
    - `routers/index.js:696 needle.get`
    - `routers/index.js:702 response.write body`
  - **Sink**: `server fetch + reflected body/URL`
- Evidence: needle.get(url, { timeout: 3000 }, function(error, response1) {
  - Validation: routers/index.js:685-702 GET /secret/ takes request.query['url'] with no allowlist and calls needle.get(url) then reflects url and response1.body; no auth gate, only rate-limit at app.js:25-30
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:685-702 GET /secret/ takes request.query['url'] with no allowlist and calls needle.get(url) then reflects url and response1.body; no auth gate, only rate-limit at app.js:25-30 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove open fetch or enforce allowlisted hosts/schemes, block internal/metadata IPs, validate mime, and avoid reflecting body/URL.

<a id="finding-10"></a>
### HIGH Reflected XSS via SSRF url in success branch
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `routers/index.js:700-700`
- Vulnerable code (`routers/index.js`):
```javascript
response.write('<h2>I am an application. I want to be useful, so I requested: <font color="red">'+url+'</font> for you\n</h2><br><br>\n\n\n');
```
- Taint Flow:
  - **Source**: `?url= query parameter`
  - **Path**:
    - `routers/index.js:687 req.query url`
    - `routers/index.js:700 response.write url`
  - **Sink**: `reflected HTML with attacker URL`
- Evidence: response.write('<h2>I am an application. I want to be useful, so I requested: <font color="red">'+url+'</font> for you\n</h2><br><br>\n\n\n');
  - Validation: routers/index.js:687 url=req.query[url] flows unescaped to routers/index.js:700 response.write(...url...) with Content-Type text/html at routers/index.js:696
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:687 url=req.query[url] flows unescaped to routers/index.js:700 response.write(...url...) with Content-Type text/html at routers/index.js:696 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: HTML-escape url before response.write and/or set Content-Type text/plain; validate url scheme.

<a id="finding-11"></a>
### HIGH Reflected XSS via SSRF url in error branch
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `routers/index.js:706-706`
- Vulnerable code (`routers/index.js`):
```javascript
response.write('<h2>I wanted to be useful, but I could not find: <font color="red">'+url+'</font> for you\n</h2><br><br>\n\n\n');
```
- Taint Flow:
  - **Source**: `?url= query parameter`
  - **Path**:
    - `routers/index.js:687 req.query url`
    - `routers/index.js:706 error-branch write`
  - **Sink**: `reflected HTML in error page`
- Evidence: response.write('<h2>I wanted to be useful, but I could not find: <font color="red">'+url+'</font> for you\n</h2><br><br>\n\n\n');
  - Validation: routers/index.js:687 url=req.query[url] flows unescaped to routers/index.js:706 error-branch response.write(...url...) with Content-Type text/html at routers/index.js:703
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:687 url=req.query[url] flows unescaped to routers/index.js:706 error-branch response.write(...url...) with Content-Type text/html at routers/index.js:703 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: HTML-escape url in 404 branch before response.write; validate url scheme.

<a id="finding-12"></a>
### HIGH Sensitive SSRF and user-dump endpoints lack authentication
- CVSS: **7.2** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.92
- Location: `routers/index.js:685-685`
- Vulnerable code (`routers/index.js`):
```javascript
router.get('/secret/', function(request, response){
```
- Taint Flow:
  - **Source**: `unauthenticated network input (query/body)`
  - **Path**:
    - `routers/index.js:685 unauthenticated entry`
    - `routers/index.js:230 unauthenticated entry`
    - `routers/index.js:259 unauthenticated entry`
  - **Sink**: `SSRF fetch + full user document disclosure without auth`
- Evidence: routers/index.js:685 GET /secret/ has no authenticateToken; routers/index.js:230 POST /secret/?user has no authenticateToken; routers/index.js:259 POST /secret/username has no authenticateToken; siblings routers/index.js:357,366,434 require authenticateToken
  - Validation: routers/index.js:685 GET /secret/ (needle.get(url)) has no authenticateToken; routers/index.js:230 POST /secret/?user res.json(full user doc) has no auth; routers/index.js:259 POST /secret/username res.json(full doc) has no auth; siblings routers/index.js:357,366,434 require authenticateToken
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:685 GET /secret/ (needle.get(url)) has no authenticateToken; routers/index.js:230 POST /secret/?user res.json(full user doc) has no auth; routers/index.js:259 POST /secret/username res.json(full doc) has no auth; siblings routers/index.js:357,366,434 require authenticateToken | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add authenticateToken to routers/index.js:230,259,685; restrict user-dump to self/minimal fields; allowlist SSRF outbound hosts, block metadata/internal IPs, and validate mime/redirects.

<a id="finding-13"></a>
### HIGH Directory traversal via express-blinker static mount
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.9
- Location: `app.js:27-36`
- Vulnerable code (`app.js`):
```javascript
app.use(blinker(basePath, [
```
- Taint Flow:
  - **Source**: `URL path`
  - **Path**:
    - `app.js:124 URL path`
    - `app.js:27 blinker file serve`
  - **Sink**: `filesystem file read`
- Evidence: app.use(blinker(basePath, [
  - Validation: app.js:27 blinker(basePath, [{test:/.*/}]) mounted; node_modules/express-blinker/index.js:126 filePath=basePath+req.url with no normalization allowing ../ escape
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:27 blinker(basePath, [{test:/.*/}]) mounted; node_modules/express-blinker/index.js:126 filePath=basePath+req.url with no normalization allowing ../ escape | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Normalize and contain resolved path under basePath with path.join/normalize check; reject traversals.

<a id="finding-14"></a>
### HIGH Global multer middleware enables unauthenticated file persistence via any POST endpoint
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-434 | confidence: 0.9
- Location: `app.js:74-74`
- Vulnerable code (`app.js`):
```javascript
app.use(imageUpload.single('file'))
```
- Taint Flow:
  - **Source**: `unauthenticated multipart field 'file' on any POST endpoint`
  - **Path**:
    - `app.js:74 global multer -> diskStorage images/`
    - `routers/index.js:118 POST /secret/login (unauth multipart parsed)`
    - `routers/index.js:292 POST /secret/signup (unauth multipart parsed)`
    - `routers/index.js:499 POST /secret/forgot (unauth multipart parsed)`
  - **Sink**: `persistent file write to images/ served via static/blinker`
- Evidence: app.js:74 mounts multer globally before router mount; app.js:42 destination images/ with diskStorage; routers/index.js:673 postcheck reflects req.file unauthenticated proving global parsing; images/ served via blinker app.js:27 and serve-static
  - Validation: app.js:74 app.use(imageUpload.single('file')) mounts multer globally before router; app.js:42 diskStorage destination images/; routers/index.js:673 POST /secret/postcheck (no auth) reflects req.file proving unauth file write; app.js:60 fileFilter only checks /\.(png|jpg)$/ extension
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:74 app.use(imageUpload.single('file')) mounts multer globally before router; app.js:42 diskStorage destination images/; routers/index.js:673 POST /secret/postcheck (no auth) reflects req.file proving unauth file write; app.js:60 fileFilter only checks /\.(png|jpg)$/ extension | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove global app.use(imageUpload.single) at app.js:74; apply multer only on routers/index.js:434 POST /secret/addpost behind authenticateToken with content-type sniffing, random names, and storage outside webroot.

<a id="finding-15"></a>
### HIGH Broken access control allows reading any user's posts
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.9
- Location: `routers/index.js:381-391`
- Vulnerable code (`routers/index.js`):
```javascript
if(payload.username){ // broken access control
```
- Taint Flow:
  - **Source**: `:username path param + any valid Auth JWT`
  - **Path**:
    - `routers/index.js:366 req.params.username`
    - `routers/index.js:381 payload check`
  - **Sink**: `res.render postview with other user's posts`
- Evidence: if(payload.username){ // broken access control
  - Validation: routers/index.js:366 GET /secret/posts/:username queries req.params.username; routers/index.js:381 if(payload.username) truthiness check instead of payload.username==req.params.username
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:366 GET /secret/posts/:username queries req.params.username; routers/index.js:381 if(payload.username) truthiness check instead of payload.username==req.params.username | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enforce payload.username===req.params.username (plus admin exception) before rendering other user posts.

<a id="finding-16"></a>
### HIGH Global-state post attribution enables cross-user forgery and stored XSS
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-362 | confidence: 0.9
- Location: `routers/index.js:436-449`
- Vulnerable code (`routers/index.js`):
```javascript
postSchema.find({

username: hello
```
- Taint Flow:
  - **Source**: `global.hello set by other sessions`
  - **Path**:
    - `routers/index.js:170 global.hello=result.username`
    - `routers/index.js:436 username:hello`
  - **Sink**: `post creation attributed to global user`
- Evidence: postSchema.find({  username: hello
  - Validation: routers/index.js:170 global.hello=result.username set on login; routers/index.js:438-450 addpost uses bare hello for find and new postSchema instead of req.user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:170 global.hello=result.username set on login; routers/index.js:438-450 addpost uses bare hello for find and new postSchema instead of req.user | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Use req.user.username from authenticateToken for attribution; remove global.hello shared state.

<a id="finding-17"></a>
### HIGH Password-reset user enumeration and Host-header poisonable reset link
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-203 | confidence: 0.9
- Location: `routers/index.js:546-550`
- Vulnerable code (`routers/index.js`):
```javascript
const link = `http://${host}/secret/password-reset/${result.username}/${resettoken}`;
```
- Taint Flow:
  - **Source**: `email body + Host header`
  - **Path**:
    - `routers/index.js:499 req.body.email + req.get(host)`
    - `routers/index.js:546 link`
    - `routers/index.js:547 sendEmail`
  - **Sink**: `password-reset email with poisonable host`
- Evidence: const link = 'http://${host}/secret/password-reset/${result.username}/${resettoken}';
  - Validation: routers/index.js:514 renders Email not associated vs Reset Mail Sent oracle; routers/index.js:545-546 var host=req.get('host') and link http://${host}/secret/password-reset then sendEmail
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:514 renders Email not associated vs Reset Mail Sent oracle; routers/index.js:545-546 var host=req.get('host') and link http://${host}/secret/password-reset then sendEmail | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Use uniform forgot response and build reset link from configured absolute base URL, not Host header.

<a id="finding-18"></a>
### HIGH Password reset overwrites plaintext password without token invalidation or expiry
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-620 | confidence: 0.9
- Location: `routers/index.js:613-618`
- Vulnerable code (`routers/index.js`):
```javascript
let doc =  userSchema.findOneAndUpdate(filter, update, {
```
- Taint Flow:
  - **Source**: `path token + new password body`
  - **Path**:
    - `routers/index.js:595 req.params.token + req.body.password`
    - `routers/index.js:613 findOneAndUpdate`
  - **Sink**: `password overwrite with plaintext, token not burned`
- Evidence: let doc =  userSchema.findOneAndUpdate(filter, update, {
  - Validation: routers/index.js:606-618 verify() then findOneAndUpdate password with req.body.password plaintext and no Token delete; commented reset.delete shows no invalidation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:606-618 verify() then findOneAndUpdate password with req.body.password plaintext and no Token delete; commented reset.delete shows no invalidation | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Hash password with bcrypt, verify DB token + signature + expiry, then delete/burn Token after use.

<a id="finding-19"></a>
### HIGH Typeless password field disables casting and preserves operator injection
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-915 | confidence: 0.85
- Location: `models/user.js:11-19`
- Vulnerable code (`models/user.js`):
```javascript
password: {
```
- Taint Flow:
  - **Source**: `JSON body operator object`
  - **Path**:
    - `models/user.js:11 typeless password`
    - `routers/index.js:148 findOne`
  - **Sink**: `query casting bypass preserving operators`
- Evidence: password: {
  - Validation: models/user.js:11 password:{} with no String type disables casting; routers/index.js:148 findOne({username:req.body.username,password:req.body.password}) passes JSON operators via bodyParser.json
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: models/user.js:11 password:{} with no String type disables casting; routers/index.js:148 findOne({username:req.body.username,password:req.body.password}) passes JSON operators via bodyParser.json | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Type password as String, reject non-string/operator objects, and use strict query sanitization.

<a id="finding-20"></a>
### HIGH OAuth token exfiltration via wildcard postMessage
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.85
- Location: `public/redirect.html:31-31`
- Vulnerable code (`public/redirect.html`):
```html
window.opener.postMessage({"accesstoken": params.access_token}, "*");
```
- Taint Flow:
  - **Source**: `URL hash access_token`
  - **Path**:
    - `public/redirect.html:24 location.hash`
    - `public/redirect.html:31 postMessage`
  - **Sink**: `postMessage token to *`
- Evidence: window.opener.postMessage({"accesstoken": params.access_token}, "*");
  - Validation: public/redirect.html:24 parses location.hash access_token; public/redirect.html:31 window.opener.postMessage({accesstoken},"*") served via app.js:119 serve-static public
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: public/redirect.html:24 parses location.hash access_token; public/redirect.html:31 window.opener.postMessage({accesstoken},"*") served via app.js:119 serve-static public | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Replace "*" with explicit expected origin and validate opener; avoid forwarding raw OAuth token via postMessage.

<a id="finding-21"></a>
### MEDIUM CSRF protection defined but never enforced on state-changing routes
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `routers/index.js:33-33`
- Vulnerable code (`routers/index.js`):
```javascript
var csrfProtection = csrf({ cookie: true })
```
- Taint Flow:
  - **Source**: `cross-site forged request with cookies`
  - **Sink**: `state-changing POSTs without CSRF check`
- Evidence: var csrfProtection = csrf({ cookie: true })
  - Validation: routers/index.js:33 csrfProtection defined but never used as middleware; app.js has no csrf mount and forms use secrettoken random string never verified
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:33 csrfProtection defined but never used as middleware; app.js has no csrf mount and forms use secrettoken random string never verified | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Mount csrfProtection on state-changing POSTs and validate token; set SameSite/HttpOnly on Auth cookie.

<a id="finding-22"></a>
### MEDIUM Password-reset token rotation no-op leaves old token valid
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-620 | confidence: 0.9
- Location: `routers/index.js:539-539`
- Vulnerable code (`routers/index.js`):
```javascript
Token.updateOne({'token':resettoken},function(err,t1){
```
- Taint Flow:
  - **Source**: `second forgot request for same email`
  - **Path**:
    - `routers/index.js:526 Token.findOne existing token`
    - `routers/index.js:539 Token.updateOne no-op`
  - **Sink**: `token rotation silently skipped`
- Evidence: Token.updateOne({'token':resettoken},function(err,t1){
  - Validation: routers/index.js:539 Token.updateOne({'token':resettoken},function) passes no update document so rotation is no-op while new link emailed at routers/index.js:544-547
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:539 Token.updateOne({'token':resettoken},function) passes no update document so rotation is no-op while new link emailed at routers/index.js:544-547 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Pass update doc e.g. updateOne({email},{$set:{token:resettoken}}) or delete-then-insert; send only stored token.

<a id="finding-23"></a>
### MEDIUM Weak upload validation allows malicious file persistence in webroot
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-434 | confidence: 0.85
- Location: `app.js:61-66`
- Vulnerable code (`app.js`):
```javascript
if (!file.originalname.match(/\.(png|jpg)$/)) {
```
- Taint Flow:
  - **Source**: `multipart file name/content`
  - **Path**:
    - `app.js:60 file.originalname`
    - `app.js:47 filename + extname`
  - **Sink**: `disk write in webroot + static serve`
- Evidence: if (!file.originalname.match(/\.(png|jpg)$/)) {
  - Validation: app.js:47-66 filename fieldname+Date+extname with fileFilter only originalname.match(/\.(png|jpg)$/); app.js:74 app.use(imageUpload.single('file')) globally before auth saves file pre-gate
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:47-66 filename fieldname+Date+extname with fileFilter only originalname.match(/\.(png|jpg)$/); app.js:74 app.use(imageUpload.single('file')) globally before auth saves file pre-gate | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Validate content-type/magic bytes, randomize names, store outside webroot/no-exec and serve with safe Content-Type.

<a id="finding-24"></a>
### MEDIUM OAuth implicit flow with static state never validated enables login CSRF
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `routers/index.js:79-83`
- Vulnerable code (`routers/index.js`):
```javascript
router.post("/auth/callback", async (req, res) => {
  try {
    console.log(req.body)
    const { token } = req.body;
```
- Taint Flow:
  - **Source**: `attacker-influenced OAuth token / cross-site request to callback`
  - **Path**:
    - `views/login.pug:359 (static state OAuth URL)`
    - `public/redirect.html:11 hash parsing`
    - `routers/index.js:79 POST /auth/callback (no state check)`
    - `routers/index.js:97 JWT mint`
  - **Sink**: `session minted without OAuth CSRF validation`
- Evidence: views/login.pug:359 builds Google OAuth URL with response_type=token and state=random_state_string hardcoded; routers/index.js:79-83 POST /auth/callback reads only {token} from body and never validates state, nonce, or PKCE
  - Validation: views/login.pug:359 builds Google OAuth URL with hardcoded state=random_state_string; public/redirect.html ignores state; routers/index.js:79-83 POST /auth/callback reads only {token} and mints JWT at routers/index.js:97 with no state/nonce/PKCE check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: views/login.pug:359 builds Google OAuth URL with hardcoded state=random_state_string; public/redirect.html ignores state; routers/index.js:79-83 POST /auth/callback reads only {token} and mints JWT at routers/index.js:97 with no state/nonce/PKCE check | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Generate per-session crypto-random OAuth state/nonce, store in session, validate it in POST /auth/callback, and switch from implicit token flow to authorization-code + PKCE.

<a id="finding-25"></a>
### MEDIUM JWT verification without algorithm allowlist or expiry enables forgery
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-287 | confidence: 0.85
- Location: `routers/index.js:206-211`
- Vulnerable code (`routers/index.js`):
```javascript
jwt.verify(token, accessTokenSecret, (err,user) => {
```
- Taint Flow:
  - **Source**: `client-supplied Auth cookie`
  - **Path**:
    - `routers/index.js:200 req.cookies.Auth`
    - `routers/index.js:206 jwt.verify`
  - **Sink**: `authentication decision req.user= user; next()`
- Evidence: jwt.verify(token, accessTokenSecret, (err,user) => {
  - Validation: routers/index.js:206 jwt.verify(token,accessTokenSecret) with no algorithms/expiry options and routers/index.js:165 jwt.sign with no expiresIn creates indefinite tokens; forgery via known secret already covered but indefinite validity and alg-confusion hardening missing
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:206 jwt.verify(token,accessTokenSecret) with no algorithms/expiry options and routers/index.js:165 jwt.sign with no expiresIn creates indefinite tokens; forgery via known secret already covered but indefinite validity and alg-confusion hardening missing | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Call jwt.verify with algorithms:['HS256'] and maxAge, and sign with short expiresIn; reject alg none.

<a id="finding-26"></a>
### MEDIUM Href attribute injection via poisonable reset link
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.85
- Location: `utils/sendemail.js:212-212`
- Vulnerable code (`utils/sendemail.js`):
```javascript
<a href=${text} target="_blank" style="display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #ffffff; text-decoration: none; border-radius: 6px;">Do Something Sweet</a>
```
- Taint Flow:
  - **Source**: `Host header + reset token URL`
  - **Path**:
    - `routers/index.js:544 Host header`
    - `routers/index.js:546 reset link`
    - `utils/sendemail.js:212 href interpolation`
  - **Sink**: `unquoted href attribute injection`
- Evidence: <a href=${text} target="_blank" style="display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #ffffff; text-decoration: none; border-radius: 6px;">Do Something Sweet</a>
  - Validation: routers/index.js:542-546 link built from req.get('host') with no allowlist then utils/sendemail.js:212 interpolated unquoted href=${text} emailed to victim
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:542-546 link built from req.get('host') with no allowlist then utils/sendemail.js:212 interpolated unquoted href=${text} emailed to victim | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Build reset links from allowlisted base URL, quote/escape href attribute, and store-then-send same token.

<a id="finding-27"></a>
### MEDIUM Implicit global assignments enable cross-request state pollution and data leakage
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-362 | confidence: 0.8
- Location: `models/strict.js:5-6`
- Vulnerable code (`models/strict.js`):
```javascript
email = req.body.email;
```
- Taint Flow:
  - **Source**: `attacker-controlled request bodies/files on concurrent requests`
  - **Path**:
    - `models/strict.js:5 email = req.body.email (global write)`
    - `routers/index.js:314 email = req.email (global read/write)`
    - `routers/index.js:500 email1 = req.body.email (global write)`
    - `routers/index.js:438 file = req.file.filename (global write)`
  - **Sink**: `cross-request use of poisoned globals in DB queries and post creation`
- Evidence: models/strict.js:5 assigns email without declaration; models/strict.js:9 assigns regex without declaration; routers/index.js:314-315,500-501,438,453-454,530 assign email/email1/file/title/description/token without var/let/const, creating Node globals shared across concurrent requests
  - Validation: models/strict.js:5 email=req.body.email and models/strict.js:9 regex= without declaration; routers/index.js:314 email=req.email, routers/index.js:500 email1=req.body.email, routers/index.js:438 file=req.file.filename, routers/index.js:453-454 title=/description= create Node globals shared across requests with async DB gaps (e.g. sendEmail(email1) at routers/index.js:548 inside callback)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: models/strict.js:5 email=req.body.email and models/strict.js:9 regex= without declaration; routers/index.js:314 email=req.email, routers/index.js:500 email1=req.body.email, routers/index.js:438 file=req.file.filename, routers/index.js:453-454 title=/description= create Node globals shared across requests with async DB gaps (e.g. sendEmail(email1) at routers/index.js:548 inside callback) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Declare all request-scoped values with const/let (email, regex, email1, file, title, description, token) in models/strict.js and routers/index.js and enable strict mode to prevent implicit globals.

<a id="finding-28"></a>
### MEDIUM Unrestricted CORS allows cross-origin reads of sensitive data
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-942 | confidence: 0.8
- Location: `routers/index.js:46-46`
- Vulnerable code (`routers/index.js`):
```javascript
router.use(cors())
```
- Taint Flow:
  - **Source**: `server middleware config`
  - **Sink**: `CORS wildcard on all router responses`
- Evidence: router.use(cors())
  - Validation: routers/index.js:46 router.use(cors()) defaults to ACAO *; routers/index.js:259 res.json(result) dumps full user doc on unauthenticated endpoint readable cross-origin
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:46 router.use(cors()) defaults to ACAO *; routers/index.js:259 res.json(result) dumps full user doc on unauthenticated endpoint readable cross-origin | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Restrict CORS to explicit allowlisted origins and disable for sensitive routes; do not use default wildcard.

<a id="finding-29"></a>
### LOW Auth cookie in OAuth callback lacks HttpOnly/Secure/SameSite
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.95
- Location: `routers/index.js:99-99`
- Vulnerable code (`routers/index.js`):
```javascript
res.cookie("Auth",accessToken)
```
- Taint Flow:
  - **Source**: `server-minted JWT`
  - **Sink**: `res.cookie Auth without flags`
- Evidence: res.cookie("Auth",accessToken)
  - Validation: routers/index.js:99 res.cookie("Auth",accessToken) sets JWT with no httpOnly/secure/sameSite/maxAge; no httpOnly flag anywhere in routers/index.js or app.js
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:99 res.cookie("Auth",accessToken) sets JWT with no httpOnly/secure/sameSite/maxAge; no httpOnly flag anywhere in routers/index.js or app.js | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Set res.cookie Auth with httpOnly:true, secure:true, sameSite:'strict' and short maxAge aligned with JWT expiry.

<a id="finding-30"></a>
### LOW Password-reset mailer references undefined res causing crash on success
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-248 | confidence: 0.95
- Location: `utils/sendemail.js:294-299`
- Vulnerable code (`utils/sendemail.js`):
```javascript
mailTransporter.sendMail(mailDetails, function(err, data) {
    if(err) {
        console.log('Error Occurs');
    } else {
        res.render('forgot',{forgotmsg:" Reset Mail Sent to " + email})
```
- Taint Flow:
  - **Source**: `unauthenticated forgot-password email body`
  - **Path**:
    - `routers/index.js:499 POST /secret/forgot (email input)`
    - `routers/index.js:547 sendEmail(email1,...)`
    - `utils/sendemail.js:298 res.render with undefined res`
  - **Sink**: `ReferenceError / uncaught exception on email success`
- Evidence: utils/sendemail.js:5 defines sendEmail(email,subject,text,username) with no res param, but utils/sendemail.js:298 calls res.render in sendMail success callback; caller routers/index.js:547 invokes sendEmail without res and already renders at routers/index.js:553
  - Validation: utils/sendemail.js:5 defines sendEmail(email,subject,text,username) with no res param but utils/sendemail.js:298 calls res.render in sendMail success callback (ReferenceError on success); caller routers/index.js:548 calls sendEmail without res and already renders at routers/index.js:553
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: utils/sendemail.js:5 defines sendEmail(email,subject,text,username) with no res param but utils/sendemail.js:298 calls res.render in sendMail success callback (ReferenceError on success); caller routers/index.js:548 calls sendEmail without res and already renders at routers/index.js:553 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove res.render from utils/sendemail.js:298 callback (return status/log only) and let caller routers/index.js:553 render once; handle err/success via promise return.

<a id="finding-31"></a>
### LOW Hardcoded express-session secret with insecure cookie defaults
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-798 | confidence: 0.9
- Location: `app.js:92-92`
- Vulnerable code (`app.js`):
```javascript
secret: 'Your_Secret_Key',
```
- Taint Flow:
  - **Source**: `hardcoded literal`
  - **Sink**: `express-session cookie signing`
- Evidence: secret: 'Your_Secret_Key',
  - Validation: app.js:92 hardcodes express-session secret 'Your_Secret_Key'; no session-based authz relies on it (routers/index.js:55,100 show req.session use commented out), so forgery impact is limited
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:92 hardcodes express-session secret 'Your_Secret_Key'; no session-based authz relies on it (routers/index.js:55,100 show req.session use commented out), so forgery impact is limited | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Load session secret from env with strong random value and set secure/httpOnly/sameSite cookie options.

<a id="finding-32"></a>
### LOW Session JWT written to server logs in profile handler
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.9
- Location: `routers/index.js:54-54`
- Vulnerable code (`routers/index.js`):
```javascript
console.log(req.cookies.Auth);
```
- Taint Flow:
  - **Source**: `client-supplied Auth cookie`
  - **Path**:
    - `routers/index.js:52 req.cookies.Auth`
    - `routers/index.js:54 console.log`
  - **Sink**: `sensitive JWT written to logs`
- Evidence: console.log(req.cookies.Auth);
  - Validation: routers/index.js:54 console.log(req.cookies.Auth) logs full JWT bearer on active GET /secret/profile
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:54 console.log(req.cookies.Auth) logs full JWT bearer on active GET /secret/profile | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove console.log of Auth cookie; replace with structured logger that redacts Authorization/cookies.

<a id="finding-33"></a>
### LOW Plaintext login password written to logs
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.9
- Location: `routers/index.js:138-138`
- Vulnerable code (`routers/index.js`):
```javascript
console.log(data)
```
- Taint Flow:
  - **Source**: `login POST body credentials`
  - **Path**:
    - `routers/index.js:118 req.body.username/password`
    - `routers/index.js:138 console.log(data)`
  - **Sink**: `plaintext password to logs`
- Evidence: console.log(data)
  - Validation: routers/index.js:118-138 data built from req.body.username/password then routers/index.js:138 console.log(data) writes plaintext password to logs
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:118-138 data built from req.body.username/password then routers/index.js:138 console.log(data) writes plaintext password to logs | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove console.log(data) containing password; never log credentials.

<a id="finding-34"></a>
### LOW Minted session JWT logged after login
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.9
- Location: `routers/index.js:166-166`
- Vulnerable code (`routers/index.js`):
```javascript
console.log(accessToken)
```
- Taint Flow:
  - **Source**: `server-minted Auth token`
  - **Path**:
    - `routers/index.js:165 jwt.sign session token`
    - `routers/index.js:166 console.log`
  - **Sink**: `session JWT to logs`
- Evidence: console.log(accessToken)
  - Validation: routers/index.js:165 jwt.sign session then routers/index.js:166 console.log(accessToken) writes mintable Auth JWT to logs
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:165 jwt.sign session then routers/index.js:166 console.log(accessToken) writes mintable Auth JWT to logs | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove console.log(accessToken); never log session JWTs.

<a id="finding-35"></a>
### LOW Login Auth cookie lacks HttpOnly/Secure/SameSite and has no expiry
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `routers/index.js:168-168`
- Vulnerable code (`routers/index.js`):
```javascript
res.cookie("Auth",accessToken)
```
- Taint Flow:
  - **Source**: `server-minted login JWT`
  - **Sink**: `res.cookie Auth without flags, indefinite JWT`
- Evidence: res.cookie("Auth",accessToken)
  - Validation: routers/index.js:165 jwt.sign without expiresIn and routers/index.js:168 res.cookie("Auth",accessToken) with no httpOnly/secure/sameSite flags
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:165 jwt.sign without expiresIn and routers/index.js:168 res.cookie("Auth",accessToken) with no httpOnly/secure/sameSite flags | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Add short expiresIn to jwt.sign and set Auth cookie with httpOnly/secure/sameSite/maxAge.

<a id="finding-36"></a>
### LOW Null dereference and global pollution on missing upload file
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-476 | confidence: 0.9
- Location: `routers/index.js:438-438`
- Vulnerable code (`routers/index.js`):
```javascript
file = req.file.filename;
```
- Taint Flow:
  - **Source**: `authenticated multipart request without valid file`
  - **Path**:
    - `routers/index.js:434 multipart file input`
    - `routers/index.js:438 req.file.filename`
  - **Sink**: `null dereference + global pollution`
- Evidence: file = req.file.filename;
  - Validation: routers/index.js:438 file=req.file.filename dereferences possibly-undefined req.file with implicit global and no guard
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:438 file=req.file.filename dereferences possibly-undefined req.file with implicit global and no guard | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Guard missing/rejected file: if(!req.file) return 400; declare with const/let.

<a id="finding-37"></a>
### LOW Unchecked email dereference DoS in forgot handler
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-252 | confidence: 0.9
- Location: `routers/index.js:501-501`
- Vulnerable code (`routers/index.js`):
```javascript
email =email1.toLowerCase();
```
- Taint Flow:
  - **Source**: `forgot POST email parameter`
  - **Path**:
    - `routers/index.js:499 req.body.email`
    - `routers/index.js:501 toLowerCase`
  - **Sink**: `TypeError crash + global assignment`
- Evidence: email =email1.toLowerCase();
  - Validation: routers/index.js:499-501 email1=req.body.email then email1.toLowerCase() with no missing/object check and implicit global
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:499-501 email1=req.body.email then email1.toLowerCase() with no missing/object check and implicit global | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Validate typeof email1==='string' before toLowerCase; declare with const/let and return 400 on missing/invalid.

<a id="finding-38"></a>
### LOW OAuth bearer token logged in auth callback
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.85
- Location: `routers/index.js:82-82`
- Vulnerable code (`routers/index.js`):
```javascript
console.log(req.body)
```
- Taint Flow:
  - **Source**: `unauthenticated POST body {token}`
  - **Path**:
    - `routers/index.js:79 req.body.token`
    - `routers/index.js:82 console.log(req.body)`
  - **Sink**: `OAuth bearer written to logs`
- Evidence: console.log(req.body)
  - Validation: routers/index.js:79 req.body.token holds Google OAuth bearer then routers/index.js:82 console.log(req.body) writes it to server logs
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:79 req.body.token holds Google OAuth bearer then routers/index.js:82 console.log(req.body) writes it to server logs | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove console.log of request body/token; log only non-sensitive metadata with redaction.

<a id="finding-39"></a>
### LOW Logout clears cookie but does not invalidate JWT/server session
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-613 | confidence: 0.85
- Location: `routers/index.js:487-489`
- Vulnerable code (`routers/index.js`):
```javascript
router.get('/secret/logout',(req, res) => {
  res.clearCookie('Auth');
```
- Taint Flow:
  - **Source**: `authenticated user logout request`
  - **Path**:
    - `routers/index.js:165 JWT minted on login`
    - `routers/index.js:488 logout clears cookie only`
    - `routers/index.js:206 jwt.verify still accepts old token`
  - **Sink**: `session remains valid after logout`
- Evidence: routers/index.js:487 defines GET /secret/logout without authenticateToken; handler at routers/index.js:488 only does res.clearCookie('Auth') with no req.session.destroy and no JWT revocation/denylist, while authenticateToken at routers/index.js:199-211 accepts any valid JWT signed with hardcoded secret
  - Validation: routers/index.js:487-489 GET /secret/logout only does res.clearCookie('Auth') with no denylist/expiry; tokens minted at routers/index.js:165 and routers/index.js:523 have no exp, and routers/index.js:199-211 verify still accepts old JWT
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:487-489 GET /secret/logout only does res.clearCookie('Auth') with no denylist/expiry; tokens minted at routers/index.js:165 and routers/index.js:523 have no exp, and routers/index.js:199-211 verify still accepts old JWT | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Issue short-lived JWTs with exp, set HttpOnly/SameSite cookies, and add server-side revocation/denylist checked in authenticateToken and cleared on logout.

<a id="finding-40"></a>
### LOW Password-reset first request never sends email (inverted Token branch)
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-640 | confidence: 0.85
- Location: `routers/index.js:529-534`
- Vulnerable code (`routers/index.js`):
```javascript
if(reset == null) {
```
- Taint Flow:
  - **Source**: `unauthenticated email input`
  - **Path**:
    - `routers/index.js:499 POST /secret/forgot entry`
    - `routers/index.js:529 Token.findOne branch`
    - `routers/index.js:548 sendEmail (only in else)`
  - **Sink**: `password-reset email delivery skipped on first request`
- Evidence: routers/index.js:529 if(reset==null) only saves Token and never calls sendEmail; routers/index.js:537 else branch is the only place sendEmail is called; routers/index.js:553 still renders 'Reset Mail Sent' in both cases
  - Validation: routers/index.js:529 if(reset==null) only saves Token and never calls sendEmail; routers/index.js:537-548 else is the only sendEmail site; routers/index.js:553 renders 'Reset Mail Sent' in both branches
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routers/index.js:529 if(reset==null) only saves Token and never calls sendEmail; routers/index.js:537-548 else is the only sendEmail site; routers/index.js:553 renders 'Reset Mail Sent' in both branches | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Send reset email in both Token branches (create and update) at routers/index.js:529-548, fix Token.updateOne filter to match by email/username, and only render success after mail queued.
