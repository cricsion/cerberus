# Cerberus Report

**Findings:** 47 actionable — 5 critical, 23 high, 12 medium, 7 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 14 false positives and 1 duplicate — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 5 | 0 / 5 (0%) | 5 |
| HIGH | 23 | 0 / 23 (0%) | 23 |
| MEDIUM | 12 | 0 / 12 (0%) | 12 |
| LOW | 7 | 0 / 7 (0%) | 7 |
| **TOTAL** | **47** | **0 / 47 (0%)** | **47** |

## Table of Contents

- [Confirmed (47)](#confirmed)
  - [CRITICAL: OS Command Injection in create via identify URL (`routes/index.js:161`)](#finding-1)
  - [CRITICAL: Cross-Unit Authentication Bypass to Template Takeover via Session (NoSQLi to HBS Layout Control) (`routes/index.js:107`)](#finding-2)
  - [CRITICAL: Cross-Unit Prototype-Pollution Authentication Bypass (PUT /chat to isLoggedIn via Object.prototype.loggedIn) (`routes/index.js:115`)](#finding-3)
  - [CRITICAL: Missing Authorization in import allows anonymous file upload (`routes/index.js:241`)](#finding-4)
  - [CRITICAL: Dust Template Injection via device in about_new (`routes/index.js:300`)](#finding-5)
  - [HIGH: Hardcoded Session Secret keyboard cat (`app.js:43`)](#finding-6)
  - [HIGH: Missing Authentication on /users API Allows Unauthenticated Admin Creation and Enumeration (`app.js:69`)](#finding-7)
  - [HIGH: Plaintext Password Storage in Mongoose User Schema (`mongoose-db.js:14`)](#finding-8)
  - [HIGH: NoSQL Operator Injection in loginHandler password (`routes/index.js:39`)](#finding-9)
  - [HIGH: Open Redirect in adminLoginSuccess via redirectPage (`routes/index.js:61`)](#finding-10)
  - [HIGH: Hardcoded Chat Credential Enables Authenticated Prototype-Pollution Entry (`routes/index.js:315`)](#finding-11)
  - [HIGH: Hardcoded MySQL root Credentials (`typeorm-db.js:12`)](#finding-12)
  - [HIGH: Missing Authorization and IDOR on Todo lifecycle routes (create/destroy/edit/update/import) (`app.js:61`)](#finding-13)
  - [HIGH: MongoDB Connection String Disclosure in Logs (`mongoose-db.js:43`)](#finding-14)
  - [HIGH: User Password Disclosure via console.log(users) (`mongoose-db.js:49`)](#finding-15)
  - [HIGH: Hardcoded Plaintext Mongo Admin Password (`mongoose-db.js:52`)](#finding-16)
  - [HIGH: Server-Side Request Forgery via ImageMagick identify URL fetch in POST /create (`routes/index.js:161`)](#finding-17)
  - [HIGH: Missing Authorization in destroy allows arbitrary deletion (`routes/index.js:191`)](#finding-18)
  - [HIGH: Missing Authorization in update allows arbitrary overwrite (`routes/index.js:221`)](#finding-19)
  - [HIGH: Zip-Slip Arbitrary File Overwrite in import (`routes/index.js:257`)](#finding-20)
  - [HIGH: Prototype Pollution in chat.add via lodash merge (`routes/index.js:347`)](#finding-21)
  - [HIGH: Unauthenticated User Enumeration in GET /users (`routes/users.js:16`)](#finding-22)
  - [HIGH: Mass Assignment Role Escalation in POST /users (`routes/users.js:36`)](#finding-23)
  - [HIGH: Reflected XSS via redirectPage in admin.ejs (`views/admin.ejs:17`)](#finding-24)
  - [HIGH: Template Layout Control via save_account_details (`routes/index.js:107`)](#finding-25)
  - [HIGH: Missing Authorization in edit exposes all todos (`routes/index.js:203`)](#finding-26)
  - [HIGH: Cross-Unit Prototype-Pollution Privilege Escalation (PUT /chat to DELETE /chat and /users Query Hijack) (`routes/index.js:359`)](#finding-27)
  - [HIGH: Stored XSS via Todo content in index.ejs (`views/index.ejs:20`)](#finding-28)
  - [MEDIUM: Missing Authentication on GET /chat Exposes In-Memory Chat History (`app.js:66`)](#finding-29)
  - [MEDIUM: Unbounded File Upload Size in express-fileupload (`app.js:49`)](#finding-30)
  - [MEDIUM: CSRF via State-Changing GET /destroy/:id route (`app.js:61`)](#finding-31)
  - [MEDIUM: Cloud Environment Disclosure in Logs (`mongoose-db.js:21`)](#finding-32)
  - [MEDIUM: Missing Authorization in create allows anonymous todo creation (`routes/index.js:152`)](#finding-33)
  - [MEDIUM: Unbounded Zip Decompression in import enables zip-bomb DoS (`routes/index.js:255`)](#finding-34)
  - [MEDIUM: Unauthenticated Chat History Disclosure in chat.get (`routes/index.js:332`)](#finding-35)
  - [MEDIUM: Missing CSRF, Security Headers, Rate Limiting and Hardened Cookies (`app.js:42`)](#finding-36)
  - [MEDIUM: Session Fixation in adminLoginSuccess missing regeneration (`routes/index.js:55`)](#finding-37)
  - [MEDIUM: Null-Dereference DoS in update missing existence check (`routes/index.js:219`)](#finding-38)
  - [MEDIUM: Attacker-Controlled Moment Locale in import (`routes/index.js:279`)](#finding-39)
  - [MEDIUM: Insecure HTTP Script Include in layout.ejs (`views/layout.ejs:7`)](#finding-40)
  - [LOW: Insecure Session Cookie Flags (`app.js:45`)](#finding-41)
  - [LOW: Hardcoded SECRET_TOKEN Logged to Console (`app.js:83`)](#finding-42)
  - [LOW: Stored XSS via import CSV content persistence (`routes/index.js:285`)](#finding-43)
  - [LOW: Verbose Error Disclosure via development errorHandler (`app.js:80`)](#finding-44)
  - [LOW: Weak Random Admin Password in chat users (`routes/index.js:317`)](#finding-45)
  - [LOW: Log Injection via Unsanitized CSV Field in POST /import (`routes/index.js:271`)](#finding-46)
  - [LOW: Verbose SQL Logging Leaks PII in TypeORM (`typeorm-db.js:15`)](#finding-47)

<a id="confirmed"></a>
## Confirmed (47)

<a id="finding-1"></a>
### CRITICAL OS Command Injection in create via identify URL
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.95
- Location: `routes/index.js:161-161`
- Vulnerable code (`routes/index.js`):
```javascript
exec('identify ' + url, function (err, stdout, stderr) {
```
- Taint Flow:
  - **Source**: `req.body.content POST /create`
  - **Path**:
    - `routes/index.js:155 req.body.content`
    - `routes/index.js:161 exec sink`
  - **Sink**: `child_process.exec shell string`
- Evidence: exec('identify ' + url, function (err, stdout, stderr) {
  - Validation: routes/index.js:161 exec('identify '+url) with url derived at routes/index.js:155-157 from req.body.content; reachable unauth via app.js:60 POST /create with no sanitization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:161 exec('identify '+url) with url derived at routes/index.js:155-157 from req.body.content; reachable unauth via app.js:60 POST /create with no sanitization | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace exec shell string with execFile('identify',[url]) and validate url against http(s) allowlist; reject shell metachars.

<a id="finding-2"></a>
### CRITICAL Cross-Unit Authentication Bypass to Template Takeover via Session (NoSQLi to HBS Layout Control)
- CVSS: **8.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.85
- Location: `routes/index.js:107-107`
- Vulnerable code (`routes/index.js`):
```javascript
return res.render('account.hbs', profile)
```
- Taint Flow:
  - **Source**: `POST /login username/password JSON operators`
  - **Path**:
    - `routes/index.js:39 User.find({username,password})`
    - `routes/index.js:55 session.loggedIn=1`
    - `routes/index.js:116 isLoggedIn gate`
    - `routes/index.js:89 profile=req.body with extra layout`
  - **Sink**: `res.render('account.hbs', profile) layout-controlled template render`
- Evidence: routes/index.js:39 User.find with attacker JSON operators bypasses password check, routes/index.js:55 sets session.loggedIn=1 on any non-empty result, routes/index.js:116 isLoggedIn gates only on that flag, routes/index.js:89-107 passes full req.body including extra layout key to res.render account.hbs
  - Validation: routes/index.js:39 User.find password unsanitized + routes/index.js:55 session.loggedIn=1 + routes/index.js:116 isLoggedIn + routes/index.js:89-107 profile=req.body layout to res.render account.hbs via app.js:55/58
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:39 User.find password unsanitized + routes/index.js:55 session.loggedIn=1 + routes/index.js:116 isLoggedIn + routes/index.js:89-107 profile=req.body layout to res.render account.hbs via app.js:55/58 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Cast/validate username/password to strings with parameterized query, set session only on verified password, allowlist render locals and block layout override

<a id="finding-3"></a>
### CRITICAL Cross-Unit Prototype-Pollution Authentication Bypass (PUT /chat to isLoggedIn via Object.prototype.loggedIn)
- CVSS: **8.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.85
- Location: `routes/index.js:115-117`
- Vulnerable code (`routes/index.js`):
```javascript
if (req.session.loggedIn === 1) {
```
- Taint Flow:
  - **Source**: `PUT /chat JSON message.__proto__.loggedIn`
  - **Path**:
    - `app.js:67 PUT /chat -> routes/index.js:335 req.body.message`
    - `routes/index.js:347 _.merge(message, req.body.message) -> Object.prototype.loggedIn`
    - `routes/index.js:116 req.session.loggedIn lookup -> app.js:56-58 /admin,/account_details`
  - **Sink**: `isLoggedIn authorization check (req.session.loggedIn===1)`
- Evidence: PUT /chat _.merge pollutes Object.prototype (routes/index.js:347) with attacker key loggedIn; isLoggedIn at routes/index.js:115-116 reads req.session.loggedIn via prototype chain; guarded routes at app.js:56-58; entry auth uses known user:pwd at routes/index.js:313-317
  - Validation: PUT /chat unauth reachable at app.js:67 with known user:pwd at routes/index.js:308-312; _.merge(message, req.body.message) at routes/index.js:347 with lodash 4.17.4 (package.json:32) allows __proto__.loggedIn pollution; isLoggedIn checks req.session.loggedIn===1 at routes/index.js:115-116 inheriting polluted Object.prototype, guarding /admin and /account_details at app.js:56-58
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: PUT /chat unauth reachable at app.js:67 with known user:pwd at routes/index.js:308-312; _.merge(message, req.body.message) at routes/index.js:347 with lodash 4.17.4 (package.json:32) allows __proto__.loggedIn pollution; isLoggedIn checks req.session.loggedIn===1 at routes/index.js:115-116 inheriting polluted Object.prototype, guarding /admin and /account_details at app.js:56-58 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Upgrade lodash past 4.17.5, replace _.merge of req.body.message with allowlisted assignment, and make isLoggedIn check own-property (Object.hasOwn) with falsy default.

<a id="finding-4"></a>
### CRITICAL Missing Authorization in import allows anonymous file upload
- CVSS: **8.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.85
- Location: `routes/index.js:241-241`
- Vulnerable code (`routes/index.js`):
```javascript
exports.import = function (req, res, next) {
```
- Taint Flow:
  - **Source**: `unauthenticated multipart upload`
  - **Path**:
    - `app.js:64 POST /import`
    - `routes/index.js:241 import handler`
  - **Sink**: `AdmZip extract + Todo.save`
- Evidence: exports.import = function (req, res, next) {
  - Validation: routes/index.js:303-304 device=req.query.device flows to res.render about_new.dust at routes/index.js:300; views/about_new.dust:5 interpolates device inside @if cond evaluated as JS (see exploits/dustjs-exploits.sh RCE)
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: routes/index.js:303-304 device=req.query.device flows to res.render about_new.dust at routes/index.js:300; views/about_new.dust:5 interpolates device inside @if cond evaluated as JS (see exploits/dustjs-exploits.sh RCE) | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Stop evaluating user input as Dust code; remove device from cond eval and treat as plain string context.

<a id="finding-5"></a>
### CRITICAL Dust Template Injection via device in about_new
- CVSS: **8.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.85
- Location: `routes/index.js:300-300`
- Vulnerable code (`routes/index.js`):
```javascript
return res.render("about_new.dust",
```
- Taint Flow:
  - **Source**: `req.query.device GET /about_new`
  - **Path**:
    - `routes/index.js:304 req.query.device`
    - `routes/index.js:300 dust render`
  - **Sink**: `dust render with attacker value`
- Evidence: return res.render("about_new.dust",
  - Validation: routes/index.js:303-304 device=req.query.device flows to res.render about_new.dust at routes/index.js:300; views/about_new.dust:5 interpolates device inside @if cond evaluated as JS (see exploits/dustjs-exploits.sh RCE)
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: routes/index.js:303-304 device=req.query.device flows to res.render about_new.dust at routes/index.js:300; views/about_new.dust:5 interpolates device inside @if cond evaluated as JS (see exploits/dustjs-exploits.sh RCE) | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Stop evaluating user input as Dust code; remove device from cond eval and treat as plain string context.

<a id="finding-6"></a>
### HIGH Hardcoded Session Secret keyboard cat
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `app.js:43-43`
- Vulnerable code (`app.js`):
```javascript
secret: 'keyboard cat',
```
- Taint Flow:
  - **Source**: `source literal`
  - **Sink**: `session secret hardcoded`
- Evidence: secret: 'keyboard cat',
  - Validation: app.js:43 session secret hardcoded to 'keyboard cat' with no env override; active for all routes via app.js:42-46 session middleware
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:43 session secret hardcoded to 'keyboard cat' with no env override; active for all routes via app.js:42-46 session middleware | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Load session secret from env/vault, rotate, require strong random value and fail closed if unset.

<a id="finding-7"></a>
### HIGH Missing Authentication on /users API Allows Unauthenticated Admin Creation and Enumeration
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `app.js:69-69`
- Vulnerable code (`app.js`):
```javascript
app.use('/users', routesUsers)
```
- Taint Flow:
  - **Source**: `unauthenticated network JSON to GET/POST /users`
  - **Path**:
    - `app.js:69 unauthenticated mount`
    - `routes/users.js:23 req.body.name/address/role`
    - `routes/users.js:16 repo.find({id:1}) disclosure`
  - **Sink**: `TypeORM repo.save / repo.find on MySQL Users without auth`
- Evidence: app.js:69 mounts /users router with no auth middleware, while sibling routes app.js:56-58 require routes.isLoggedIn; routes/users.js:8 GET returns repo.find({id:1}) and routes/users.js:23 POST does repo.save(user with attacker role) with comment admitting auth not implemented
  - Validation: app.js:69 mounts /users with no isLoggedIn vs app.js:56-58 guards; routes/users.js:8 GET repo.find and routes/users.js:25-33 POST repo.save(role) unauthenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:69 mounts /users with no isLoggedIn vs app.js:56-58 guards; routes/users.js:8 GET repo.find and routes/users.js:25-33 POST repo.save(role) unauthenticated | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require isLoggedIn/session auth on /users router and enforce server-side role allowlist

<a id="finding-8"></a>
### HIGH Plaintext Password Storage in Mongoose User Schema
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `mongoose-db.js:14-14`
- Vulnerable code (`mongoose-db.js`):
```javascript
password: String,
```
- Taint Flow:
  - **Source**: `hardcoded schema without hashing`
  - **Sink**: `plaintext password persistence`
- Evidence: password: String,
  - Validation: mongoose-db.js:12-14 User schema password:String with no hash; mongoose-db.js:52 seeds SuperSecretPassword plaintext and routes/index.js:42 queries plaintext
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: mongoose-db.js:12-14 User schema password:String with no hash; mongoose-db.js:52 seeds SuperSecretPassword plaintext and routes/index.js:42 queries plaintext | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Hash passwords with bcrypt/scrypt on save and compare hashes on login.

<a id="finding-9"></a>
### HIGH NoSQL Operator Injection in loginHandler password
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `routes/index.js:39-39`
- Vulnerable code (`routes/index.js`):
```javascript
User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
```
- Taint Flow:
  - **Source**: `req.body.password`
  - **Path**:
    - `routes/index.js:39`
  - **Sink**: `User.find NoSQL query`
- Evidence: User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
  - Validation: routes/index.js:39 User.find takes req.body.password object as query operator; gate at routes/index.js:38 only checks username isEmail, password unsanitized; reachable unauth via app.js:55 POST /login
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: routes/index.js:39 User.find takes req.body.password object as query operator; gate at routes/index.js:38 only checks username isEmail, password unsanitized; reachable unauth via app.js:55 POST /login | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Reject non-string username/password (typeof check), strip $/dot keys or use $eq, and enforce allowlisted query construction.

<a id="finding-10"></a>
### HIGH Open Redirect in adminLoginSuccess via redirectPage
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `routes/index.js:61-61`
- Vulnerable code (`routes/index.js`):
```javascript
User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
```
- Taint Flow:
  - **Source**: `req.body.redirectPage POST /login`
  - **Path**:
    - `routes/index.js:41 req.body.redirectPage`
    - `routes/index.js:61 res.redirect sink`
  - **Sink**: `res.redirect(redirectPage)`
- Evidence: return res.redirect(redirectPage)
  - Validation: routes/index.js:39 User.find takes req.body.password object as query operator; gate at routes/index.js:38 only checks username isEmail, password unsanitized; reachable unauth via app.js:55 POST /login
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: routes/index.js:39 User.find takes req.body.password object as query operator; gate at routes/index.js:38 only checks username isEmail, password unsanitized; reachable unauth via app.js:55 POST /login | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Reject non-string username/password (typeof check), strip $/dot keys or use $eq, and enforce allowlisted query construction.

<a id="finding-11"></a>
### HIGH Hardcoded Chat Credential Enables Authenticated Prototype-Pollution Entry
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `routes/index.js:315-315`
- Vulnerable code (`routes/index.js`):
```javascript
{ name: 'user', password: *** },
```
- Taint Flow:
  - **Source**: `hardcoded credential committed in source`
  - **Path**:
    - `routes/index.js:315 hardcoded credential definition`
    - `app.js:67 PUT /chat without session guard`
    - `routes/index.js:335 findUser(req.body.auth) check`
  - **Sink**: `authenticated PUT /chat access via known credential`
- Evidence: routes/index.js:315 defines default chat credential password=*** with comment that password is known; PUT /chat at routes/index.js:335 authenticates via findUser against this value, app.js:67 exposes PUT /chat without session guard
  - Validation: routes/index.js:315 hardcodes {name:user,password:pwd}; app.js:67 PUT/chat with no session guard authenticates via findUser at routes/index.js:323-327
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:315 hardcodes {name:user,password:pwd}; app.js:67 PUT/chat with no session guard authenticates via findUser at routes/index.js:323-327 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded chat passwords; require per-user secrets from env/vault and random admin password

<a id="finding-12"></a>
### HIGH Hardcoded MySQL root Credentials
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `typeorm-db.js:12-12`
- Vulnerable code (`typeorm-db.js`):
```javascript
password: "root",
```
- Taint Flow:
  - **Source**: `source literal root`
  - **Sink**: `DB credential hardcoded`
- Evidence: password: "root",
  - Validation: typeorm-db.js:12 password hardcoded to "root" (username root per typeorm-db.js:11, db acme per typeorm-db.js:13); connection active on require via app.js:27
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: typeorm-db.js:12 password hardcoded to "root" (username root per typeorm-db.js:11, db acme per typeorm-db.js:13); connection active on require via app.js:27 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Move DB username/password/host to env/vault, rotate root/root, do not commit credentials.

<a id="finding-13"></a>
### HIGH Missing Authorization and IDOR on Todo lifecycle routes (create/destroy/edit/update/import)
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.9
- Location: `app.js:61-61`
- Vulnerable code (`app.js`):
```javascript
app.get('/destroy/:id', routes.destroy);
```
- Taint Flow:
  - **Source**: `unauthenticated URL path :id plus publicly disclosed ObjectIDs`
  - **Path**:
    - `app.js:53 GET / renders todo._id links (views/index.ejs)`
    - `app.js:61 GET /destroy/:id req.params.id`
    - `routes/index.js:191 Todo.findById(req.params.id)->todo.remove`
  - **Sink**: `Todo.remove/save on arbitrary ID without ownership check`
- Evidence: app.js:60 POST /create, app.js:61 GET /destroy/:id, app.js:62 GET /edit/:id, app.js:63 POST /update/:id, app.js:64 POST /import have no isLoggedIn guard unlike app.js:56-58; handlers use req.params.id directly in Todo.findById/remove/save (routes/index.js:191,203,219) with no ownership check; IDs are publicly leaked at GET / via views/index.ejs edit/destroy links
  - Validation: app.js:60-64 POST/create destroy/edit/update/import lack isLoggedIn vs app.js:56 guard; routes/index.js:191 remove and routes/index.js:215-219 save use req.params.id with no owner check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:60-64 POST/create destroy/edit/update/import lack isLoggedIn vs app.js:56 guard; routes/index.js:191 remove and routes/index.js:215-219 save use req.params.id with no owner check | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add isLoggedIn plus Todo ownership check on create/destroy/edit/update/import and use non-guessable IDs

<a id="finding-14"></a>
### HIGH MongoDB Connection String Disclosure in Logs
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-532 | confidence: 0.9
- Location: `mongoose-db.js:43-43`
- Vulnerable code (`mongoose-db.js`):
```javascript
console.log("Using Mongo URI " + mongoUri);
```
- Taint Flow:
  - **Source**: `MONGOLAB_URI/MONGODB_URI secret`
  - **Path**:
    - `mongoose-db.js:35 env URI`
    - `mongoose-db.js:43 console.log`
  - **Sink**: `credential disclosure in logs`
- Evidence: console.log("Using Mongo URI " + mongoUri);
  - Validation: mongoose-db.js:35-43 mongoUri from MONGOLAB_URI/MONGODB_URI logged verbatim via console.log Using Mongo URI at line 43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: mongoose-db.js:35-43 mongoUri from MONGOLAB_URI/MONGODB_URI logged verbatim via console.log Using Mongo URI at line 43 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove credential-bearing URI from logs; log redacted host/db only.

<a id="finding-15"></a>
### HIGH User Password Disclosure via console.log(users)
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-532 | confidence: 0.9
- Location: `mongoose-db.js:49-49`
- Vulnerable code (`mongoose-db.js`):
```javascript
console.log(users);
```
- Taint Flow:
  - **Source**: `Mongo User records`
  - **Path**:
    - `mongoose-db.js:48 User.find`
    - `mongoose-db.js:49 console.log`
  - **Sink**: `plaintext passwords in logs`
- Evidence: console.log(users);
  - Validation: mongoose-db.js:48-49 User.find then console.log(users) logs full User records including password String
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: mongoose-db.js:48-49 User.find then console.log(users) logs full User records including password String | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove user dump log; never log password fields.

<a id="finding-16"></a>
### HIGH Hardcoded Plaintext Mongo Admin Password
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.9
- Location: `mongoose-db.js:52-52`
- Vulnerable code (`mongoose-db.js`):
```javascript
new User({ username: 'admin@snyk.io', password: 'SuperSecretPassword' }).save
```
- Taint Flow:
  - **Source**: `hardcoded SuperSecretPassword`
  - **Path**:
    - `mongoose-db.js:52 hardcoded password`
  - **Sink**: `Mongo save plaintext password`
- Evidence: new User({ username: 'admin@snyk.io', password: 'SuperSecretPassword' }).save
  - Validation: mongoose-db.js:52 seeds new User({username:'admin@snyk.io',password:'SuperSecretPassword'}) in plaintext and compares plaintext at routes/index.js:39; no hashing
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: mongoose-db.js:52 seeds new User({username:'admin@snyk.io',password:'SuperSecretPassword'}) in plaintext and compares plaintext at routes/index.js:39; no hashing | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded seed, store bcrypt/scrypt hash, rotate admin password via env.

<a id="finding-17"></a>
### HIGH Server-Side Request Forgery via ImageMagick identify URL fetch in POST /create
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.9
- Location: `routes/index.js:161-161`
- Vulnerable code (`routes/index.js`):
```javascript
exec('identify ' + url, function (err, stdout, stderr) {
```
- Taint Flow:
  - **Source**: `POST /create todo content image markdown URL`
  - **Path**:
    - `app.js:60 POST /create -> routes/index.js:152 req.body.content`
    - `routes/index.js:156 imgRegex extracts url group`
    - `routes/index.js:161 identify url outbound fetch`
  - **Sink**: `ImageMagick identify remote URL fetch (outbound request)`
- Evidence: POST /create imgRegex extracts http* URL at routes/index.js:156-158; URL passed to exec('identify '+url) at routes/index.js:161 where ImageMagick identify fetches remote URL server-side
  - Validation: POST /create reachable unauth at app.js:60; req.body.content source at routes/index.js:153, imgRegex extracts attacker http URL at routes/index.js:154-156, passed unsanitized to exec('identify '+url) at routes/index.js:161 causing server-side fetch + shell
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: POST /create reachable unauth at app.js:60; req.body.content source at routes/index.js:153, imgRegex extracts attacker http URL at routes/index.js:154-156, passed unsanitized to exec('identify '+url) at routes/index.js:161 causing server-side fetch + shell | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove server-side identify fetch or replace exec string concat with execFile + strict http(s) URL allowlist/validation and no shell.

<a id="finding-18"></a>
### HIGH Missing Authorization in destroy allows arbitrary deletion
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.9
- Location: `routes/index.js:191-191`
- Vulnerable code (`routes/index.js`):
```javascript
Todo.findById(req.params.id, function (err, todo) {
```
- Taint Flow:
  - **Source**: `req.params.id unauthenticated`
  - **Path**:
    - `app.js:61 GET /destroy/:id`
    - `routes/index.js:191 findById`
  - **Sink**: `Todo.findById + remove`
- Evidence: Todo.findById(req.params.id, function (err, todo) {
  - Validation: app.js:61 GET /destroy/:id has no isLoggedIn unlike app.js:56-58 guarded routes; handler at routes/index.js:191 Todo.findById(req.params.id)+remove deletes arbitrary id
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:61 GET /destroy/:id has no isLoggedIn unlike app.js:56-58 guarded routes; handler at routes/index.js:191 Todo.findById(req.params.id)+remove deletes arbitrary id | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add isLoggedIn plus ownership check on destroy; use POST/DELETE with CSRF.

<a id="finding-19"></a>
### HIGH Missing Authorization in update allows arbitrary overwrite
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.9
- Location: `routes/index.js:221-221`
- Vulnerable code (`routes/index.js`):
```javascript
todo.content = req.body.content;
```
- Taint Flow:
  - **Source**: `req.body.content unauthenticated`
  - **Path**:
    - `app.js:63 POST /update/:id`
    - `routes/index.js:221 assignment`
  - **Sink**: `todo.content assignment + save`
- Evidence: todo.content = req.body.content;
  - Validation: app.js:63 POST /update/:id has no isLoggedIn unlike app.js:56-58; handler at routes/index.js:217-221 Todo.findById then todo.content=req.body.content+save allows unauth overwrite
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:63 POST /update/:id has no isLoggedIn unlike app.js:56-58; handler at routes/index.js:217-221 Todo.findById then todo.content=req.body.content+save allows unauth overwrite | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add isLoggedIn plus ownership check on update; validate content type/length.

<a id="finding-20"></a>
### HIGH Zip-Slip Arbitrary File Overwrite in import
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.9
- Location: `routes/index.js:257-257`
- Vulnerable code (`routes/index.js`):
```javascript
zip.extractAllTo(extracted_path, true);
```
- Taint Flow:
  - **Source**: `multipart importFile POST /import`
  - **Path**:
    - `routes/index.js:247 req.files.importFile`
    - `routes/index.js:257 extractAllTo`
  - **Sink**: `AdmZip.extractAllTo filesystem write`
- Evidence: zip.extractAllTo(extracted_path, true);
  - Validation: routes/index.js:257 zip.extractAllTo(extracted_path,true) on req.files.importFile at routes/index.js:247 via app.js:64 POST /import; adm-zip 0.4.7 per package.json:18 with only file-type mime check, no traversal validation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:257 zip.extractAllTo(extracted_path,true) on req.files.importFile at routes/index.js:247 via app.js:64 POST /import; adm-zip 0.4.7 per package.json:18 with only file-type mime check, no traversal validation | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Validate zip entries against traversal, cap count/size, extract to isolated mkdtemp dir, upgrade adm-zip.
  - +1 duplicate(s): `routes/index.js:256`

<a id="finding-21"></a>
### HIGH Prototype Pollution in chat.add via lodash merge
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-1321 | confidence: 0.9
- Location: `routes/index.js:347-347`
- Vulnerable code (`routes/index.js`):
```javascript
_.merge(message, req.body.message, {
```
- Taint Flow:
  - **Source**: `req.body.message PUT /chat`
  - **Path**:
    - `routes/index.js:347 req.body.message`
    - `routes/index.js:347 merge sink`
  - **Sink**: `_.merge prototype pollution`
- Evidence: _.merge(message, req.body.message, {
  - Validation: routes/index.js:347 _.merge(message, req.body.message,...) with lodash 4.17.4 per package.json:34 (pre-fix for CVE-2018-16487); reachable via app.js:66 PUT /chat with known creds at routes/index.js:315-317
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:347 _.merge(message, req.body.message,...) with lodash 4.17.4 per package.json:34 (pre-fix for CVE-2018-16487); reachable via app.js:66 PUT /chat with known creds at routes/index.js:315-317 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Upgrade lodash past 4.17.11, block __proto__/constructor/prototype keys and use safe merge/Object.create(null).

<a id="finding-22"></a>
### HIGH Unauthenticated User Enumeration in GET /users
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.9
- Location: `routes/users.js:16-16`
- Vulnerable code (`routes/users.js`):
```javascript
const results = await repo.find({ id: 1 })
```
- Taint Flow:
  - **Source**: `unauthenticated GET /users`
  - **Path**:
    - `app.js:69 USE /users`
    - `routes/users.js:16 repo.find`
  - **Sink**: `TypeORM find returning rows`
- Evidence: const results = await repo.find({ id: 1 })
  - Validation: app.js:69 app.use('/users') mounts without auth; handler at routes/users.js:16 repo.find({id:1}) returns rows via routes/users.js:23 res.json without session check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:69 app.use('/users') mounts without auth; handler at routes/users.js:16 repo.find({id:1}) returns rows via routes/users.js:23 res.json without session check | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication/authorization on /users and scope query to session user, not hardcoded id.

<a id="finding-23"></a>
### HIGH Mass Assignment Role Escalation in POST /users
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-915 | confidence: 0.9
- Location: `routes/users.js:36-36`
- Vulnerable code (`routes/users.js`):
```javascript
const savedRecord = await repo.save(user)
```
- Taint Flow:
  - **Source**: `req.body role POST /users`
  - **Path**:
    - `routes/users.js:34 req.body.role`
    - `routes/users.js:36 repo.save`
  - **Sink**: `TypeORM save with attacker role`
- Evidence: const savedRecord = await repo.save(user)
  - Validation: routes/users.js:32-36 copies req.body.role into user then repo.save(user); entity/Users.js:15 role is persisted column; app.js:69 /users mounted with no auth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:32-36 copies req.body.role into user then repo.save(user); entity/Users.js:15 role is persisted column; app.js:69 /users mounted with no auth | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist assignable fields and enforce server-side role; require auth and drop client-controlled role.

<a id="finding-24"></a>
### HIGH Reflected XSS via redirectPage in admin.ejs
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `views/admin.ejs:17-17`
- Vulnerable code (`views/admin.ejs`):
```ejs
<input type="hidden" name="redirectPage" value="<%- redirectPage %>" />
```
- Taint Flow:
  - **Source**: `req.query.redirectPage GET /login`
  - **Path**:
    - `routes/index.js:71 req.query.redirectPage`
    - `views/admin.ejs:17 <%- sink`
  - **Sink**: `<%- redirectPage %> unescaped emission`
- Evidence: <input type="hidden" name="redirectPage" value="<%- redirectPage %>" />
  - Validation: views/admin.ejs:17 <%- redirectPage %> unescaped emission of routes/index.js:71 req.query.redirectPage via routes.login; reachable via app.js:54 GET /login
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: views/admin.ejs:17 <%- redirectPage %> unescaped emission of routes/index.js:71 req.query.redirectPage via routes.login; reachable via app.js:54 GET /login | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Change <%- redirectPage %> to <%= redirectPage %> and validate redirectPage allowlist.

<a id="finding-25"></a>
### HIGH Template Layout Control via save_account_details
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.85
- Location: `routes/index.js:107-107`
- Vulnerable code (`routes/index.js`):
```javascript
return res.render('account.hbs', profile)
```
- Taint Flow:
  - **Source**: `req.body POST /account_details`
  - **Path**:
    - `routes/index.js:91 req.body`
    - `routes/index.js:107 res.render`
  - **Sink**: `hbs res.render with attacker layout`
- Evidence: return res.render('account.hbs', profile)
  - Validation: routes/index.js:91 profile=req.body flows to routes/index.js:107 res.render('account.hbs',profile) with only email/phone/ascii checks, extra layout key passes to hbs.__express (app.js:37)
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: routes/index.js:91 profile=req.body flows to routes/index.js:107 res.render('account.hbs',profile) with only email/phone/ascii checks, extra layout key passes to hbs.__express (app.js:37) | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Construct explicit allowlisted view model and block layout/partial overrides instead of passing req.body.

<a id="finding-26"></a>
### HIGH Missing Authorization in edit exposes all todos
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.85
- Location: `routes/index.js:203-203`
- Vulnerable code (`routes/index.js`):
```javascript
exports.edit = function (req, res, next) {
```
- Taint Flow:
  - **Source**: `unauthenticated GET /edit`
  - **Path**:
    - `app.js:62 GET /edit/:id`
    - `routes/index.js:203 edit handler`
  - **Sink**: `full todo disclosure without auth`
- Evidence: exports.edit = function (req, res, next) {
  - Validation: routes/index.js:91 profile=req.body flows to routes/index.js:107 res.render('account.hbs',profile) with only email/phone/ascii checks, extra layout key passes to hbs.__express (app.js:37)
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: routes/index.js:91 profile=req.body flows to routes/index.js:107 res.render('account.hbs',profile) with only email/phone/ascii checks, extra layout key passes to hbs.__express (app.js:37) | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Construct explicit allowlisted view model and block layout/partial overrides instead of passing req.body.

<a id="finding-27"></a>
### HIGH Cross-Unit Prototype-Pollution Privilege Escalation (PUT /chat to DELETE /chat and /users Query Hijack)
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-1321 | confidence: 0.85
- Location: `routes/index.js:359-359`
- Vulnerable code (`routes/index.js`):
```javascript
if (!user || !user.canDelete) {
```
- Taint Flow:
  - **Source**: `PUT /chat req.body.message with __proto__ keys from low-priv authenticated user`
  - **Path**:
    - `routes/index.js:347 _.merge(message, req.body.message)`
    - `Object.prototype shared carrier (canDelete/where)`
    - `routes/index.js:359 canDelete authz check`
    - `routes/users.js:16 repo.find({id:1})`
  - **Sink**: `DELETE /chat authorization + GET /users TypeORM query via inherited prototype`
- Evidence: routes/index.js:347 _.merge(message, req.body.message) with lodash 4.17.4 allows __proto__ pollution by low-priv holder of hardcoded credential; polluted Object.prototype.canDelete=true makes routes/index.js:359 !user.canDelete check pass for non-admin; polluted Object.prototype.where observed at routes/users.js:20 affects repo.find({id:1}) at routes/users.js:16
  - Validation: routes/index.js:343-347 _.merge with lodash 4.17.4 (package.json:32) merges __proto__; routes/index.js:359 !user.canDelete inherits polluted prototype; routes/users.js:16-20 {}.where carrier
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:343-347 _.merge with lodash 4.17.4 (package.json:32) merges __proto__; routes/index.js:359 !user.canDelete inherits polluted prototype; routes/users.js:16-20 {}.where carrier | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Upgrade lodash past pollution fix, block __proto__/constructor keys and avoid _.merge on untrusted objects

<a id="finding-28"></a>
### HIGH Stored XSS via Todo content in index.ejs
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.85
- Location: `views/index.ejs:20-20`
- Vulnerable code (`views/index.ejs`):
```ejs
<%- marked(new String(todo.content)) %>
```
- Taint Flow:
  - **Source**: `req.body.content stored in Mongo Todo`
  - **Path**:
    - `routes/index.js:155 req.body.content`
    - `views/index.ejs:20 marked sink`
  - **Sink**: `<%- marked() unescaped HTML`
- Evidence: <%- marked(new String(todo.content)) %>
  - Validation: views/index.ejs:20 <%- marked(new String(todo.content)) %> unescaped renders stored req.body.content persisted at routes/index.js:172 via app.js:60; sanitize:true at app.js:75 bypassable in marked 0.3.5 per package.json:35 (CVE-2016-10531/CVE-2017-1000427)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: views/index.ejs:20 <%- marked(new String(todo.content)) %> unescaped renders stored req.body.content persisted at routes/index.js:172 via app.js:60; sanitize:true at app.js:75 bypassable in marked 0.3.5 per package.json:35 (CVE-2016-10531/CVE-2017-1000427) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Upgrade marked, render with maintained sanitizer (DOMPurify) or escape by default; validate content on create.

<a id="finding-29"></a>
### MEDIUM Missing Authentication on GET /chat Exposes In-Memory Chat History
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-306 | confidence: 0.92
- Location: `app.js:66-66`
- Vulnerable code (`app.js`):
```javascript
app.get('/chat', routes.chat.get);
```
- Taint Flow:
  - **Source**: `unauthenticated GET /chat request`
  - **Path**:
    - `app.js:66 GET /chat -> routes/index.js:331 chat.get`
    - `routes/index.js:332 res.send(messages)`
  - **Sink**: `unauthenticated disclosure of in-memory messages`
- Evidence: app.js:66 GET /chat has no isLoggedIn or auth; handler at routes/index.js:331-333 unconditionally res.send(messages) disclosing all in-memory chat (userNames, timestamps, attacker-polluted fields)
  - Validation: app.js:66 GET/chat has no auth; routes/index.js:330-332 chat.get unconditionally res.send(messages)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:66 GET/chat has no auth; routes/index.js:330-332 chat.get unconditionally res.send(messages) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication on GET/chat or restrict disclosure to authorized principals

<a id="finding-30"></a>
### MEDIUM Unbounded File Upload Size in express-fileupload
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `app.js:49-49`
- Vulnerable code (`app.js`):
```javascript
app.use(fileUpload());
```
- Taint Flow:
  - **Source**: `multipart importFile`
  - **Path**:
    - `app.js:49 unlimited upload`
    - `routes/index.js:247 buffer consumption`
  - **Sink**: `memory exhaustion`
- Evidence: app.use(fileUpload());
  - Validation: app.js:49 app.use(fileUpload()) with no limits buffers entire upload in memory consumed at routes/index.js:247 importFile.data; reachable unauthenticated via app.js:64 POST /import with no size check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:49 app.use(fileUpload()) with no limits buffers entire upload in memory consumed at routes/index.js:247 importFile.data; reachable unauthenticated via app.js:64 POST /import with no size check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
print('upload 1GB file, no limits configured')
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Configure express-fileupload limits:{fileSize, files} and reject oversize uploads before buffering.

<a id="finding-31"></a>
### MEDIUM CSRF via State-Changing GET /destroy/:id route
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `app.js:61-61`
- Vulnerable code (`app.js`):
```javascript
app.get('/destroy/:id', routes.destroy);
```
- Taint Flow:
  - **Source**: `cross-site forged GET request`
  - **Path**:
    - `app.js:61 GET route`
    - `routes/index.js:191 Todo.findById+remove`
  - **Sink**: `unauthenticated state change via GET`
- Evidence: app.get('/destroy/:id', routes.destroy);
  - Validation: app.js:61 mounts state-changing destroy on GET with no CSRF token; routes/index.js:190-198 Todo.findById+remove executes on forged GET
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:61 mounts state-changing destroy on GET with no CSRF token; routes/index.js:190-198 Todo.findById+remove executes on forged GET | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Change destroy to POST/DELETE with CSRF token and require auth/ownership check.

<a id="finding-32"></a>
### MEDIUM Cloud Environment Disclosure in Logs
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.9
- Location: `mongoose-db.js:21-21`
- Vulnerable code (`mongoose-db.js`):
```javascript
console.log(JSON.stringify(cfenv.getAppEnv()));
```
- Taint Flow:
  - **Source**: `cfenv.getAppEnv credentials`
  - **Sink**: `console.log env disclosure`
- Evidence: console.log(JSON.stringify(cfenv.getAppEnv()));
  - Validation: mongoose-db.js:21 console.log(JSON.stringify(cfenv.getAppEnv())) dumps full CF env including bound-service credentials
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: mongoose-db.js:21 console.log(JSON.stringify(cfenv.getAppEnv())) dumps full CF env including bound-service credentials | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove env dump log; log only non-secret status without VCAP_SERVICES.

<a id="finding-33"></a>
### MEDIUM Missing Authorization in create allows anonymous todo creation
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-862 | confidence: 0.9
- Location: `routes/index.js:152-152`
- Vulnerable code (`routes/index.js`):
```javascript
exports.create = function (req, res, next) {
```
- Taint Flow:
  - **Source**: `unauthenticated POST /create`
  - **Path**:
    - `app.js:60 unauthenticated POST /create`
    - `routes/index.js:152 create handler`
  - **Sink**: `Todo.save without authorization`
- Evidence: exports.create = function (req, res, next) {
  - Validation: app.js:60 POST /create mounted without isLoggedIn vs app.js:56-58 guarded admin/account_details; routes/index.js:152 create does Todo.save with no session check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:60 POST /create mounted without isLoggedIn vs app.js:56-58 guarded admin/account_details; routes/index.js:152 create does Todo.save with no session check | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add isLoggedIn/ownership gate to /create or enforce explicit public-create policy with abuse limits.
  - +1 duplicate(s): `routes/index.js:256`

<a id="finding-34"></a>
### MEDIUM Unbounded Zip Decompression in import enables zip-bomb DoS
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `routes/index.js:255-255`
- Vulnerable code (`routes/index.js`):
```javascript
var zip = AdmZip(importFile.data);
```
- Taint Flow:
  - **Source**: `multipart importFile bytes`
  - **Path**:
    - `routes/index.js:247 req.files.importFile`
    - `routes/index.js:255 AdmZip sink`
  - **Sink**: `unbounded decompression`
- Evidence: var zip = AdmZip(importFile.data);
  - Validation: routes/index.js:247 req.files.importFile attacker bytes to routes/index.js:255 new AdmZip(importFile.data) and routes/index.js:257 zip.extractAllTo(/tmp/extracted_files,true) with no size/count limits; reachable via app.js:64 POST /import and app.js:49 fileUpload() with no limits
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:247 req.files.importFile attacker bytes to routes/index.js:255 new AdmZip(importFile.data) and routes/index.js:257 zip.extractAllTo(/tmp/extracted_files,true) with no size/count limits; reachable via app.js:64 POST /import and app.js:49 fileUpload() with no limits | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import zipfile,io; b=io.BytesIO(); z=zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED);
z.writestr('a'*100+'.txt','x'*1000000); z.close(); print(len(b.getvalue()))
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Enforce fileSize/file count limits on fileUpload, validate zip entries against traversal, cap decompressed size/count and extract to isolated temp dir.

<a id="finding-35"></a>
### MEDIUM Unauthenticated Chat History Disclosure in chat.get
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-200 | confidence: 0.9
- Location: `routes/index.js:332-332`
- Vulnerable code (`routes/index.js`):
```javascript
res.send(messages);
```
- Taint Flow:
  - **Source**: `unauthenticated GET /chat`
  - **Path**:
    - `app.js:66 GET /chat`
    - `routes/index.js:332 res.send`
  - **Sink**: `chat history disclosure`
- Evidence: res.send(messages);
  - Validation: app.js:66 GET /chat mounted without guard; routes/index.js:331-333 chat.get does res.send(messages) with no findUser check unlike add/delete
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:66 GET /chat mounted without guard; routes/index.js:331-333 chat.get does res.send(messages) with no findUser check unlike add/delete | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication on GET /chat or scope history to authorized participants.

<a id="finding-36"></a>
### MEDIUM Missing CSRF, Security Headers, Rate Limiting and Hardened Cookies
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `app.js:42-49`
- Vulnerable code (`app.js`):
```javascript
app.use(session({
```
- Taint Flow:
  - **Source**: `victim browser with ambient session cookie (path-only)`
  - **Path**:
    - `app.js:42-49 middleware without csurf/helmet/rate-limit`
    - `app.js:60-69 mutating routes without tokens`
    - `routes/index.js:191 destroy via GET`
  - **Sink**: `unauthorized cross-site state change and clickjacking`
- Evidence: app.js:40-49 middleware stack has no csurf, no helmet/CSP/HSTS/X-Frame-Options, no rate-limit; session cookie at app.js:45 sets only path leaving httpOnly/secure/sameSite unset; state-changing routes POST /create (60), POST /update/:id (63), POST /import (64), PUT /chat (67), DELETE /chat (68), POST /users via app.js:69 and state-changing GET /destroy/:id (61) are all CSRF-able; methodOverride at app.js:41 enables verb tunneling
  - Validation: app.js:40-49 stack has no csurf/helmet/rate-limit and app.js:42-45 session cookie path-only; app.js:61 GET/destroy/:id is state-changing GET reachable cross-site
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:40-49 stack has no csurf/helmet/rate-limit and app.js:42-45 session cookie path-only; app.js:61 GET/destroy/:id is state-changing GET reachable cross-site | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add CSRF tokens, helmet/CSP/HSTS, rate-limit, SameSite/HttpOnly/Secure cookies; make destroy DELETE with CSRF

<a id="finding-37"></a>
### MEDIUM Session Fixation in adminLoginSuccess missing regeneration
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-384 | confidence: 0.85
- Location: `routes/index.js:55-55`
- Vulnerable code (`routes/index.js`):
```javascript
session.loggedIn = 1
```
- Taint Flow:
  - **Source**: `pre-login attacker-controlled session`
  - **Path**:
    - `routes/index.js:44 session object reused`
  - **Sink**: `privilege escalation on same session ID`
- Evidence: session.loggedIn = 1
  - Validation: routes/index.js:54-55 adminLoginSuccess sets session.loggedIn=1 on pre-login session without regenerate; no session.regenerate in repo; reachable via app.js:55 POST /login with express-session app.js:42-46 reusing attacker-planted connect.sid
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:54-55 adminLoginSuccess sets session.loggedIn=1 on pre-login session without regenerate; no session.regenerate in repo; reachable via app.js:55 POST /login with express-session app.js:42-46 reusing attacker-planted connect.sid | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Call req.session.regenerate() on successful login before setting loggedIn flag.

<a id="finding-38"></a>
### MEDIUM Null-Dereference DoS in update missing existence check
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-476 | confidence: 0.85
- Location: `routes/index.js:219-219`
- Vulnerable code (`routes/index.js`):
```javascript
Todo.findById(req.params.id, function (err, todo) {
```
- Taint Flow:
  - **Source**: `req.params.id URL path`
  - **Path**:
    - `routes/index.js:219 req.params.id`
    - `routes/index.js:221 todo.content deref`
  - **Sink**: `null dereference crash`
- Evidence: Todo.findById(req.params.id, function (err, todo) {
  - Validation: routes/index.js:219 Todo.findById(req.params.id) with no err/null guard flows to routes/index.js:221 todo.content assignment; reachable unauthenticated via app.js:63 POST /update/:id, throwing TypeError on invalid/missing id as uncaught exception
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:219 Todo.findById(req.params.id) with no err/null guard flows to routes/index.js:221 todo.content assignment; reachable unauthenticated via app.js:63 POST /update/:id, throwing TypeError on invalid/missing id as uncaught exception | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import http.client; c=http.client.HTTPConnection('localhost',3001,timeout=3);
c.request('POST','/update/invalid-id', 'content=x', {'Content-Type':'application/x-www-form-urlencoded'});
print(c.getresponse().status)
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Check err||!todo after findById and return 404/next(err) before dereferencing todo.

<a id="finding-39"></a>
### MEDIUM Attacker-Controlled Moment Locale in import
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.8
- Location: `routes/index.js:279-279`
- Vulnerable code (`routes/index.js`):
```javascript
moment.locale(locale);
```
- Taint Flow:
  - **Source**: `importFile CSV locale column`
  - **Path**:
    - `routes/index.js:273 CSV locale field`
    - `routes/index.js:279 moment.locale sink`
  - **Sink**: `global locale mutation / parser DoS`
- Evidence: moment.locale(locale);
  - Validation: routes/index.js:273 locale from CSV parts[2] split flows to routes/index.js:279 moment.locale(locale) mutating global locale for all users; reachable via app.js:64 POST /import with no allowlist, only isBlank check routes/index.js:277
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:273 locale from CSV parts[2] split flows to routes/index.js:279 moment.locale(locale) mutating global locale for all users; reachable via app.js:64 POST /import with no allowlist, only isBlank check routes/index.js:277 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
print('locale=xx'*1000)
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Allowlist locales or avoid global moment.locale; parse dates without mutating global state.

<a id="finding-40"></a>
### MEDIUM Insecure HTTP Script Include in layout.ejs
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-829 | confidence: 0.8
- Location: `views/layout.ejs:7-7`
- Vulnerable code (`views/layout.ejs`):
```ejs
<script src="http://html5shiv.googlecode.com/svn/trunk/html5.js"></script>
```
- Taint Flow:
  - **Source**: `hardcoded http URL`
  - **Sink**: `remote script execution over HTTP`
- Evidence: <script src="http://html5shiv.googlecode.com/svn/trunk/html5.js"></script>
  - Validation: views/layout.ejs:7 hardcodes http://html5shiv.googlecode.com script rendered via ejs-locals layout to browsers
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: views/layout.ejs:7 hardcodes http://html5shiv.googlecode.com script rendered via ejs-locals layout to browsers | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
print('http://html5shiv script over HTTP')
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Remove IE shim or serve over https/inline; add CSP to block http scripts

<a id="finding-41"></a>
### LOW Insecure Session Cookie Flags
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `app.js:45-45`
- Vulnerable code (`app.js`):
```javascript
cookie: { path: '/' }
```
- Taint Flow:
  - **Source**: `express-session config`
  - **Sink**: `session cookie without flags`
- Evidence: cookie: { path: '/' }
  - Validation: app.js:44-46 session cookie is { path: '/' } with no httpOnly/secure/sameSite flags
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: app.js:44-46 session cookie is { path: '/' } with no httpOnly/secure/sameSite flags | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Set cookie httpOnly:true, secure:true, sameSite:'lax' (or strict) in express-session config.

<a id="finding-42"></a>
### LOW Hardcoded SECRET_TOKEN Logged to Console
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-798 | confidence: 0.9
- Location: `app.js:83-83`
- Vulnerable code (`app.js`):
```javascript
var token = 'SECRET_TOKEN_f8ed84e8f41e4146403dd4a6bbcea5e418d23a9';
```
- Taint Flow:
  - **Source**: `hardcoded SECRET_TOKEN`
  - **Path**:
    - `app.js:83 token literal`
    - `app.js:84 console.log`
  - **Sink**: `console.log token disclosure`
- Evidence: var token = 'SECRET_TOKEN_f8ed84e8f41e4146403dd4a6bbcea5e418d23a9';
  - Validation: app.js:83 hardcoded var token SECRET_TOKEN_f8ed84e8f41e4146403dd4a6bbcea5e418d23a9 logged at app.js:84 console.log; value in source, no use as auth but exposed in logs/source
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:83 hardcoded var token SECRET_TOKEN_f8ed84e8f41e4146403dd4a6bbcea5e418d23a9 logged at app.js:84 console.log; value in source, no use as auth but exposed in logs/source | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded token from source, load from env/vault if needed, never log secrets.

<a id="finding-43"></a>
### LOW Stored XSS via import CSV content persistence
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `routes/index.js:285-288`
- Vulnerable code (`routes/index.js`):
```javascript
new Todo({
        content: item,
```
- Taint Flow:
  - **Source**: `importFile CSV content`
  - **Path**:
    - `routes/index.js:270 CSV what`
    - `routes/index.js:285 Todo.save`
    - `views/index.ejs:20 marked sink`
  - **Sink**: `stored XSS payload persistence`
- Evidence: new Todo({ content: item,
  - Validation: app.js:44-46 session cookie is { path: '/' } with no httpOnly/secure/sameSite flags
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: app.js:44-46 session cookie is { path: '/' } with no httpOnly/secure/sameSite flags | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Set cookie httpOnly:true, secure:true, sameSite:'lax' (or strict) in express-session config.

<a id="finding-44"></a>
### LOW Verbose Error Disclosure via development errorHandler
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `app.js:80-80`
- Vulnerable code (`app.js`):
```javascript
app.use(errorHandler());
```
- Taint Flow:
  - **Source**: `error paths e.g. invalid ids`
  - **Path**:
    - `app.js:79 env check`
    - `app.js:80 errorHandler`
  - **Sink**: `stack trace disclosure`
- Evidence: app.use(errorHandler());
  - Validation: app.js:79-80 if(app.get('env')=='development') app.use(errorHandler()) defaults to development when NODE_ENV unset, returning stack traces on next(err) paths
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:79-80 if(app.get('env')=='development') app.use(errorHandler()) defaults to development when NODE_ENV unset, returning stack traces on next(err) paths | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import http.client; c=http.client.HTTPConnection('localhost',3001,timeout=3);
c.request('GET','/edit/invalid-id-that-crashes'); print(c.getresponse().read()[:200])
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Enable errorHandler only when explicitly development and return generic message in production.

<a id="finding-45"></a>
### LOW Weak Random Admin Password in chat users
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `routes/index.js:317-317`
- Vulnerable code (`routes/index.js`):
```javascript
{ name: 'admin', password: Math.random().toString(32), canDelete: true },
```
- Taint Flow:
  - **Source**: `Math.random PRNG`
  - **Sink**: `predictable admin password`
- Evidence: { name: 'admin', password: Math.random().toString(32), canDelete: true },
  - Validation: routes/index.js:317 uses Math.random().toString(32) as admin chat password with no CSPRNG; routes/index.js:324 findUser compares it directly
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:317 uses Math.random().toString(32) as admin chat password with no CSPRNG; routes/index.js:324 findUser compares it directly | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Generate admin secret with crypto.randomBytes at startup and store outside code.

<a id="finding-46"></a>
### LOW Log Injection via Unsanitized CSV Field in POST /import
- CVSS: **2.2** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-117 | confidence: 0.8
- Location: `routes/index.js:271-271`
- Vulnerable code (`routes/index.js`):
```javascript
console.log('importing ' + what);
```
- Taint Flow:
  - **Source**: `uploaded import file CSV first column`
  - **Path**:
    - `app.js:64 POST /import -> routes/index.js:241 req.files.importFile.data`
    - `routes/index.js:270 parts[0] CSV field`
    - `routes/index.js:271 console.log concatenation`
  - **Sink**: `console.log log forgery`
- Evidence: POST /import CSV line split at routes/index.js:268-271; what=parts[0] from uploaded file bytes flows unsanitized to console.log at line 271; attacker controls newlines to forge log lines; distinct from reported log sinks at lines 58 and 299
  - Validation: routes/index.js:268-271 splits uploaded file to what=parts[0] then console.log(importing+what) at routes/index.js:271 with no sanitization via app.js:64 POST/import
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/index.js:268-271 splits uploaded file to what=parts[0] then console.log(importing+what) at routes/index.js:271 with no sanitization via app.js:64 POST/import | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Strip CR/LF/ANSI and encode CSV field before console.log or use structured logging

<a id="finding-47"></a>
### LOW Verbose SQL Logging Leaks PII in TypeORM
- CVSS: **2.2** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.75
- Location: `typeorm-db.js:15-15`
- Vulnerable code (`typeorm-db.js`):
```javascript
"logging": true,
```
- Taint Flow:
  - **Source**: `ORM queries`
  - **Sink**: `SQL/PII in logs`
- Evidence: "logging": true,
  - Validation: typeorm-db.js:15 logging:true logs SQL with user PII saved at routes/users.js:30-32 to stdout
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: typeorm-db.js:15 logging:true logs SQL with user PII saved at routes/users.js:30-32 to stdout | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Set logging:false in production or route TypeORM logs to protected sink with parameter redaction
