# Cerberus Report

**Findings:** 22 actionable — 4 critical, 12 high, 3 medium, 3 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 1 false positive — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 4 | 0 / 4 (0%) | 4 |
| HIGH | 12 | 0 / 12 (0%) | 12 |
| MEDIUM | 3 | 0 / 3 (0%) | 3 |
| LOW | 3 | 0 / 3 (0%) | 3 |
| **TOTAL** | **22** | **0 / 22 (0%)** | **22** |

## Table of Contents

- [Confirmed (22)](#confirmed)
  - [CRITICAL: OS command injection in ExecPHP parseFile (`execphp.js:22`)](#finding-1)
  - [CRITICAL: Missing authentication on GET *.php code-execution bridge (`routes/php.js:28`)](#finding-2)
  - [CRITICAL: Unauthenticated bulk disclosure (`routes/users.js:10`)](#finding-3)
  - [CRITICAL: NoSQL auth bypass in login (`routes/users.js:58`)](#finding-4)
  - [HIGH: XXE in PHP order bridge (`phpFiles/order.php:21`)](#finding-5)
  - [HIGH: Missing authorization on GET admin (`routes/admin.js:5`)](#finding-6)
  - [HIGH: IDOR on DELETE deleteuser (`routes/users.js:38`)](#finding-7)
  - [HIGH: Plaintext password handling (`views/login.jade:40`)](#finding-8)
  - [HIGH: Path traversal / unrestricted file control in PHP bridge file parameter (`execphp.js:18`)](#finding-9)
  - [HIGH: Reflected XSS via unescaped PHP echo (`phpFiles/order.php:27`)](#finding-10)
  - [HIGH: Stored XSS in admin table (`public/javascripts/global.js:46`)](#finding-11)
  - [HIGH: Missing authentication allows unauthenticated account creation via POST /users/adduser (`routes/users.js:16`)](#finding-12)
  - [HIGH: Unsanitized insert in adduser (`routes/users.js:25`)](#finding-13)
  - [HIGH: Mass-assignment in PUT modify (`routes/users.js:113`)](#finding-14)
  - [HIGH: Active content loaded over plaintext HTTP without integrity (`views/layout.jade:9`)](#finding-15)
  - [HIGH: Weak default credential: new-user password set equal to username (`public/javascripts/global.js:85`)](#finding-16)
  - [MEDIUM: Missing rate limiting on POST /users/session login (`routes/users.js:46`)](#finding-17)
  - [MEDIUM: Sensitive data exposure: GET /users returns full user object with password and credit-card (`routes/users.js:97`)](#finding-18)
  - [MEDIUM: Missing CSRF protection on PUT /users/modify (`routes/users.js:104`)](#finding-19)
  - [LOW: Session cookie missing Secure/HttpOnly/SameSite hardening (`app.js:30`)](#finding-20)
  - [LOW: Stack-trace disclosure in development error handler (`views/error.jade:6`)](#finding-21)
  - [LOW: Log injection via unsanitized PHP-bridge parameters (`routes/php.js:23`)](#finding-22)

<a id="confirmed"></a>
## Confirmed (22)

<a id="finding-1"></a>
### CRITICAL OS command injection in ExecPHP parseFile
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.95
- Location: `execphp.js:22-23`
- Vulnerable code (`execphp.js`):
```javascript
let cmd = this.phpPath + ' ' + realFileName + ' ' + arg1 + ' ' + arg2;
```
- Taint Flow:
  - **Source**: `HTTP URL query item price`
  - **Path**:
    - `routes/php.js line 30 queryParams`
    - `execphp.js line 22 cmd`
  - **Sink**: `child_process exec shell`
- Evidence: let cmd = this.phpPath + realFileName + arg1 + arg2;
  - Validation: execphp.js:22 shell-concatenates attacker item/price into cmd executed via child_process.exec at execphp.js:23 reachable unauth from routes/php.js:30-34 with no sanitizer
  - Alternatives considered: secret test | let db = monk('localhost:27017/nodetest2');
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: execphp.js:22 shell-concatenates attacker item/price into cmd executed via child_process.exec at execphp.js:23 reachable unauth from routes/php.js:30-34 with no sanitizer | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace exec with execFile/allowlisted dispatch: validate path against allowlist and pass item/price as argv array without shell.

<a id="finding-2"></a>
### CRITICAL Missing authentication on GET *.php code-execution bridge
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `routes/php.js:28-28`
- Vulnerable code (`routes/php.js`):
```javascript
router.get('*.php', function (request, response, next) {
```
- Taint Flow:
  - **Source**: `untrusted network request, no session required`
  - **Path**:
    - `routes/php.js:28 unauthenticated GET *.php entry`
    - `routes/php.js:30 parseFile dispatch`
    - `execphp.js:22 child_process.exec sink`
  - **Sink**: `unauthenticated access to OS command / PHP execution`
- Evidence: routes/php.js:28 registers GET *.php with no session check, no auth middleware; reaches execphp.js:22 child_process.exec and phpFiles/order.php XML parser
  - Validation: routes/php.js:28 GET *.php no auth guard mounted at app.js:52 reaching execphp.js:22 child_process.exec shell-concatenated cmd
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/php.js:28 GET *.php no auth guard mounted at app.js:52 reaching execphp.js:22 child_process.exec shell-concatenated cmd | consensus: 1/1 confirmed | triage: Unauth entry to OS command execution
- Patch:
  - **Summary**: Remove shell bridge or gate with auth plus execFile allowlisted file and validated args

<a id="finding-3"></a>
### CRITICAL Unauthenticated bulk disclosure
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.95
- Location: `routes/users.js:10-11`
- Vulnerable code (`routes/users.js`):
```javascript
collection.find({}, {}, function (e, docs) {
```
- Taint Flow:
  - **Source**: `HTTP GET userlist`
  - **Path**:
    - `GET userlist anonymous`
  - **Sink**: `res.json docs bulk`
- Evidence: routes/users.js:7 GET userlist no auth; find all docs; global.js:34 fetches it exposing passwords PII cards
  - Validation: routes/users.js:7 GET userlist no auth + routes/users.js:10 find({},{}) + routes/users.js:11 res.json bulk mounted at app.js:48, fetched at public/javascripts/global.js:34
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:7 GET userlist no auth + routes/users.js:10 find({},{}) + routes/users.js:11 res.json bulk mounted at app.js:48, fetched at public/javascripts/global.js:34 | consensus: 1/1 confirmed | triage: Unauth bulk exfil of passwords PII cards
- Patch:
  - **Summary**: Require authenticated session/role on GET userlist, paginate and filter secret fields (password/card)

<a id="finding-4"></a>
### CRITICAL NoSQL auth bypass in login
- CVSS: **8.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.9
- Location: `routes/users.js:58-58`
- Vulnerable code (`routes/users.js`):
```javascript
var user = await collection.findOne({ username: req.body.username, password: req.body.password });
```
- Taint Flow:
  - **Source**: `HTTP POST body`
  - **Path**:
    - `POST session body`
  - **Sink**: `collection.findOne attacker query`
- Evidence: routes/users.js:58 findOne uses req.body verbatim; app.js:37 extended true enables operator objects; only empty-string check at routes/users.js:52
  - Validation: routes/users.js:58 findOne({username:req.body.username,password:req.body.password}) verbatim with only empty check at routes/users.js:52 and extended:true at app.js:37 enabling $gt objects
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:58 findOne({username:req.body.username,password:req.body.password}) verbatim with only empty check at routes/users.js:52 and extended:true at app.js:37 enabling $gt objects | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Strict string type-check, reject $-prefixed operators, schema validation before findOne

<a id="finding-5"></a>
### HIGH XXE in PHP order bridge
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-611 | confidence: 0.95
- Location: `phpFiles/order.php:21-23`
- Vulnerable code (`phpFiles/order.php`):
```php
libxml_disable_entity_loader (false);
```
- Taint Flow:
  - **Source**: `HTTP GET *.php item param`
  - **Path**:
    - `routes/php.js:28 originalUrl item`
    - `phpFiles/order.php:12 argv into XML`
  - **Sink**: `DOMDocument loadXML with NOENT DTDLOAD`
- Evidence: routes/php.js:30-34 item forwarded to PHP argv; phpFiles/order.php:12 urldecode argv interpolated; phpFiles/order.php:21-23 loadXML with LIBXML_NOENT DTDLOAD and entity loader enabled
  - Validation: phpFiles/order.php:21 loader enabled (false) + phpFiles/order.php:23 loadXML LIBXML_NOENT|DTDLOAD on attacker $name from phpFiles/order.php:12 via routes/php.js:30-34 and execphp.js:22
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: phpFiles/order.php:21 loader enabled (false) + phpFiles/order.php:23 loadXML LIBXML_NOENT|DTDLOAD on attacker $name from phpFiles/order.php:12 via routes/php.js:30-34 and execphp.js:22 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Disable external entities (loader true), drop NOENT/DTDLOAD, use LIBXML_NONET, validate item/price and allowlist PHP file

<a id="finding-6"></a>
### HIGH Missing authorization on GET admin
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `routes/admin.js:5-6`
- Vulnerable code (`routes/admin.js`):
```javascript
router.get('/admin', function(req, res) {
```
- Taint Flow:
  - **Source**: `HTTP GET admin`
  - **Path**:
    - `GET admin anonymous`
  - **Sink**: `render admin UI`
- Evidence: routes/admin.js:5 GET admin renders UI with no check; mounted at app.js:47
  - Validation: routes/admin.js:5 router.get('/admin') with no session check rendering admin UI, mounted at app.js:47 without middleware
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/admin.js:5 router.get('/admin') with no session check rendering admin UI, mounted at app.js:47 without middleware | consensus: 1/1 confirmed | triage: Unauth GET admin renders privileged UI
- Patch:
  - **Summary**: Enforce server-side session/role check on GET /admin before render

<a id="finding-7"></a>
### HIGH IDOR on DELETE deleteuser
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `routes/users.js:38-38`
- Vulnerable code (`routes/users.js`):
```javascript
collection.remove({ '_id': userToDelete }, function (err) {
```
- Taint Flow:
  - **Source**: `HTTP DELETE param`
  - **Path**:
    - `userlist leaks _id`
    - `DELETE id param`
  - **Sink**: `collection.remove attacker id`
- Evidence: routes/users.js:34 DELETE deleteuser id from URL no check; IDs enumerable via bulk userlist
  - Validation: routes/users.js:32 DELETE deleteuser/:id + routes/users.js:38 remove by attacker id with no ownership check, IDs enumerable via routes/users.js:10
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:32 DELETE deleteuser/:id + routes/users.js:38 remove by attacker id with no ownership check, IDs enumerable via routes/users.js:10 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require auth + ownership/admin check on delete, validate ObjectId

<a id="finding-8"></a>
### HIGH Plaintext password handling
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `views/login.jade:40-40`
- Vulnerable code (`views/login.jade`):
```jade
input#loginPassword(type='text', placeholder='Password')
```
- Taint Flow:
  - **Source**: `password input no hashing`
  - **Path**:
    - `login form capture`
  - **Sink**: `plaintext compare and disclosure`
- Evidence: views/login.jade:40 type text password; routes/users.js:58 plaintext compare; bulk disclosure returns plaintext
  - Validation: views/login.jade:40 password field type='text'; routes/users.js:58 plaintext findOne compare; no bcrypt in package.json; bulk leak via routes/users.js:7
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: views/login.jade:40 password field type='text'; routes/users.js:58 plaintext findOne compare; no bcrypt in package.json; bulk leak via routes/users.js:7 | consensus: 1/1 confirmed | triage: Plaintext password capture compare storage
- Patch:
  - **Summary**: Hash passwords with bcrypt/argon2, set input type=password, never return password/card to client.

<a id="finding-9"></a>
### HIGH Path traversal / unrestricted file control in PHP bridge file parameter
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.9
- Location: `execphp.js:18-18`
- Vulnerable code (`execphp.js`):
```javascript
let realFileName = this.phpFolder + fileName;
```
- Taint Flow:
  - **Source**: `untrusted URL path component`
  - **Path**:
    - `routes/php.js:28 GET *.php receives originalUrl`
    - `routes/php.js:12 result.path = query.split("?")[0] attacker-controlled`
    - `routes/php.js:30 execPHP.parseFile(queryParams.path,...)`
    - `execphp.js:18 phpFolder + fileName concatenation`
  - **Sink**: `filesystem path handed to /usr/bin/php execution`
- Evidence: routes/php.js:12 derives result.path directly from request.originalUrl; routes/php.js:30-31 passes queryParams.path to parseFile; execphp.js:18 concatenates without validation
  - Validation: routes/php.js:12 path derived from originalUrl and forwarded at routes/php.js:30 to execphp.js:18 phpFolder+fileName concat with no validation then executed at execphp.js:22
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/php.js:12 path derived from originalUrl and forwarded at routes/php.js:30 to execphp.js:18 phpFolder+fileName concat with no validation then executed at execphp.js:22 | consensus: 1/1 confirmed | triage: Unauth path control selects PHP file executed
- Patch:
  - **Summary**: Allowlist PHP filenames and canonicalize with path.resolve containment check; never concatenate URL path.

<a id="finding-10"></a>
### HIGH Reflected XSS via unescaped PHP echo
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `phpFiles/order.php:27-27`
- Vulnerable code (`phpFiles/order.php`):
```php
echo You have ordered name with price;
```
- Taint Flow:
  - **Source**: `HTTP GET item param`
  - **Path**:
    - `routes/php.js:28 item`
    - `phpFiles/order.php:12 name`
  - **Sink**: `echo name unescaped`
- Evidence: phpFiles/order.php:12 name from argv; phpFiles/order.php:27 unescaped echo; routes/php.js:32 sends PHP output verbatim
  - Validation: phpFiles/order.php:12 $name from argv + phpFiles/order.php:27 unescaped echo sent verbatim at routes/php.js:32 response.send
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: phpFiles/order.php:12 $name from argv + phpFiles/order.php:27 unescaped echo sent verbatim at routes/php.js:32 response.send | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Context-encode $name/$price with htmlspecialchars before echo

<a id="finding-11"></a>
### HIGH Stored XSS in admin table
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `public/javascripts/global.js:46-46`
- Vulnerable code (`public/javascripts/global.js`):
```javascript
$('.userList table tbody').html(tableContent);
```
- Taint Flow:
  - **Source**: `attacker username`
  - **Path**:
    - `adduser username`
    - `userlist JSON`
  - **Sink**: `jQuery html`
- Evidence: adduser stores username verbatim; userlist returns them; global.js:40 concat; global.js:46 html sink
  - Validation: public/javascripts/global.js:40 concat username/email unsanitized + public/javascripts/global.js:46 .html sink with verbatim insert at routes/users.js:25 returned at routes/users.js:10
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: public/javascripts/global.js:40 concat username/email unsanitized + public/javascripts/global.js:46 .html sink with verbatim insert at routes/users.js:25 returned at routes/users.js:10 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: HTML-encode username/email on render (use .text) and validate on adduser

<a id="finding-12"></a>
### HIGH Missing authentication allows unauthenticated account creation via POST /users/adduser
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.9
- Location: `routes/users.js:16-16`
- Vulnerable code (`routes/users.js`):
```javascript
router.post('/adduser', async function (req, res) {
```
- Taint Flow:
  - **Source**: `untrusted request body, no session required`
  - **Path**:
    - `routes/users.js:16 unauthenticated POST /users/adduser entry`
    - `routes/users.js:25 collection.insert(req.body)`
  - **Sink**: `unauthenticated creation of persistent user document`
- Evidence: routes/users.js:16 POST /adduser handler has no req.session / role check, unlike PUT /modify at routes/users.js:104-107 which checks login; mounted in app.js:48 without auth middleware
  - Validation: routes/users.js:16 POST adduser no session check inserting at routes/users.js:25 mounted at app.js:48, contrast PUT modify check at routes/users.js:104
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:16 POST adduser no session check inserting at routes/users.js:25 mounted at app.js:48, contrast PUT modify check at routes/users.js:104 | consensus: 1/1 confirmed | triage: Unauth persistent account creation
- Patch:
  - **Summary**: Require admin session/role on POST adduser

<a id="finding-13"></a>
### HIGH Unsanitized insert in adduser
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.9
- Location: `routes/users.js:25-25`
- Vulnerable code (`routes/users.js`):
```javascript
collection.insert(req.body, function (err, result) {
```
- Taint Flow:
  - **Source**: `HTTP POST body`
  - **Path**:
    - `POST adduser body`
  - **Sink**: `collection.insert body`
- Evidence: routes/users.js:16 POST adduser; routes/users.js:25 insert req.body verbatim
  - Validation: routes/users.js:25 collection.insert(req.body) verbatim on active POST /users/adduser (app.js:48) with only duplicate check at routes/users.js:21 and no operator/field validation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:25 collection.insert(req.body) verbatim on active POST /users/adduser (app.js:48) with only duplicate check at routes/users.js:21 and no operator/field validation | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist insertable fields and reject keys starting with $; enforce string types before insert.

<a id="finding-14"></a>
### HIGH Mass-assignment in PUT modify
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-915 | confidence: 0.9
- Location: `routes/users.js:113-113`
- Vulnerable code (`routes/users.js`):
```javascript
collection.findOneAndUpdate({ username: req.session.user.username }, { $set: query },
```
- Taint Flow:
  - **Source**: `HTTP PUT body`
  - **Path**:
    - `PUT modify body`
  - **Sink**: `findOneAndUpdate $set`
- Evidence: routes/users.js:104 PUT modify; routes/users.js:111 req.body verbatim; routes/users.js:113 $set query
  - Validation: routes/users.js:111 query=req.body verbatim + routes/users.js:113 findOneAndUpdate $set query gated only by routes/users.js:104 session check with no field allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:111 query=req.body verbatim + routes/users.js:113 findOneAndUpdate $set query gated only by routes/users.js:104 session check with no field allowlist | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist updatable fields and reject username/_id/operators before $set

<a id="finding-15"></a>
### HIGH Active content loaded over plaintext HTTP without integrity
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-829 | confidence: 0.9
- Location: `views/layout.jade:9-9`
- Vulnerable code (`views/layout.jade`):
```jade
script(src='http://ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js')
```
- Taint Flow:
  - **Source**: `remote CDN fetch over HTTP`
  - **Path**:
    - `views/layout.jade:9 CDN script include`
    - `views/login.jade:33 password/card forms in same DOM`
  - **Sink**: `browser executes MITM-controlled JavaScript`
- Evidence: views/layout.jade:9 loads jQuery 2.1.1 over plaintext http:// with no integrity/subresource-integrity hash; every view extends layout so every page executes the MITM-able script
  - Validation: views/layout.jade:9 script http://ajax.googleapis.com jquery 2.1.1 no integrity, extended by all views e.g. views/login.jade:1
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: views/layout.jade:9 script http://ajax.googleapis.com jquery 2.1.1 no integrity, extended by all views e.g. views/login.jade:1 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Load over https with SRI hash and pin version, or vendor locally

<a id="finding-16"></a>
### HIGH Weak default credential: new-user password set equal to username
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-521 | confidence: 0.85
- Location: `public/javascripts/global.js:85-85`
- Vulnerable code (`public/javascripts/global.js`):
```javascript
'password': $('#addUser fieldset input#inputUserName').val()
```
- Taint Flow:
  - **Source**: `admin UI username input reused as password`
  - **Path**:
    - `public/javascripts/global.js:85 password derived from username input`
    - `routes/users.js:16 POST /users/adduser receives newUser`
    - `routes/users.js:25 collection.insert(req.body) persists weak password`
    - `routes/users.js:58 collection.findOne login accepts it`
  - **Sink**: `MongoDB persistence of attacker-guessable password`
- Evidence: public/javascripts/global.js:85 sets password from username field; routes/users.js:16-25 inserts req.body verbatim without password policy; routes/users.js:58 logs in with that password
  - Validation: public/javascripts/global.js:85 password copied from username input persisted verbatim at routes/users.js:25 and accepted at routes/users.js:58 with no policy
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: public/javascripts/global.js:85 password copied from username input persisted verbatim at routes/users.js:25 and accepted at routes/users.js:58 with no policy | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Stop deriving password from username, enforce random/password policy and hash with bcrypt

<a id="finding-17"></a>
### MEDIUM Missing rate limiting on POST /users/session login
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-307 | confidence: 0.85
- Location: `routes/users.js:46-46`
- Vulnerable code (`routes/users.js`):
```javascript
router.post('/session', async function (req, res) {
```
- Taint Flow:
  - **Source**: `remote HTTP request body`
  - **Path**:
    - `routes/users.js:46 login entry`
    - `routes/users.js:58 Mongo findOne credential check`
  - **Sink**: `unbounded authentication attempts`
- Evidence: routes/users.js:46 POST /users/session performs credential verification with no rate-limit, lockout, or CAPTCHA middleware; app.js:28-52 registers no throttling; handler returns distinguishable unauthorized vs field messages enabling online guessing
  - Validation: routes/users.js:46 POST /users/session credential check at routes/users.js:58 has no throttle/lockout and app.js:28-52 registers no rate-limiter; distinguishable unauthorized vs fill-fields messages
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:46 POST /users/session credential check at routes/users.js:58 has no throttle/lockout and app.js:28-52 registers no rate-limiter; distinguishable unauthorized vs fill-fields messages | consensus: 1/1 confirmed | triage: Unbounded login enables online guessing
- Patch:
  - **Summary**: Add rate-limiting, account lockout/backoff and generic auth-failure messages on login.

<a id="finding-18"></a>
### MEDIUM Sensitive data exposure: GET /users returns full user object with password and credit-card
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-200 | confidence: 0.85
- Location: `routes/users.js:97-97`
- Vulnerable code (`routes/users.js`):
```javascript
res.status(200).send({ user: req.session.user }).end();
```
- Taint Flow:
  - **Source**: `MongoDB user document persisted in server session`
  - **Path**:
    - `routes/users.js:58 findOne returns full doc with password/card`
    - `routes/users.js:65 req.session.user = user stores secrets`
    - `routes/users.js:97 GET /users sends session user verbatim`
  - **Sink**: `sensitive password + credit-card disclosure to session holder`
- Evidence: routes/users.js:64-65 stores full DB user object in req.session.user; routes/users.js:97 returns it verbatim including plaintext password and credit-card fields
  - Validation: routes/users.js:65 stores full Mongo doc in session and routes/users.js:97 returns it verbatim including password/card rendered at global.js:236
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:65 stores full Mongo doc in session and routes/users.js:97 returns it verbatim including password/card rendered at global.js:236 | consensus: 1/1 confirmed | triage: Auth session holder reads own password and card
- Patch:
  - **Summary**: Store minimal session fields and strip password/card before send; project only needed fields.

<a id="finding-19"></a>
### MEDIUM Missing CSRF protection on PUT /users/modify
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `routes/users.js:104-104`
- Vulnerable code (`routes/users.js`):
```javascript
router.put('/modify', async function (req, res) {
```
- Taint Flow:
  - **Source**: `cross-site forged request carrying victim cookies`
  - **Path**:
    - `app.js:28 cookie session auth`
    - `routes/users.js:104 PUT /modify state change`
  - **Sink**: `MongoDB findOneAndUpdate of victim account`
- Evidence: routes/users.js:104 PUT /users/modify mutates the logged-in user via cookie session with no CSRF token, SameSite, or Origin check; app.js:28-38 shows cookie session and no csurf/helmet middleware; public/javascripts/global.js:256-260 issues the PUT via plain AJAX
  - Validation: routes/users.js:104 PUT /modify does state-changing findOneAndUpdate at routes/users.js:113 on cookie session from app.js:28 with no csurf/SameSite/Origin check and tokenless AJAX at global.js:256
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/users.js:104 PUT /modify does state-changing findOneAndUpdate at routes/users.js:113 on cookie session from app.js:28 with no csurf/SameSite/Origin check and tokenless AJAX at global.js:256 | consensus: 1/1 confirmed | triage: Cookie state change needs victim interaction
- Patch:
  - **Summary**: Add CSRF tokens with SameSite=Lax/Strict cookies plus Origin/Referer check on state-changing routes.

<a id="finding-20"></a>
### LOW Session cookie missing Secure/HttpOnly/SameSite hardening
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `app.js:30-32`
- Vulnerable code (`app.js`):
```javascript
resave: true,
  saveUninitialized: true,
  expires: new Date(Date.now() + (30 * 86400 * 1000)),
```
- Taint Flow:
  - **Source**: `server session configuration`
  - **Path**:
    - `app.js:28 session middleware issues cookie`
    - `routes/users.js:65 session stores full user object`
  - **Sink**: `session cookie issued without Secure/HttpOnly/SameSite`
- Evidence: app.js:28-33 configures cookie-based express-session with resave/saveUninitialized and invalid expires option and no cookie.secure/httpOnly/sameSite/maxAge; app.js:35-38 shows logger and cookieParser with no helmet or csrf middleware
  - Validation: app.js:28 session() with no cookie.secure/sameSite/maxAge and invalid expires at app.js:32, no helmet at app.js:35
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:28 session() with no cookie.secure/sameSite/maxAge and invalid expires at app.js:32, no helmet at app.js:35 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set cookie.secure/httpOnly/sameSite/maxAge, load secret from env, fix expires placement

<a id="finding-21"></a>
### LOW Stack-trace disclosure in development error handler
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.9
- Location: `views/error.jade:6-6`
- Vulnerable code (`views/error.jade`):
```jade
pre #{error.stack}
```
- Taint Flow:
  - **Source**: `server exception object`
  - **Path**:
    - `app.js:63 res.locals.error = err`
    - `views/error.jade:6 pre #{error.stack} render`
  - **Sink**: `HTTP response body containing stack trace`
- Evidence: app.js:60-67 forwards full err object to error view when env is development (the default); views/error.jade:4-6 renders message, status and full error.stack to the client
  - Validation: app.js:63 res.locals.error=err in development default + views/error.jade:6 pre #{error.stack} rendered to client
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:63 res.locals.error=err in development default + views/error.jade:6 pre #{error.stack} rendered to client | consensus: 1/1 confirmed | triage: Dev error view renders stack trace
- Patch:
  - **Summary**: Render generic message outside development, never send error.stack to client

<a id="finding-22"></a>
### LOW Log injection via unsanitized PHP-bridge parameters
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-117 | confidence: 0.85
- Location: `routes/php.js:23-24`
- Vulnerable code (`routes/php.js`):
```javascript
console.log(result.item)
  console.log(result.price)
```
- Taint Flow:
  - **Source**: `HTTP GET *.php query string (request.originalUrl)`
  - **Path**:
    - `routes/php.js:28 request.originalUrl`
    - `routes/php.js:21 substr item/price extraction`
    - `routes/php.js:23 console.log sink`
  - **Sink**: `console.log with attacker-controlled string`
- Evidence: routes/php.js:20-24 extracts attacker-controlled item/price via substr and passes them unsanitized to console.log; routes/php.js:28-31 shows the same values flow from request.originalUrl into the bridge
  - Validation: routes/php.js:20 substr item/price from request.originalUrl logged unsanitized at routes/php.js:23 console.log via routes/php.js:28 entry
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/php.js:20 substr item/price from request.originalUrl logged unsanitized at routes/php.js:23 console.log via routes/php.js:28 entry | consensus: 1/1 confirmed | triage: Unauth log forgery only, no integrity impact
- Patch:
  - **Summary**: Strip CRLF/control chars or use structured logger for item/price before console.log
