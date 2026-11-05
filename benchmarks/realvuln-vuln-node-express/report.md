# Cerberus Report

**Findings:** 13 actionable — 6 critical, 3 high, 2 medium, 2 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 37 false positives and 7 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 6 | 0 / 6 (0%) | 6 |
| HIGH | 3 | 0 / 3 (0%) | 3 |
| MEDIUM | 2 | 0 / 2 (0%) | 2 |
| LOW | 2 | 0 / 2 (0%) | 2 |
| **TOTAL** | **13** | **0 / 13 (0%)** | **13** |

## Table of Contents

- [Confirmed (13)](#confirmed)
  - [CRITICAL: SQL Injection entry via POST /search searchText (`routes/search.js:11`)](#finding-1)
  - [CRITICAL: Intrinsic SQL concatenation sink in searchByName (`service/search.js:4`)](#finding-2)
  - [CRITICAL: test (`service/search.js:6`)](#finding-3)
  - [CRITICAL: SQL Injection entry via GET /api/search query searchText (`routes/api.js:7`)](#finding-4)
  - [CRITICAL: Hardcoded seed credentials including admin password (`bootstrapdb.js:43`)](#finding-5)
  - [CRITICAL: Plaintext password storage without hashing (`bootstrapdb.js:34`)](#finding-6)
  - [HIGH: Reflected XSS render via POST /search searchResult (`routes/search.js:17`)](#finding-7)
  - [HIGH: Plaintext password storage without hashing (`bootstrapdb.js:30`)](#finding-8)
  - [HIGH: Reflected XSS via unescaped Pug render of searchText (`views/searchResult.pug:4`)](#finding-9)
  - [MEDIUM: Verbose SQLite error disclosure in GET /api/search (`routes/api.js:11`)](#finding-10)
  - [MEDIUM: Log injection via unsanitized req.query logging (`routes/api.js:8`)](#finding-11)
  - [LOW: Missing security headers and CSP baseline amplifies XSS (`app.js:23`)](#finding-12)
  - [LOW: Sensitive SQL errors and DB rows logged to stdout in shared search service (`service/search.js:9`)](#finding-13)

<a id="confirmed"></a>
## Confirmed (13)

<a id="finding-1"></a>
### CRITICAL SQL Injection entry via POST /search searchText
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.98
- Location: `routes/search.js:11-13`
- Vulnerable code (`routes/search.js`):
```javascript
const searchText = req.body.searchText; searchService.searchByName(searchText,...)
```
- Taint Flow:
  - **Source**: `POST /search body param searchText`
  - **Path**:
    - `routes/search.js:11 req.body.searchText`
    - `routes/search.js:13 searchByName(searchText)`
    - `service/search.js:6 db.all concatenation`
  - **Sink**: `sqlite db.all with concatenated LIKE query`
- Evidence: const searchText = req.body.searchText;  searchService.searchByName(searchText, function (err, ret) {
  - Validation: routes/search.js:11 reads req.body.searchText with no validation; routes/search.js:13 forwards to searchByName; service/search.js:6 concatenates into db.all; app.js:30 mounts /search unauthenticated with urlencoded parser app.js:24
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/search.js:11 reads req.body.searchText with no validation; routes/search.js:13 forwards to searchByName; service/search.js:6 concatenates into db.all; app.js:30 mounts /search unauthenticated with urlencoded parser app.js:24 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl -s -X POST --data-urlencode "searchText=' UNION ALL SELECT id,username,password FROM user-- " http://localhost:3000/search | head`
  - Control Command: `curl -s -X POST --data-urlencode "searchText=' UNION ALL SELECT id,username,password FROM user-- " http://localhost:3000/search | head --control`
- Patch:
  - **Summary**: Use parameterized query: db.all("select ... where name like ?", ['%'+searchText+'%']) and validate searchText type/length.
  - +2 duplicate(s): `service/search.js:6`, `routes/search.js:10`

<a id="finding-2"></a>
### CRITICAL Intrinsic SQL concatenation sink in searchByName
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.98
- Location: `service/search.js:4-7`
- Vulnerable code (`service/search.js`):
```javascript
db.all("select id,name,description from item where name like '%" + searchText + "%'", [], ...)
```
- Taint Flow:
  - **Source**: `searchText argument from route handlers`
  - **Path**:
    - `service/search.js:4 searchText param`
    - `service/search.js:6 string concat into db.all`
  - **Sink**: `sqlite3 db.all dynamic SQL`
- Evidence: const searchByName = function (searchText, cb) {  db.all("select id,name,description from item where name like '%" + searchText + "%'", [], function (err, rows) {
  - Validation: service/search.js:6 db.all("... like '%" + searchText + "%'",...) string-concatenates parameter; called unauthenticated from routes/search.js:13 and routes/api.js:10; no parameterization/sanitization in service/search.js:4-7
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: service/search.js:6 db.all("... like '%" + searchText + "%'",...) string-concatenates parameter; called unauthenticated from routes/search.js:13 and routes/api.js:10; no parameterization/sanitization in service/search.js:4-7 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `node -e "require('./service/search').searchByName(\"' OR '1'='1\",(e,r)=>console.log(e||r))"`
  - Control Command: `node -e "require('./service/search').searchByName(\"' OR '1'='1\",(e,r)=>console.log(e||r))" --control`
- Patch:
  - **Summary**: Replace string concat with placeholder: db.all("select id,name,description from item where name like ?", ['%'+searchText+'%'],...).

<a id="finding-3"></a>
### CRITICAL test
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.98
- Location: `service/search.js:6-6`
- Vulnerable code (`service/search.js`):
```javascript
const searchText = req.body.searchText; searchService.searchByName(searchText,...)
```
- Evidence: db.all test
  - Validation: routes/search.js:11 reads req.body.searchText with no validation; routes/search.js:13 forwards to searchByName; service/search.js:6 concatenates into db.all; app.js:30 mounts /search unauthenticated with urlencoded parser app.js:24
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/search.js:11 reads req.body.searchText with no validation; routes/search.js:13 forwards to searchByName; service/search.js:6 concatenates into db.all; app.js:30 mounts /search unauthenticated with urlencoded parser app.js:24 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use parameterized query: db.all("select ... where name like ?", ['%'+searchText+'%']) and validate searchText type/length.
  - +2 duplicate(s): `service/search.js:6`, `routes/search.js:10`

<a id="finding-4"></a>
### CRITICAL SQL Injection entry via GET /api/search query searchText
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.97
- Location: `routes/api.js:7-10`
- Vulnerable code (`routes/api.js`):
```javascript
const searchText = req.query.searchText !== undefined ? req.query.searchText : '';
```
- Taint Flow:
  - **Source**: `GET /api/search query searchText`
  - **Path**:
    - `routes/api.js:7 req.query.searchText`
    - `routes/api.js:10 searchByName(searchText)`
    - `service/search.js:6 db.all concatenation`
  - **Sink**: `sqlite db.all concatenated query`
- Evidence: const searchText = req.query.searchText !== undefined ? req.query.searchText : ''; console.log(req.query); console.log('search text: ' + searchText); searchService.searchByName(searchText, function (err, ret) {
  - Validation: routes/api.js:7 reads req.query.searchText unauthenticated; routes/api.js:10 forwards to searchByName; service/search.js:6 concatenates into sqlite db.all; app.js:31 mounts /api without guards
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/api.js:7 reads req.query.searchText unauthenticated; routes/api.js:10 forwards to searchByName; service/search.js:6 concatenates into sqlite db.all; app.js:31 mounts /api without guards | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl -s "http://localhost:3000/api/search?searchText=%27%20UNION%20ALL%20SELECT%20id,username,password%20FROM%20user--%20" | head`
  - Control Command: `curl -s "http://localhost:3000/api/search?searchText=%27%20UNION%20ALL%20SELECT%20id,username,password%20FROM%20user--%20" | head --control`
- Patch:
  - **Summary**: Use parameterized LIKE query and validate/coerce req.query.searchText to string with length limit.

<a id="finding-5"></a>
### CRITICAL Hardcoded seed credentials including admin password
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `bootstrapdb.js:43-46`
- Vulnerable code (`bootstrapdb.js`):
```javascript
userTbl.run('admin', 'S3cr37P@$$w0rD!');
```
- Taint Flow:
  - **Source**: `static strings in seed script`
  - **Sink**: `hardcoded credentials into user table/image`
- Evidence: userTbl.run('admin', 'S3cr37P@$$w0rD!'); userTbl.run('user1', 'bad_password'); userTbl.run('user2', 'worse'); userTbl.run('user3', 'fail');
  - Validation: bootstrapdb.js:43 userTbl.run('admin','S3cr37P@$$w0rD!') plus bootstrapdb.js:44-46 weak passwords hardcoded in repo and seeded into db/vulny.db via service/search.js:2 file DB
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bootstrapdb.js:43 userTbl.run('admin','S3cr37P@$$w0rD!') plus bootstrapdb.js:44-46 weak passwords hardcoded in repo and seeded into db/vulny.db via service/search.js:2 file DB | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `grep -rn S3cr37 --include=*.js .; ls -l db/vulny.db`
  - Control Command: `grep -rn S3cr37 --include=*.js .; ls -l db/vulny.db --control`
- Patch:
  - **Summary**: Remove hardcoded passwords; seed via env secrets and store bcrypt hashes, keep seed DB out of image.

<a id="finding-6"></a>
### CRITICAL Plaintext password storage without hashing
- CVSS: **8.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.92
- Location: `bootstrapdb.js:34-34`
- Vulnerable code (`bootstrapdb.js`):
```javascript
CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username NVARCHAR(1024) NOT NULL, password TEXT NOT NULL)
```
- Taint Flow:
  - **Source**: `seed design without hashing`
  - **Path**:
    - `bootstrapdb.js:34 password TEXT schema`
    - `bootstrapdb.js:43 plaintext insert`
  - **Sink**: `plaintext credential persistence in sqlite file`
- Evidence: db.run('CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username NVARCHAR(1024) NOT NULL, password TEXT NOT NULL)', function (err) {
  - Validation: bootstrapdb.js:34 CREATE TABLE user(... password TEXT ...) with bootstrapdb.js:43-46 plaintext inserts and no hashing; exfiltratable via service/search.js:6 SQLi UNION
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bootstrapdb.js:34 CREATE TABLE user(... password TEXT ...) with bootstrapdb.js:43-46 plaintext inserts and no hashing; exfiltratable via service/search.js:6 SQLi UNION | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl -s -X POST --data-urlencode "searchText=item%' union all select * from user; -- " http://localhost:3000/search | head`
  - Control Command: `curl -s -X POST --data-urlencode "searchText=item%' union all select * from user; -- " http://localhost:3000/search | head --control`
- Patch:
  - **Summary**: Hash passwords with bcrypt/scrypt before INSERT and never persist plaintext.

<a id="finding-7"></a>
### HIGH Reflected XSS render via POST /search searchResult
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.96
- Location: `routes/search.js:17-17`
- Vulnerable code (`routes/search.js`):
```javascript
h1!= 'Search Results for: ' + searchText
```
- Taint Flow:
  - **Source**: `POST /search body searchText`
  - **Path**:
    - `routes/search.js:11 req.body.searchText`
    - `service/search.js:16 ret.searchText`
    - `routes/search.js:17 res.render`
    - `views/searchResult.pug:4 h1!= searchText`
  - **Sink**: `Pug unescaped h1!= render`
- Evidence: res.render('searchResult', ret)
  - Validation: routes/search.js:11 tainted searchText echoed via service/search.js:16 ret.searchText=searchText then routes/search.js:17 res.render('searchResult',ret) to views/searchResult.pug:4 h1!= unescaped output
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/search.js:11 tainted searchText echoed via service/search.js:16 ret.searchText=searchText then routes/search.js:17 res.render('searchResult',ret) to views/searchResult.pug:4 h1!= unescaped output | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl -s -X POST --data-urlencode "searchText=<script>alert(1)</script>" http://localhost:3000/search | grep -i script`
  - Control Command: `curl -s -X POST --data-urlencode "searchText=<script>alert(1)</script>" http://localhost:3000/search | grep -i script --control`
- Patch:
  - **Summary**: Change views/searchResult.pug:4 h1!= to h1= for auto-escaping and validate searchText.

<a id="finding-8"></a>
### HIGH Plaintext password storage without hashing
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `bootstrapdb.js:30-34`
- Vulnerable code (`bootstrapdb.js`):
```javascript
db.run('CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username NVARCHAR(1024) NOT NULL, password TEXT NOT NULL)'
```
- Taint Flow:
  - **Source**: `seed inserts`
  - **Sink**: `plaintext password storage in SQLite user table`
- Evidence: bootstrapdb.js:30 CREATE TABLE user with password TEXT and bootstrapdb.js:43-46 inserts without any hash; login-equivalent SQLi can read plaintext
  - Validation: bootstrapdb.js:30 CREATE TABLE user password TEXT with no hash column and bootstrapdb.js:43 inserts admin/S3cr37P@$$w0rD! and bad_password plaintext via db.prepare without hashing
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bootstrapdb.js:30 CREATE TABLE user password TEXT with no hash column and bootstrapdb.js:43 inserts admin/S3cr37P@$$w0rD! and bad_password plaintext via db.prepare without hashing | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Hash passwords with bcrypt/scrypt before INSERT in bootstrapdb.js:43 and change schema to store hash, never plaintext; remove seed secrets from repo

<a id="finding-9"></a>
### HIGH Reflected XSS via unescaped Pug render of searchText
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `views/searchResult.pug:4-4`
- Vulnerable code (`views/searchResult.pug`):
```pug
h1!= 'Search Results for: ' + searchText
```
- Taint Flow:
  - **Source**: `POST /search body field searchText`
  - **Path**:
    - `routes/search.js:11 req.body.searchText`
    - `service/search.js:18 ret.searchText assignment`
    - `routes/search.js:17 res.render('searchResult', ret)`
    - `views/searchResult.pug:4 h1!= render`
  - **Sink**: `Pug unescaped output h1!=`
- Evidence: Cross-unit flow: routes/search.js:11 req.body.searchText -> service/search.js:15-18 ret.searchText passthrough -> routes/search.js:17 res.render -> views/searchResult.pug:4 unescaped render
  - Validation: routes/search.js:11 req.body.searchText via service/search.js:18 ret.searchText to routes/search.js:17 res.render reaches views/searchResult.pug:4 h1!= unescaped output with no escaping or CSP (views/layout.pug:1-7)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/search.js:11 req.body.searchText via service/search.js:18 ret.searchText to routes/search.js:17 res.render reaches views/searchResult.pug:4 h1!= unescaped output with no escaping or CSP (views/layout.pug:1-7) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Change views/searchResult.pug:4 h1!= to escaped h1= and add CSP/helmet plus output-encoding validation

<a id="finding-10"></a>
### MEDIUM Verbose SQLite error disclosure in GET /api/search
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.92
- Location: `routes/api.js:11-12`
- Vulnerable code (`routes/api.js`):
```javascript
if (err) { res.json(err);
```
- Taint Flow:
  - **Source**: `query searchText inducing DB error`
  - **Path**:
    - `routes/api.js:7 attacker searchText`
    - `service/search.js:10 cb(err)`
    - `routes/api.js:12 res.json(err)`
  - **Sink**: `JSON error response disclosing internals`
- Evidence: if (err) { res.json(err);
  - Validation: service/search.js:10 cb(err) forwards raw sqlite error; routes/api.js:11-12 if(err) res.json(err) serializes internals unauthenticated to GET /api/search
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: service/search.js:10 cb(err) forwards raw sqlite error; routes/api.js:11-12 if(err) res.json(err) serializes internals unauthenticated to GET /api/search | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl -s "http://localhost:3000/api/search?searchText=%27" | head`
  - Control Command: `curl -s "http://localhost:3000/api/search?searchText=%27" | head --control`
- Patch:
  - **Summary**: Return generic error message and log details server-side instead of res.json(err).
  - +1 duplicate(s): `routes/api.js:11`

<a id="finding-11"></a>
### MEDIUM Log injection via unsanitized req.query logging
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-117 | confidence: 0.85
- Location: `routes/api.js:8-9`
- Vulnerable code (`routes/api.js`):
```javascript
console.log(req.query); console.log('search text: ' + searchText);
```
- Taint Flow:
  - **Source**: `GET /api/search query string`
  - **Path**:
    - `routes/api.js:7 req.query.searchText`
    - `routes/api.js:8 console.log(req.query)`
  - **Sink**: `console.log unsanitized attacker input`
- Evidence: console.log(req.query); console.log('search text: ' + searchText);
  - Validation: routes/api.js:7 attacker-controlled req.query.searchText logged unsanitized via routes/api.js:8 console.log(req.query) and routes/api.js:9 console.log('search text: '+searchText) with no CRLF neutralization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: routes/api.js:7 attacker-controlled req.query.searchText logged unsanitized via routes/api.js:8 console.log(req.query) and routes/api.js:9 console.log('search text: '+searchText) with no CRLF neutralization | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl -s "http://localhost:3000/api/search?searchText=foo%0d%0aFORGED" `
  - Control Command: `curl -s "http://localhost:3000/api/search?searchText=foo%0d%0aFORGED"  --control`
- Patch:
  - **Summary**: Remove raw query logging or sanitize with structured logger stripping CR/LF/control chars.
  - +3 duplicate(s): `routes/api.js:8`, `app.js:41`, `app.js:42`

<a id="finding-12"></a>
### LOW Missing security headers and CSP baseline amplifies XSS
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-693 | confidence: 0.85
- Location: `app.js:23-27`
- Vulnerable code (`app.js`):
```javascript
app.use(logger('dev'));
```
- Taint Flow:
  - **Source**: `missing hardening baseline`
  - **Path**:
    - `app.js:12 app=express()`
    - `app.js:23-27 middleware without security headers`
    - `views/searchResult.pug:4 unescaped render`
  - **Sink**: `responses without CSP/HSTS/X-Frame-Options`
- Evidence: app.js:23-27 middleware stack is logger/json/urlencoded/cookieParser/static with no helmet, no CSP, no HSTS; package.json has no helmet dependency
  - Validation: app.js:23-27 middleware is logger/json/urlencoded/cookieParser/static with no helmet/CSP, package.json:10 has no helmet, views/layout.pug:1-7 has no CSP meta; amplifies views/searchResult.pug:4 XSS
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.js:23-27 middleware is logger/json/urlencoded/cookieParser/static with no helmet/CSP, package.json:10 has no helmet, views/layout.pug:1-7 has no CSP meta; amplifies views/searchResult.pug:4 XSS | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add helmet() with CSP/HSTS/X-Frame-Options in app.js:23 and CSP meta in views/layout.pug

<a id="finding-13"></a>
### LOW Sensitive SQL errors and DB rows logged to stdout in shared search service
- CVSS: **2.2** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.8
- Location: `service/search.js:9-15`
- Vulnerable code (`service/search.js`):
```javascript
console.log('error ' + err);
```
- Taint Flow:
  - **Source**: `untrusted searchText plus DB-derived err/rows`
  - **Path**:
    - `routes/search.js:11 req.body.searchText`
    - `routes/api.js:7 req.query.searchText`
    - `service/search.js:6 db.all(...) -> err/rows`
    - `service/search.js:9 console.log('error '+err)`
    - `service/search.js:14 console.log('rows? '+rows)`
  - **Sink**: `console.log of err and rows in shared service`
- Evidence: service/search.js:9 logs SQL err; service/search.js:14 logs full rows array; service/search.js:15 logs row count — shared sink for both /search and /api/search
  - Validation: service/search.js:9 console.log('error '+err) and service/search.js:14 console.log('rows? '+rows) log attacker-influenced SQL errors and full DB rows to stdout on both /search and /api/search paths
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: service/search.js:9 console.log('error '+err) and service/search.js:14 console.log('rows? '+rows) log attacker-influenced SQL errors and full DB rows to stdout on both /search and /api/search paths | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove verbose console.log of err/rows in service/search.js:9,14-15; log generic message with structured logger and redact PII/secrets
