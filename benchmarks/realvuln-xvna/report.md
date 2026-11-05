# Cerberus Report

**Findings:** 17 actionable — 5 critical, 8 high, 3 medium, 1 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 12 false positives — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 5 | 0 / 5 (0%) | 5 |
| HIGH | 8 | 0 / 8 (0%) | 8 |
| MEDIUM | 3 | 0 / 3 (0%) | 3 |
| LOW | 1 | 0 / 1 (0%) | 1 |
| **TOTAL** | **17** | **0 / 17 (0%)** | **17** |

## Table of Contents

- [Confirmed (17)](#confirmed)
  - [CRITICAL: Server-side JavaScript injection (eval) RCE via /eval (`index.js:202`)](#finding-1)
  - [CRITICAL: NoSQL injection login bypass (`index.js:44`)](#finding-2)
  - [CRITICAL: NoSQL operator injection in GET /getdata via JSON.parse (`index.js:83`)](#finding-3)
  - [CRITICAL: NoSQL injection + verbose error disclosure in POST /a6_misconfig (`index.js:179`)](#finding-4)
  - [CRITICAL: Insecure deserialization RCE via node-serialize (`index.js:218`)](#finding-5)
  - [HIGH: Missing authentication on GET /ping (pre-auth command execution) (`index.js:152`)](#finding-6)
  - [HIGH: Missing authentication on GET /eval (pre-auth code execution) (`index.js:198`)](#finding-7)
  - [HIGH: Default hardcoded admin credentials in seed data (`collection/login.json:3`)](#finding-8)
  - [HIGH: Missing authentication on GET /getdata user lookup (`index.js:81`)](#finding-9)
  - [HIGH: Sensitive data exposure (plaintext passwords) in GET /a3sensitive (`index.js:106`)](#finding-10)
  - [HIGH: Missing authorization (IDOR) on POST /insecure_dor bank lookup (`index.js:142`)](#finding-11)
  - [HIGH: Reflected XSS via /xss_r echoed search + explicit trustAsHtml bypass (`public/app/js/controllers/a7_xss_reflected.js:10`)](#finding-12)
  - [HIGH: Missing authentication on POST /insecure_deserialization (pre-auth deserialization) (`index.js:207`)](#finding-13)
  - [MEDIUM: Denial of service via hanging GET /a4xxe handler (no response sent) (`index.js:119`)](#finding-14)
  - [MEDIUM: Plaintext credentials written to logs in login handler (`index.js:40`)](#finding-15)
  - [MEDIUM: Session fixation: no session regeneration after login (`index.js:48`)](#finding-16)
  - [LOW: Uncaught JSON.parse exception enables DoS in login handler (`index.js:31`)](#finding-17)

<a id="confirmed"></a>
## Confirmed (17)

<a id="finding-1"></a>
### CRITICAL Server-side JavaScript injection (eval) RCE via /eval
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.98
- Location: `index.js:202-203`
- Vulnerable code (`index.js`):
```javascript
result = eval(id + id2);
```
- Taint Flow:
  - **Source**: `GET /eval query params id, id2 (unauthenticated)`
  - **Path**:
    - `public/app/js/controllers/eval.js:9 userid,userid2 -> GET /eval`
    - `index.js:200 var id=req.query['id']`
    - `index.js:201 var id2=req.query['id2']`
    - `index.js:202 eval(id+id2)`
  - **Sink**: `eval() server-side JS execution`
- Evidence: Cross-unit: public/app/js/controllers/eval.js:9 builds GET /eval?id=+userid+&id2=+userid2 -> index.js:200-202 var id=req.query['id']; var id2=req.query['id2']; result=eval(id+id2) -> index.js:203 res.json({cmd:result}); partial public/app/partials/eval.html renders via ng-bind-html
  - Validation: index.js:200-202 var id=req.query['id']; var id2=req.query['id2']; result=eval(id+id2) with no auth/sanitizer; route index.js:198 has no session check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:200-202 var id=req.query['id']; var id2=req.query['id2']; result=eval(id+id2) with no auth/sanitizer; route index.js:198 has no session check | consensus: 1/1 confirmed | triage: Unauthenticated eval(id+id2) server-side JS execution
- Patch:
  - **Summary**: Remove /eval endpoint or replace eval(id+id2) with allowlisted parsing; never eval query input

<a id="finding-2"></a>
### CRITICAL NoSQL injection login bypass
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `index.js:44-44`
- Vulnerable code (`index.js`):
```javascript
dbase.collection("login").find(searchstring).toArray(function (err, result) {
```
- Taint Flow:
  - **Source**: `POST body`
  - **Path**:
    - `index.js:31`
  - **Sink**: `Mongo find`
- Evidence: dbase.collection("login").find(searchstring).toArray(function (err, result) {
  - Validation: index.js:27-31 branches on password indexOf('{') then JSON.parse(req.body.password) into selector, reaching index.js:44 find(searchstring) with no $/operator rejection allowing {"$gt":""} auth bypass
  - Alternatives considered: exec('ping ' + id, function (err, stdout, stderr) { | secret: "Your secret key"
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:27-31 branches on password indexOf('{') then JSON.parse(req.body.password) into selector, reaching index.js:44 find(searchstring) with no $/operator rejection allowing {"$gt":""} auth bypass | consensus: 1/1 confirmed | triage: JSON.parse password into selector allows $gt auth bypass
- Patch:
  - **Summary**: Enforce string-typed email/password, reject objects and keys starting with $/containing operators before Mongo find; never JSON.parse input into selector.

<a id="finding-3"></a>
### CRITICAL NoSQL operator injection in GET /getdata via JSON.parse
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `index.js:83-87`
- Vulnerable code (`index.js`):
```javascript
id = JSON.parse(id);
```
- Taint Flow:
  - **Source**: `GET /getdata?id= unauthenticated query param`
  - **Path**:
    - `public/app/js/controllers/a1_injection_sql.js:7 GET /getdata?id=`
    - `index.js:82 var id=req.query['id']`
    - `index.js:83 JSON.parse(id)`
    - `index.js:87 find({id:id})`
  - **Sink**: `MongoDB find() selector with operator injection`
- Evidence: Cross-unit: public/app/js/controllers/a1_injection_sql.js:7 $http.get("/getdata?id="+userid) -> index.js:82-83 var id=req.query['id']; id=JSON.parse(id); -> index.js:87 find({id:id}) on users collection; attacker can send {"$gt":0} or {"$ne":null} to match arbitrary docs
  - Validation: index.js:82-83 var id=req.query['id']; id=JSON.parse(id) then index.js:87 find({id:id}) allows operator object e.g. {"$gt":0} to match arbitrary docs
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:82-83 var id=req.query['id']; id=JSON.parse(id) then index.js:87 find({id:id}) allows operator object e.g. {"$gt":0} to match arbitrary docs | consensus: 1/1 confirmed | triage: JSON.parse id into find({id}) allows $gt/$ne match-all
- Patch:
  - **Summary**: Remove JSON.parse of query input; validate id as scalar string/number and reject objects containing $ operators

<a id="finding-4"></a>
### CRITICAL NoSQL injection + verbose error disclosure in POST /a6_misconfig
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `index.js:179-186`
- Vulnerable code (`index.js`):
```javascript
var accno = JSON.parse(req.body.accountno);
```
- Taint Flow:
  - **Source**: `POST /a6_misconfig body.accountno unauthenticated`
  - **Path**:
    - `public/app/js/controllers/a6_misconfig.js:11 POST accountno`
    - `index.js:179 JSON.parse(req.body.accountno)`
    - `index.js:186 find({accountno:accno})`
  - **Sink**: `MongoDB find selector + verbose error disclosure`
- Evidence: Cross-unit: public/app/js/controllers/a6_misconfig.js:11 posts accountno -> index.js:179 JSON.parse(req.body.accountno) -> index.js:186 find({accountno:accno}); errors echoed via res.json(err) at index.js:183,188 disclosing stack/query details
  - Validation: index.js:179 var accno=JSON.parse(req.body.accountno) then index.js:186 find({accountno:accno}); index.js:183,188 res.json(err) echoes DB errors
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:179 var accno=JSON.parse(req.body.accountno) then index.js:186 find({accountno:accno}); index.js:183,188 res.json(err) echoes DB errors | consensus: 1/1 confirmed | triage: JSON.parse accountno into selector plus verbose error disclosure
- Patch:
  - **Summary**: Stop JSON.parse into selector, type-validate accountno scalar and reject $ keys; do not return raw err to client

<a id="finding-5"></a>
### CRITICAL Insecure deserialization RCE via node-serialize
- CVSS: **8.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 0.9
- Location: `index.js:218-218`
- Vulnerable code (`index.js`):
```javascript
serialize.unserialize(objS).say();
```
- Taint Flow:
  - **Source**: `POST /insecure_deserialization body.userid`
  - **Path**:
    - `public/app/js/controllers/a8_insecure_deserialization.js:5 POST userid`
    - `index.js:208 var id=req.body.userid.toString()`
    - `index.js:216 serialize.serialize(obj)`
    - `index.js:218 serialize.unserialize(objS)`
  - **Sink**: `node-serialize unserialize code execution`
- Evidence: index.js:207-218 POST /insecure_deserialization reads req.body.userid.toString(), embeds in object then serialize.serialize/unserialize (node-serialize 0.0.4 per package.json:18); classic _$$ND_FUNC$$_ RCE: attacker value survives serialize and executes on unserialize eval; followed by cart lookup echoing search:id
  - Validation: index.js:208 id=req.body.userid.toString() embedded at index.js:216 serialize.serialize then index.js:218 serialize.unserialize(objS) evals _$$ND_FUNC$$_ prefix (node_modules/node-serialize/lib/serialize.js:63 eval); package.json:18 pins node-serialize 0.0.4
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:208 id=req.body.userid.toString() embedded at index.js:216 serialize.serialize then index.js:218 serialize.unserialize(objS) evals _$$ND_FUNC$$_ prefix (node_modules/node-serialize/lib/serialize.js:63 eval); package.json:18 pins node-serialize 0.0.4 | consensus: 1/1 confirmed | triage: Unauthenticated node-serialize _$$ND_FUNC$$_ RCE
- Patch:
  - **Summary**: Remove node-serialize; use JSON.parse/stringify only and never unserialize attacker-influenced strings.

<a id="finding-6"></a>
### HIGH Missing authentication on GET /ping (pre-auth command execution)
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.98
- Location: `index.js:152-152`
- Vulnerable code (`index.js`):
```javascript
app.get('/ping', function(req, res){
```
- Taint Flow:
  - **Source**: `unauthenticated GET /ping?id query parameter`
  - **Path**:
    - `index.js:153 req.query id`
    - `index.js:155 exec`
  - **Sink**: `child_process.exec shell command`
- Evidence: index.js:152 defines GET /ping with no session/auth check; handler at index.js:153-155 directly uses req.query id in exec; POST /service_login at index.js:60 is a separate endpoint never used as middleware
  - Validation: index.js:152 app.get('/ping') has no session check; index.js:153-155 exec('ping '+id) executes unauthenticated query input in shell
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:152 app.get('/ping') has no session check; index.js:153-155 exec('ping '+id) executes unauthenticated query input in shell | consensus: 1/1 confirmed | triage: No auth on /ping exposes shell exec pre-auth
- Patch:
  - **Summary**: Require auth and replace exec string concat with execFile allowlist without shell

<a id="finding-7"></a>
### HIGH Missing authentication on GET /eval (pre-auth code execution)
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.98
- Location: `index.js:198-198`
- Vulnerable code (`index.js`):
```javascript
app.get('/eval', function(req, res){
```
- Taint Flow:
  - **Source**: `unauthenticated GET /eval?id&id2 query parameters`
  - **Path**:
    - `index.js:200 req.query id`
    - `index.js:201 req.query id2`
    - `index.js:202 eval`
  - **Sink**: `eval() server-side JS execution`
- Evidence: index.js:198 defines GET /eval with no session/auth check; handler at index.js:200-202 uses req.query id/id2 in eval(); no service_login middleware enforced
  - Validation: index.js:198 app.get('/eval') has no session check; index.js:200-202 eval(id+id2) reachable pre-auth with no service_login middleware
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:198 app.get('/eval') has no session check; index.js:200-202 eval(id+id2) reachable pre-auth with no service_login middleware | consensus: 1/1 confirmed | triage: No auth on /eval exposes eval() pre-auth
- Patch:
  - **Summary**: Require auth and remove eval; same fix as XVNA-EVAL-RCE

<a id="finding-8"></a>
### HIGH Default hardcoded admin credentials in seed data
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `collection/login.json:3-5`
- Vulnerable code (`collection/login.json`):
```json
"email" : "***",
```
- Taint Flow:
  - **Source**: `hardcoded seed credential`
  - **Path**:
    - `collection/login.json:1 default credential seed`
    - `index.js:44 find(searchstring) auth`
  - **Sink**: `authentication with default password`
- Evidence: collection/login.json:1-5 seeds MongoDB login collection with plaintext default admin credential; used by POST /api/users auth check index.js:44
  - Validation: collection/login.json:1-5 seeds email admin@xvna.com password password in plaintext; used as auth selector at index.js:44 dbase.collection("login").find(searchstring)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: collection/login.json:1-5 seeds email admin@xvna.com password password in plaintext; used as auth selector at index.js:44 dbase.collection("login").find(searchstring) | consensus: 1/1 confirmed | triage: Plaintext default admin@xvna.com/password seeds auth bypass
- Patch:
  - **Summary**: Remove checked-in default credential, require unique passwords and store salted hashes, not plaintext seed

<a id="finding-9"></a>
### HIGH Missing authentication on GET /getdata user lookup
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `index.js:81-81`
- Vulnerable code (`index.js`):
```javascript
app.get('/getdata', function(req, res){
```
- Taint Flow:
  - **Source**: `unauthenticated network client GET /getdata?id=`
  - **Path**:
    - `public/app/js/controllers/a1_injection_sql.js:7 frontend GET /getdata?id=`
    - `index.js:81 route entry without session check`
    - `index.js:87 dbase.collection("users").find sink`
  - **Sink**: `MongoDB users find returning PII without authorization`
- Evidence: index.js:81 route handler has no req.session/user check in body index.js:81-96; only gate is POST /service_login (index.js:60) which is client-side redirect and never enforced on data routes; frontend public/app/js/controllers/a1_injection_sql.js calls GET /getdata?id= with no token
  - Validation: index.js:81-87 app.get('/getdata') has no req.session check and reaches dbase.collection("users").find at index.js:87; service_login at index.js:60 is separate POST never used as middleware
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:81-87 app.get('/getdata') has no req.session check and reaches dbase.collection("users").find at index.js:87; service_login at index.js:60 is separate POST never used as middleware | consensus: 1/1 confirmed | triage: No session check on /getdata exposes users PII pre-auth
- Patch:
  - **Summary**: Add session/auth middleware to /getdata and enforce authorization before Mongo find

<a id="finding-10"></a>
### HIGH Sensitive data exposure (plaintext passwords) in GET /a3sensitive
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.95
- Location: `index.js:106-106`
- Vulnerable code (`index.js`):
```javascript
res.json({cmd: result, search: id});
```
- Taint Flow:
  - **Source**: `GET /a3sensitive?id= unauthenticated`
  - **Path**:
    - `public/app/js/controllers/a3_sensitive.js:7 GET /a3sensitive?id=`
    - `index.js:99 var id=req.query['id']`
    - `index.js:103 find({id:parseInt(id)})`
    - `index.js:106 res.json({cmd:result})`
  - **Sink**: `HTTP response disclosing plaintext passwords/PII`
- Evidence: index.js:98-103 GET /a3sensitive takes req.query id, find({id:parseInt(id)}) and res.json({cmd:result}) returns full user documents including name,password,age per collection/users.json; no auth check; reachable via public/app/js/controllers/a3_sensitive.js:7
  - Validation: index.js:98-106 GET /a3sensitive find({id:parseInt(id)}) then res.json({cmd:result}) returns full user docs including password per collection/users.json; no auth at index.js:98
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:98-106 GET /a3sensitive find({id:parseInt(id)}) then res.json({cmd:result}) returns full user docs including password per collection/users.json; no auth at index.js:98 | consensus: 1/1 confirmed | triage: Unauthenticated PII/password disclosure via /a3sensitive
- Patch:
  - **Summary**: Add authentication/authorization and return only non-sensitive fields; never return password hashes/plaintext

<a id="finding-11"></a>
### HIGH Missing authorization (IDOR) on POST /insecure_dor bank lookup
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `index.js:142-143`
- Vulnerable code (`index.js`):
```javascript
dbase.collection("a5_insecure_dor").find({ accountno: accno }).toArray(function(err, result) {
```
- Taint Flow:
  - **Source**: `POST /insecure_dor body.accountno unauthenticated`
  - **Path**:
    - `public/app/js/controllers/a5_insecure_dor.js:7 accountno message`
    - `index.js:138 var accno=req.body.accountno`
    - `index.js:142 find({accountno:accno})`
  - **Sink**: `cross-user bank record read without authorization`
- Evidence: Endpoint index.js:137 app.post('/insecure_dor') reads req.body.accountno at index.js:138 and uses verbatim as {accountno:accno} at index.js:142 with no session check, no ownership check; frontend public/app/js/controllers/a5_insecure_dor.js:7 posts arbitrary accountno; any account 1001-1010 in collection/a5_insecure_dor.json retrievable
  - Validation: index.js:137-142 app.post('/insecure_dor') reads req.body.accountno at index.js:138 and find({accountno:accno}) at index.js:142 with no req.session/user or ownership check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:137-142 app.post('/insecure_dor') reads req.body.accountno at index.js:138 and find({accountno:accno}) at index.js:142 with no req.session/user or ownership check | consensus: 1/1 confirmed | triage: Unauthenticated arbitrary accountno lookup with no ownership check
- Patch:
  - **Summary**: Require authenticated session and enforce ownership check that accno belongs to req.session.user before find

<a id="finding-12"></a>
### HIGH Reflected XSS via /xss_r echoed search + explicit trustAsHtml bypass
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `public/app/js/controllers/a7_xss_reflected.js:10-10`
- Vulnerable code (`public/app/js/controllers/a7_xss_reflected.js`):
```javascript
$scope.trustedMessage =  $sce.trustAsHtml( response['data'].search );
```
- Taint Flow:
  - **Source**: `GET /xss_r?id= attacker input reflected as search`
  - **Path**:
    - `index.js:163 var id=req.query['id']`
    - `index.js:170 res.json({cmd:result, search:id})`
    - `public/app/js/controllers/a7_xss_reflected.js:10 trustAsHtml(search)`
  - **Sink**: `$sce.trustAsHtml + ng-bind-html DOM XSS sink`
- Evidence: Cross-unit stored/reflected flow: index.js:162-170 GET /xss_r takes req.query['id'], echoes as search:id in JSON; public/app/js/controllers/a7_xss_reflected.js:10 passes response['data'].search to $sce.trustAsHtml; public/app/partials/a7_xss_reflected.html:34 renders via ng-bind-html=trustedMessage bypassing Angular sanitization
  - Validation: index.js:163 var id=req.query['id']; index.js:170 res.json({cmd:result,search:id}) echoes input; public/app/js/controllers/a7_xss_reflected.js:10 $sce.trustAsHtml(response['data'].search) with ng-bind-html at public/app/partials/a7_xss_reflected.html:34 bypasses escaping
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:163 var id=req.query['id']; index.js:170 res.json({cmd:result,search:id}) echoes input; public/app/js/controllers/a7_xss_reflected.js:10 $sce.trustAsHtml(response['data'].search) with ng-bind-html at public/app/partials/a7_xss_reflected.html:34 bypasses escaping | consensus: 1/1 confirmed | triage: Reflected id echoed as search then trustAsHtml + ng-bind-html
- Patch:
  - **Summary**: Remove $sce.trustAsHtml and ng-bind-html for search; output-encode with {{ }} interpolation

<a id="finding-13"></a>
### HIGH Missing authentication on POST /insecure_deserialization (pre-auth deserialization)
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.9
- Location: `index.js:207-207`
- Vulnerable code (`index.js`):
```javascript
app.post('/insecure_deserialization', function (req, res) {
```
- Taint Flow:
  - **Source**: `unauthenticated POST /insecure_deserialization userid body`
  - **Path**:
    - `index.js:208 req.body.userid`
    - `index.js:216 serialize.serialize`
    - `index.js:218 unserialize`
  - **Sink**: `node-serialize unserialize deserialization`
- Evidence: index.js:207 defines POST /insecure_deserialization with no session/auth check; handler at index.js:208 uses req.body.userid in serialize/unserialize + Mongo lookup; reachable without login
  - Validation: index.js:207 app.post('/insecure_deserialization') has no req.session.user/auth guard unlike index.js:57-66 service_login gate, exposing node-serialize sink at index.js:218 pre-auth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:207 app.post('/insecure_deserialization') has no req.session.user/auth guard unlike index.js:57-66 service_login gate, exposing node-serialize sink at index.js:218 pre-auth | consensus: 1/1 confirmed | triage: No auth on /insecure_deserialization exposes unserialize pre-auth
- Patch:
  - **Summary**: Require authenticated session (req.session.user) before /insecure_deserialization handler; deny unauthenticated POST.

<a id="finding-14"></a>
### MEDIUM Denial of service via hanging GET /a4xxe handler (no response sent)
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `index.js:119-120`
- Vulnerable code (`index.js`):
```javascript
app.get('/a4xxe', function(req, res){
    var id = req.query['id'];
```
- Taint Flow:
  - **Source**: `unauthenticated GET /a4xxe request`
  - **Path**:
    - `index.js:119 GET /a4xxe entry`
    - `index.js:133 console.log only, no response`
  - **Sink**: `missing HTTP response (hanging connection)`
- Evidence: index.js:119-135 handler for GET /a4xxe never calls res.send/res.json/res.end; only console.log(orderIds) at index.js:133. Every request holds connection open until timeout.
  - Validation: index.js:119-133 app.get('/a4xxe') never calls res.send/res.json/res.end; only console.log(orderIds) at index.js:133, holding connection until timeout
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:119-133 app.get('/a4xxe') never calls res.send/res.json/res.end; only console.log(orderIds) at index.js:133, holding connection until timeout | consensus: 1/1 confirmed | triage: GET /a4xxe never sends response, holds connection until timeout
- Patch:
  - **Summary**: Send HTTP response (res.json/res.send) on all paths of /a4xxe or remove stub endpoint

<a id="finding-15"></a>
### MEDIUM Plaintext credentials written to logs in login handler
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.9
- Location: `index.js:40-40`
- Vulnerable code (`index.js`):
```javascript
console.log("searchstring", searchstring)
```
- Taint Flow:
  - **Source**: `POST /api/users JSON body email/password`
  - **Path**:
    - `index.js:25 POST /api/users req.body.email/password source`
    - `index.js:29 searchstring construction`
    - `index.js:40 console.log sink`
  - **Sink**: `console.log of object containing plaintext password`
- Evidence: index.js:40 logs searchstring built from req.body.email/password at index.js:29-38; plaintext credential material written to stdout/logs; also logged via req.session.user at index.js:61/73
  - Validation: index.js:29-38 searchstring built from req.body.email/password; index.js:40 console.log("searchstring",searchstring) writes plaintext password to stdout/logs
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:29-38 searchstring built from req.body.email/password; index.js:40 console.log("searchstring",searchstring) writes plaintext password to stdout/logs | consensus: 1/1 confirmed | triage: Plaintext email/password written to stdout via console.log
- Patch:
  - **Summary**: Remove logging of searchstring/password; log only non-sensitive metadata or redacted values

<a id="finding-16"></a>
### MEDIUM Session fixation: no session regeneration after login
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-384 | confidence: 0.8
- Location: `index.js:48-50`
- Vulnerable code (`index.js`):
```javascript
if (result.length > 0) {
					req.session.user = cope;
```
- Taint Flow:
  - **Source**: `login POST /api/users credentials + attacker-set session cookie`
  - **Path**:
    - `index.js:26 cope=req.body`
    - `index.js:49 req.session.user=cope`
    - `index.js:62 service_login trust`
  - **Sink**: `authenticated session without ID rotation`
- Evidence: index.js:48-50 assigns req.session.user=cope on successful login with no req.session.regenerate(); attacker-fixated connect.sid is retained after privilege change
  - Validation: index.js:48-50 sets req.session.user=cope on login with no req.session.regenerate(); repo grep shows regenerate only in node_modules, never in index.js, so pre-login session ID is retained
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:48-50 sets req.session.user=cope on login with no req.session.regenerate(); repo grep shows regenerate only in node_modules, never in index.js, so pre-login session ID is retained | consensus: 1/1 confirmed | triage: No session regeneration after login retains fixated ID
- Patch:
  - **Summary**: Regenerate session ID on successful login (req.session.regenerate then set user) to invalidate fixated IDs.

<a id="finding-17"></a>
### LOW Uncaught JSON.parse exception enables DoS in login handler
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-248 | confidence: 0.85
- Location: `index.js:31-31`
- Vulnerable code (`index.js`):
```javascript
, password: JSON.parse(req.body.password)
```
- Taint Flow:
  - **Source**: `POST /api/users password field containing '{' with invalid JSON`
  - **Path**:
    - `index.js:25 POST /api/users req.body.password source`
    - `index.js:28 indexOf('{') branch gate`
    - `index.js:31 JSON.parse sink throwing on malformed input`
  - **Sink**: `uncaught JSON.parse exception (DoS / error disclosure)`
- Evidence: index.js:28 checks password contains '{' then index.js:31 JSON.parse without try/catch; malformed value triggers synchronous SyntaxError uncaught by Express, returning 500 and allowing error probing/DoS
  - Validation: index.js:28-31 JSON.parse(req.body.password) on attacker password containing '{' with no try/catch; malformed JSON throws sync SyntaxError yielding 500/error disclosure
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: index.js:28-31 JSON.parse(req.body.password) on attacker password containing '{' with no try/catch; malformed JSON throws sync SyntaxError yielding 500/error disclosure | consensus: 1/1 confirmed | triage: Uncaught JSON.parse on password containing '{' causes 500/DoS
- Patch:
  - **Summary**: Wrap JSON.parse in try/catch and return 400 on invalid input; validate password is string before indexOf/parse.
