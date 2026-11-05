# Cerberus Report

**Findings:** 44 actionable — 3 critical, 26 high, 11 medium, 4 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 14 false positives and 5 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 3 | 0 / 3 (0%) | 3 |
| HIGH | 26 | 0 / 26 (0%) | 26 |
| MEDIUM | 11 | 0 / 11 (0%) | 11 |
| LOW | 4 | 0 / 4 (0%) | 4 |
| **TOTAL** | **44** | **0 / 44 (0%)** | **44** |

## Table of Contents

- [Confirmed (44)](#confirmed)
  - [CRITICAL: Server-Side JS Injection via eval(req.body.preTax) in handleContributionsUpdate (`app/routes/contributions.js:32`)](#finding-1)
  - [CRITICAL: Default Administrative Credentials in db-reset.js (`artifacts/db-reset.js:20`)](#finding-2)
  - [CRITICAL: NoSQL/JavaScript Injection via $where threshold interpolation in getByUserIdAndThreshold (`app/data/allocations-dao.js:78`)](#finding-3)
  - [HIGH: Plaintext Password Storage in UserDAO.addUser (`app/data/user-dao.js:30`)](#finding-4)
  - [HIGH: Plaintext Password Comparison in validateLogin (`app/data/user-dao.js:62`)](#finding-5)
  - [HIGH: Hardcoded Session Secret and Crypto Key in default config (`config/env/all.js:8`)](#finding-6)
  - [HIGH: Global Template Autoescape Disabled in server.js (`server.js:137`)](#finding-7)
  - [HIGH: Insecure Direct Object Reference in displayAllocations uses URL userId (`app/routes/allocations.js:22`)](#finding-8)
  - [HIGH: Missing Function-Level Authorization on GET /benefits (`app/routes/index.js:55`)](#finding-9)
  - [HIGH: Server-Side Request Forgery in displayResearch via url+symbol (`app/routes/research.js:16`)](#finding-10)
  - [HIGH: Committed TLS Private Key in artifacts/cert/server.key (`artifacts/cert/server.key:1`)](#finding-11)
  - [HIGH: Missing CSRF Protection (csurf disabled) in server.js (`server.js:108`)](#finding-12)
  - [HIGH: Horizontal IDOR / Missing Authorization in POST /benefits updateBenefits (`app/routes/benefits.js:35`)](#finding-13)
  - [HIGH: Unencrypted Sensitive PII Storage in ProfileDAO.updateUser (`app/data/profile-dao.js:86`)](#finding-14)
  - [HIGH: Spoofed Admin Flag in BenefitsHandler.displayBenefits (`app/routes/benefits.js:19`)](#finding-15)
  - [HIGH: Stored XSS via memo Markdown rendering in MemosHandler (`app/routes/memos.js:15`)](#finding-16)
  - [HIGH: Cross-Site Scripting via unescaped firstNameSafeString in handleProfileUpdate error path (`app/routes/profile.js:60`)](#finding-17)
  - [HIGH: Stored XSS via profile fields rendered unescaped on update success (`app/routes/profile.js:95`)](#finding-18)
  - [HIGH: Reflected XSS via unsanitized SSRF body in displayResearch (`app/routes/research.js:23`)](#finding-19)
  - [HIGH: Session Fixation in handleLoginRequest (no session regeneration) (`app/routes/session.js:118`)](#finding-20)
  - [HIGH: Stored XSS via allocation owner name in allocations.html (`app/views/allocations.html:35`)](#finding-21)
  - [HIGH: Stored XSS via firstName in benefits.html (`app/views/benefits.html:51`)](#finding-22)
  - [HIGH: Stored XSS via benefitStartDate in benefits.html (`app/views/benefits.html:57`)](#finding-23)
  - [HIGH: Cross-Unit Stored XSS: POST /profile names persist to layout.html top-nav (`app/views/layout.html:75`)](#finding-24)
  - [HIGH: Reflected XSS via userName in login.html (`app/views/login.html:110`)](#finding-25)
  - [HIGH: Cross-Unit Stored XSS: POST /memos memo persistence to memos.html (`app/views/memos.html:30`)](#finding-26)
  - [HIGH: Reflected XSS via userName in signup.html (`app/views/signup.html:75`)](#finding-27)
  - [HIGH: Cleartext HTTP Transport (HTTPS disabled) in server.js (`server.js:145`)](#finding-28)
  - [HIGH: NoSQL Operator Injection Authentication Bypass in validateLogin (`app/data/user-dao.js:97`)](#finding-29)
  - [MEDIUM: Open Redirect in /learn via req.query.url (`app/routes/index.js:72`)](#finding-30)
  - [MEDIUM: Regular Expression DoS (ReDoS) in bankRouting validation (`app/routes/profile.js:57`)](#finding-31)
  - [MEDIUM: Weak Password Policy in validateSignup (`app/routes/session.js:150`)](#finding-32)
  - [MEDIUM: Verbose Error Disclosure and XSS in errorHandler (`app/routes/error.js:11`)](#finding-33)
  - [MEDIUM: User Enumeration via Distinct Login Error Messages in handleLoginRequest (`app/routes/session.js:65`)](#finding-34)
  - [MEDIUM: Secret Disclosure via Config Dump to Logs (`config/config.js:13`)](#finding-35)
  - [MEDIUM: Disabled Helmet Security Headers in server.js (`server.js:90`)](#finding-36)
  - [MEDIUM: Spoofed Admin Flag in BenefitsHandler.updateBenefits (`app/routes/benefits.js:44`)](#finding-37)
  - [MEDIUM: Error-Handler Reflected XSS via Attacker-Influenced DB Error (`app/routes/error.js:10`)](#finding-38)
  - [MEDIUM: Missing Rate Limiting / Brute-Force Protection on POST /login (`app/routes/index.js:34`)](#finding-39)
  - [MEDIUM: NoSQL Operator Injection in getUserByUserName (`app/data/user-dao.js:104`)](#finding-40)
  - [LOW: Insecure Session Cookie Configuration (missing HttpOnly/Secure) in server.js (`server.js:73`)](#finding-41)
  - [LOW: Logout CSRF via State-Changing GET /logout (`app/routes/index.js:41`)](#finding-42)
  - [LOW: Log Forging via Unsanitized userName in handleLoginRequest (`app/routes/session.js:64`)](#finding-43)
  - [LOW: Hardcoded ZAP API Key in test config (`config/env/test.js:6`)](#finding-44)

<a id="confirmed"></a>
## Confirmed (44)

<a id="finding-1"></a>
### CRITICAL Server-Side JS Injection via eval(req.body.preTax) in handleContributionsUpdate
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 1.0
- Location: `app/routes/contributions.js:32-32`
- Vulnerable code (`app/routes/contributions.js`):
```javascript
const preTax = eval(req.body.preTax);
```
- Taint Flow:
  - **Source**: `req.body.preTax (POST /contributions)`
  - **Sink**: `eval() server-side JS execution`
- Evidence: const preTax = eval(req.body.preTax);
  - Validation: app/routes/contributions.js:32 eval(req.body.preTax) active with fix commented; reachable via POST /contributions app/routes/index.js:52 isLoggedIn only
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/contributions.js:32 eval(req.body.preTax) active with fix commented; reachable via POST /contributions app/routes/index.js:52 isLoggedIn only | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Replace eval with parseInt/Number validation as in commented fix and reject non-numeric input
  - +2 duplicate(s): `app/routes/contributions.js:33`, `app/routes/contributions.js:34`

<a id="finding-2"></a>
### CRITICAL Default Administrative Credentials in db-reset.js
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 1.0
- Location: `artifacts/db-reset.js:20-20`
- Vulnerable code (`artifacts/db-reset.js`):
```javascript
"password": "Admin_123",
```
- Taint Flow:
  - **Source**: `hardcoded default passwords`
  - **Sink**: `users collection seeded credentials`
- Evidence: "password": "Admin_123",
  - Validation: artifacts/db-reset.js:14 password Admin_123 and :20 User1_123 seeded with bcrypt hashes commented out; known default accounts
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: artifacts/db-reset.js:14 password Admin_123 and :20 User1_123 seeded with bcrypt hashes commented out; known default accounts | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove seeded default plaintext credentials; require generated passwords and hashed storage

<a id="finding-3"></a>
### CRITICAL NoSQL/JavaScript Injection via $where threshold interpolation in getByUserIdAndThreshold
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.95
- Location: `app/data/allocations-dao.js:78-78`
- Vulnerable code (`app/data/allocations-dao.js`):
```javascript
$where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
```
- Taint Flow:
  - **Source**: `req.query.threshold via displayAllocations`
  - **Sink**: `MongoDB $where JavaScript query`
- Evidence: $where: 'this.userId == ${parsedUserId} && this.stocks > '${threshold}''
  - Validation: app/data/allocations-dao.js:78 $where string interpolation of raw threshold with parseInt fix commented out; caller app/routes/allocations.js:27 passes req.query.threshold raw
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/allocations-dao.js:78 $where string interpolation of raw threshold with parseInt fix commented out; caller app/routes/allocations.js:27 passes req.query.threshold raw | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enable commented parseInt threshold validation 0-99 and interpolate only parsedThreshold integer

<a id="finding-4"></a>
### HIGH Plaintext Password Storage in UserDAO.addUser
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 1.0
- Location: `app/data/user-dao.js:30-30`
- Vulnerable code (`app/data/user-dao.js`):
```javascript
password //received from request param
```
- Taint Flow:
  - **Source**: `req.body.password`
  - **Sink**: `usersCol.insert() plaintext password persist`
- Evidence: password //received from request param
  - Validation: app/data/user-dao.js:30 stores password raw with bcrypt.hashSync fix commented out; caller app/routes/session.js:220 passes req.body.password raw
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/user-dao.js:30 stores password raw with bcrypt.hashSync fix commented out; caller app/routes/session.js:220 passes req.body.password raw | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Hash passwords with bcrypt.hashSync before insert as in commented fix

<a id="finding-5"></a>
### HIGH Plaintext Password Comparison in validateLogin
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 1.0
- Location: `app/data/user-dao.js:62-62`
- Vulnerable code (`app/data/user-dao.js`):
```javascript
return fromDB === fromUser;
```
- Taint Flow:
  - **Source**: `req.body.password vs stored password`
  - **Sink**: `plaintext password comparison`
- Evidence: return fromDB === fromUser;
  - Validation: app/data/user-dao.js:62 return fromDB === fromUser plaintext compare with bcrypt.compareSync fix commented out
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/user-dao.js:62 return fromDB === fromUser plaintext compare with bcrypt.compareSync fix commented out | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Verify with bcrypt.compareSync against stored hash instead of === plaintext compare

<a id="finding-6"></a>
### HIGH Hardcoded Session Secret and Crypto Key in default config
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 1.0
- Location: `config/env/all.js:8-8`
- Vulnerable code (`config/env/all.js`):
```javascript
cookieSecret: "session_cookie_secret_key_here",
```
- Taint Flow:
  - **Source**: `hardcoded config value`
  - **Sink**: `express-session secret`
- Evidence: cookieSecret: "session_cookie_secret_key_here",
  - Validation: config/env/all.js:8 cookieSecret hardcoded session_cookie_secret_key_here and :9 cryptoKey hardcoded; used as session secret server.js:70
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: config/env/all.js:8 cookieSecret hardcoded session_cookie_secret_key_here and :9 cryptoKey hardcoded; used as session secret server.js:70 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Load cookieSecret/cryptoKey from environment/secret manager, remove hardcoded defaults

<a id="finding-7"></a>
### HIGH Global Template Autoescape Disabled in server.js
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `server.js:137-137`
- Vulnerable code (`server.js`):
```javascript
autoescape: false
```
- Taint Flow:
  - **Source**: `any stored/reflected user input`
  - **Sink**: `all swig template interpolations`
- Evidence: autoescape: false
  - Validation: server.js:137 swig.setDefaults autoescape:false globally disables escaping with autoescape:true fix commented out
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server.js:137 swig.setDefaults autoescape:false globally disables escaping with autoescape:true fix commented out | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Set swig autoescape:true to escape all template interpolations by default

<a id="finding-8"></a>
### HIGH Insecure Direct Object Reference in displayAllocations uses URL userId
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `app/routes/allocations.js:22-24`
- Vulnerable code (`app/routes/allocations.js`):
```javascript
} = req.params;
```
- Taint Flow:
  - **Source**: `req.params.userId`
  - **Sink**: `allocationsDAO.getByUserIdAndThreshold arbitrary user read + render`
- Evidence: } = req.params;
  - Validation: app/routes/allocations.js:22-24 userId taken from req.params without session ownership check; route app/routes/index.js:63 guarded only by isLoggedIn
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/allocations.js:22-24 userId taken from req.params without session ownership check; route app/routes/index.js:63 guarded only by isLoggedIn | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Take userId from req.session per commented fix and enforce ownership / isAdmin check

<a id="finding-9"></a>
### HIGH Missing Function-Level Authorization on GET /benefits
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.95
- Location: `app/routes/index.js:55-55`
- Vulnerable code (`app/routes/index.js`):
```javascript
app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
```
- Taint Flow:
  - **Source**: `GET /benefits by non-admin`
  - **Sink**: `benefitsHandler.displayBenefits admin-only data exposure`
- Evidence: app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
  - Validation: app/routes/index.js:55 GET /benefits uses only isLoggedIn, isAdmin defined at :28 but unused; fix at :58 shows intended isAdmin; app/routes/benefits.js:12 leaks all non-admin users
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/index.js:55 GET /benefits uses only isLoggedIn, isAdmin defined at :28 but unused; fix at :58 shows intended isAdmin; app/routes/benefits.js:12 leaks all non-admin users | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Add isAdmin middleware to GET /benefits route: app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits).
  - +1 duplicate(s): `app/routes/index.js:56`

<a id="finding-10"></a>
### HIGH Server-Side Request Forgery in displayResearch via url+symbol
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `app/routes/research.js:16-16`
- Vulnerable code (`app/routes/research.js`):
```javascript
return needle.get(url, (error, newResponse, body) => {
```
- Taint Flow:
  - **Source**: `req.query.url + req.query.symbol`
  - **Sink**: `needle.get() server-side fetch`
- Evidence: return needle.get(url, (error, newResponse, body) => {
  - Validation: app/routes/research.js:15 url=req.query.url+req.query.symbol with hidden url field app/views/research.html:17 client-controlled; sink app/routes/research.js:16 needle.get(url) no allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/research.js:15 url=req.query.url+req.query.symbol with hidden url field app/views/research.html:17 client-controlled; sink app/routes/research.js:16 needle.get(url) no allowlist | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Allowlist base URL server-side and validate/encode symbol instead of concatenating req.query.url
  - +1 duplicate(s): `app/routes/research.js:15`

<a id="finding-11"></a>
### HIGH Committed TLS Private Key in artifacts/cert/server.key
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `artifacts/cert/server.key:1-1`
- Vulnerable code (`artifacts/cert/server.key`):
```key
-----BEGIN RSA PRIVATE KEY-----
```
- Taint Flow:
  - **Source**: `checked-in credential`
  - **Sink**: `committed private key file`
- Evidence: artifacts/cert/server.key:1 contains committed RSA private key header; server.js:19-25 references this key for HTTPS (commented fix) confirming it is a live TLS credential, not a placeholder
  - Validation: artifacts/cert/server.key:1 committed -----BEGIN RSA PRIVATE KEY-----; referenced as TLS key in server.js:22
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: artifacts/cert/server.key:1 committed -----BEGIN RSA PRIVATE KEY-----; referenced as TLS key in server.js:22 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove private key from repo and git history, rotate certificate, load key at deploy time from secret manager/env.

<a id="finding-12"></a>
### HIGH Missing CSRF Protection (csurf disabled) in server.js
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-352 | confidence: 0.95
- Location: `server.js:108-108`
- Vulnerable code (`server.js`):
```javascript
// app.use(csrf());
```
- Taint Flow:
  - **Source**: `cross-site forged request`
  - **Sink**: `state-changing POST handlers without token check`
- Evidence: // app.use(csrf());
  - Validation: server.js:107 app.use(csrf()) commented inside /* block; POST routes in app/routes/index.js:34,38,48,52,56 lack token check and contributions.html token commented
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server.js:107 app.use(csrf()) commented inside /* block; POST routes in app/routes/index.js:34,38,48,52,56 lack token check and contributions.html token commented | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Uncomment csurf middleware and token injection in server.js:107-112 and enforce csrf token validation on all POST routes; uncomment _csrf inputs in templates.

<a id="finding-13"></a>
### HIGH Horizontal IDOR / Missing Authorization in POST /benefits updateBenefits
- CVSS: **7.2** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.92
- Location: `app/routes/benefits.js:35-35`
- Vulnerable code (`app/routes/benefits.js`):
```javascript
benefitsDAO.updateBenefits(userId, benefitStartDate, (error) => {
```
- Taint Flow:
  - **Source**: `POST /benefits req.body.userId (authenticated attacker)`
  - **Path**:
    - `app/routes/index.js:56 POST /benefits req.body`
    - `app/routes/benefits.js:32 const {userId,benefitStartDate}=req.body`
    - `app/routes/benefits.js:35 benefitsDAO.updateBenefits(userId,...)`
    - `app/data/benefits-dao.js:24 usersCol.update({_id:parseInt(userId)},$set:{benefitStartDate})`
  - **Sink**: `usersCol.update by attacker-controlled _id (BOLA/IDOR write)`
- Evidence: app/routes/index.js:56 POST /benefits only requires isLoggedIn; app/routes/benefits.js:32 userId taken from req.body without ownership/admin check; app/data/benefits-dao.js:24-25 update({_id:parseInt(userId)},$set:{benefitStartDate}) modifies arbitrary user
  - Validation: app/routes/index.js:56 POST /benefits only isLoggedIn (isAdmin commented out); app/routes/benefits.js:32 userId from req.body passed at :35 to app/data/benefits-dao.js:24 update({_id:parseInt(userId)}) modifying arbitrary user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/index.js:56 POST /benefits only isLoggedIn (isAdmin commented out); app/routes/benefits.js:32 userId from req.body passed at :35 to app/data/benefits-dao.js:24 update({_id:parseInt(userId)}) modifying arbitrary user | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enforce authorization in updateBenefits: derive userId from session for non-admins and require isAdmin middleware for arbitrary userId updates.

<a id="finding-14"></a>
### HIGH Unencrypted Sensitive PII Storage in ProfileDAO.updateUser
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-312 | confidence: 0.9
- Location: `app/data/profile-dao.js:86-86`
- Vulnerable code (`app/data/profile-dao.js`):
```javascript
user.ssn = ssn;
```
- Taint Flow:
  - **Source**: `req.body.ssn/dob/bankAcc`
  - **Sink**: `users.update $set plaintext PII`
- Evidence: user.ssn = ssn;
  - Validation: app/data/profile-dao.js:86 user.ssn=ssn plaintext into $set at :68-70; encrypt/decrypt fix commented at :15-36 and :74-83 not active
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/profile-dao.js:86 user.ssn=ssn plaintext into $set at :68-70; encrypt/decrypt fix commented at :15-36 and :74-83 not active | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Encrypt ssn/dob before $set with crypto cipher as in commented fix and decrypt on read.

<a id="finding-15"></a>
### HIGH Spoofed Admin Flag in BenefitsHandler.displayBenefits
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/routes/benefits.js:19-24`
- Vulnerable code (`app/routes/benefits.js`):
```javascript
return res.render("benefits", {
```
- Taint Flow:
  - **Source**: `BenefitsHandler.displayBenefits hardcoded literal`
  - **Path**:
    - `app/routes/benefits.js:21 user:{isAdmin:true}`
    - `app/views/layout.html:48 {% if user.isAdmin %}`
  - **Sink**: `template trust of spoofed isAdmin flag`
- Evidence: return res.render("benefits", {
  - Validation: app/routes/session.js:83 res.render login with raw userName; app/views/login.html:110 value="{{userName}}" raw; server.js:133 autoescape:false disables escaping
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: app/routes/session.js:83 res.render login with raw userName; app/views/login.html:110 value="{{userName}}" raw; server.js:133 autoescape:false disables escaping | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Enable swig autoescape:true and HTML-attribute encode userName before render.
  - +2 duplicate(s): `app/routes/contributions.js:33`, `app/routes/contributions.js:34`

<a id="finding-16"></a>
### HIGH Stored XSS via memo Markdown rendering in MemosHandler
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/routes/memos.js:15-15`
- Vulnerable code (`app/routes/memos.js`):
```javascript
memosDAO.insert(req.body.memo, (err, docs) => {
```
- Taint Flow:
  - **Source**: `req.body.memo`
  - **Sink**: `marked() + swig render unescaped`
- Evidence: memosDAO.insert(req.body.memo, (err, docs) => {
  - Validation: app/routes/memos.js:15 memosDAO.insert(req.body.memo) stored raw; rendered unescaped app/views/memos.html:32 marked(doc.memo) with autoescape:false server.js:137; marked sanitize:true bypassable via js URLs
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/memos.js:15 memosDAO.insert(req.body.memo) stored raw; rendered unescaped app/views/memos.html:32 marked(doc.memo) with autoescape:false server.js:137; marked sanitize:true bypassable via js URLs | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Sanitize memo markdown on store/render with robust HTML sanitizer and enable autoescape, strip javascript: URLs

<a id="finding-17"></a>
### HIGH Cross-Site Scripting via unescaped firstNameSafeString in handleProfileUpdate error path
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/routes/profile.js:60-60`
- Vulnerable code (`app/routes/profile.js`):
```javascript
const firstNameSafeString = firstName;
```
- Taint Flow:
  - **Source**: `req.body.firstName`
  - **Sink**: `profile.html value/href interpolation with autoescape false`
- Evidence: const firstNameSafeString = firstName;
  - Validation: app/routes/profile.js:64 firstNameSafeString=firstName raw reflected on bankRouting failure; app/views/profile.html:41 value and :77 href interpolate unescaped with server.js:137 autoescape:false
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/profile.js:64 firstNameSafeString=firstName raw reflected on bankRouting failure; app/views/profile.html:41 value and :77 href interpolate unescaped with server.js:137 autoescape:false | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Encode firstName for HTML/URL context (ESAPI) or enable autoescape and use URL-encoded variable for href.

<a id="finding-18"></a>
### HIGH Stored XSS via profile fields rendered unescaped on update success
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/routes/profile.js:95-95`
- Vulnerable code (`app/routes/profile.js`):
```javascript
return res.render("profile", {
```
- Taint Flow:
  - **Source**: `stored profile fields firstName/lastName/ssn/address`
  - **Sink**: `swig render with autoescape false`
- Evidence: return res.render("profile", {
  - Validation: app/routes/profile.js:95 res.render profile with ...user raw stored fields; layout.html:73 {{firstName}} {{lastName}} unescaped with server.js:137 autoescape:false persists across displayProfile
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/profile.js:95 res.render profile with ...user raw stored fields; layout.html:73 {{firstName}} {{lastName}} unescaped with server.js:137 autoescape:false persists across displayProfile | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enable swig autoescape:true and context-encode profile fields on render/storage.

<a id="finding-19"></a>
### HIGH Reflected XSS via unsanitized SSRF body in displayResearch
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/routes/research.js:23-23`
- Vulnerable code (`app/routes/research.js`):
```javascript
res.write(body);
```
- Taint Flow:
  - **Source**: `needle response body from attacker URL`
  - **Sink**: `res.write() HTML response`
- Evidence: res.write(body);
  - Validation: app/routes/research.js:17 url built from req.query.url+symbol, :23 res.write(body) with text/html at :18-20 and no sanitization; swig autoescape false at server.js:137
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/research.js:17 url built from req.query.url+symbol, :23 res.write(body) with text/html at :18-20 and no sanitization; swig autoescape false at server.js:137 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Stop writing remote body as HTML; set Content-Type text/plain or sanitize with escaping, and validate/allowlist url param to block SSRF.

<a id="finding-20"></a>
### HIGH Session Fixation in handleLoginRequest (no session regeneration)
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-384 | confidence: 0.9
- Location: `app/routes/session.js:118-118`
- Vulnerable code (`app/routes/session.js`):
```javascript
req.session.userId = user._id;
```
- Taint Flow:
  - **Source**: `pre-login session ID`
  - **Sink**: `authenticated session binding`
- Evidence: req.session.userId = user._id;
  - Validation: app/routes/session.js:116 req.session.userId assignment without regenerate in handleLoginRequest; comments :106-115 prescribe regenerate, signup at :234 does regenerate
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/session.js:116 req.session.userId assignment without regenerate in handleLoginRequest; comments :106-115 prescribe regenerate, signup at :234 does regenerate | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Wrap login success in req.session.regenerate(()=>{req.session.userId=user._id; ...}) to issue new session ID on privilege change.

<a id="finding-21"></a>
### HIGH Stored XSS via allocation owner name in allocations.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/views/allocations.html:35-35`
- Vulnerable code (`app/views/allocations.html`):
```html
<strong>Asset Allocations for {{allocation.firstName}} {{allocation.lastName}}</strong>
```
- Taint Flow:
  - **Source**: `stored profile firstName/lastName`
  - **Path**:
    - `app/routes/profile.js:82 stored firstName`
    - `app/data/allocations-dao.js:97 alloc.firstName assignment`
    - `app/views/allocations.html:35 render`
  - **Sink**: `swig unescaped heading`
- Evidence: <strong>Asset Allocations for {{allocation.firstName}} {{allocation.lastName}}</strong>
  - Validation: app/data/allocations-dao.js:97 alloc.firstName assignment from stored user; app/views/allocations.html:35 {{allocation.firstName}} {{allocation.lastName}} raw heading with server.js:133 autoescape:false
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/allocations-dao.js:97 alloc.firstName assignment from stored user; app/views/allocations.html:35 {{allocation.firstName}} {{allocation.lastName}} raw heading with server.js:133 autoescape:false | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable autoescape:true and HTML-encode allocation owner names on render.
  - +1 duplicate(s): `app/routes/index.js:56`

<a id="finding-22"></a>
### HIGH Stored XSS via firstName in benefits.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/views/benefits.html:51-51`
- Vulnerable code (`app/views/benefits.html`):
```html
<td>{{user.firstName}}</td>
```
- Taint Flow:
  - **Source**: `stored profile firstName`
  - **Path**:
    - `app/routes/profile.js:82 profile.updateUser firstName`
    - `app/data/benefits-dao.js:15 getAllNonAdminUsers`
    - `app/views/benefits.html:51 interpolation`
  - **Sink**: `swig unescaped table cell`
- Evidence: <td>{{user.firstName}}</td>
  - Validation: app/routes/profile.js:82 profile.updateUser stores raw firstName; app/data/benefits-dao.js:15 getAllNonAdminUsers returns stored names; app/views/benefits.html:51 <td>{{user.firstName}}</td> raw with autoescape:false
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/profile.js:82 profile.updateUser stores raw firstName; app/data/benefits-dao.js:15 getAllNonAdminUsers returns stored names; app/views/benefits.html:51 <td>{{user.firstName}}</td> raw with autoescape:false | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable autoescape:true and HTML-encode firstName/lastName on render; validate profile inputs.

<a id="finding-23"></a>
### HIGH Stored XSS via benefitStartDate in benefits.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/views/benefits.html:57-57`
- Vulnerable code (`app/views/benefits.html`):
```html
<input type="date" class="form-control" name="benefitStartDate" value="{{user.benefitStartDate}}"></input>
```
- Taint Flow:
  - **Source**: `req.body.benefitStartDate (POST /benefits)`
  - **Path**:
    - `app/routes/benefits.js:32 req.body.benefitStartDate`
    - `app/data/benefits-dao.js:28 $set persistence`
    - `app/views/benefits.html:57 value interpolation`
  - **Sink**: `swig interpolation with autoescape false`
- Evidence: <input type="date" class="form-control" name="benefitStartDate" value="{{user.benefitStartDate}}"></input>
  - Validation: app/routes/benefits.js:29-32 raw req.body.benefitStartDate; app/data/benefits-dao.js:28 $set persistence without encoding; app/views/benefits.html:57 value="{{user.benefitStartDate}}" raw with server.js:133 autoescape:false
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/benefits.js:29-32 raw req.body.benefitStartDate; app/data/benefits-dao.js:28 $set persistence without encoding; app/views/benefits.html:57 value="{{user.benefitStartDate}}" raw with server.js:133 autoescape:false | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable autoescape:true, validate benefitStartDate format, and HTML-attribute encode on render.
  - +1 duplicate(s): `app/views/benefits.html:57`

<a id="finding-24"></a>
### HIGH Cross-Unit Stored XSS: POST /profile names persist to layout.html top-nav
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/views/layout.html:75-75`
- Vulnerable code (`app/views/layout.html`):
```html
<a href="#" class="dropdown-toggle" data-toggle="dropdown"><i class="fa fa-user"></i> {{firstName}} {{lastName}} <b class="caret"></b></a>
```
- Taint Flow:
  - **Source**: `POST /profile req.body.firstName/lastName`
  - **Path**:
    - `app/routes/profile.js:43 req.body.firstName`
    - `app/data/profile-dao.js:47 user.firstName assignment`
    - `app/data/profile-dao.js:78 users.update $set persistence`
    - `app/routes/session.js:263 getUserById -> res.render dashboard`
    - `app/views/layout.html:75 {{firstName}} {{lastName}}`
  - **Sink**: `layout.html unescaped {{firstName}} {{lastName}} with autoescape:false`
- Evidence: POST /profile firstName/lastName persisted unsanitized via ProfileDAO.updateUser then rendered unescaped in layout.html top-nav on every authenticated page with autoescape disabled
  - Validation: app/routes/profile.js:43 firstName/lastName from req.body stored via app/data/profile-dao.js:47-78 users.update $set without sanitization; retrieved in app/routes/session.js:263 and rendered unescaped at app/views/layout.html:75 {{firstName}} {{lastName}} with server.js:137 autoescape:false
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/profile.js:43 firstName/lastName from req.body stored via app/data/profile-dao.js:47-78 users.update $set without sanitization; retrieved in app/routes/session.js:263 and rendered unescaped at app/views/layout.html:75 {{firstName}} {{lastName}} with server.js:137 autoescape:false | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable autoescape:true and HTML-escape firstName/lastName on store and render; validate profile fields.

<a id="finding-25"></a>
### HIGH Reflected XSS via userName in login.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/views/login.html:110-110`
- Vulnerable code (`app/views/login.html`):
```html
<input type="text" class="form-control" id="userName" name="userName" value="{{userName}}" placeholder="Enter User Name">
```
- Evidence: <input type="text" class="form-control" id="userName" name="userName" value="{{userName}}" placeholder="Enter User Name">
  - Validation: app/routes/session.js:83 res.render login with raw userName; app/views/login.html:110 value="{{userName}}" raw; server.js:133 autoescape:false disables escaping
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: app/routes/session.js:83 res.render login with raw userName; app/views/login.html:110 value="{{userName}}" raw; server.js:133 autoescape:false disables escaping | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Enable swig autoescape:true and HTML-attribute encode userName before render.
  - +2 duplicate(s): `app/routes/contributions.js:33`, `app/routes/contributions.js:34`

<a id="finding-26"></a>
### HIGH Cross-Unit Stored XSS: POST /memos memo persistence to memos.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/views/memos.html:30-30`
- Vulnerable code (`app/views/memos.html`):
```html
{{ marked(doc.memo) }}
```
- Taint Flow:
  - **Source**: `POST /memos req.body.memo (authenticated attacker)`
  - **Path**:
    - `app/routes/memos.js:13 req.body.memo`
    - `app/data/memos-dao.js:18 memos={memo}`
    - `app/data/memos-dao.js:23 memosCol.insert`
    - `app/routes/memos.js:25 getAllMemos`
    - `app/views/memos.html:30 marked(doc.memo)`
  - **Sink**: `unescaped template render of stored markdown/HTML`
- Evidence: app/routes/memos.js:13 memosDAO.insert(req.body.memo) with no validation; app/data/memos-dao.js:18-23 persists raw memo to memos collection; app/routes/memos.js:25-31 getAllMemos returns all docs to any user; app/views/memos.html:30 {{ marked(doc.memo) }} with swig autoescape:false in server.js:137 renders attacker markdown/HTML unescaped
  - Validation: app/routes/memos.js:13 raw req.body.memo via app/data/memos-dao.js:18-23 insert persisted and app/routes/memos.js:25 getAllMemos returned to all users; app/views/memos.html:30 {{marked(doc.memo)}} rendered with swig autoescape:false (server.js:137) — marked sanitize:true bypassable via javascript: URLs
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/memos.js:13 raw req.body.memo via app/data/memos-dao.js:18-23 insert persisted and app/routes/memos.js:25 getAllMemos returned to all users; app/views/memos.html:30 {{marked(doc.memo)}} rendered with swig autoescape:false (server.js:137) — marked sanitize:true bypassable via javascript: URLs | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable swig autoescape:true, sanitize markdown output (strip javascript: URLs/HTML) and scope memos per user.

<a id="finding-27"></a>
### HIGH Reflected XSS via userName in signup.html
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/views/signup.html:75-75`
- Vulnerable code (`app/views/signup.html`):
```html
<input type="text" class="form-control" id="userName" value="{{userName}}" name="userName" placeholder="Enter user name">
```
- Taint Flow:
  - **Source**: `req.body.userName (POST /signup)`
  - **Path**:
    - `app/routes/session.js:191 req.body.userName`
    - `app/routes/session.js:214 res.render signup with errors`
    - `app/views/signup.html:75 value interpolation`
  - **Sink**: `unescaped value attribute`
- Evidence: <input type="text" class="form-control" id="userName" value="{{userName}}" name="userName" placeholder="Enter user name">
  - Validation: app/routes/session.js:202 errors.userName holds raw req.body.userName and 214-217/231 renders signup with ...errors; app/views/signup.html:75 value="{{userName}}" raw with autoescape:false
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/session.js:202 errors.userName holds raw req.body.userName and 214-217/231 renders signup with ...errors; app/views/signup.html:75 value="{{userName}}" raw with autoescape:false | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable autoescape:true and HTML-attribute encode userName/firstName on signup render.

<a id="finding-28"></a>
### HIGH Cleartext HTTP Transport (HTTPS disabled) in server.js
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-319 | confidence: 0.9
- Location: `server.js:145-145`
- Vulnerable code (`server.js`):
```javascript
http.createServer(app).listen(port, () => {
```
- Taint Flow:
  - **Source**: `all requests including credentials/PII`
  - **Sink**: `cleartext HTTP transport`
- Evidence: http.createServer(app).listen(port, () => {
  - Validation: server.js:145 http.createServer(app).listen active; httpsOptions+https.createServer commented at :17-28 and :149-154, so creds/PII traverse cleartext
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server.js:145 http.createServer(app).listen active; httpsOptions+https.createServer commented at :17-28 and :149-154, so creds/PII traverse cleartext | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Serve via https.createServer(httpsOptions,app) and redirect HTTP to HTTPS; enable secure cookies.

<a id="finding-29"></a>
### HIGH NoSQL Operator Injection Authentication Bypass in validateLogin
- CVSS: **6.8** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-943 | confidence: 0.8
- Location: `app/data/user-dao.js:97-98`
- Vulnerable code (`app/data/user-dao.js`):
```javascript
usersCol.findOne({
```
- Taint Flow:
  - **Source**: `req.body.userName (JSON object)`
  - **Sink**: `MongoDB findOne selector`
- Evidence: usersCol.findOne({
  - Validation: app/data/user-dao.js:97 usersCol.findOne({userName:userName}) with userName from app/routes/session.js:54 req.body and server.js:71 bodyParser.json allowing operator objects, no string type check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/user-dao.js:97 usersCol.findOne({userName:userName}) with userName from app/routes/session.js:54 req.body and server.js:71 bodyParser.json allowing operator objects, no string type check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Validate typeof userName==='string' and reject objects/operators before findOne; cast/escape selector.

<a id="finding-30"></a>
### MEDIUM Open Redirect in /learn via req.query.url
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-601 | confidence: 0.95
- Location: `app/routes/index.js:72-72`
- Vulnerable code (`app/routes/index.js`):
```javascript
return res.redirect(req.query.url);
```
- Taint Flow:
  - **Source**: `req.query.url (GET /learn)`
  - **Sink**: `res.redirect()`
- Evidence: return res.redirect(req.query.url);
  - Validation: app/routes/index.js:72 return res.redirect(req.query.url) with no allowlist validation on GET /learn
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/index.js:72 return res.redirect(req.query.url) with no allowlist validation on GET /learn | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Validate redirect against allowlisted relative paths instead of raw req.query.url

<a id="finding-31"></a>
### MEDIUM Regular Expression DoS (ReDoS) in bankRouting validation
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-1333 | confidence: 0.95
- Location: `app/routes/profile.js:57-57`
- Vulnerable code (`app/routes/profile.js`):
```javascript
const regexPattern = /([0-9]+)+\#;
```
- Taint Flow:
  - **Source**: `req.body.bankRouting`
  - **Sink**: `RegExp.test() catastrophic backtracking`
- Evidence: const regexPattern = /([0-9]+)+\#;
  - Validation: app/routes/profile.js:57 vulnerable /([0-9]+)+\#/ with safe /([0-9]+)\#/ fix commented; sink app/routes/profile.js:59 regexPattern.test(bankRouting) on req.body.bankRouting
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/profile.js:57 vulnerable /([0-9]+)+\#/ with safe /([0-9]+)\#/ fix commented; sink app/routes/profile.js:59 regexPattern.test(bankRouting) on req.body.bankRouting | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Use fixed regex /([0-9]+)\#/ without nested quantifier and add input length bound

<a id="finding-32"></a>
### MEDIUM Weak Password Policy in validateSignup
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-521 | confidence: 0.95
- Location: `app/routes/session.js:150-150`
- Vulnerable code (`app/routes/session.js`):
```javascript
const PASS_RE = /^.{1,20}$/;
```
- Taint Flow:
  - **Source**: `req.body.password`
  - **Sink**: `password acceptance check`
- Evidence: const PASS_RE = /^.{1,20}$/;
  - Validation: app/routes/session.js:144 PASS_RE=/^.{1,20}$/ allows 1-char password; strong regex commented at :148
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/session.js:144 PASS_RE=/^.{1,20}$/ allows 1-char password; strong regex commented at :148 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enforce strong PASS_RE /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/ as in commented fix.

<a id="finding-33"></a>
### MEDIUM Verbose Error Disclosure and XSS in errorHandler
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.9
- Location: `app/routes/error.js:11-11`
- Vulnerable code (`app/routes/error.js`):
```javascript
res.render("error-template", {
```
- Taint Flow:
  - **Source**: `err.message/stack + attacker-influenced threshold`
  - **Sink**: `error-template {{error}} render`
- Evidence: res.render("error-template", {
  - Validation: app/routes/error.js:11 res.render error-template with {error:err}; app/views/error-template.html:11 {{error}} unescaped with server.js:137 autoescape:false leaks message+stack
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/error.js:11 res.render error-template with {error:err}; app/views/error-template.html:11 {{error}} unescaped with server.js:137 autoescape:false leaks message+stack | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Render generic message, log stack server-side only, and enable swig autoescape:true.

<a id="finding-34"></a>
### MEDIUM User Enumeration via Distinct Login Error Messages in handleLoginRequest
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-204 | confidence: 0.9
- Location: `app/routes/session.js:65-78`
- Vulnerable code (`app/routes/session.js`):
```javascript
loginError: invalidUserNameErrorMessage,
```
- Taint Flow:
  - **Source**: `login oracle (user existence)`
  - **Sink**: `distinct loginError render`
- Evidence: loginError: invalidUserNameErrorMessage,
  - Validation: app/routes/session.js:60-61 defines distinct invalidUserNameErrorMessage vs invalidPasswordErrorMessage, rendered at :85 vs :93; fix comment at :86 proposes identical errorMessage
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/session.js:60-61 defines distinct invalidUserNameErrorMessage vs invalidPasswordErrorMessage, rendered at :85 vs :93; fix comment at :86 proposes identical errorMessage | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Render identical generic loginError for both noSuchUser and invalidPassword branches.

<a id="finding-35"></a>
### MEDIUM Secret Disclosure via Config Dump to Logs
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.9
- Location: `config/config.js:13-13`
- Vulnerable code (`config/config.js`):
```javascript
console.log(util.inspect(config, false, null));
```
- Taint Flow:
  - **Source**: `hardcoded secrets in merged config`
  - **Path**:
    - `config/config.js:7 allConf with cookieSecret/cryptoKey`
    - `config/config.js:8 envConf with zapApiKey`
    - `app/views/benefits.html:57 value interpolation`
  - **Sink**: `stdout/log secret disclosure`
- Evidence: console.log(util.inspect(config, false, null));
  - Validation: config/config.js:12-13 console.log(util.inspect(config)) dumps merged secrets; config/env/all.js:7-9 defines cookieSecret/cryptoKey in dumped object
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: config/config.js:12-13 console.log(util.inspect(config)) dumps merged secrets; config/env/all.js:7-9 defines cookieSecret/cryptoKey in dumped object | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove config dump to stdout; gate debug logging behind env and redact secrets.

<a id="finding-36"></a>
### MEDIUM Disabled Helmet Security Headers in server.js
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-693 | confidence: 0.9
- Location: `server.js:90-90`
- Vulnerable code (`server.js`):
```javascript
// app.use(helmet.frameguard()); //xframe deprecated
```
- Taint Flow:
  - **Source**: `missing hardening middleware`
  - **Sink**: `HTTP response headers`
- Evidence: // app.use(helmet.frameguard()); //xframe deprecated
  - Validation: server.js:45 helmet.frameguard/noCache/csp/hsts/nosniff block commented out starting at :33; no alternative headers set
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server.js:45 helmet.frameguard/noCache/csp/hsts/nosniff block commented out starting at :33; no alternative headers set | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enable helmet (frameguard, hsts, csp, noCache, nosniff) and disable x-powered-by.

<a id="finding-37"></a>
### MEDIUM Spoofed Admin Flag in BenefitsHandler.updateBenefits
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-862 | confidence: 0.85
- Location: `app/routes/benefits.js:44-48`
- Vulnerable code (`app/routes/benefits.js`):
```javascript
user: {
                    isAdmin: true
                },
```
- Taint Flow:
  - **Source**: `POST /benefits by non-admin`
  - **Path**:
    - `app/routes/benefits.js:30 req.body.userId/benefitStartDate`
    - `app/routes/benefits.js:44 hardcoded admin flag render`
  - **Sink**: `benefits render with forged admin context`
- Evidence: user: { isAdmin: true },
  - Validation: app/routes/benefits.js:29-48 updateBenefits writes arbitrary userId benefitStartDate with hardcoded user:{isAdmin:true}; app/routes/index.js:56 POST /benefits guarded only by isLoggedIn, isAdmin commented out
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/benefits.js:29-48 updateBenefits writes arbitrary userId benefitStartDate with hardcoded user:{isAdmin:true}; app/routes/index.js:56 POST /benefits guarded only by isLoggedIn, isAdmin commented out | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require isAdminUserMiddleware on POST /benefits and authorize userId against session; remove forged isAdmin context.

<a id="finding-38"></a>
### MEDIUM Error-Handler Reflected XSS via Attacker-Influenced DB Error
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.85
- Location: `app/routes/error.js:10-11`
- Vulnerable code (`app/routes/error.js`):
```javascript
res.render("error-template", {
```
- Taint Flow:
  - **Source**: `GET /allocations/:userId?threshold= attacker string`
  - **Path**:
    - `app/routes/allocations.js:20 req.query.threshold`
    - `app/data/allocations-dao.js:78 $where interpolation error`
    - `app/routes/error.js:10 res.render error-template`
    - `app/views/error-template.html:11 {{error}}`
  - **Sink**: `unescaped error reflection in HTML`
- Evidence: app/data/allocations-dao.js:78 $where string interpolation with threshold causes Mongo JS error containing payload; app/routes/allocations.js:24 forwards err via next(err); app/routes/error.js:10-11 res.render error-template {error:err}; app/views/error-template.html:11 {{error}} with autoescape:false renders attacker string as HTML
  - Validation: app/data/allocations-dao.js:78 threshold interpolated into $where without sanitization; app/routes/allocations.js:24 forwards DAO err via next(err); app/routes/error.js:10-11 renders err object; app/views/error-template.html:11 {{error}} with server.js:135-137 autoescape:false renders attacker-influenced DB error unescaped
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/allocations-dao.js:78 threshold interpolated into $where without sanitization; app/routes/allocations.js:24 forwards DAO err via next(err); app/routes/error.js:10-11 renders err object; app/views/error-template.html:11 {{error}} with server.js:135-137 autoescape:false renders attacker-influenced DB error unescaped | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Enable swig autoescape:true and validate threshold with parseInt range check before $where, and escape/sanitize error output instead of rendering raw err object.

<a id="finding-39"></a>
### MEDIUM Missing Rate Limiting / Brute-Force Protection on POST /login
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-307 | confidence: 0.85
- Location: `app/routes/index.js:34-34`
- Vulnerable code (`app/routes/index.js`):
```javascript
app.post("/login", sessionHandler.handleLoginRequest);
```
- Taint Flow:
  - **Source**: `network attacker POST /login userName/password`
  - **Path**:
    - `app/routes/index.js:34 POST /login`
    - `app/routes/session.js:58 userDAO.validateLogin(userName,password)`
  - **Sink**: `unthrottled authentication decision`
- Evidence: app/routes/index.js:34 POST /login has no rate-limit, throttle, lockout or CAPTCHA; app/routes/session.js:53-118 handleLoginRequest directly validates without counters; server.js:70-75 only bodyParser, no rate-limit middleware in repo
  - Validation: app/routes/index.js:34 POST /login has no rate-limit middleware; app/routes/session.js:53-118 validates with distinct Invalid username/password messages and no counters; server.js:70-75 no rate-limit registered
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/index.js:34 POST /login has no rate-limit middleware; app/routes/session.js:53-118 validates with distinct Invalid username/password messages and no counters; server.js:70-75 no rate-limit registered | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add rate-limiting/lockout on POST /login (e.g. express-rate-limit) and use generic auth failure message.

<a id="finding-40"></a>
### MEDIUM NoSQL Operator Injection in getUserByUserName
- CVSS: **4.4** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-943 | confidence: 0.75
- Location: `app/data/user-dao.js:104-105`
- Vulnerable code (`app/data/user-dao.js`):
```javascript
usersCol.findOne({
```
- Taint Flow:
  - **Source**: `req.body.userName via handleSignup`
  - **Sink**: `MongoDB findOne selector`
- Evidence: usersCol.findOne({
  - Validation: app/data/user-dao.js:104 usersCol.findOne({userName:userName}) sink; app/routes/session.js:206-208 passes req.body.userName after USER_RE regex that coerces objects; server.js:62 bodyParser.json() allows object body
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/data/user-dao.js:104 usersCol.findOne({userName:userName}) sink; app/routes/session.js:206-208 passes req.body.userName after USER_RE regex that coerces objects; server.js:62 bodyParser.json() allows object body | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enforce typeof userName==='string' and strict allow-list match before query; reject/cast non-strings and escape query operators.

<a id="finding-41"></a>
### LOW Insecure Session Cookie Configuration (missing HttpOnly/Secure) in server.js
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.95
- Location: `server.js:73-75`
- Vulnerable code (`server.js`):
```javascript
saveUninitialized: true,
```
- Taint Flow:
  - **Source**: `session middleware config`
  - **Sink**: `Set-Cookie session cookie`
- Evidence: saveUninitialized: true,
  - Validation: server.js:70 session() with saveUninitialized:true resave:true and no cookie flags; httpOnly/secure fix commented out
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server.js:70 session() with saveUninitialized:true resave:true and no cookie flags; httpOnly/secure fix commented out | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Set cookie:{httpOnly:true,secure:true} with generic key/maxAge as in commented fix

<a id="finding-42"></a>
### LOW Logout CSRF via State-Changing GET /logout
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `app/routes/index.js:41-41`
- Vulnerable code (`app/routes/index.js`):
```javascript
app.get("/logout", sessionHandler.displayLogoutPage);
```
- Taint Flow:
  - **Source**: `cross-site forged request with victim cookies`
  - **Path**:
    - `app/routes/index.js:41 GET /logout`
  - **Sink**: `req.session.destroy on cross-site GET`
- Evidence: app.get("/logout", sessionHandler.displayLogoutPage);
  - Validation: app/routes/index.js:41 GET /logout state-changing route; app/routes/session.js:121 req.session.destroy on GET; server.js:103 csrf protection commented out
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/index.js:41 GET /logout state-changing route; app/routes/session.js:121 req.session.destroy on GET; server.js:103 csrf protection commented out | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Change logout to POST with CSRF token validation.

<a id="finding-43"></a>
### LOW Log Forging via Unsanitized userName in handleLoginRequest
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-117 | confidence: 0.85
- Location: `app/routes/session.js:64-64`
- Vulnerable code (`app/routes/session.js`):
```javascript
console.log("Error: attempt to login with invalid user: ", userName);
```
- Taint Flow:
  - **Source**: `req.body.userName`
  - **Sink**: `console.log log file`
- Evidence: console.log("Error: attempt to login with invalid user: ", userName);
  - Validation: app/routes/session.js:64 console.log with raw userName; CRLF encode/replace fix commented at :66-78 not active
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/routes/session.js:64 console.log with raw userName; CRLF encode/replace fix commented at :66-78 not active | consensus: 1/1 confirmed | triage: unsanitized userName to console.log
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Strip CRLF (userName.replace(/(\r\n|\r|\n)/g,'_')) or encode before logging.

<a id="finding-44"></a>
### LOW Hardcoded ZAP API Key in test config
- CVSS: **2.2** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-798 | confidence: 0.75
- Location: `config/env/test.js:6-6`
- Vulnerable code (`config/env/test.js`):
```javascript
zapApiKey: "***",
```
- Taint Flow:
  - **Source**: `hardcoded credential in repo`
  - **Path**:
    - `config/env/test.js:6 hardcoded key`
    - `config/config.js:9-13 merged and logged`
  - **Sink**: `secret committed in source and emitted to logs`
- Evidence: config/env/test.js:6 defines hardcoded zapApiKey; same key pattern as development.js; committed to repo, loaded via config/config.js into runtime config and logged
  - Validation: config/env/test.js:6 hardcoded zapApiKey committed; loaded via config/config.js:8-13 merged and logged with util.inspect
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: config/env/test.js:6 hardcoded zapApiKey committed; loaded via config/config.js:8-13 merged and logged with util.inspect | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded zapApiKey from config/env/test.js and development.js; load from env var, exclude from logs, rotate exposed key.
