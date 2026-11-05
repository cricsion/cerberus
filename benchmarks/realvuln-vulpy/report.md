# Cerberus Report

**Findings:** 15 actionable — 3 critical, 9 high, 3 medium
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 6 false positives — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 3 | 0 / 3 (0%) | 3 |
| HIGH | 9 | 0 / 9 (0%) | 9 |
| MEDIUM | 3 | 0 / 3 (0%) | 3 |
| **TOTAL** | **15** | **0 / 15 (0%)** | **15** |

## Table of Contents

- [Confirmed (15)](#confirmed)
  - [CRITICAL: Broken authentication: unsigned base64 session cookie allows forgery (`bad/libsession.py:20`)](#finding-1)
  - [CRITICAL: SQL injection in bad libuser.login (`bad/libuser.py:12`)](#finding-2)
  - [CRITICAL: API key issuance authentication bypass with empty password (`bad/libapi.py:10`)](#finding-3)
  - [HIGH: Stored XSS via posts rendered with |safe (cross-unit web+API to template) (`bad/templates/posts.view.html:23`)](#finding-4)
  - [HIGH: SQL injection in password_change via chpasswd (cross-unit) (`bad/libuser.py:53`)](#finding-5)
  - [HIGH: Hardcoded secrets and default credentials (`bad/vulpy.py:16`)](#finding-6)
  - [HIGH: API mass-assignment allows forging posts as arbitrary user (`bad/mod_api.py:69`)](#finding-7)
  - [HIGH: Glob-injection arbitrary file deletion in API key rotation (`bad/libapi.py:16`)](#finding-8)
  - [HIGH: API authentication bypass via glob injection in /tmp key lookup (`bad/libapi.py:30`)](#finding-9)
  - [HIGH: Missing authentication/CSRF controls on chpasswd and MFA disable (`bad/mod_user.py:64`)](#finding-10)
  - [HIGH: template reflection surface (`good/templates/posts.view.html:0`)](#finding-11)
  - [HIGH: MFA disable protected only by spoofable Referer check plus state-changing GET (`good/mod_mfa.py:64`)](#finding-12)
  - [MEDIUM: Insecure configuration: cookie without flags, debug mode, no brute-force protection (`bad/libsession.py:7`)](#finding-13)
  - [MEDIUM: Predictable API keys from non-cryptographic PRNG (`bad/libapi.py:14`)](#finding-14)
  - [MEDIUM: Missing CSRF on POST /posts enables forced stored-post creation (`bad/mod_posts.py:25`)](#finding-15)

<a id="confirmed"></a>
## Confirmed (15)

<a id="finding-1"></a>
### CRITICAL Broken authentication: unsigned base64 session cookie allows forgery
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.98
- Location: `bad/libsession.py:20-20`
- Vulnerable code (`bad/libsession.py`):
```python
session = json.loads(base64.b64decode(cookie))
```
- Taint Flow:
  - **Source**: `Cookie vulpy_session (client-controlled)`
  - **Path**:
    - `attacker cookie vulpy_session`
    - `bad/libsession.py:20 b64decode+json loads`
    - `bad/vulpy.py:42 g.session assignment`
    - `bad/mod_posts.py:28 / bad/mod_user.py:80 / bad/mod_mfa.py:57 auth checks`
  - **Sink**: `server trusts client-controlled session dict for authorization`
- Evidence: bad/libsession.py:18-20 base64+json decode with no HMAC; bad/vulpy.py:42 before_request trusts g.session username for all authz
  - Validation: bad/libsession.py:6 creates base64(JSON) with no MAC; bad/libsession.py:12-24 load() trusts client cookie via b64decode+json.loads with bare except; bad/vulpy.py:42 assigns g.session for all authz (bad/mod_posts.py:28, bad/mod_mfa.py:60)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/libsession.py:6 creates base64(JSON) with no MAC; bad/libsession.py:12-24 load() trusts client cookie via b64decode+json.loads with bare except; bad/vulpy.py:42 assigns g.session for all authz (bad/mod_posts.py:28, bad/mod_mfa.py:60) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace client cookie with random server-side session or HMAC/Fernet-signed token and validate integrity/expiry on load.

<a id="finding-2"></a>
### CRITICAL SQL injection in bad libuser.login
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.98
- Location: `bad/libuser.py:12-12`
- Vulnerable code (`bad/libuser.py`):
```python
c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password))
```
- Taint Flow:
  - **Source**: `request.form username password via do_login`
  - **Path**:
    - `bad/mod_user.py:16 form to login`
    - `bad/libuser.py:12 execute`
  - **Sink**: `sqlite3 execute with formatted SQL`
- Evidence: user = c.execute(SELECT FROM users WHERE username format username password).fetchone()
  - Validation: bad/libuser.py:12 SELECT with .format(username,password) reaches sqlite3 execute; reachable unauthenticated via bad/mod_user.py:16-20 request.form username/password -> libuser.login
  - Alternatives considered: c.execute(INSERT INTO users percent formatting username password)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/libuser.py:12 SELECT with .format(username,password) reaches sqlite3 execute; reachable unauthenticated via bad/mod_user.py:16-20 request.form username/password -> libuser.login | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use parameterized query: c.execute("SELECT * FROM users WHERE username=? and password=?", (username,password)).

<a id="finding-3"></a>
### CRITICAL API key issuance authentication bypass with empty password
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.97
- Location: `bad/libapi.py:10-12`
- Vulnerable code (`bad/libapi.py`):
```python
if password: if not libuser.login(username, password): return None
```
- Taint Flow:
  - **Source**: `POST /api/key JSON username/password`
  - **Path**:
    - `bad/mod_api.py:32 request.get_json attacker JSON`
    - `bad/mod_api.py:39 libapi.keygen(data['username'], data['password'])`
    - `bad/libapi.py:10 truthiness gate skips login`
    - `bad/libapi.py:20-24 key file created and returned`
  - **Sink**: `API key issuance without authentication`
- Evidence: bad/mod_api.py:39 passes attacker JSON password (empty string passes key_schema) to bad/libapi.py:10 where falsy check skips libuser.login and returns a valid key
  - Validation: bad/libapi.py:10-12 if password: skips libuser.login on falsy password; bad/mod_api.py:12-19 key_schema allows empty string (no minLength) so bad/mod_api.py:39 keygen(data username, '') returns valid /tmp key accepted at bad/libapi.py:27
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/libapi.py:10-12 if password: skips libuser.login on falsy password; bad/mod_api.py:12-19 key_schema allows empty string (no minLength) so bad/mod_api.py:39 keygen(data username, '') returns valid /tmp key accepted at bad/libapi.py:27 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Always authenticate: remove truthiness gate, require non-empty password and return None unless libuser.login succeeds.

<a id="finding-4"></a>
### HIGH Stored XSS via posts rendered with |safe (cross-unit web+API to template)
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.97
- Location: `bad/templates/posts.view.html:23-23`
- Vulnerable code (`bad/templates/posts.view.html`):
```html
<li><span class="w3-h3">{{ post.text | safe }}</span></li>
```
- Taint Flow:
  - **Source**: `POST /posts/ text and POST /api/post JSON text`
  - **Path**:
    - `bad/mod_posts.py:34 request.form text`
    - `bad/mod_api.py:61 request JSON text`
    - `bad/libposts.py:25 INSERT posts`
    - `bad/libposts.py:13 SELECT posts`
    - `bad/templates/posts.view.html:23 |safe render`
  - **Sink**: `Jinja |safe render of stored post.text`
- Evidence: bad/mod_posts.py:34 text and bad/mod_api.py:61-68 JSON text stored via libposts.post then rendered unescaped at posts.view.html:23 with |safe | safe }} reachable via bad/mod_posts.py:11-21
  - Validation: bad/mod_posts.py:34 request.form text + bad/mod_api.py:61-62 JSON text stored via bad/libposts.py:25 INSERT without sanitization, then rendered unescaped at bad/templates/posts.view.html:23 {{ post.text
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/mod_posts.py:34 request.form text + bad/mod_api.py:61-62 JSON text stored via bad/libposts.py:25 INSERT without sanitization, then rendered unescaped at bad/templates/posts.view.html:23 {{ post.text | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe at bad/templates/posts.view.html:23 and HTML-escape/sanitize post.text on input/output.

<a id="finding-5"></a>
### HIGH SQL injection in password_change via chpasswd (cross-unit)
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.95
- Location: `bad/libuser.py:53-53`
- Vulnerable code (`bad/libuser.py`):
```python
c.execute("UPDATE users SET password = '{}' WHERE username = '{}'".format(password, username))
```
- Taint Flow:
  - **Source**: `POST /user/chpasswd form password`
  - **Path**:
    - `bad/mod_user.py:69 request.form.get password`
    - `bad/mod_user.py:80 libuser.password_change(g.session username,password)`
    - `bad/libuser.py:53 c.execute format UPDATE`
  - **Sink**: `c.execute string-format UPDATE in password_change`
- Evidence: bad/mod_user.py:69-80 new password flows into bad/libuser.py:53 UPDATE with format(); no current-password check and no auth gate on route
  - Validation: bad/mod_user.py:69 request.form password -> bad/mod_user.py:80 password_change(g.session username,password) -> bad/libuser.py:53 UPDATE ... format(password,username) with no parameterization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/mod_user.py:69 request.form password -> bad/mod_user.py:80 password_change(g.session username,password) -> bad/libuser.py:53 UPDATE ... format(password,username) with no parameterization | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use parameterized UPDATE with placeholders for password/username and validate inputs.

<a id="finding-6"></a>
### HIGH Hardcoded secrets and default credentials
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `bad/vulpy.py:16-16`
- Vulnerable code (`bad/vulpy.py`):
```python
app.config['SECRET_KEY'] = 'aaaaaaa'
```
- Taint Flow:
  - **Source**: `committed source/config`
  - **Sink**: `hardcoded crypto/session secrets and default credentials in source`
- Evidence: hardcoded app secrets in source: Flask SECRET_KEY in bad/vulpy.py:16 and bad/vulpy-ssl.py:13, Fernet key in good/libsession.py:11, JWT secret in good/libapi.py:11; default seeded passwords in bad/db_init.py:11-15
  - Validation: bad/vulpy.py:16 SECRET_KEY='aaaaaaa' and bad/vulpy-ssl.py:13 same; good/libsession.py:11 Fernet key and good/libapi.py:11 JWT secret MYSUPERSECRETKEY committed; bad/db_init.py:11-15 seeds admin/SuperSecret, elliot/123123123, tim/12345678
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/vulpy.py:16 SECRET_KEY='aaaaaaa' and bad/vulpy-ssl.py:13 same; good/libsession.py:11 Fernet key and good/libapi.py:11 JWT secret MYSUPERSECRETKEY committed; bad/db_init.py:11-15 seeds admin/SuperSecret, elliot/123123123, tim/12345678 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Load Flask/Fernet/JWT secrets from env/secret manager, rotate, hash passwords with salted KDF and remove seeded defaults.

<a id="finding-7"></a>
### HIGH API mass-assignment allows forging posts as arbitrary user
- CVSS: **7.2** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-863 | confidence: 0.92
- Location: `bad/mod_api.py:69-69`
- Vulnerable code (`bad/mod_api.py`):
```python
libposts.post(data['username'], data['text'])
```
- Taint Flow:
  - **Source**: `POST /api/post JSON body username plus X-APIKEY header`
  - **Path**:
    - `bad/mod_api.py:57 X-APIKEY -> authenticate -> data['username']`
    - `bad/mod_api.py:62 request.get_json()['username'] overwrites data['username']`
  - **Sink**: `libposts.post with forged username`
- Evidence: bad/mod_api.py:57 authenticates as self, bad/mod_api.py:62 overwrites username from request JSON, bad/mod_api.py:69 writes post as forged username; post_schema at bad/mod_api.py:21 allows extra properties
  - Validation: bad/mod_api.py:57 auth username in data then bad/mod_api.py:62 data.update(request.get_json()) overwrites it; bad/mod_api.py:21-28 post_schema lacks additionalProperties:False so forged username passes validate and bad/mod_api.py:69 libposts.post writes as victim
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/mod_api.py:57 auth username in data then bad/mod_api.py:62 data.update(request.get_json()) overwrites it; bad/mod_api.py:21-28 post_schema lacks additionalProperties:False so forged username passes validate and bad/mod_api.py:69 libposts.post writes as victim | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not merge client JSON over authenticated identity; use server-side username only and set post_schema additionalProperties:False.

<a id="finding-8"></a>
### HIGH Glob-injection arbitrary file deletion in API key rotation
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-73 | confidence: 0.9
- Location: `bad/libapi.py:16-18`
- Vulnerable code (`bad/libapi.py`):
```python
for f in Path('/tmp/').glob('vulpy.apikey.' + username + '.*'):
```
- Taint Flow:
  - **Source**: `POST /api/key JSON username`
  - **Path**:
    - `bad/mod_api.py:32 request.get_json username`
    - `bad/mod_api.py:39 libapi.keygen(data['username'],...)`
    - `bad/libapi.py:16 glob with attacker username`
    - `bad/libapi.py:18 f.unlink() deletion`
  - **Sink**: `Path.glob + unlink on attacker-controlled pattern in /tmp`
- Evidence: bad/mod_api.py:39 flows JSON username into bad/libapi.py:16 glob pattern; username='*' matches all vulpy.apikey files and f.unlink deletes them
  - Validation: bad/libapi.py:16 glob('vulpy.apikey.'+username+'.*') with bad/libapi.py:18 f.unlink() reachable from bad/mod_api.py:39 with no username validation; bad/mod_user.py:38 allows creating '*' user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/libapi.py:16 glob('vulpy.apikey.'+username+'.*') with bad/libapi.py:18 f.unlink() reachable from bad/mod_api.py:39 with no username validation; bad/mod_user.py:38 allows creating '*' user | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Validate username against ^[a-z]+$ and replace glob+unlink with exact-path lookup or directory listing with equality check before unlink.

<a id="finding-9"></a>
### HIGH API authentication bypass via glob injection in /tmp key lookup
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.9
- Location: `bad/libapi.py:30-31`
- Vulnerable code (`bad/libapi.py`):
```python
for f in Path('/tmp/').glob('vulpy.apikey.*.' + key):
```
- Taint Flow:
  - **Source**: `HTTP header X-APIKEY`
  - **Path**:
    - `bad/mod_api.py:57 libapi.authenticate(request)`
    - `bad/libapi.py:28 request.headers X-APIKEY`
    - `bad/libapi.py:30 Path glob with key`
  - **Sink**: `filesystem glob as auth decision`
- Evidence: bad/mod_api.py:54-57 X-APIKEY header flows into bad/libapi.py:30 glob pattern; '*' matches any key file and returns victim username
  - Validation: bad/libapi.py:28 X-APIKEY header flows unsanitized into bad/libapi.py:30 Path.glob('vulpy.apikey.*.'+key) returning bad/libapi.py:31 split('.')[2]; reachable unauthenticated via bad/mod_api.py:54 do_post_create
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/libapi.py:28 X-APIKEY header flows unsanitized into bad/libapi.py:30 Path.glob('vulpy.apikey.*.'+key) returning bad/libapi.py:31 split('.')[2]; reachable unauthenticated via bad/mod_api.py:54 do_post_create | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Store keys server-side indexed by exact key hash and compare with hmac.compare_digest; reject glob metacharacters and never use glob as auth decision.

<a id="finding-10"></a>
### HIGH Missing authentication/CSRF controls on chpasswd and MFA disable
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-352 | confidence: 0.9
- Location: `bad/mod_user.py:64-65`
- Vulnerable code (`bad/mod_user.py`):
```python
@mod_user.route('/chpasswd', methods=['GET', 'POST'])
```
- Taint Flow:
  - **Source**: `cross-site request + forgeable session`
  - **Path**:
    - `bad/mod_user.py:64 unauthenticated POST chpasswd`
    - `bad/mod_mfa.py:56 unauthenticated GET disable`
  - **Sink**: `password_change and mfa_disable state changes`
- Evidence: bad/mod_user.py:64-65 chpasswd route has no session check, no current-password, no CSRF; bad/mod_mfa.py:56-57 disable is state-changing GET with no OTP/CSRF
  - Validation: bad/mod_user.py:64-65 chpasswd route has no session/auth check, no current-password, no CSRF token (vs good/mod_user.py:67,73 checks); bad/mod_mfa.py:56-63 disable is state-changing GET with only session check, no CSRF/OTP (vs good/mod_mfa.py:64 Referer check still weak)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/mod_user.py:64-65 chpasswd route has no session/auth check, no current-password, no CSRF token (vs good/mod_user.py:67,73 checks); bad/mod_mfa.py:56-63 disable is state-changing GET with only session check, no CSRF/OTP (vs good/mod_mfa.py:64 Referer check still weak) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authenticated session + current-password re-auth for chpasswd and POST+anti-CSRF token (+OTP) for MFA disable; make state changes POST-only.

<a id="finding-11"></a>
### HIGH template reflection surface
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `good/templates/posts.view.html:0-0`
- Vulnerable code (`good/templates/posts.view.html`):
```html
<li><span class="w3-h3">{{ post.text | safe }}</span></li>
```
- Taint Flow:
  - **Source**: `form input`
  - **Sink**: `template render`
- Evidence: heuristic: form + {{ }} co-occurrence | safe }} renders attacker text stored via good/mod_posts.py:33-35 -> good/libposts.py:21 INSERT without sanitization, reachable via GET good/mod_posts.py:11-21
  - Validation: good/templates/posts.view.html:23 {{ post.text
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: good/templates/posts.view.html:23 {{ post.text | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe in good/templates/posts.view.html:23 (rely on Jinja autoescape) and/or sanitize/escape post.text on store/render.

<a id="finding-12"></a>
### HIGH MFA disable protected only by spoofable Referer check plus state-changing GET
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-352 | confidence: 0.85
- Location: `good/mod_mfa.py:64-65`
- Vulnerable code (`good/mod_mfa.py`):
```python
if 'referer' not in request.headers or request.headers['referer'] != 'vulpy.com':
```
- Taint Flow:
  - **Source**: `authenticated GET + spoofable Referer header`
  - **Path**:
    - `good/mod_mfa.py:58 GET /mfa/disable with victim cookie`
    - `good/mod_mfa.py:64 Referer header check (attacker-controlled)`
    - `good/mod_mfa.py:67 libmfa.mfa_disable`
  - **Sink**: `MFA disable without OTP/CSRF`
- Evidence: good/mod_mfa.py:64 checks client-controlled Referer header for exact 'vulpy.com'; attacker sets Referer to bypass and GET /mfa/disable disables MFA without OTP or CSRF token
  - Validation: good/mod_mfa.py:58 state-changing GET /mfa/disable with only good/mod_mfa.py:64 Referer=='vulpy.com' check before good/mod_mfa.py:67 mfa_disable; header is attacker-controlled, no CSRF token or OTP re-auth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: good/mod_mfa.py:58 state-changing GET /mfa/disable with only good/mod_mfa.py:64 Referer=='vulpy.com' check before good/mod_mfa.py:67 mfa_disable; header is attacker-controlled, no CSRF token or OTP re-auth | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Make disable POST-only with anti-CSRF token and require current-password or OTP re-authentication; remove Referer-equality gate.

<a id="finding-13"></a>
### MEDIUM Insecure configuration: cookie without flags, debug mode, no brute-force protection
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `bad/libsession.py:7-7`
- Vulnerable code (`bad/libsession.py`):
```python
response.set_cookie('vulpy_session', session)
```
- Taint Flow:
  - **Source**: `missing cookie flags, debug mode, missing throttling`
  - **Path**:
    - `bad/libsession.py:7 cookie issuance without flags`
    - `bad/templates/posts.view.html:23 XSS exfiltration`
  - **Sink**: `cookie theft + debug exposure + brute force`
- Evidence: bad/libsession.py:7 and good/libsession.py:32 set_cookie without HttpOnly/Secure/SameSite; bad/vulpy.py:55 and good/vulpy.py:53 run debug=True; no rate-limit on login/key endpoints
  - Validation: bad/libsession.py:7 set_cookie without Secure/HttpOnly/SameSite; bad/vulpy.py:55 app.run(debug=True); bad/mod_user.py:9 and bad/mod_api.py:30 login/key endpoints have no rate-limit/lockout
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/libsession.py:7 set_cookie without Secure/HttpOnly/SameSite; bad/vulpy.py:55 app.run(debug=True); bad/mod_user.py:9 and bad/mod_api.py:30 login/key endpoints have no rate-limit/lockout | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set HttpOnly;Secure;SameSite on session cookie, disable debug in prod, add login/key rate-limiting/lockout.

<a id="finding-14"></a>
### MEDIUM Predictable API keys from non-cryptographic PRNG
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `bad/libapi.py:14-14`
- Vulnerable code (`bad/libapi.py`):
```python
key = hashlib.sha256(str(random.getrandbits(2048)).encode()).hexdigest()
```
- Taint Flow:
  - **Source**: `CSPRNG misuse (no untrusted source needed)`
  - **Path**:
    - `bad/mod_api.py:39 libapi.keygen`
    - `bad/libapi.py:14 random.getrandbits key derivation`
  - **Sink**: `predictable API bearer token generation`
- Evidence: bad/libapi.py:14 derives 256-bit API key hex via random.getrandbits (Mersenne Twister, non-CSPRNG) instead of secrets module
  - Validation: bad/libapi.py:14 derives bearer API key via random.getrandbits (Mersenne Twister) hashed with sha256 instead of secrets module
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/libapi.py:14 derives bearer API key via random.getrandbits (Mersenne Twister) hashed with sha256 instead of secrets module | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Generate keys with secrets.token_hex(32) or secrets.token_urlsafe.

<a id="finding-15"></a>
### MEDIUM Missing CSRF on POST /posts enables forced stored-post creation
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `bad/mod_posts.py:25-26`
- Vulnerable code (`bad/mod_posts.py`):
```python
@mod_posts.route('/', methods=['POST'])
def do_create():
```
- Taint Flow:
  - **Source**: `cross-site form POST to /posts/`
  - **Path**:
    - `bad/mod_posts.py:25 cross-site POST with victim cookie`
    - `bad/mod_posts.py:31 g.session username + form text`
    - `bad/mod_posts.py:33 libposts.post`
  - **Sink**: `authenticated post creation without CSRF check`
- Evidence: bad/mod_posts.py:25-26 POST /posts creates stored post from session cookie with no CSRF token; forged cross-site POST writes attacker post.text later rendered with |safe
  - Validation: bad/mod_posts.py:25 POST /posts/ creates post from bad/mod_posts.py:31 g.session cookie with no CSRF token; cookie set in bad/libsession.py:5 without SameSite/token and payload later rendered via bad/templates/posts.view.html:30 |safe
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: bad/mod_posts.py:25 POST /posts/ creates post from bad/mod_posts.py:31 g.session cookie with no CSRF token; cookie set in bad/libsession.py:5 without SameSite/token and payload later rendered via bad/templates/posts.view.html:30 |safe | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add per-session anti-CSRF token validated on POST and set session cookie with SameSite=Lax/Strict.
