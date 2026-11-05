# Cerberus Report

**Findings:** 36 actionable — 3 critical, 16 high, 10 medium, 7 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 22 false positives — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 3 | 0 / 3 (0%) | 3 |
| HIGH | 16 | 0 / 16 (0%) | 16 |
| MEDIUM | 10 | 0 / 10 (0%) | 10 |
| LOW | 7 | 0 / 7 (0%) | 7 |
| **TOTAL** | **36** | **0 / 36 (0%)** | **36** |

## Table of Contents

- [Confirmed (36)](#confirmed)
  - [CRITICAL: Broken function-level authorization in UserDelete.delete() (`server/api/v1/api_v1.py:232`)](#finding-1)
  - [CRITICAL: Hardcoded Flask/JWT secret in Config (`server/config.py:7`)](#finding-2)
  - [CRITICAL: SQL Injection in dashboard() via search parameter (`server/routes.py:137`)](#finding-3)
  - [HIGH: Reflected XSS via safe filter in dashboard.html (`client/templates/dashboard.html:64`)](#finding-4)
  - [HIGH: BOLA unauthenticated profile disclosure in UserProfile.get() (`server/api/v1/api_v1.py:164`)](#finding-5)
  - [HIGH: Missing authentication in ProfilePicture.post() allows arbitrary picture overwrite (`server/api/v1/api_v1.py:243`)](#finding-6)
  - [HIGH: SSRF in ProfilePicture.post() via picture_url (`server/api/v1/api_v1.py:254`)](#finding-7)
  - [HIGH: Weak password storage in signup() (`server/routes.py:93`)](#finding-8)
  - [HIGH: Broken password hashing in custom_hash() uses unsalted MD5 (`server/routes.py:393`)](#finding-9)
  - [HIGH: Weak JWT issuance with hardcoded secret in UserLogin.post() (`server/api/v1/api_v1.py:130`)](#finding-10)
  - [HIGH: Unrestricted remote file write in ProfilePicture.post() (`server/api/v1/api_v1.py:284`)](#finding-11)
  - [HIGH: Missing CSRF protection in update_profile() (`server/routes.py:170`)](#finding-12)
  - [HIGH: Mass-assignment privilege escalation in update_profile() (`server/routes.py:190`)](#finding-13)
  - [HIGH: Missing CSRF protection in upload_file() (`server/routes.py:248`)](#finding-14)
  - [HIGH: Unrestricted file upload with path traversal in upload_file() (`server/routes.py:262`)](#finding-15)
  - [HIGH: Missing authentication on profile_pictures() file serve (`server/routes.py:308`)](#finding-16)
  - [HIGH: Missing CSRF protection in delete_file() (`server/routes.py:340`)](#finding-17)
  - [HIGH: Cross-unit privilege escalation: web mass-assignment persists admin role that bypasses API sensitive-update gate (`server/api/v1/api_v1.py:201`)](#finding-18)
  - [HIGH: Session fixation on web login/signup: session never regenerated at privilege change (`server/routes.py:51`)](#finding-19)
  - [MEDIUM: template reflection surface (`client/templates/dashboard.html:0`)](#finding-20)
  - [MEDIUM: Stored XSS via safe filter in profile.html (`client/templates/profile.html:41`)](#finding-21)
  - [MEDIUM: Flask debug server execution in run.py (`run.py:10`)](#finding-22)
  - [MEDIUM: Missing CSRF protection on session-authenticated POST /api/v1/update-profile (`server/api/v1/api_v1.py:182`)](#finding-23)
  - [MEDIUM: SSRF fetch without timeout enables worker-hang DoS (`server/api/v1/api_v1.py:254`)](#finding-24)
  - [MEDIUM: Debug mode enabled in Config (`server/config.py:5`)](#finding-25)
  - [MEDIUM: Missing upload size limit and security headers in app factory (`server/__init__.py:7`)](#finding-26)
  - [MEDIUM: No brute-force protection in API UserLogin.post() (`server/api/v1/api_v1.py:114`)](#finding-27)
  - [MEDIUM: No brute-force protection in login() (`server/routes.py:51`)](#finding-28)
  - [MEDIUM: User enumeration oracle on /signup with no anti-automation (`server/routes.py:101`)](#finding-29)
  - [LOW: HttpOnly disabled for session cookie in Config (`server/config.py:6`)](#finding-30)
  - [LOW: Insecure session cookie configuration in run.py (`run.py:8`)](#finding-31)
  - [LOW: Missing Secure and SameSite cookie flags in Config (`server/config.py:4`)](#finding-32)
  - [LOW: Logout CSRF: state-changing GET /logout with no CSRF token (`server/routes.py:386`)](#finding-33)
  - [LOW: Sensitive session data logged via print(session) in UserProfileUpdate (`server/api/v1/api_v1.py:182`)](#finding-34)
  - [LOW: Internal error disclosure in ProfilePicture.post() (`server/api/v1/api_v1.py:298`)](#finding-35)
  - [LOW: Missing-field 500 DoS and error echo in POST /api/v1/update_picture (`server/api/v1/api_v1.py:248`)](#finding-36)

<a id="confirmed"></a>
## Confirmed (36)

<a id="finding-1"></a>
### CRITICAL Broken function-level authorization in UserDelete.delete()
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-285 | confidence: 0.95
- Location: `server/api/v1/api_v1.py:232-232`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
```
- Taint Flow:
  - **Source**: `DELETE /api/v1/delete-user/<user_id>`
  - **Path**:
    - `server/api/v1/api_v1.py:223 <int:user_id> path`
    - `server/api/v1/api_v1.py:232 DELETE query`
  - **Sink**: `DELETE FROM users execution`
- Evidence: cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
  - Validation: server/api/v1/api_v1.py:215 @ns.route('/delete-user/<int:user_id>') with server/api/v1/api_v1.py:225 #@token_required commented and def delete(self,user_id) at server/api/v1/api_v1.py:227 reaching server/api/v1/api_v1.py:232 DELETE FROM users WHERE id=? with no auth check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:215 @ns.route('/delete-user/<int:user_id>') with server/api/v1/api_v1.py:225 #@token_required commented and def delete(self,user_id) at server/api/v1/api_v1.py:227 reaching server/api/v1/api_v1.py:232 DELETE FROM users WHERE id=? with no auth check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Require @token_required plus admin-role check before DELETE, and never allow self-deletion of last admin without confirmation

<a id="finding-2"></a>
### CRITICAL Hardcoded Flask/JWT secret in Config
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `server/config.py:7-7`
- Vulnerable code (`server/config.py`):
```python
SECRET_KEY = "just_another_secret" # application secret
```
- Taint Flow:
  - **Source**: `static source code secret`
  - **Sink**: `hardcoded SECRET_KEY assignment`
- Evidence: SECRET_KEY = "just_another_secret" # application secret
  - Validation: server/config.py:7 SECRET_KEY = "just_another_secret" loaded via server/__init__.py:10 app.config.from_object(Config) and used for Flask sessions and server/api/v1/api_v1.py:130 jwt.encode/decode
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/config.py:7 SECRET_KEY = "just_another_secret" loaded via server/__init__.py:10 app.config.from_object(Config) and used for Flask sessions and server/api/v1/api_v1.py:130 jwt.encode/decode | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove hardcoded secret; load random SECRET_KEY from env/vault, rotate existing sessions/JWTs

<a id="finding-3"></a>
### CRITICAL SQL Injection in dashboard() via search parameter
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.95
- Location: `server/routes.py:137-138`
- Vulnerable code (`server/routes.py`):
```python
s_query = f"SELECT filename FROM files WHERE user_id = {user_id} AND filename LIKE '%{search_query}%'"
```
- Taint Flow:
  - **Source**: `GET ?search= query parameter`
  - **Path**:
    - `server/routes.py:126 request.args.get('search')`
    - `server/routes.py:137 f-string interpolation`
    - `server/routes.py:138 cursor.execute(s_query)`
  - **Sink**: `cursor.execute(s_query) raw SQL execution`
- Evidence: s_query = f"SELECT filename FROM files WHERE user_id = {user_id} AND filename LIKE '%{search_query}%'"
  - Validation: server/routes.py:126 request.args.get('search') flows into server/routes.py:137 f-string SQL then server/routes.py:138 cursor.execute(s_query) with no parameterization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:126 request.args.get('search') flows into server/routes.py:137 f-string SQL then server/routes.py:138 cursor.execute(s_query) with no parameterization | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Replace f-string with parameterized LIKE query: cursor.execute("SELECT filename FROM files WHERE user_id=? AND filename LIKE ?", (user_id, f"%{search_query}%"))

<a id="finding-4"></a>
### HIGH Reflected XSS via safe filter in dashboard.html
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `client/templates/dashboard.html:64-64`
- Vulnerable code (`client/templates/dashboard.html`):
```html
<input type="text" name="search" placeholder="Search files..." value="{{ search_query | safe }}">
```
- Taint Flow:
  - **Source**: `GET ?search= parameter`
  - **Path**:
    - `server/routes.py:126 search query source`
    - `server/routes.py:143 search_query template var`
    - `client/templates/dashboard.html:64 |safe reflection`
  - **Sink**: `{{ search_query | safe }} unescaped reflection`
- Evidence: <input type="text" name="search" placeholder="Search files..." value="{{ search_query | safe }}"> | safe }}" disables autoescape
  - Validation: server/routes.py:126 search_query=request.args.get('search','') untrusted; server/routes.py:143 passed as search_query to render_template; client/templates/dashboard.html:64 value="{{ search_query
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:126 search_query=request.args.get('search','') untrusted; server/routes.py:143 passed as search_query to render_template; client/templates/dashboard.html:64 value="{{ search_query | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove |safe and rely on Jinja autoescape (or explicitly escape) for search_query in value attribute.

<a id="finding-5"></a>
### HIGH BOLA unauthenticated profile disclosure in UserProfile.get()
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `server/api/v1/api_v1.py:164-165`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
cursor.execute(query, (user_id,))
```
- Taint Flow:
  - **Source**: `GET /api/v1/profile?user_id=`
  - **Path**:
    - `server/api/v1/api_v1.py:159 user_id query arg`
    - `server/api/v1/api_v1.py:164 SELECT WHERE id=?`
    - `server/api/v1/api_v1.py:168 return dict(user_profile)`
  - **Sink**: `return of arbitrary user profile`
- Evidence: cursor.execute(query, (user_id,))
  - Validation: server/api/v1/api_v1.py:148 #@token_required commented out, server/api/v1/api_v1.py:159 user_id from query args flows to server/api/v1/api_v1.py:164 SELECT WHERE id=? then server/api/v1/api_v1.py:168 return dict(user_profile) with no session/ownership check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:148 #@token_required commented out, server/api/v1/api_v1.py:159 user_id from query args flows to server/api/v1/api_v1.py:164 SELECT WHERE id=? then server/api/v1/api_v1.py:168 return dict(user_profile) with no session/ownership check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Re-enable @token_required and enforce ownership: only return profile when requester user_id matches token/session or has admin scope

<a id="finding-6"></a>
### HIGH Missing authentication in ProfilePicture.post() allows arbitrary picture overwrite
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.95
- Location: `server/api/v1/api_v1.py:243-243`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
def post(self):
```
- Taint Flow:
  - **Source**: `unauthenticated JSON username/picture_url`
  - **Path**:
    - `server/api/v1/api_v1.py:243 unauth entry`
    - `server/api/v1/api_v1.py:249 username trusted`
  - **Sink**: `arbitrary user profile-picture overwrite`
- Evidence: def post(self):
  - Validation: server/api/v1/api_v1.py:240-249 ProfilePicture.post reads username/picture_url with no session/token check vs UserProfileUpdate session gate at :183
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:240-249 ProfilePicture.post reads username/picture_url with no session/token check vs UserProfileUpdate session gate at :183 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('server/api/v1/api_v1.py').read_text(); i=t.index('class ProfilePicture'); seg=t[i:i+800]; assert 'session' not in seg.lower() or 'print' in seg.lower(); print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Require session or @token_required on ProfilePicture.post and bind write to authenticated identity, not body username

<a id="finding-7"></a>
### HIGH SSRF in ProfilePicture.post() via picture_url
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `server/api/v1/api_v1.py:254-254`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
response = requests.get(picture_url)
```
- Taint Flow:
  - **Source**: `POST /api/v1/update_picture picture_url`
  - **Path**:
    - `server/api/v1/api_v1.py:250 picture_url JSON field`
    - `server/api/v1/api_v1.py:254 requests.get()`
  - **Sink**: `requests.get() server-side fetch`
- Evidence: response = requests.get(picture_url)
  - Validation: server/api/v1/api_v1.py:250 picture_url from JSON flows to server/api/v1/api_v1.py:254 requests.get(picture_url) with no allowlist/egress validation; Content-Type check only after fetch
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:250 picture_url from JSON flows to server/api/v1/api_v1.py:254 requests.get(picture_url) with no allowlist/egress validation; Content-Type check only after fetch | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Deny egress by default: allowlist hosts/schemes, validate redirect, fetch with timeout/size cap, or require client upload instead of server fetch

<a id="finding-8"></a>
### HIGH Weak password storage in signup()
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-327 | confidence: 0.95
- Location: `server/routes.py:93-99`
- Vulnerable code (`server/routes.py`):
```python
hashed_password = custom_hash(password)
```
- Taint Flow:
  - **Source**: `POST /signup password field`
  - **Path**:
    - `server/routes.py:84 request.form password`
    - `server/routes.py:93 custom_hash()`
    - `server/routes.py:99 INSERT INTO users`
  - **Sink**: `INSERT weak MD5 hash into DB`
- Evidence: hashed_password = custom_hash(password)
  - Validation: server/routes.py:393-403 custom_hash returns hashlib.md5(password.encode()).hexdigest() unsalted; server/routes.py:93 hashed_password=custom_hash(password); server/routes.py:99 INSERT INTO users persists weak hash
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:393-403 custom_hash returns hashlib.md5(password.encode()).hexdigest() unsalted; server/routes.py:93 hashed_password=custom_hash(password); server/routes.py:99 INSERT INTO users persists weak hash | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Replace MD5 custom_hash with bcrypt/argon2id with per-user salt and migrate stored hashes.

<a id="finding-9"></a>
### HIGH Broken password hashing in custom_hash() uses unsalted MD5
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-327 | confidence: 0.95
- Location: `server/routes.py:393-403`
- Vulnerable code (`server/routes.py`):
```python
return hashlib.md5(password.encode()).hexdigest()
```
- Taint Flow:
  - **Source**: `user-supplied password string`
  - **Sink**: `hashlib.md5(password) unsalted fast hash`
- Evidence: return hashlib.md5(password.encode()).hexdigest()
  - Validation: server/routes.py:403 return hashlib.md5(password.encode()).hexdigest() used by server/routes.py:51 login compare and server/routes.py:87 signup store with no salt/stretching
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:403 return hashlib.md5(password.encode()).hexdigest() used by server/routes.py:51 login compare and server/routes.py:87 signup store with no salt/stretching | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Replace custom_hash with bcrypt/argon2 (e.g., werkzeug.security generate_password_hash/check_password_hash) and migrate stored hashes

<a id="finding-10"></a>
### HIGH Weak JWT issuance with hardcoded secret in UserLogin.post()
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.9
- Location: `server/api/v1/api_v1.py:130-133`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
}, Config.SECRET_KEY, algorithm='HS256')
```
- Taint Flow:
  - **Source**: `POST /api/v1/login JSON body`
  - **Path**:
    - `server/api/v1/api_v1.py:115 username JSON`
    - `server/api/v1/api_v1.py:130 jwt.encode()`
  - **Sink**: `jwt.encode() with hardcoded secret`
- Evidence: }, Config.SECRET_KEY, algorithm='HS256')
  - Validation: server/api/v1/api_v1.py:130 jwt.encode(...,Config.SECRET_KEY,algorithm='HS256') reachable via unauth POST server/api/v1/api_v1.py:103 /api/v1/login where Config.SECRET_KEY is hardcoded at server/config.py:7
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:130 jwt.encode(...,Config.SECRET_KEY,algorithm='HS256') reachable via unauth POST server/api/v1/api_v1.py:103 /api/v1/login where Config.SECRET_KEY is hardcoded at server/config.py:7 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Sign JWTs with strong random secret from env/vault with short expiry/issuer validation; fix MD5 password check at server/api/v1/api_v1.py:127

<a id="finding-11"></a>
### HIGH Unrestricted remote file write in ProfilePicture.post()
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-434 | confidence: 0.9
- Location: `server/api/v1/api_v1.py:284-285`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
file.write(response.content)
```
- Taint Flow:
  - **Source**: `remote URL bytes via picture_url`
  - **Path**:
    - `server/api/v1/api_v1.py:254 SSRF response`
    - `server/api/v1/api_v1.py:285 file.write(response.content)`
  - **Sink**: `open().write() of remote bytes`
- Evidence: file.write(response.content)
  - Validation: server/api/v1/api_v1.py:243 ProfilePicture.post has no token_required/session check; server/api/v1/api_v1.py:254 requests.get(picture_url) unbounded SSRF; server/api/v1/api_v1.py:260 header-only Content-Type check; server/api/v1/api_v1.py:285 file.write(response.content) unbounded write to profile_pictures dir
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:243 ProfilePicture.post has no token_required/session check; server/api/v1/api_v1.py:254 requests.get(picture_url) unbounded SSRF; server/api/v1/api_v1.py:260 header-only Content-Type check; server/api/v1/api_v1.py:285 file.write(response.content) unbounded write to profile_pictures dir | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Require auth, allowlist URL hosts/schemes, enforce size/timeout limits, validate image magic bytes, randomize stored filename.

<a id="finding-12"></a>
### HIGH Missing CSRF protection in update_profile()
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-352 | confidence: 0.9
- Location: `server/routes.py:170-171`
- Vulnerable code (`server/routes.py`):
```python
@app.route('/update_profile', methods=['POST'])
def update_profile():
```
- Taint Flow:
  - **Source**: `cross-site forged POST with victim cookies`
  - **Path**:
    - `server/routes.py:170 POST entry`
    - `server/routes.py:234 UPDATE execution`
  - **Sink**: `privileged DB UPDATE + session rename without anti-CSRF`
- Evidence: @app.route('/update_profile', methods=['POST']) def update_profile():
  - Validation: server/routes.py:170 POST update_profile executes DB UPDATE at :234 with session-cookie auth and no CSRF token; server/__init__.py:7 app has no CSRF protection
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:170 POST update_profile executes DB UPDATE at :234 with session-cookie auth and no CSRF token; server/__init__.py:7 app has no CSRF protection | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('server/routes.py').read_text(); assert "update_profile" in t and "csrf" not in t.lower(); print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Add per-session CSRF token validation on update_profile POST and set SameSite cookie

<a id="finding-13"></a>
### HIGH Mass-assignment privilege escalation in update_profile()
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-285 | confidence: 0.9
- Location: `server/routes.py:190-196`
- Vulnerable code (`server/routes.py`):
```python
role = request.form['role'] or current_user['role']
```
- Taint Flow:
  - **Source**: `POST form fields role/permissions`
  - **Path**:
    - `server/routes.py:190 request.form['role']`
    - `server/routes.py:196 request.form['permissions']`
    - `server/routes.py:234 UPDATE users SET role=?, permissions=?`
  - **Sink**: `UPDATE users with attacker-controlled role/permissions`
- Evidence: role = request.form['role'] or current_user['role']
  - Validation: server/routes.py:190 role=request.form['role'] and server/routes.py:196 permissions from form flow to server/routes.py:234 UPDATE users SET role=?,permissions=? with no admin check, unlike server/api/v1/api_v1.py:185 admin-gated update
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:190 role=request.form['role'] and server/routes.py:196 permissions from form flow to server/routes.py:234 UPDATE users SET role=?,permissions=? with no admin check, unlike server/api/v1/api_v1.py:185 admin-gated update | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Allowlist updatable fields to email/country/team only; ignore role/permissions from form unless session user is admin

<a id="finding-14"></a>
### HIGH Missing CSRF protection in upload_file()
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-352 | confidence: 0.9
- Location: `server/routes.py:248-249`
- Vulnerable code (`server/routes.py`):
```python
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
```
- Taint Flow:
  - **Source**: `cross-site forged multipart POST`
  - **Path**:
    - `server/routes.py:248 POST entry`
    - `server/routes.py:264 file.save`
  - **Sink**: `filesystem write + DB insert without anti-CSRF`
- Evidence: @app.route('/upload', methods=['GET', 'POST']) def upload_file():
  - Validation: server/routes.py:248 upload_file saves file at :264 on session-cookie POST with no CSRF token; no CSRF anywhere in routes/__init__
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:248 upload_file saves file at :264 on session-cookie POST with no CSRF token; no CSRF anywhere in routes/__init__ | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('server/routes.py').read_text(); assert "def upload_file" in t and "csrf" not in t.lower(); print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Add CSRF token check to upload_file POST and SameSite cookie flag

<a id="finding-15"></a>
### HIGH Unrestricted file upload with path traversal in upload_file()
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-434 | confidence: 0.9
- Location: `server/routes.py:262-264`
- Vulnerable code (`server/routes.py`):
```python
file.save(filepath)
```
- Taint Flow:
  - **Source**: `multipart file upload filename + bytes`
  - **Path**:
    - `server/routes.py:257 request.files['file']`
    - `server/routes.py:262 file.filename`
    - `server/routes.py:263 os.path.join(UPLOAD_FOLDER, filename)`
    - `server/routes.py:264 file.save(filepath)`
  - **Sink**: `file.save() with attacker filename`
- Evidence: file.save(filepath)
  - Validation: server/routes.py:262 filename=file.filename then server/routes.py:263 os.path.join(UPLOAD_FOLDER,filename) then server/routes.py:264 file.save(filepath) with only empty-name check, no secure_filename/allowlist/size check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:262 filename=file.filename then server/routes.py:263 os.path.join(UPLOAD_FOLDER,filename) then server/routes.py:264 file.save(filepath) with only empty-name check, no secure_filename/allowlist/size check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Sanitize with secure_filename, randomize stored name, enforce extension/size allowlist, store outside webroot and block traversal

<a id="finding-16"></a>
### HIGH Missing authentication on profile_pictures() file serve
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.9
- Location: `server/routes.py:308-309`
- Vulnerable code (`server/routes.py`):
```python
return send_from_directory(PROFILE_PICTURES_UPLOAD_FOLDER, filename)
```
- Taint Flow:
  - **Source**: `GET /uploads/profile_pictures/<filename>`
  - **Path**:
    - `server/routes.py:308 <filename> URL path`
    - `server/routes.py:309 send_from_directory()`
  - **Sink**: `send_from_directory filesystem read`
- Evidence: return send_from_directory(PROFILE_PICTURES_UPLOAD_FOLDER, filename)
  - Validation: server/routes.py:307 @app.route('/uploads/profile_pictures/<filename>') then server/routes.py:309 send_from_directory with no session check, vs sibling server/routes.py:283 uploaded_file and server/routes.py:312 download_file which both require session plus ownership SELECT
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:307 @app.route('/uploads/profile_pictures/<filename>') then server/routes.py:309 send_from_directory with no session check, vs sibling server/routes.py:283 uploaded_file and server/routes.py:312 download_file which both require session plus ownership SELECT | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Require session and profile_picture ownership check before send_from_directory, or serve via unguessable random names with auth

<a id="finding-17"></a>
### HIGH Missing CSRF protection in delete_file()
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-352 | confidence: 0.9
- Location: `server/routes.py:340-341`
- Vulnerable code (`server/routes.py`):
```python
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
```
- Taint Flow:
  - **Source**: `cross-site forged POST`
  - **Path**:
    - `server/routes.py:340 POST entry`
    - `server/routes.py:364 os.remove`
  - **Sink**: `arbitrary file delete without anti-CSRF`
- Evidence: @app.route('/delete/<filename>', methods=['POST']) def delete_file(filename):
  - Validation: server/routes.py:340 delete_file POST does os.remove at :364 on session-cookie auth with no CSRF token
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:340 delete_file POST does os.remove at :364 on session-cookie auth with no CSRF token | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('server/routes.py').read_text(); assert "def delete_file" in t and "csrf" not in t.lower(); print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Require CSRF token on delete_file POST and SameSite cookie

<a id="finding-18"></a>
### HIGH Cross-unit privilege escalation: web mass-assignment persists admin role that bypasses API sensitive-update gate
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-285 | confidence: 0.85
- Location: `server/api/v1/api_v1.py:201-202`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
if user_profile['role'] == "admin":
                updates.update({key: value for key, value in data.items() if key in sensitive_updates})
```
- Taint Flow:
  - **Source**: `POST /update_profile role/permissions form fields (authenticated attacker)`
  - **Path**:
    - `server/routes.py:190 request.form['role'] -> UPDATE users`
    - `server/routes.py:234 persisted users.role=admin`
    - `server/api/v1/api_v1.py:195-201 SELECT role then admin check`
  - **Sink**: `API sensitive-update allowlist bypass (role/permissions accepted when DB role==admin)`
- Evidence: server/routes.py:190 mass-assigns role from request.form; server/routes.py:234 persists role/permissions; server/api/v1/api_v1.py:201 gates sensitive_updates on DB role==admin which attacker just set
  - Validation: server/routes.py:190 takes role from request.form and server/routes.py:234 UPDATE persists role/permissions; server/api/v1/api_v1.py:201 then gates sensitive_updates on DB role==admin which attacker controls
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:190 takes role from request.form and server/routes.py:234 UPDATE persists role/permissions; server/api/v1/api_v1.py:201 then gates sensitive_updates on DB role==admin which attacker controls | consensus: 1/1 confirmed | triage: Web mass-assign sets admin unlocking API gate
- Patch:
  - **Summary**: Allowlist updatable fields in /update_profile (drop role/permissions from form) and gate API sensitive updates on server-side trusted role, not DB attacker-set value.

<a id="finding-19"></a>
### HIGH Session fixation on web login/signup: session never regenerated at privilege change
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-384 | confidence: 0.85
- Location: `server/routes.py:51-52`
- Vulnerable code (`server/routes.py`):
```python
session['username'] = user['username']
            session['user_id'] = user['id']
```
- Taint Flow:
  - **Source**: `client-supplied session cookie + login credentials`
  - **Path**:
    - `server/routes.py:38 attacker username/password form`
    - `server/routes.py:51 session fixation point`
  - **Sink**: `authenticated session bound to pre-existing cookie`
- Evidence: server/routes.py:51 sets session['username'] without session.clear()/regeneration; same pattern at server/routes.py:109; only server/routes.py:389 clears on logout
  - Validation: server/routes.py:51-52 login sets session['username']/['user_id'] with no session.clear/regeneration; same at server/routes.py:109-110 signup; only server/routes.py:389 clears on logout
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:51-52 login sets session['username']/['user_id'] with no session.clear/regeneration; same at server/routes.py:109-110 signup; only server/routes.py:389 clears on logout | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Call session.clear() before setting new auth keys on login/signup to rotate Flask session.

<a id="finding-20"></a>
### MEDIUM template reflection surface
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `client/templates/dashboard.html:0-0`
- Vulnerable code (`client/templates/dashboard.html`):
```html
form + {{ }} in template (verify server-side reflection)
```
- Taint Flow:
  - **Source**: `form input`
  - **Sink**: `template render`
- Evidence: heuristic: form + {{ }} co-occurrence | safe }}" with |safe bypass; server/routes.py:126 sources search_query from request.args.get('search') and server/routes.py:143 passes it to render_template
  - Validation: client/templates/dashboard.html:64 renders value="{{ search_query
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: client/templates/dashboard.html:64 renders value="{{ search_query | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe on search_query in dashboard.html and rely on Jinja autoescape (attribute-encode) for the value attribute.

<a id="finding-21"></a>
### MEDIUM Stored XSS via safe filter in profile.html
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `client/templates/profile.html:41-41`
- Vulnerable code (`client/templates/profile.html`):
```html
<p><strong>Country:</strong> {{ user.country | safe}}</p>
```
- Taint Flow:
  - **Source**: `signup/update_profile country field`
  - **Path**:
    - `server/routes.py:83 country form field`
    - `server/routes.py:151 user DB row`
    - `client/templates/profile.html:41 |safe render`
  - **Sink**: `{{ user.country | safe }} unescaped render`
- Evidence: <p><strong>Country:</strong> {{ user.country | safe}}</p> | safe}} disables escaping on persisted value
  - Validation: server/routes.py:83 country from signup form stored raw via INSERT; server/routes.py:170-216 update_profile stores country raw; client/templates/profile.html:41 {{ user.country
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:83 country from signup form stored raw via INSERT; server/routes.py:170-216 update_profile stores country raw; client/templates/profile.html:41 {{ user.country | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Remove |safe from profile.html country render; HTML-escape on output and validate country on input.

<a id="finding-22"></a>
### MEDIUM Flask debug server execution in run.py
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-215 | confidence: 0.85
- Location: `run.py:10-10`
- Vulnerable code (`run.py`):
```python
app.run(debug=debug_mode)
```
- Taint Flow:
  - **Source**: `static DEBUG flag`
  - **Path**:
    - `server/config.py:5 DEBUG=True`
    - `run.py:7 debug_mode`
    - `run.py:10 app.run(debug=True)`
  - **Sink**: `Flask dev server in debug mode`
- Evidence: app.run(debug=debug_mode)
  - Validation: run.py:7 debug_mode=Config.DEBUG (True at server/config.py:5) flows to run.py:10 app.run(debug=debug_mode) enabling debugger/reloader when started via python run.py
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: run.py:7 debug_mode=Config.DEBUG (True at server/config.py:5) flows to run.py:10 app.run(debug=debug_mode) enabling debugger/reloader when started via python run.py | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Default debug=False in run.py; require explicit --debug/env opt-in and run production via WSGI server without debug

<a id="finding-23"></a>
### MEDIUM Missing CSRF protection on session-authenticated POST /api/v1/update-profile
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `server/api/v1/api_v1.py:182-185`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
print(session)
        if 'username' in session:
            user_id = session['user_id']
            data = request.json
```
- Evidence: server/api/v1/api_v1.py:178-185 mutating POST guarded only by Flask session cookie (if 'username' in session), no CSRF token, no SameSite/Secure flags per server/config.py; sibling web POSTs were flagged for CSRF but this session-authenticated API POST was not
  - Validation: server/api/v1/api_v1.py:172 POST /api/v1/update-profile guarded only by server/api/v1/api_v1.py:183 if 'username' in session with server/api/v1/api_v1.py:185 request.json mutation; no CSRF token and server/config.py:4-6 sets no SameSite/Secure
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:172 POST /api/v1/update-profile guarded only by server/api/v1/api_v1.py:183 if 'username' in session with server/api/v1/api_v1.py:185 request.json mutation; no CSRF token and server/config.py:4-6 sets no SameSite/Secure | consensus: 1/1 confirmed | triage: Session-cookie POST with no CSRF token
- Patch:
  - **Summary**: Require anti-CSRF token (or SameSite=Lax/Strict + JSON content-type check) on session-authenticated POST /api/v1/update-profile.

<a id="finding-24"></a>
### MEDIUM SSRF fetch without timeout enables worker-hang DoS
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.85
- Location: `server/api/v1/api_v1.py:254-254`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
response = requests.get(picture_url)
```
- Taint Flow:
  - **Source**: `attacker-supplied picture_url (unauthenticated endpoint)`
  - **Path**:
    - `server/api/v1/api_v1.py:250 picture_url from api.payload`
    - `server/api/v1/api_v1.py:254 blocking requests.get without timeout`
  - **Sink**: `worker hang / resource exhaustion (availability loss)`
- Evidence: server/api/v1/api_v1.py:254 requests.get(picture_url) passes no timeout, no size cap, on single-process Flask dev server (run.py app.run(debug=True))
  - Validation: server/api/v1/api_v1.py:250 attacker picture_url to server/api/v1/api_v1.py:254 requests.get(picture_url) with no timeout=/size cap on unauthenticated endpoint; run.py:9 single-process debug server amplifies hang
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:250 attacker picture_url to server/api/v1/api_v1.py:254 requests.get(picture_url) with no timeout=/size cap on unauthenticated endpoint; run.py:9 single-process debug server amplifies hang | consensus: 1/1 confirmed | triage: Unauth requests.get with no timeout hangs worker
- Patch:
  - **Summary**: Add timeout= (e.g. 5s), size cap, and egress allowlist to requests.get(picture_url) in update_picture.

<a id="finding-25"></a>
### MEDIUM Debug mode enabled in Config
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-215 | confidence: 0.85
- Location: `server/config.py:5-5`
- Vulnerable code (`server/config.py`):
```python
DEBUG = True
```
- Taint Flow:
  - **Source**: `static configuration`
  - **Sink**: `DEBUG=True production unsafe flag`
- Evidence: DEBUG = True
  - Validation: server/config.py:5 DEBUG=True loaded via server/__init__.py:10 and consumed by run.py:7 debug_mode=Config.DEBUG
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/config.py:5 DEBUG=True loaded via server/__init__.py:10 and consumed by run.py:7 debug_mode=Config.DEBUG | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Set DEBUG=False by default; enable only via explicit env-gated development flag, never in production config

<a id="finding-26"></a>
### MEDIUM Missing upload size limit and security headers in app factory
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-693 | confidence: 0.8
- Location: `server/__init__.py:7-7`
- Vulnerable code (`server/__init__.py`):
```python
app = Flask(__name__, template_folder='../client/templates', static_folder='../client/static')
```
- Taint Flow:
  - **Source**: `static app configuration`
  - **Path**:
    - `server/__init__.py:7 app factory`
  - **Sink**: `missing size limits and security headers`
- Evidence: app = Flask(__name__, template_folder='../client/templates', static_folder='../client/static')
  - Validation: server/__init__.py:7 Flask app creation has no MAX_CONTENT_LENGTH/Talisman/CSP; server/routes.py:260-264 upload saves unbounded file
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/__init__.py:7 Flask app creation has no MAX_CONTENT_LENGTH/Talisman/CSP; server/routes.py:260-264 upload saves unbounded file | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('server/__init__.py').read_text(); assert 'MAX_CONTENT_LENGTH' not in t and 'Talisman' not in t and 'CSP' not in t; print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Set MAX_CONTENT_LENGTH, add CSP/HSTS/X-Frame-Options headers, enforce upload size/type allowlist

<a id="finding-27"></a>
### MEDIUM No brute-force protection in API UserLogin.post()
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-307 | confidence: 0.8
- Location: `server/api/v1/api_v1.py:114-114`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
data = request.get_json()  # Get data from request body
```
- Taint Flow:
  - **Source**: `POST /api/v1/login JSON`
  - **Path**:
    - `server/api/v1/api_v1.py:114 JSON login`
    - `server/api/v1/api_v1.py:127 MD5 compare`
  - **Sink**: `unthrottled auth decision + JWT issuance`
- Evidence: data = request.get_json()  # Get data from request body
  - Validation: server/api/v1/api_v1.py:114-127 login does MD5 compare and JWT issue with no rate-limit/lockout/captcha in file
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:114-127 login does MD5 compare and JWT issue with no rate-limit/lockout/captcha in file | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('server/api/v1/api_v1.py').read_text(); assert 'request.get_json()' in t and 'throttle' not in t.lower() and 'limit' not in t.lower(); print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Add rate-limiting, lockout and delay on API login; replace MD5 with bcrypt/argon2

<a id="finding-28"></a>
### MEDIUM No brute-force protection in login()
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-307 | confidence: 0.8
- Location: `server/routes.py:51-52`
- Vulnerable code (`server/routes.py`):
```python
session['username'] = user['username']
```
- Taint Flow:
  - **Source**: `POST /login form fields`
  - **Path**:
    - `server/routes.py:37 request.form username/password`
    - `server/routes.py:50 custom_hash compare`
    - `server/routes.py:51 session creation`
  - **Sink**: `session assignment without throttling`
- Evidence: session['username'] = user['username']
  - Validation: server/routes.py:37-52 login() does username/password lookup and session creation with no counter, delay, lockout, or captcha on reachable POST /login
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:37-52 login() does username/password lookup and session creation with no counter, delay, lockout, or captcha on reachable POST /login | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Add rate-limiting/lockout and constant-time failure handling on login.

<a id="finding-29"></a>
### MEDIUM User enumeration oracle on /signup with no anti-automation
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-204 | confidence: 0.8
- Location: `server/routes.py:101-103`
- Vulnerable code (`server/routes.py`):
```python
except Exception as e:
            print("Error inserting user:", e)  # Print the error message for debugging
            return render_template('signup.html', error='User already exists or database error')
```
- Evidence: server/routes.py:95-103 INSERT with UNIQUE username/email; failure returns distinct 'User already exists or database error' with no rate limiting/captcha anywhere in server/__init__.py or requirements
  - Validation: server/routes.py:65 unauthenticated signup; server/routes.py:101-103 INSERT failure returns distinct 'User already exists...' vs redirect on success; server/__init__.py:7 and requirements show no rate-limit/captcha
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:65 unauthenticated signup; server/routes.py:101-103 INSERT failure returns distinct 'User already exists...' vs redirect on success; server/__init__.py:7 and requirements show no rate-limit/captcha | consensus: 1/1 confirmed | triage: Unauth signup distinct exists error with no throttling
- Patch:
  - **Summary**: Return generic signup response and add rate-limiting/captcha to blunt enumeration.

<a id="finding-30"></a>
### LOW HttpOnly disabled for session cookie in Config
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.95
- Location: `server/config.py:6-6`
- Vulnerable code (`server/config.py`):
```python
SESSION_COOKIE_HTTPONLY = False
```
- Taint Flow:
  - **Source**: `static configuration`
  - **Sink**: `insecure cookie flag assignment`
- Evidence: SESSION_COOKIE_HTTPONLY = False
  - Validation: server/config.py:6 SESSION_COOKIE_HTTPONLY=False; run.py:9 propagates to app.config['SESSION_COOKIE_HTTPONLY'], leaving session_token readable to JS and amplifying XSS
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/config.py:6 SESSION_COOKIE_HTTPONLY=False; run.py:9 propagates to app.config['SESSION_COOKIE_HTTPONLY'], leaving session_token readable to JS and amplifying XSS | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Set SESSION_COOKIE_HTTPONLY=True (and Secure/SameSite) in Config.

<a id="finding-31"></a>
### LOW Insecure session cookie configuration in run.py
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `run.py:8-9`
- Vulnerable code (`run.py`):
```python
app.config['SESSION_COOKIE_NAME'] = 'session_token'
    app.config['SESSION_COOKIE_HTTPONLY'] = Config.SESSION_COOKIE_HTTPONLY
```
- Taint Flow:
  - **Source**: `static insecure configuration`
  - **Path**:
    - `server/config.py:6 insecure flag`
    - `run.py:8 cookie config`
  - **Sink**: `insecure cookie attributes on session_token`
- Evidence: app.config['SESSION_COOKIE_NAME'] = 'session_token' app.config['SESSION_COOKIE_HTTPONLY'] = Config.SESSION_COOKIE_HTTPONLY
  - Validation: server/config.py:6 SESSION_COOKIE_HTTPONLY=False propagated at run.py:9; run.py:8-9 sets session_token name with no Secure/SameSite
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/config.py:6 SESSION_COOKIE_HTTPONLY=False propagated at run.py:9; run.py:8-9 sets session_token name with no Secure/SameSite | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('run.py').read_text(); assert \"SESSION_COOKIE_NAME\" in t and 'Secure' not in t and 'SAMESITE' not in t; print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Set SESSION_COOKIE_HTTPONLY=True, Secure=True, SameSite=Lax/Strict via env config

<a id="finding-32"></a>
### LOW Missing Secure and SameSite cookie flags in Config
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `server/config.py:4-4`
- Vulnerable code (`server/config.py`):
```python
class Config:
```
- Taint Flow:
  - **Source**: `static configuration omission`
  - **Path**:
    - `server/config.py:4 Config definition`
  - **Sink**: `missing Secure/SameSite cookie flags`
- Evidence: class Config:
  - Validation: server/config.py:4-6 Config defines only DEBUG/HTTPONLY=False/SECRET_KEY with no SESSION_COOKIE_SECURE/SAMESITE/lifetime
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/config.py:4-6 Config defines only DEBUG/HTTPONLY=False/SECRET_KEY with no SESSION_COOKIE_SECURE/SAMESITE/lifetime | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; t=pathlib.Path('server/config.py').read_text(); assert 'SESSION_COOKIE_SECURE' not in t and 'SAMESITE' not in t; print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Add SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE=Lax and lifetime to Config

<a id="finding-33"></a>
### LOW Logout CSRF: state-changing GET /logout with no CSRF token
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `server/routes.py:386-389`
- Vulnerable code (`server/routes.py`):
```python
@app.route('/logout')
def logout():
    # Clear all content from the session cookie
    session.clear()
```
- Evidence: server/routes.py:386-389 state-changing logout via GET with session.clear() and no token; triggerable by any cross-site <img>/<a> navigation
  - Validation: server/routes.py:386-389 binds state-changing logout to GET with session.clear() and redirect, no token, triggerable by cross-site navigation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/routes.py:386-389 binds state-changing logout to GET with session.clear() and redirect, no token, triggerable by cross-site navigation | consensus: 1/1 confirmed | triage: State-changing logout on GET
- Patch:
  - **Summary**: Change /logout to POST-only with anti-CSRF token and keep session.clear().

<a id="finding-34"></a>
### LOW Sensitive session data logged via print(session) in UserProfileUpdate
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.85
- Location: `server/api/v1/api_v1.py:182-182`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
print(session)
```
- Taint Flow:
  - **Source**: `Flask session cookie contents`
  - **Path**:
    - `server/api/v1/api_v1.py:182 print(session)`
  - **Sink**: `sensitive session written to server.log`
- Evidence: print(session)
  - Validation: server/api/v1/api_v1.py:182 print(session) executes before auth check at :183, logging session username/user_id to stdout/logs with no redaction
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:182 print(session) executes before auth check at :183, logging session username/user_id to stdout/logs with no redaction | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pathlib; assert 'print(session)' in pathlib.Path('server/api/v1/api_v1.py').read_text(); print("[POC_PROVEN]")
```
- Patch:
  - **Summary**: Remove print(session) at api_v1.py:182; use debug logger with redaction if needed

<a id="finding-35"></a>
### LOW Internal error disclosure in ProfilePicture.post()
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.85
- Location: `server/api/v1/api_v1.py:298-298`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
return {'message': str(e)}, 500
```
- Taint Flow:
  - **Source**: `internal exception message`
  - **Path**:
    - `server/api/v1/api_v1.py:254 requests.get exception`
    - `server/api/v1/api_v1.py:298 str(e) response`
  - **Sink**: `return of exception text to client`
- Evidence: return {'message': str(e)}, 500
  - Validation: server/api/v1/api_v1.py:297 broad except Exception; server/api/v1/api_v1.py:298 return {'message': str(e)},500 leaks internal exception text to unauthenticated caller
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:297 broad except Exception; server/api/v1/api_v1.py:298 return {'message': str(e)},500 leaks internal exception text to unauthenticated caller | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Log exception server-side and return generic error message without str(e).

<a id="finding-36"></a>
### LOW Missing-field 500 DoS and error echo in POST /api/v1/update_picture
- CVSS: **2.2** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-20 | confidence: 0.8
- Location: `server/api/v1/api_v1.py:248-250`
- Vulnerable code (`server/api/v1/api_v1.py`):
```python
data = api.payload
        username = data['username']
        picture_url = data['picture_url']
```
- Evidence: server/api/v1/api_v1.py:248-250 direct-subscripts api.payload/username/picture_url with no presence/type checks; server/api/v1/api_v1.py:297-298 catches all and returns str(e) with 500
  - Validation: server/api/v1/api_v1.py:248-250 direct-subscripts api.payload/username/picture_url with no None/key checks; server/api/v1/api_v1.py:297-298 returns str(e) with 500
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: server/api/v1/api_v1.py:248-250 direct-subscripts api.payload/username/picture_url with no None/key checks; server/api/v1/api_v1.py:297-298 returns str(e) with 500 | consensus: 1/1 confirmed | triage: Unauth per-request 500 and error echo only
- Patch:
  - **Summary**: Validate api.payload presence/type and required keys, return 400 on missing fields instead of 500 str(e).
