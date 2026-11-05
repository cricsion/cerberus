# Cerberus Report

**Findings:** 26 actionable — 3 critical, 7 high, 13 medium, 3 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 15 false positives and 3 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 3 | 0 / 3 (0%) | 3 |
| HIGH | 7 | 0 / 7 (0%) | 7 |
| MEDIUM | 13 | 0 / 13 (0%) | 13 |
| LOW | 3 | 0 / 3 (0%) | 3 |
| **TOTAL** | **26** | **0 / 26 (0%)** | **26** |

## Table of Contents

- [Confirmed (26)](#confirmed)
  - [CRITICAL: Reflected XSS in unsafe_params view (`app/blueprints/sandboxes/views.py:13`)](#finding-1)
  - [CRITICAL: Reflected cookie XSS in unsafe_cookies handler (`app/blueprints/sandboxes/views.py:36`)](#finding-2)
  - [CRITICAL: Hardcoded Flask SECRET_KEY enables session forgery (`app/flask_xss.py:23`)](#finding-3)
  - [HIGH: Missing authentication on API MessagesView.post (`app/blueprints/api/views.py:43`)](#finding-4)
  - [HIGH: Plaintext password comparison in login (`app/blueprints/login/views.py:17`)](#finding-5)
  - [HIGH: Reflected XSS sink in unsafe_cookies template (`app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html:6`)](#finding-6)
  - [HIGH: Reflected XSS sink in unsafe_params template (`app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:6`)](#finding-7)
  - [HIGH: Stored XSS via from_user safe (`app/templates/admin/message.html:29`)](#finding-8)
  - [HIGH: Stored XSS via message safe (`app/templates/admin/message.html:30`)](#finding-9)
  - [HIGH: Default admin credential in manage (`manage.py:14`)](#finding-10)
  - [MEDIUM: Plaintext password storage in change_password (`app/blueprints/account_area/views.py:34`)](#finding-11)
  - [MEDIUM: Missing CSRF on change_email enables email hijack (`app/blueprints/account_area/views.py:41`)](#finding-12)
  - [MEDIUM: Stored XSS source in send_feedback (`app/blueprints/account_area/views.py:75`)](#finding-13)
  - [MEDIUM: Open redirect in xss_protection index (`app/blueprints/xss_protection/views.py:12`)](#finding-14)
  - [MEDIUM: Missing CSRF on send_feedback enables forced stored XSS (`app/blueprints/account_area/views.py:61`)](#finding-15)
  - [MEDIUM: CSRF-able session-state toggle via unauthenticated GET (`app/blueprints/xss_protection/views.py:6`)](#finding-16)
  - [MEDIUM: DEBUG True enabled (`app/flask_xss.py:26`)](#finding-17)
  - [MEDIUM: CSRF blind update in acknowledge_message (`app/blueprints/api/views.py:61`)](#finding-18)
  - [MEDIUM: Missing rate limiting on login enables brute force (`app/blueprints/login/views.py:9`)](#finding-19)
  - [MEDIUM: Login CSRF on POST auth login (`app/blueprints/login/views.py:9`)](#finding-20)
  - [MEDIUM: Session cookie missing Secure/SameSite flags (`app/flask_xss.py:22`)](#finding-21)
  - [MEDIUM: Missing Content-Security-Policy and clickjacking/sniffing headers (`app/flask_xss.py:71`)](#finding-22)
  - [MEDIUM: Unquoted attribute XSS via g.path (`app/templates/_base.html:67`)](#finding-23)
  - [LOW: Logout CSRF via GET-accessible logout (`app/blueprints/login/views.py:28`)](#finding-24)
  - [LOW: Insecure cookie flags on unsafe_cookies Set-Cookie (`app/blueprints/sandboxes/views.py:38`)](#finding-25)
  - [LOW: World-writable SQLite path in tmp (`app/flask_xss.py:24`)](#finding-26)

<a id="confirmed"></a>
## Confirmed (26)

<a id="finding-1"></a>
### CRITICAL Reflected XSS in unsafe_params view
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 1.0
- Location: `app/blueprints/sandboxes/views.py:13-14`
- Vulnerable code (`app/blueprints/sandboxes/views.py`):
```python
app.config['SECRET_KEY'] = 'Keep it secret, keep it safe'
```
- Taint Flow:
  - **Source**: `GET ?name=`
  - **Path**:
    - `app/blueprints/sandboxes/views.py:13 request.args`
    - `app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:6 |safe`
  - **Sink**: `Jinja |safe render`
- Evidence: name = request.args.get('name', 'world!')
  - Validation: app/flask_xss.py:23 hardcodes SECRET_KEY='Keep it secret, keep it safe' with no env override; Flask session signing uses it
  - Consensus: 3/3 confirmed
  - Audit Trail: validator: app/flask_xss.py:23 hardcodes SECRET_KEY='Keep it secret, keep it safe' with no env override; Flask session signing uses it | consensus: 3/3 confirmed
- Patch:
  - **Summary**: Load SECRET_KEY from environment/secret manager, require unique random value, rotate sessions.
  - +1 duplicate(s): `app/flask_xss.py:23`

<a id="finding-2"></a>
### CRITICAL Reflected cookie XSS in unsafe_cookies handler
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 1.0
- Location: `app/blueprints/sandboxes/views.py:36-37`
- Vulnerable code (`app/blueprints/sandboxes/views.py`):
```python
app.config['SECRET_KEY'] = 'Keep it secret, keep it safe'
```
- Taint Flow:
  - **Source**: `Cookie name and POST form name`
  - **Path**:
    - `app/blueprints/sandboxes/views.py:27 request.cookies`
    - `app/blueprints/sandboxes/views.py:37 render_template`
  - **Sink**: `Jinja safe render`
- Evidence: render_template('sandboxes/unsafe_cookies.html', name=name
  - Validation: app/flask_xss.py:23 hardcodes SECRET_KEY='Keep it secret, keep it safe' with no env override; Flask session signing uses it
  - Consensus: 3/3 confirmed
  - Audit Trail: validator: app/flask_xss.py:23 hardcodes SECRET_KEY='Keep it secret, keep it safe' with no env override; Flask session signing uses it | consensus: 3/3 confirmed | triage: Hardcoded SECRET_KEY enables session forgery to admin
- Patch:
  - **Summary**: Load SECRET_KEY from environment/secret manager, require unique random value, rotate sessions.
  - +1 duplicate(s): `app/flask_xss.py:23`

<a id="finding-3"></a>
### CRITICAL Hardcoded Flask SECRET_KEY enables session forgery
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 1.0
- Location: `app/flask_xss.py:23-23`
- Vulnerable code (`app/flask_xss.py`):
```python
app.config['SECRET_KEY'] = 'Keep it secret, keep it safe'
```
- Taint Flow:
  - **Source**: `hardcoded literal in config_app`
  - **Sink**: `Flask session signing via SECRET_KEY`
- Evidence: app.config[SECRET_KEY] = Keep it secret
  - Validation: app/flask_xss.py:23 hardcodes SECRET_KEY='Keep it secret, keep it safe' with no env override; Flask session signing uses it
  - Consensus: 3/3 confirmed
  - Audit Trail: validator: app/flask_xss.py:23 hardcodes SECRET_KEY='Keep it secret, keep it safe' with no env override; Flask session signing uses it | consensus: 3/3 confirmed
- Patch:
  - **Summary**: Load SECRET_KEY from environment/secret manager, require unique random value, rotate sessions.
  - +1 duplicate(s): `app/flask_xss.py:23`

<a id="finding-4"></a>
### HIGH Missing authentication on API MessagesView.post
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.95
- Location: `app/blueprints/api/views.py:43-43`
- Vulnerable code (`app/blueprints/api/views.py`):
```python
def post(self):
```
- Taint Flow:
  - **Source**: `Unauthenticated JSON POST /api/v1/messages`
  - **Path**:
    - `app/blueprints/api/views.py:43 unauthenticated entry`
    - `app/blueprints/api/views.py:52 DB write`
  - **Sink**: `Persistent message store without auth`
- Evidence: Sibling methods MessagesView.index/get/delete/acknowledge at app/blueprints/api/views.py:14,24,34,59 all carry @admin_required, while post at :43 has no decorator and accepts request.get_json() from any client, storing Message at :52
  - Validation: Siblings at app/blueprints/api/views.py:14,24,34,59 carry @admin_required while app/blueprints/api/views.py:43 post() has none and at app/blueprints/api/views.py:45-52 does request.get_json to Message add/commit; stored payload renders |safe at app/templates/admin/message.html:30
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Siblings at app/blueprints/api/views.py:14,24,34,59 carry @admin_required while app/blueprints/api/views.py:43 post() has none and at app/blueprints/api/views.py:45-52 does request.get_json to Message add/commit; stored payload renders |safe at app/templates/admin/message.html:30 | consensus: 1/1 confirmed | triage: Unauth JSON POST stores messages vs admin siblings
- Patch:
  - **Summary**: Add @admin_required to MessagesView.post or require auth + validate/sanitize message; keep admin render escaped
  - +1 duplicate(s): `app/blueprints/api/views.py:52`

<a id="finding-5"></a>
### HIGH Plaintext password comparison in login
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `app/blueprints/login/views.py:17-17`
- Vulnerable code (`app/blueprints/login/views.py`):
```python
if user and user.password == password:
```
- Taint Flow:
  - **Source**: `POST username password`
  - **Path**:
    - `app/blueprints/login/views.py:15 request.form`
    - `app/blueprints/login/views.py:17 compare`
  - **Sink**: `plaintext password comparison`
- Evidence: if user and user.password == password:
  - Validation: app/blueprints/login/views.py:17 compares user.password == password in plaintext; app/models/models.py:11-13 stores plaintext with no hashing found in repo
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/login/views.py:17 compares user.password == password in plaintext; app/models/models.py:11-13 stores plaintext with no hashing found in repo | consensus: 1/1 confirmed | triage: Unauthenticated plaintext password comparison
- Patch:
  - **Summary**: Hash passwords with bcrypt/argon2 on creation and use constant-time hash verification at login.

<a id="finding-6"></a>
### HIGH Reflected XSS sink in unsafe_cookies template
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html:6-6`
- Vulnerable code (`app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html`):
```html
{{ name | safe }} in unsafe_cookies.html:6
```
- Taint Flow:
  - **Source**: `cookie form name`
  - **Path**:
    - `app/blueprints/sandboxes/views.py:37 name`
    - `app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html:6 safe`
  - **Sink**: `name safe`
- Evidence: Hello name safe | safe }} renders cookie/form name from sandboxes/views.py:27-37 without encoding
  - Validation: app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html:6 {{ name
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/sandboxes/templates/sandboxes/unsafe_cookies.html:6 {{ name | consensus: 1/1 confirmed | triage: Cookie form name rendered safe without encoding
- Patch:
  - **Summary**: Remove |safe filter to restore Jinja autoescaping for name.

<a id="finding-7"></a>
### HIGH Reflected XSS sink in unsafe_params template
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:6-6`
- Vulnerable code (`app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html`):
```html
{{ name | safe }} in unsafe_params.html:6
```
- Taint Flow:
  - **Source**: `query name`
  - **Path**:
    - `app/blueprints/sandboxes/views.py:14 name`
    - `app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:6 safe`
  - **Sink**: `name safe`
- Evidence: Hello name safe | safe }} renders view-controlled request.args name from sandboxes/views.py:13 without encoding
  - Validation: app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:6 {{ name
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/sandboxes/templates/sandboxes/unsafe_params.html:6 {{ name | consensus: 1/1 confirmed | triage: Query name rendered safe without encoding
- Patch:
  - **Summary**: Remove |safe filter to restore Jinja autoescaping for name.

<a id="finding-8"></a>
### HIGH Stored XSS via from_user safe
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `app/templates/admin/message.html:29-29`
- Vulnerable code (`app/templates/admin/message.html`):
```html
{{ message.from_user | safe }} in admin/message.html:29
```
- Taint Flow:
  - **Source**: `from_user`
  - **Path**:
    - `app/blueprints/api/views.py:52 from_user`
    - `app/templates/admin/message.html:29 safe`
  - **Sink**: `from_user safe`
- Evidence: message from_user safe | safe }} renders attacker-spoofable from_user from api/views.py:52 unauthenticated store
  - Validation: app/templates/admin/message.html:29 {{ message.from_user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/templates/admin/message.html:29 {{ message.from_user | consensus: 1/1 confirmed | triage: Attacker-spoofable from_user rendered safe to admin
- Patch:
  - **Summary**: Remove |safe on from_user; autoescape admin table.

<a id="finding-9"></a>
### HIGH Stored XSS via message safe
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `app/templates/admin/message.html:30-30`
- Vulnerable code (`app/templates/admin/message.html`):
```html
{{ message.message | safe }} in admin/message.html:30
```
- Taint Flow:
  - **Source**: `feedback message`
  - **Path**:
    - `app/blueprints/account_area/views.py:75 store`
    - `app/templates/admin/message.html:30 safe`
  - **Sink**: `message safe`
- Evidence: message message safe | safe }} renders persistent feedback/Message from account_area/views.py:75 and api/views.py:52 to admin
  - Validation: app/templates/admin/message.html:30 {{ message.message
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/templates/admin/message.html:30 {{ message.message | consensus: 1/1 confirmed | triage: Distinct line 30 message sink requires independent fix
- Patch:
  - **Summary**: Remove |safe on message; autoescape admin table.

<a id="finding-10"></a>
### HIGH Default admin credential in manage
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `manage.py:14-14`
- Vulnerable code (`manage.py`):
```python
def add_admin(password equals admin)
```
- Taint Flow:
  - **Source**: `hardcoded default`
  - **Sink**: `default credential`
- Evidence: def add_admin(password equals admin)
  - Validation: manage.py:14 add_admin(password='admin') + manage.py:18 User(username='admin',password=password) creates remotely loginnable admin/admin via app/blueprints/login/views.py:14-17 plaintext compare
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: manage.py:14 add_admin(password='admin') + manage.py:18 User(username='admin',password=password) creates remotely loginnable admin/admin via app/blueprints/login/views.py:14-17 plaintext compare | consensus: 1/1 confirmed | triage: Default admin admin remotely loginnable
- Patch:
  - **Summary**: Remove default password; require strong password via env/prompt, hash with bcrypt/argon2, force rotation.
  - +1 duplicate(s): `manage.py:14`

<a id="finding-11"></a>
### MEDIUM Plaintext password storage in change_password
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-256 | confidence: 0.95
- Location: `app/blueprints/account_area/views.py:34-35`
- Vulnerable code (`app/blueprints/account_area/views.py`):
```python
User.query.filter_by(id=current_user.id).update({
```
- Taint Flow:
  - **Source**: `POST new-password`
  - **Path**:
    - `app/blueprints/account_area/views.py:20 new_password`
    - `app/blueprints/account_area/views.py:34 update`
  - **Sink**: `plaintext password write`
- Evidence: User.query.filter_by(id=current_user.id).update({
  - Validation: app/blueprints/account_area/views.py:34-35 updates {'password': new_password} directly from POST and commits; no hashing
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/account_area/views.py:34-35 updates {'password': new_password} directly from POST and commits; no hashing | consensus: 1/1 confirmed | triage: Authenticated plaintext password write with no hashing
- Patch:
  - **Summary**: Hash new_password with bcrypt/argon2 before User.update; require current-password re-auth.

<a id="finding-12"></a>
### MEDIUM Missing CSRF on change_email enables email hijack
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.95
- Location: `app/blueprints/account_area/views.py:41-43`
- Vulnerable code (`app/blueprints/account_area/views.py`):
```python
@account_area.route('/change_email', methods=['POST'])
@login_required
def change_email():
```
- Taint Flow:
  - **Source**: `cross-site POST to /account_area/change_email (victim session cookie)`
  - **Path**:
    - `app/blueprints/account_area/views.py:44 request.form email`
    - `app/blueprints/account_area/views.py:54 User.query.update email`
    - `app/blueprints/account_area/views.py:56 db.session.commit`
  - **Sink**: `persistent User.email overwrite without CSRF token`
- Evidence: Route app/blueprints/account_area/views.py:41 defines POST /account_area/change_email with only @login_required; repo-wide grep for csrf finds no token generation/validation and app/templates/components/forms.html:20-25 form macro emits no hidden CSRF field, so cross-site POST is accepted. Handler at views.py:44 reads request.form email and at views.py:54-55 executes User.query.update email + commit.
  - Validation: Route at app/blueprints/account_area/views.py:41 POST change_email has only @login_required; repo grep for csrf finds no token and app/templates/components/forms.html:20-25 emits no hidden field; handler at app/blueprints/account_area/views.py:44 reads form email and at app/blueprints/account_area/views.py:54-56 User.query.update+commit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Route at app/blueprints/account_area/views.py:41 POST change_email has only @login_required; repo grep for csrf finds no token and app/templates/components/forms.html:20-25 emits no hidden field; handler at app/blueprints/account_area/views.py:44 reads form email and at app/blueprints/account_area/views.py:54-56 User.query.update+commit | consensus: 1/1 confirmed | triage: POST change_email only login_required, no CSRF token
- Patch:
  - **Summary**: Add per-session CSRF token validation to change_email and include hidden token in forms macro

<a id="finding-13"></a>
### MEDIUM Stored XSS source in send_feedback
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.95
- Location: `app/blueprints/account_area/views.py:75-75`
- Vulnerable code (`app/blueprints/account_area/views.py`):
```python
new_message = Message(message=feedback, from_user=current_user.username)
```
- Taint Flow:
  - **Source**: `POST feedback`
  - **Path**:
    - `app/blueprints/account_area/views.py:66 feedback`
    - `app/blueprints/account_area/views.py:75 store`
  - **Sink**: `persistent message with safe render`
- Evidence: new_message = Message(message=feedback, from_user=current_user.username) | safe }} to admin
  - Validation: app/blueprints/account_area/views.py:75 Message(message=feedback) stores raw POST feedback; rendered unescaped at app/templates/admin/message.html:30 {{ message.message
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/account_area/views.py:75 Message(message=feedback) stores raw POST feedback; rendered unescaped at app/templates/admin/message.html:30 {{ message.message | consensus: 1/1 confirmed | triage: Authenticated feedback stored raw for admin render
- Patch:
  - **Summary**: Persist feedback as-is but remove |safe and autoescape on admin render; validate length.

<a id="finding-14"></a>
### MEDIUM Open redirect in xss_protection index
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-601 | confidence: 0.95
- Location: `app/blueprints/xss_protection/views.py:12-12`
- Vulnerable code (`app/blueprints/xss_protection/views.py`):
```python
return redirect(next)
```
- Taint Flow:
  - **Source**: `query next`
  - **Path**:
    - `app/blueprints/xss_protection/views.py:11 next`
    - `app/blueprints/xss_protection/views.py:12 redirect`
  - **Sink**: `redirect next`
- Evidence: return redirect(next)
  - Validation: app/blueprints/xss_protection/views.py:11 next=request.args.get('next') flows to :12 return redirect(next) with no allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/xss_protection/views.py:11 next=request.args.get('next') flows to :12 return redirect(next) with no allowlist | consensus: 1/1 confirmed | triage: Unvalidated next flows to redirect
- Patch:
  - **Summary**: Allowlist redirect targets (relative-only or explicit hosts) before redirect; default to index.

<a id="finding-15"></a>
### MEDIUM Missing CSRF on send_feedback enables forced stored XSS
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.92
- Location: `app/blueprints/account_area/views.py:61-63`
- Vulnerable code (`app/blueprints/account_area/views.py`):
```python
@account_area.route('/send_feedback', methods=['POST'])
@login_required
def send_feedback():
```
- Taint Flow:
  - **Source**: `cross-site POST to /account_area/send_feedback (victim session)`
  - **Path**:
    - `app/blueprints/account_area/views.py:66 feedback=request.form`
    - `app/blueprints/account_area/views.py:75 Message(message=feedback)`
    - `app/blueprints/admin/views.py:21 Message.query.filter_by(acknowledged=False)`
    - `app/templates/admin/message.html:30 {{ message.message | safe }}`
  - **Sink**: `admin browser JS execution of victim-forced stored message`
- Evidence: Route app/blueprints/account_area/views.py:61 POST /account_area/send_feedback has only @login_required; no CSRF token in views, forms macro, or session. Handler at views.py:66 reads request.form feedback and at views.py:75-77 persists Message(message=feedback, from_user=current_user.username). Persisted message later rendered unescaped at app/templates/admin/message.html:30. Forces victim to store attacker payload attributed to victim.
  - Validation: Route at app/blueprints/account_area/views.py:61 POST send_feedback has only @login_required with no CSRF token anywhere; handler at app/blueprints/account_area/views.py:66 reads feedback and at app/blueprints/account_area/views.py:75 persists Message; rendered unescaped at app/templates/admin/message.html:30 via app/blueprints/admin/views.py:21 query
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Route at app/blueprints/account_area/views.py:61 POST send_feedback has only @login_required with no CSRF token anywhere; handler at app/blueprints/account_area/views.py:66 reads feedback and at app/blueprints/account_area/views.py:75 persists Message; rendered unescaped at app/templates/admin/message.html:30 via app/blueprints/admin/views.py:21 query | consensus: 1/1 confirmed | triage: POST send_feedback no CSRF forces victim-stored XSS
- Patch:
  - **Summary**: Require CSRF token on send_feedback and escape/sanitize Message before |safe render to admin

<a id="finding-16"></a>
### MEDIUM CSRF-able session-state toggle via unauthenticated GET
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `app/blueprints/xss_protection/views.py:6-12`
- Vulnerable code (`app/blueprints/xss_protection/views.py`):
```python
session['xss_protection_enabled'] = not xss_protection_enabled
```
- Taint Flow:
  - **Source**: `unauthenticated GET request with attacker next param`
  - **Path**:
    - `app/blueprints/xss_protection/views.py:6 GET entry`
    - `app/blueprints/xss_protection/views.py:9 session write`
    - `app/flask_xss.py:73 session read in after_request`
  - **Sink**: `session state write + 302 redirect`
- Evidence: app/blueprints/xss_protection/views.py:6 route allows GET, 8-9 flips session xss_protection_enabled, 11-12 redirects to attacker next; no login_required, no CSRF token, no method restriction
  - Validation: GET route at app/blueprints/xss_protection/views.py:6 with no auth mutates session at app/blueprints/xss_protection/views.py:9 and redirects to attacker next at app/blueprints/xss_protection/views.py:11-12; consumed at app/flask_xss.py:73
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: GET route at app/blueprints/xss_protection/views.py:6 with no auth mutates session at app/blueprints/xss_protection/views.py:9 and redirects to attacker next at app/blueprints/xss_protection/views.py:11-12; consumed at app/flask_xss.py:73 | consensus: 1/1 confirmed | triage: Unauth GET flips XSS session and open-redirects
- Patch:
  - **Summary**: Require POST+CSRF for state toggle and allowlist next redirect targets

<a id="finding-17"></a>
### MEDIUM DEBUG True enabled
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-489 | confidence: 0.9
- Location: `app/flask_xss.py:26-26`
- Vulnerable code (`app/flask_xss.py`):
```python
app.config['DEBUG'] = True
```
- Taint Flow:
  - **Source**: `hardcoded config`
  - **Sink**: `debug mode`
- Evidence: app.config['DEBUG'] = True
  - Validation: app/flask_xss.py:26 hardcodes app.config['DEBUG']=True with no env override; active app enables debugger stack-trace disclosure
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/flask_xss.py:26 hardcodes app.config['DEBUG']=True with no env override; active app enables debugger stack-trace disclosure | consensus: 1/1 confirmed | triage: Hardcoded DEBUG True enables stack disclosure
- Patch:
  - **Summary**: Set DEBUG/EXPLAIN_TEMPLATE_LOADING from env, default False in production; disable Werkzeug debugger outside local dev.

<a id="finding-18"></a>
### MEDIUM CSRF blind update in acknowledge_message
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `app/blueprints/api/views.py:61-63`
- Vulnerable code (`app/blueprints/api/views.py`):
```python
Message.query.filter_by(id=id).update({
```
- Taint Flow:
  - **Source**: `cross-site POST plus id`
  - **Sink**: `acknowledge without CSRF`
- Evidence: Message.query.filter_by(id=id).update({
  - Validation: app/blueprints/api/views.py:58-64 POST /acknowledge/<id> with @admin_required updates acknowledged=True with no CSRF token; admin cookies sent cross-site, repo has zero CSRF checks
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/api/views.py:58-64 POST /acknowledge/<id> with @admin_required updates acknowledged=True with no CSRF token; admin cookies sent cross-site, repo has zero CSRF checks | consensus: 1/1 confirmed | triage: Admin acknowledge POST has no CSRF
- Patch:
  - **Summary**: Require CSRF token on acknowledge POST and SameSite cookies; verify Origin.

<a id="finding-19"></a>
### MEDIUM Missing rate limiting on login enables brute force
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-307 | confidence: 0.85
- Location: `app/blueprints/login/views.py:9-10`
- Vulnerable code (`app/blueprints/login/views.py`):
```python
@authentication.route('/login', methods=['POST', 'GET'])
def login():
```
- Taint Flow:
  - **Source**: `unauthenticated POST /auth/login form fields`
  - **Path**:
    - `app/blueprints/login/views.py:14 request.form username/password`
    - `app/blueprints/login/views.py:16 User.query.filter_by(username)`
    - `app/blueprints/login/views.py:18 login_user(user) session creation`
  - **Sink**: `unlimited authentication attempts leading to session issuance`
- Evidence: Handler app/blueprints/login/views.py:9 POST/GET /auth/login performs User.query.filter_by(username) + plaintext compare at line 17 with redirect on success; repo grep for limiter/ratelimit/throttle/lockout returns no matches and no Flask-Limiter, login-attempt counter, or sleep. Default admin/admin in manage.py:14 makes brute-force/credential-stuffing trivial, amplified by DEBUG=True.
  - Validation: Login at app/blueprints/login/views.py:9-18 does User.query.filter_by+plaintext compare with no counter/delay; grep for limiter/ratelimit/throttle/lockout returns no matches; default admin/admin at manage.py:14 makes guessing trivial
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Login at app/blueprints/login/views.py:9-18 does User.query.filter_by+plaintext compare with no counter/delay; grep for limiter/ratelimit/throttle/lockout returns no matches; default admin/admin at manage.py:14 makes guessing trivial | consensus: 1/1 confirmed | triage: Unlimited login attempts with default admin admin
- Patch:
  - **Summary**: Add rate-limiting/lockout and delay on login; remove default credential and hash passwords

<a id="finding-20"></a>
### MEDIUM Login CSRF on POST auth login
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `app/blueprints/login/views.py:9-10`
- Vulnerable code (`app/blueprints/login/views.py`):
```python
@authentication.route('/login', methods=['POST', 'GET'])
```
- Taint Flow:
  - **Source**: `cross-site POST`
  - **Sink**: `login without CSRF`
- Evidence: @authentication.route('/login', methods=['POST', 'GET'])
  - Validation: app/blueprints/login/views.py:9-17 POST /login calls login_user with no CSRF token; repo-wide grep for csrf finds zero checks, state-changing session creation CSRF-able (login-CSRF)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/login/views.py:9-17 POST /login calls login_user with no CSRF token; repo-wide grep for csrf finds zero checks, state-changing session creation CSRF-able (login-CSRF) | consensus: 1/1 confirmed | triage: Login creates session with no CSRF token
- Patch:
  - **Summary**: Add per-session CSRF tokens to login and all state-changing POSTs; set SameSite=Lax cookies.

<a id="finding-21"></a>
### MEDIUM Session cookie missing Secure/SameSite flags
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.85
- Location: `app/flask_xss.py:22-26`
- Vulnerable code (`app/flask_xss.py`):
```python
def config_app(app):
```
- Taint Flow:
  - **Source**: `authenticated session cookie stored in browser`
  - **Path**:
    - `app/blueprints/login/views.py:18 login_user(user) session issuance`
    - `app/flask_xss.py:22 config_app without SESSION_COOKIE_*`
  - **Sink**: `session cookie transmitted without Secure/SameSite restrictions`
- Evidence: Function app/flask_xss.py:22 config_app sets only SECRET_KEY/SQLALCHEMY_DATABASE_URI/EXPLAIN/DEBUG; repo grep for SESSION_COOKIE returns no matches so Flask session cookie (issued via login_user at app/blueprints/login/views.py:18) has no Secure/SameSite hardening. Combined with prevalent XSS (|safe sinks) and HTTP localhost deployment, session theft via script or network sniffing is unmitigated. Distinct from unsafe_cookies name-cookie flags already reported.
  - Validation: config_app at app/flask_xss.py:22-26 sets only SECRET_KEY/DB/DEBUG with no SESSION_COOKIE_SECURE/SAMESITE/HTTPONLY (grep returns no matches); session issued via login_user at app/blueprints/login/views.py:18
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: config_app at app/flask_xss.py:22-26 sets only SECRET_KEY/DB/DEBUG with no SESSION_COOKIE_SECURE/SAMESITE/HTTPONLY (grep returns no matches); session issued via login_user at app/blueprints/login/views.py:18 | consensus: 1/1 confirmed | triage: Session cookie has no Secure SameSite hardening
- Patch:
  - **Summary**: Set SESSION_COOKIE_SECURE/SAMESITE=Lax/HTTPONLY and lifetime in config

<a id="finding-22"></a>
### MEDIUM Missing Content-Security-Policy and clickjacking/sniffing headers
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-693 | confidence: 0.8
- Location: `app/flask_xss.py:71-77`
- Vulnerable code (`app/flask_xss.py`):
```python
def after_request(response):
```
- Evidence: app/flask_xss.py:71-77 after_request only sets X-XSS-Protection:0 when disabled; no Content-Security-Policy, X-Frame-Options, X-Content-Type-Options set anywhere (grep confirms no CSP header)
  - Validation: Central header hook at app/flask_xss.py:71-77 only sets X-XSS-Protection:0; grep confirms no Content-Security-Policy/X-Frame-Options/X-Content-Type-Options, leaving |safe sinks e.g. app/templates/admin/message.html:30 without containment
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Central header hook at app/flask_xss.py:71-77 only sets X-XSS-Protection:0; grep confirms no Content-Security-Policy/X-Frame-Options/X-Content-Type-Options, leaving |safe sinks e.g. app/templates/admin/message.html:30 without containment | consensus: 1/1 confirmed | triage: No CSP frame and sniffing headers
- Patch:
  - **Summary**: Emit fixed CSP, X-Frame-Options:DENY/SAMEORIGIN, X-Content-Type-Options:nosniff in after_request

<a id="finding-23"></a>
### MEDIUM Unquoted attribute XSS via g.path
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.8
- Location: `app/templates/_base.html:67-67`
- Vulnerable code (`app/templates/_base.html`):
```html
input name equals next type hidden
```
- Taint Flow:
  - **Source**: `URL path`
  - **Path**:
    - `app/flask_xss.py:68 request.path`
    - `app/templates/_base.html:67 value`
  - **Sink**: `unquoted attribute`
- Evidence: input name equals next type hidden
  - Validation: Untrusted URL path at app/flask_xss.py:68 g.path=request.path reflected unquoted at app/templates/_base.html:67 value={{ g.path }}; Jinja autoescape does not strip spaces so attribute injection e.g. /%20onfocus= works
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Untrusted URL path at app/flask_xss.py:68 g.path=request.path reflected unquoted at app/templates/_base.html:67 value={{ g.path }}; Jinja autoescape does not strip spaces so attribute injection e.g. /%20onfocus= works | consensus: 1/1 confirmed | triage: URL path reflected unquoted in hidden input
- Patch:
  - **Summary**: Quote attribute value="{{ g.path }}" and rely on autoescape; prefer url_for for next values

<a id="finding-24"></a>
### LOW Logout CSRF via GET-accessible logout
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `app/blueprints/login/views.py:28-30`
- Vulnerable code (`app/blueprints/login/views.py`):
```python
def logout(): logout_user() via GET+POST
```
- Taint Flow:
  - **Source**: `cross-site GET`
  - **Sink**: `logout_user via GET`
- Evidence: def logout():
  - Validation: app/blueprints/login/views.py:27 @authentication.route('/logout', methods=['POST','GET']) with :28-30 logout_user() allows cross-site GET to terminate session; no CSRF token anywhere
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/login/views.py:27 @authentication.route('/logout', methods=['POST','GET']) with :28-30 logout_user() allows cross-site GET to terminate session; no CSRF token anywhere | consensus: 1/1 confirmed | triage: GET-accessible logout allows cross-site termination
- Patch:
  - **Summary**: Restrict logout to POST with per-session CSRF token and SameSite cookies.

<a id="finding-25"></a>
### LOW Insecure cookie flags on unsafe_cookies Set-Cookie
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `app/blueprints/sandboxes/views.py:38-38`
- Vulnerable code (`app/blueprints/sandboxes/views.py`):
```python
response.set_cookie('name', name)
```
- Taint Flow:
  - **Source**: `server-set cookie`
  - **Sink**: `set_cookie without flags`
- Evidence: response.set_cookie('name', name)
  - Validation: app/blueprints/sandboxes/views.py:38 response.set_cookie('name', name) sets cookie with no httponly/secure/samesite flags
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/blueprints/sandboxes/views.py:38 response.set_cookie('name', name) sets cookie with no httponly/secure/samesite flags | consensus: 1/1 confirmed | triage: Demo name cookie missing HttpOnly Secure SameSite
- Patch:
  - **Summary**: Set httponly=True, secure=True, samesite='Lax' on set_cookie; set session cookie flags app-wide.

<a id="finding-26"></a>
### LOW World-writable SQLite path in tmp
- CVSS: **2.2** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-668 | confidence: 0.8
- Location: `app/flask_xss.py:24-24`
- Vulnerable code (`app/flask_xss.py`):
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
```
- Taint Flow:
  - **Source**: `hardcoded URI`
  - **Sink**: `SQLite in tmp`
- Evidence: app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
  - Validation: app/flask_xss.py:24 hardcodes sqlite:////tmp/test.db predictable path in sticky world-writable /tmp with no env override; local users can pre-create/symlink/replace DB
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/flask_xss.py:24 hardcodes sqlite:////tmp/test.db predictable path in sticky world-writable /tmp with no env override; local users can pre-create/symlink/replace DB | consensus: 1/1 confirmed | triage: Predictable SQLite in world-writable tmp needs local
- Patch:
  - **Summary**: Configure DB URI from env outside /tmp with 0600 perms; create directory securely, fail closed if unwritable.
