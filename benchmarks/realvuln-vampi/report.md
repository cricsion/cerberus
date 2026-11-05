# Cerberus Report

**Findings:** 13 actionable — 3 critical, 4 high, 6 medium
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 1 duplicate — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 3 | 0 / 3 (0%) | 3 |
| HIGH | 4 | 0 / 4 (0%) | 4 |
| MEDIUM | 6 | 0 / 6 (0%) | 6 |
| **TOTAL** | **13** | **0 / 13 (0%)** | **13** |

## Table of Contents

- [Confirmed (13)](#confirmed)
  - [CRITICAL: Mass-assignment in registration allows unauthenticated admin account creation (`api_views/users.py:60`)](#finding-1)
  - [CRITICAL: Missing authorization allows any authenticated user to overwrite any user's password (`api_views/users.py:186`)](#finding-2)
  - [CRITICAL: SQL Injection in User.get_user (`models/user_model.py:72`)](#finding-3)
  - [HIGH: Broken Object Level Authorization allows any user to read any book secret (`api_views/books.py:50`)](#finding-4)
  - [HIGH: Unauthenticated database reset endpoint allows arbitrary DB wipe (`api_views/main.py:6`)](#finding-5)
  - [HIGH: Unauthenticated debug endpoint exposes all user passwords and admin flags (`api_views/users.py:24`)](#finding-6)
  - [HIGH: Hardcoded default credentials with plaintext password storage (`models/user_model.py:97`)](#finding-7)
  - [MEDIUM: Missing authentication on book-list endpoint exposes inventory (`api_views/books.py:12`)](#finding-8)
  - [MEDIUM: Missing authentication on user-list endpoint exposes all users (`api_views/users.py:19`)](#finding-9)
  - [MEDIUM: Missing authentication on user lookup endpoint enables unauthenticated enumeration (`api_views/users.py:45`)](#finding-10)
  - [MEDIUM: Login oracle enables username and password enumeration (`api_views/users.py:101`)](#finding-11)
  - [MEDIUM: Flask debug mode enabled on public interface (`app.py:17`)](#finding-12)
  - [MEDIUM: Regular expression denial of service in email update via nested-quantifier regex (`api_views/users.py:144`)](#finding-13)

<a id="confirmed"></a>
## Confirmed (13)

<a id="finding-1"></a>
### CRITICAL Mass-assignment in registration allows unauthenticated admin account creation
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-915 | confidence: 0.95
- Location: `api_views/users.py:60-66`
- Vulnerable code (`api_views/users.py`):
```python
if vuln and 'admin' in request_data:  # User is possible to define if she/he wants to be an admin !!
                if request_data['admin']:
                    admin = True
                user = User(username=request_data['username'], password=request_data['password'],
```
- Taint Flow:
  - **Source**: `unauthenticated JSON body admin in POST /users/v1/register`
  - **Path**:
    - `openapi_specs/openapi3.yml:120 /users/v1/register`
    - `api_views/users.py:52 register_user()`
    - `api_views/users.py:60 admin branch`
    - `api_views/users.py:65 User(...,admin=...)`
  - **Sink**: `User(admin=True) persistence via db.session.add/commit`
- Evidence: api_views/users.py:60 honors client admin flag; api_views/users.py:65-66 User created with admin=True; api_views/users.py:212 delete_user trusts user.admin
  - Validation: api_views/users.py:60 honors client-controlled admin flag when vuln=1 and api_views/users.py:65 persists User(admin=True) via db.session.add/commit; api_views/json_schemas.py register schema omits admin allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/users.py:60 honors client-controlled admin flag when vuln=1 and api_views/users.py:65 persists User(admin=True) via db.session.add/commit; api_views/json_schemas.py register schema omits admin allowlist | consensus: 1/1 confirmed | triage: Unauthenticated mass-assignment creates admin accounts via client flag
- Patch:
  - **Summary**: Remove admin from user-controlled input; force admin=False on registration and require separate privileged role-grant.

<a id="finding-2"></a>
### CRITICAL Missing authorization allows any authenticated user to overwrite any user's password
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `api_views/users.py:186-190`
- Vulnerable code (`api_views/users.py`):
```python
if vuln:  # Unauthorized update of password of another user
                user = User.query.filter_by(username=username).first()
                    user.password = request_data.get('password')
                    db.session.commit()
```
- Taint Flow:
  - **Source**: `authenticated path param username + JSON password in PUT /users/v1/{username}/password`
  - **Path**:
    - `openapi_specs/openapi3.yml:426 PUT /users/v1/{username}/password`
    - `api_views/users.py:179 update_password(username)`
    - `api_views/users.py:187 User.query.filter_by(username=username)`
    - `api_views/users.py:189 user.password assignment`
  - **Sink**: `user.password overwrite + db.session.commit()`
- Evidence: api_views/users.py:179 update_password(username) takes path username; api_views/users.py:187 victim selected by path param; api_views/users.py:189 attacker password written; safe branch api_views/users.py:194 would use resp['sub'] instead
  - Validation: api_views/users.py:179 update_password validates token but vuln branch api_views/users.py:187 looks up victim by path username and api_views/users.py:189 overwrites user.password + commit; safe branch api_views/users.py:194 would use resp[sub]
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/users.py:179 update_password validates token but vuln branch api_views/users.py:187 looks up victim by path username and api_views/users.py:189 overwrites user.password + commit; safe branch api_views/users.py:194 would use resp[sub] | consensus: 1/1 confirmed | triage: Authenticated IDOR allows overwriting any user's password and admin takeover
- Patch:
  - **Summary**: Bind password update to authenticated identity resp[sub] only; reject path-username mismatches unless admin.

<a id="finding-3"></a>
### CRITICAL SQL Injection in User.get_user
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.95
- Location: `models/user_model.py:72-73`
- Vulnerable code (`models/user_model.py`):
```python
user_query = f"SELECT * FROM users WHERE username = '{username}'"
```
- Taint Flow:
  - **Source**: `username path param`
  - **Path**:
    - `api_views/users.py:45 get_by_username`
    - `models/user_model.py:72 interpolated SQL`
  - **Sink**: `db.session.execute(text(user_query))`
- Evidence: user_query = f"SELECT * FROM users WHERE username = '{username}'"
  - Validation: models/user_model.py:72 f-string interpolates username into SQL executed at models/user_model.py:73 via db.session.execute(text(user_query)); reachable unauthenticated from api_views/users.py:45-46 get_by_username; default vulnerable=1 per Dockerfile:14
  - Alternatives considered: vuln_app.app.config['SECRET_KEY'] = 'random' | return '{ "status": "fail", "message": "' + msg['error'] + '"}'
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: models/user_model.py:72 f-string interpolates username into SQL executed at models/user_model.py:73 via db.session.execute(text(user_query)); reachable unauthenticated from api_views/users.py:45-46 get_by_username; default vulnerable=1 per Dockerfile:14 | consensus: 1/1 confirmed | triage: Unauthenticated SQLi f-string flows from path param to execute
- Patch:
  - **Summary**: Replace f-string SQL with parameterized query: db.session.execute(text("SELECT * FROM users WHERE username=:u"), {"u": username}) or ORM filter_by.
  - +1 duplicate(s): `models/user_model.py:72`

<a id="finding-4"></a>
### HIGH Broken Object Level Authorization allows any user to read any book secret
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.95
- Location: `api_views/books.py:50-56`
- Vulnerable code (`api_views/books.py`):
```python
if vuln:  # Broken Object Level Authorization
            book = Book.query.filter_by(book_title=str(book_title)).first()
                'secret': book.secret_content,
```
- Taint Flow:
  - **Source**: `authenticated path param book_title in GET /books/v1/{book_title}`
  - **Path**:
    - `openapi_specs/openapi3.yml:585 /books/v1/{book_title}`
    - `api_views/books.py:45 get_by_title(book_title)`
    - `api_views/books.py:51 Book.query.filter_by(book_title=...)`
    - `api_views/books.py:55 secret_content in response`
  - **Sink**: `Book.secret_content disclosure without ownership check`
- Evidence: api_views/books.py:46 token validated but identity not used in vuln branch; api_views/books.py:51 query by title only; api_views/books.py:55 secret disclosed; contrast safe branch api_views/books.py:62-63 filtering by user
  - Validation: api_views/books.py:45 get_by_title validates token at line 46 but vuln branch api_views/books.py:51 queries by book_title only and api_views/books.py:55 returns secret_content without ownership check; safe branch api_views/books.py:62-63 filters by user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/books.py:45 get_by_title validates token at line 46 but vuln branch api_views/books.py:51 queries by book_title only and api_views/books.py:55 returns secret_content without ownership check; safe branch api_views/books.py:62-63 filters by user | consensus: 1/1 confirmed | triage: Authenticated BOLA discloses any book secret without ownership check
- Patch:
  - **Summary**: Enforce ownership check on all branches: query Book by (user, book_title) from resp[sub] and return 404/403 for non-owners.

<a id="finding-5"></a>
### HIGH Unauthenticated database reset endpoint allows arbitrary DB wipe
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `api_views/main.py:6-9`
- Vulnerable code (`api_views/main.py`):
```python
def populate_db():
    db.drop_all()
    db.create_all()
    User.init_db_users()
```
- Taint Flow:
  - **Source**: `unauthenticated GET /createdb`
  - **Path**:
    - `openapi_specs/openapi3.yml:16 /createdb`
    - `api_views/main.py:6 populate_db()`
    - `api_views/main.py:7 db.drop_all()`
  - **Sink**: `db.drop_all()/create_all() destructive reset`
- Evidence: api_views/main.py:6 populate_db() has no token_validator; openapi_specs/openapi3.yml:16 /createdb defines no security
  - Validation: api_views/main.py:6 populate_db() calls db.drop_all()/create_all() with no token_validator; openapi_specs/openapi3.yml:16 /createdb defines no security scheme
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/main.py:6 populate_db() calls db.drop_all()/create_all() with no token_validator; openapi_specs/openapi3.yml:16 /createdb defines no security scheme | consensus: 1/1 confirmed | triage: Unauthenticated DB drop/create allows full wipe and reset to known creds
- Patch:
  - **Summary**: Require admin authentication on /createdb and remove drop_all/create_all from unauthenticated path.

<a id="finding-6"></a>
### HIGH Unauthenticated debug endpoint exposes all user passwords and admin flags
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.95
- Location: `api_views/users.py:24-26`
- Vulnerable code (`api_views/users.py`):
```python
def debug():
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value
```
- Taint Flow:
  - **Source**: `unauthenticated GET /users/v1/_debug`
  - **Path**:
    - `openapi_specs/openapi3.yml:88 /users/v1/_debug`
    - `api_views/users.py:24 debug()`
    - `models/user_model.py:66 get_all_users_debug()`
    - `models/user_model.py:58 json_debug()`
  - **Sink**: `jsonify password/admin disclosure`
- Evidence: api_views/users.py:24 debug() has no token_validator call; models/user_model.py:58 json_debug returns password+admin; models/user_model.py:66 get_all_users_debug aggregates all users; openapi_specs/openapi3.yml:88 /users/v1/_debug has no security scheme
  - Validation: api_views/users.py:24 debug() has no token_validator call and returns User.get_all_users_debug(); models/user_model.py:58 json_debug returns password+admin aggregated at models/user_model.py:66; openapi_specs/openapi3.yml:88 /users/v1/_debug defines no security; app.py:8-10 notes debug stays vulnerable even when vuln=0
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/users.py:24 debug() has no token_validator call and returns User.get_all_users_debug(); models/user_model.py:58 json_debug returns password+admin aggregated at models/user_model.py:66; openapi_specs/openapi3.yml:88 /users/v1/_debug defines no security; app.py:8-10 notes debug stays vulnerable even when vuln=0 | consensus: 1/1 confirmed | triage: Unauthenticated _debug discloses all passwords and admin flags
- Patch:
  - **Summary**: Require authentication/authorization on debug() or remove endpoint; never return password hashes/plaintexts in API responses.

<a id="finding-7"></a>
### HIGH Hardcoded default credentials with plaintext password storage
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.85
- Location: `models/user_model.py:97-101`
- Vulnerable code (`models/user_model.py`):
```python
def init_db_users():
        User.register_user("name1", "***", "mail1@mail.com", False)
        User.register_user("name2", "***", "mail2@mail.com", False)
        User.register_user("admin", "***", "admin@mail.com", True)
```
- Taint Flow:
  - **Source**: `hardcoded credentials in init_db_users`
  - **Path**:
    - `models/user_model.py:97 init_db_users()`
    - `models/user_model.py:84 register_user()`
    - `api_views/main.py:9 User.init_db_users()`
  - **Sink**: `plaintext persistence + unauthenticated activation via /createdb`
- Evidence: models/user_model.py:97 init_db_users seeds default accounts; models/user_model.py:14 password column is plaintext String; api_views/main.py:9 /createdb invokes seeding unauthenticated
  - Validation: models/user_model.py:97 init_db_users seeds name1/pass1, name2/pass2, admin/pass1; models/user_model.py:14 password is plaintext String with no hashing (no bcrypt/hash found); api_views/main.py:9 triggers seeding via unauthenticated /createdb
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: models/user_model.py:97 init_db_users seeds name1/pass1, name2/pass2, admin/pass1; models/user_model.py:14 password is plaintext String with no hashing (no bcrypt/hash found); api_views/main.py:9 triggers seeding via unauthenticated /createdb | consensus: 1/1 confirmed | triage: Hardcoded plaintext defaults activated via unauthenticated reset
- Patch:
  - **Summary**: Remove hardcoded seeds, hash passwords with bcrypt/argon2, and gate DB seeding behind admin auth.

<a id="finding-8"></a>
### MEDIUM Missing authentication on book-list endpoint exposes inventory
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-306 | confidence: 0.9
- Location: `api_views/books.py:12-14`
- Vulnerable code (`api_views/books.py`):
```python
def get_all_books():
    return_value = jsonify({'Books': Book.get_all_books()})
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP GET /books/v1`
  - **Path**:
    - `api_views/books.py:12 unauthenticated GET /books/v1 entry`
    - `models/books_model.py:27 Book.get_all_books DB read`
  - **Sink**: `JSON disclosure of all book titles and owners`
- Evidence: api_views/books.py:12 get_all_books has no token_validator; openapi /books/v1 GET defines no security block, unlike POST /books/v1 which requires bearerAuth
  - Validation: api_views/books.py:12 get_all_books has no token_validator and returns Book.get_all_books() at api_views/books.py:13; openapi /books/v1 GET has no security while POST /books/v1 requires bearerAuth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/books.py:12 get_all_books has no token_validator and returns Book.get_all_books() at api_views/books.py:13; openapi /books/v1 GET has no security while POST /books/v1 requires bearerAuth | consensus: 1/1 confirmed | triage: Unauthenticated book inventory disclosure with no token check
- Patch:
  - **Summary**: Require bearerAuth on GET /books/v1 or return only non-sensitive public fields.

<a id="finding-9"></a>
### MEDIUM Missing authentication on user-list endpoint exposes all users
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-306 | confidence: 0.9
- Location: `api_views/users.py:19-21`
- Vulnerable code (`api_views/users.py`):
```python
def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP GET /users/v1`
  - **Path**:
    - `api_views/users.py:19 unauthenticated GET /users/v1 entry`
    - `models/user_model.py:62 User.get_all_users DB read`
  - **Sink**: `JSON disclosure of all usernames/emails`
- Evidence: api_views/users.py:19 get_all_users has no token_validator call; openapi_specs/openapi3.yml /users/v1 get defines no security block while /me and other endpoints do
  - Validation: api_views/users.py:19 get_all_users has no token_validator and returns User.get_all_users() at api_views/users.py:20; openapi_specs/openapi3.yml /users/v1 GET has no security while /me requires bearerAuth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/users.py:19 get_all_users has no token_validator and returns User.get_all_users() at api_views/users.py:20; openapi_specs/openapi3.yml /users/v1 GET has no security while /me requires bearerAuth | consensus: 1/1 confirmed | triage: Unauthenticated user-list discloses all usernames and emails
- Patch:
  - **Summary**: Require bearerAuth on GET /users/v1 or restrict to admin/minimal fields.

<a id="finding-10"></a>
### MEDIUM Missing authentication on user lookup endpoint enables unauthenticated enumeration
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-306 | confidence: 0.9
- Location: `api_views/users.py:45-49`
- Vulnerable code (`api_views/users.py`):
```python
def get_by_username(username):
    if User.get_user(username):
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP GET /users/v1/{username} path parameter`
  - **Path**:
    - `api_views/users.py:45 path param username entry`
    - `models/user_model.py:70 User.get_user`
  - **Sink**: `database lookup and response disclosure of user existence`
- Evidence: api_views/users.py:45 get_by_username(username) never calls token_validator; openapi /users/v1/{username} GET has no security; path param flows into User.get_user -> raw SQL without any auth gate
  - Validation: api_views/users.py:45 get_by_username takes path username with no token_validator and calls User.get_user at api_views/users.py:46; openapi /users/v1/{username} GET defines no security, enabling unauthenticated enumeration/SQLi trigger
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/users.py:45 get_by_username takes path username with no token_validator and calls User.get_user at api_views/users.py:46; openapi /users/v1/{username} GET defines no security, enabling unauthenticated enumeration/SQLi trigger | consensus: 1/1 confirmed | triage: Unauthenticated user lookup enables enumeration, distinct auth gate from SQLi sink
- Patch:
  - **Summary**: Require authentication on user lookup and use parameterized ORM query.

<a id="finding-11"></a>
### MEDIUM Login oracle enables username and password enumeration
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-203 | confidence: 0.9
- Location: `api_views/users.py:101-106`
- Vulnerable code (`api_views/users.py`):
```python
if vuln:  # Password Enumeration
            if user and request_data.get('password') != user.password:
                return Response(error_message_helper("Password is not correct for the given username."), 200,
            elif not user:  # User enumeration
```
- Taint Flow:
  - **Source**: `unauthenticated JSON username/password in POST /users/v1/login`
  - **Path**:
    - `openapi_specs/openapi3.yml:162 /users/v1/login`
    - `api_views/users.py:85 login_user()`
    - `api_views/users.py:101 enumeration branch`
  - **Sink**: `distinguishable error responses revealing account existence`
- Evidence: api_views/users.py:101 vuln branch splits cases; api_views/users.py:103 distinct wrong-password message; api_views/users.py:106 distinct unknown-user message; contrast generic message api_views/users.py:108
  - Validation: api_views/users.py:101 vuln branch returns distinct messages at api_views/users.py:103 wrong-password vs api_views/users.py:106 unknown-user, vs generic message at api_views/users.py:108 in secure branch; reachable unauthenticated via api_views/users.py:85 login_user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/users.py:101 vuln branch returns distinct messages at api_views/users.py:103 wrong-password vs api_views/users.py:106 unknown-user, vs generic message at api_views/users.py:108 in secure branch; reachable unauthenticated via api_views/users.py:85 login_user | consensus: 1/1 confirmed | triage: Unauthenticated login oracle distinguishes wrong-password vs unknown-user
- Patch:
  - **Summary**: Return single generic login-failure message for both unknown user and wrong password.

<a id="finding-12"></a>
### MEDIUM Flask debug mode enabled on public interface
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-215 | confidence: 0.9
- Location: `app.py:17-17`
- Vulnerable code (`app.py`):
```python
vuln_app.run(host='0.0.0.0', port=5000, debug=True)
```
- Evidence: app.py:17 vuln_app.run(host='0.0.0.0', port=5000, debug=True) enables Werkzeug debugger in the shipped entrypoint
  - Validation: app.py:17 vuln_app.run(host=0.0.0.0, port=5000, debug=True) under __main__ is the container entrypoint per Dockerfile:16-17 CMD app.py, exposing Werkzeug debugger/info leaks
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app.py:17 vuln_app.run(host=0.0.0.0, port=5000, debug=True) under __main__ is the container entrypoint per Dockerfile:16-17 CMD app.py, exposing Werkzeug debugger/info leaks | consensus: 1/1 confirmed | triage: Shipped entrypoint runs Flask debug on 0.0.0.0:5000
- Patch:
  - **Summary**: Run with debug=False in production; bind to localhost behind WSGI server and disable debugger.

<a id="finding-13"></a>
### MEDIUM Regular expression denial of service in email update via nested-quantifier regex
- CVSS: **4.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-1333 | confidence: 0.8
- Location: `api_views/users.py:144-146`
- Vulnerable code (`api_views/users.py`):
```python
match = re.search(
                r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
                str(request_data.get('email')))
```
- Taint Flow:
  - **Source**: `authenticated JSON email in PUT /users/v1/{username}/email`
  - **Path**:
    - `openapi_specs/openapi3.yml:366 PUT /users/v1/{username}/email`
    - `api_views/users.py:132 update_email()`
    - `api_views/users.py:144 re.search()`
  - **Sink**: `re.search with catastrophic-backtracking regex`
- Evidence: api_views/users.py:132 update_email reads JSON email; api_views/users.py:144 re.search with evil pattern on attacker string
  - Validation: api_views/users.py:132 update_email reads attacker email from JSON body; api_views/users.py:144 re.search with nested-quantifier regex ^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])@...) on unbounded str(request_data.get(email)) with no length/timeout guard
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: api_views/users.py:132 update_email reads attacker email from JSON body; api_views/users.py:144 re.search with nested-quantifier regex ^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])@...) on unbounded str(request_data.get(email)) with no length/timeout guard | consensus: 1/1 confirmed | triage: Authenticated ReDoS in email regex with no length guard
- Patch:
  - **Summary**: Replace custom regex with simple validator or email-validator library, enforce max length and avoid nested quantifiers.
