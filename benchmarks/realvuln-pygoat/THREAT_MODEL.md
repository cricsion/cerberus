# Threat Model: realvuln-pygoat

## 1. System context

Repo: realvuln-pygoat. Threat model for realvuln-pygoat | stack: unknown stack | entry points: ~40 routes | prefilter signal classes: hardcoded-secret, sqli-cursor, shell-true, eval-exec, jinja-render, pickle-loads, yaml-load, ssrf-requests, redos-regex, xpath-xml, jwt-decode-verify-false, md5-sha1, path-open-join, csrf-exempt, cookie-flags, js-xss, tpl-xss, debug-exposure, upload, plaintext-creds, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, sqli-cursor, shell-true, eval-exec, jinja-render, pickle-loads, yaml-load, ssrf-requests, redos-regex, xpath-xml, jwt-decode-verify-false, md5-sha1, path-open-join, csrf-exempt, cookie-flags, js-xss, tpl-xss, debug-exposure, upload, plaintext-creds, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.md, docs/dev_guide.md.

## 2. Assets

| source code integrity | .github (2 files), challenge (16 files), dockerized_labs (35 files), introduction (148 files), pygoat (5 files), root (7 files) | high |
| data assets | _unknown — owner to confirm_ | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP request handlers (40 routes detected) | Web and REST API endpoints (~40 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~40 framework routes:*

- `<str:challenge>` (`challenge/urls.py:5`)
- `GET /` (`dockerized_labs/broken_auth_lab/app.py:27`)
- `GET /lab` (`dockerized_labs/broken_auth_lab/app.py:31`)
- `POST /login` (`dockerized_labs/broken_auth_lab/app.py:35`)
- `POST /register` (`dockerized_labs/broken_auth_lab/app.py:58`)
- `POST /reset-password` (`dockerized_labs/broken_auth_lab/app.py:78`)
- `GET /reset/<token>` (`dockerized_labs/broken_auth_lab/app.py:97`)
- `GET /dashboard` (`dockerized_labs/broken_auth_lab/app.py:103`)
- `POST /serialize` (`dockerized_labs/insec_des_lab/main.py:21`)
- `POST /deserialize` (`dockerized_labs/insec_des_lab/main.py:30`)
- `about/` (`dockerized_labs/sensitive_data_exposure/dataexposure/urls.py:6`)
- `login/` (`dockerized_labs/sensitive_data_exposure/dataexposure/urls.py:7`)
- `register/` (`dockerized_labs/sensitive_data_exposure/dataexposure/urls.py:8`)
- `profile/` (`dockerized_labs/sensitive_data_exposure/dataexposure/urls.py:9`)
- `api/user-data/` (`dockerized_labs/sensitive_data_exposure/dataexposure/urls.py:12`)
- *(and ~25 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Database compromise and sensitive data exfiltration via SQL injection | remote_unauth | introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:158 [SQL injection in sql_lab via string-concatenated raw query]; introduction/views.py:864 [SQL injection in injection_sql_lab via raw query] |
| T2 | Remote code execution via untrusted object deserialization | remote_unauth | dockerized_labs/insec_des_lab/main.py, introduction/views.py | application data and system state | critical | almost_certain | unmitigated | none | introduction/views.py:214 [Insecure deserialization in insec_des_lab via pickle cookie]; introduction/views.py:560 [Unsafe YAML deserialization in a9_lab via yaml.Loader]; dockerized_labs/insec_des_lab/main.py:38 [Pickle RCE in insec_des_lab deserialize_data] |
| T3 | Arbitrary file disclosure via XML External Entity (XXE) injection | remote_unauth | introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:258 [XXE in xxe_parse with external entities enabled] |
| T4 | Remote code execution via untrusted operating system command injection | remote_unauth | introduction/mitre.py, introduction/views.py | application data and system state | critical | almost_certain | unmitigated | none | introduction/views.py:430 [OS command injection in cmd_lab via shell=True]; introduction/mitre.py:241 [OS command injection in mitre_lab_17_api via nmap concatenation]; introduction/mitre.py:233 [Shell wrapper command_out executes caller string with shell=True] |
| T5 | Security compromise via Code injection in cmd_lab2 via eval | remote_unauth | introduction/mitre.py, introduction/views.py | application data and system state | critical | almost_certain | unmitigated | none | introduction/views.py:460 [Code injection in cmd_lab2 via eval]; introduction/views.py:588 [Code injection in a9_lab2 via ImageMath.eval]; introduction/mitre.py:218 [Code injection in mitre_lab_25_api via eval] |
| T6 | Internal service access and cloud metadata exposure via Server-Side Request Forgery (SSRF) | remote_unauth | introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:963 [SSRF in ssrf_lab2 via unchecked requests.get] |
| T7 | Arbitrary code execution via dynamic code evaluation | remote_unauth | introduction/apis.py, introduction/utility.py, introduction/views.py | application data and system state | critical | almost_certain | unmitigated | none | introduction/views.py:995 [Stored SSTI in ssti_lab via template file write]; introduction/apis.py:69 [Arbitrary file write RCE in log_function_checker]; introduction/apis.py:131 [Arbitrary file write in A6_disscussion_api_2]; introduction/utility.py:35 [Code injection file write in ssrf_code_converter] |
| T8 | Security compromise via Forgeable JWT in sec_misconfig_lab3 via hardcoded key | remote_unauth | dockerized_labs/broken_auth_lab/app.py, dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py, dockerized_labs/sensitive_data_exposure/templates/login.html | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:1095 [Forgeable JWT in sec_misconfig_lab3 via hardcoded key]; introduction/mitre.py:169 [Hardcoded JWT secret in csrf_lab_login]; pygoat/settings.py:25 [Hardcoded Django SECRET_KEY in pygoat settings]; dockerized_labs/sensitive_data_exposure/templates/login.html:73 [Hardcoded demo credentials in login template]; pygoat/settings.py:171 [Hardcoded JWT cookie signing key in settings]; dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8 [Hardcoded Django SECRET_KEY in sensitive-data lab]; dockerized_labs/broken_auth_lab/app.py:8 [Hardcoded Flask secret_key in broken-auth lab]; dockerized_labs/broken_auth_lab/app.py:13 [Hardcoded weak default credentials in broken-auth lab]; introduction/views.py:831 [Hardcoded credentials in a1_broken_access_lab_3]; i |
| T9 | Authentication bypass via flawed credential or identity validation | remote_unauth | dockerized_labs/broken_auth_lab/app.py, introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | dockerized_labs/broken_auth_lab/app.py:42 [Forgeable session token in broken_auth_lab login]; dockerized_labs/broken_auth_lab/app.py:112 [Authentication bypass in broken_auth_lab dashboard]; introduction/views.py:302 [Authentication bypass in auth_lab_login via userid cookie]; introduction/views.py:514 [OTP verification bypass via admin-OTP OR condition] |
| T10 | Security compromise via Predictable reset token with disclosure in reset_password | remote_unauth | dockerized_labs/broken_auth_lab/app.py, introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | dockerized_labs/broken_auth_lab/app.py:84 [Predictable reset token with disclosure in reset_password]; introduction/views.py:496 [Predictable and disclosed OTP in Otp handler] |
| T11 | Security compromise via Missing authorization on debug log disclosure | remote_unauth | introduction/playground/A9/archive.py, introduction/views.py | application data and system state | medium | almost_certain | unmitigated | none | introduction/views.py:636 [Missing authorization on debug log disclosure]; introduction/playground/A9/archive.py:12 [Plaintext credential logging in log_function_target] |
| T12 | Security compromise via Insecure custom hash in crypto_failure_lab2 | remote_unauth | challenge/models.py, introduction/mitre.py, introduction/utility.py | application data and system state | medium | almost_certain | unmitigated | none | introduction/views.py:1042 [Insecure custom hash in crypto_failure_lab2]; introduction/views.py:1026 [Weak MD5 password hashing in crypto_failure_lab]; introduction/utility.py:58 [Weak reversible customHash primitive (SHA256 reversed)]; introduction/views.py:1194 [Unsalted SHA256 password check in auth_failure_lab3]; introduction/mitre.py:161 [MD5 password hashing in csrf_lab_login]; challenge/models.py:28 [Unsalted SHA256 flag hashing with prefix bypass in Challenge.save] |
| T13 | Information disclosure of sensitive application or configuration data | remote_unauth | dockerized_labs/sensitive_data_exposure/dataexposure/views.py, dockerized_labs/sensitive_data_exposure/templates/profile.html, introduction/templates/Lab_2021/A3_Injection/Blogs/9d73d120683d.html | application data and system state | high | almost_certain | unmitigated | none | dockerized_labs/sensitive_data_exposure/dataexposure/views.py:109 [Unmasked PII disclosure in api_data_view]; dockerized_labs/sensitive_data_exposure/dataexposure/views.py:130 [Unauthenticated bulk PII exposure in all_users_data_view]; introduction/templates/Lab_2021/A3_Injection/Blogs/9d73d120683d.html:2 [SSTI artifact discloses password hashes]; introduction/templates/Lab_2021/A3_Injection/Blogs/a2538af1b5e4.html:1 [SSTI artifact discloses SECRET_KEY]; dockerized_labs/sensitive_data_exposure/templates/profile.html:128 [Full PII disclosure in HTML comment on profile page]; introduction/views.py:571 [Version disclosure in get_version] |
| T14 | Arbitrary file disclosure or tampering via path traversal | remote_unauth | introduction/playground/ssrf/main.py, introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/playground/ssrf/main.py:8 [Path traversal in playground ssrf_lab]; introduction/views.py:1006 [Template path traversal in ssti_view_blog]; introduction/views.py:927 [Path traversal file read in ssrf_lab] |
| T15 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | introduction/static/js/a9.js, introduction/templates/Lab/XSS/xss_lab.html, introduction/templates/Lab/XSS/xss_lab_2.html | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:111 [Inadequate XSS filter in xss_lab2]; introduction/views.py:129 [XSS bypass in xss_lab3 via alphanumeric strip]; introduction/templates/Lab/XSS/xss_lab_2.html:20 [Reflected XSS via /safe in xss_lab_2.html]; introduction/templates/Lab/XSS/xss_lab_3.html:20 [JS-context XSS via {{code}} in script block]; introduction/templates/Lab/ssrf/ssrf_lab2.html:23 [XSS via /safe rendering of SSRF response]; introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11 [Reflected XSS via /safe username in A8 lab2]; introduction/static/js/a9.js:40 [DOM XSS via innerHTML in a9.js]; introduction/views.py:101 [Reflected XSS in xss_lab via q parameter]; introduction/views.py:1223 [Reflected XSS in software_and_data_integrity_failure_lab2]; introduction/templates/ |
| T16 | Horizontal privilege escalation via Insecure Direct Object References (IDOR) | remote_auth | introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:537 [Header-spoof authorization in secret view]; introduction/views.py:946 [IP spoofing bypass in ssrf_target via X-Forwarded-For]; introduction/views.py:349 [Broken access control in ba_lab via client-side admin cookie]; introduction/views.py:754 [Broken access control in a1_broken_access_lab_1 via admin cookie]; introduction/views.py:794 [Authorization bypass in a1_broken_access_lab_2 via User-Agent header]; introduction/views.py:1003 [IDOR in ssti_view_blog missing author check] |
| T17 | Security compromise via Weak PRNG API key generation in generate_api_key | remote_unauth | dockerized_labs/sensitive_data_exposure/dataexposure/views.py, introduction/views.py | application data and system state | medium | almost_certain | unmitigated | none | dockerized_labs/sensitive_data_exposure/dataexposure/views.py:41 [Weak PRNG API key generation in generate_api_key]; introduction/views.py:680 [Weak PRNG ticket codes in gentckt] |
| T18 | Security compromise via Plaintext password storage in auth_lab_signup | remote_unauth | dockerized_labs/broken_auth_lab/app.py, introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:286 [Plaintext password storage in auth_lab_signup]; introduction/views.py:628 [Plaintext credential comparison in a10_lab]; dockerized_labs/broken_auth_lab/app.py:68 [Plaintext password storage in broken-auth register] |
| T19 | Unauthorized access via missing authorization checks | remote_auth | introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:837 [Missing authorization in a1_broken_access_lab3_secret] |
| T20 | Security compromise via Unsigned cookie privilege escalation in crypto_failure_lab3 | remote_unauth | introduction/views.py | application data and system state | high | almost_certain | unmitigated | none | introduction/views.py:1065 [Unsigned cookie privilege escalation in crypto_failure_lab3] |
| T21 | Unauthorized state change via cross-site request forgery (CSRF) | remote_unauth | introduction/mitre.py, introduction/templates/Lab/A9/a9_lab.html, introduction/templates/Lab/A9/a9_lab2.html | application data and system state | high | almost_certain | unmitigated | none | introduction/mitre.py:191 [CSRF money transfer in csrf_transfer_monei_api via GET]; introduction/templates/Lab/BrokenAccess/ba_lab.html:11 [Missing CSRF token in ba_lab form]; introduction/templates/Lab/CMD/cmd_lab.html:9 [Missing CSRF token in cmd_lab form]; introduction/templates/Lab/CMD/cmd_lab2.html:10 [Missing CSRF token in cmd_lab2 form]; introduction/templates/Lab/A9/a9_lab.html:10 [Missing CSRF token in a9_lab upload form]; introduction/templates/Lab/A9/a9_lab2.html:21 [Missing CSRF token in a9_lab2 form]; introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html:11 [Missing CSRF token in broken_access_lab_1 form]; introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html:11 [Missing CSRF token in broken_access_lab_2 form]; introduction/t |
| T22 | Security compromise via Seeded MD5 hashes without salt (0017) | remote_unauth | introduction/migrations/0017_cf_user.py, introduction/migrations/0018_cf_user_password2.py | application data and system state | medium | almost_certain | unmitigated | none | introduction/migrations/0017_cf_user.py:21 [Seeded MD5 hashes without salt (0017)]; introduction/migrations/0018_cf_user_password2.py:21 [Seeded weak hashes without salt (0018)] |
| T23 | Security compromise via Insecure persistent session cookie without flags in broken-auth login | remote_unauth | dockerized_labs/broken_auth_lab/app.py, introduction/views.py | application data and system state | medium | almost_certain | unmitigated | none | dockerized_labs/broken_auth_lab/app.py:49 [Insecure persistent session cookie without flags in broken-auth login]; introduction/views.py:291 [Insecure userid cookie flags in auth_lab_signup]; introduction/views.py:305 [Insecure userid cookie flags in auth_lab_login GET branch]; introduction/views.py:319 [Insecure userid cookie flags in auth_lab_login POST branch]; introduction/views.py:1076 [Insecure cookie flags in crypto_failure_lab3]; introduction/views.py:1204 [Insecure persistent session_id cookie in auth_failure_lab3] |
| T24 | Security compromise via Flask debug mode enabled in broken-auth lab | remote_unauth | dockerized_labs/broken_auth_lab/app.py, dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py, pygoat/settings.py | application data and system state | medium | almost_certain | unmitigated | none | dockerized_labs/broken_auth_lab/app.py:123 [Flask debug mode enabled in broken-auth lab]; pygoat/settings.py:30 [Django DEBUG enabled in production settings]; dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:11 [DEBUG True in sensitive-data lab settings] |
| T25 | Security compromise via Plaintext PAN storage in UserData model | remote_unauth | dockerized_labs/sensitive_data_exposure/dataexposure/models.py | application data and system state | high | almost_certain | unmitigated | none | dockerized_labs/sensitive_data_exposure/dataexposure/models.py:6 [Plaintext PAN storage in UserData model] |
| T26 | Security compromise via Missing authentication on xxe_parse endpoint | remote_unauth | introduction/apis.py, introduction/mitre.py, introduction/views.py | application data and system state | critical | almost_certain | unmitigated | none | introduction/views.py:256 [Missing authentication on xxe_parse endpoint]; introduction/apis.py:61 [Missing authentication on log_function_checker file-write API]; introduction/apis.py:126 [Missing authentication on A6_disscussion_api_2 arbitrary file-write]; introduction/mitre.py:215 [Missing authentication on MITRE RCE APIs (eval and nmap)] |
| T27 | Security compromise via Wildcard ALLOWED_HOSTS in sensitive-data lab | remote_unauth | dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py | application data and system state | medium | almost_certain | unmitigated | none | dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:13 [Wildcard ALLOWED_HOSTS in sensitive-data lab] |
| T28 | Audit log tampering or log injection via unneutralized log input | remote_unauth | introduction/views.py | application data and system state | medium | almost_certain | unmitigated | none | introduction/views.py:654 [Log injection via spoofable IP in a10_lab2] |
| T29 | Security compromise via Image decompression bomb DoS in a9_lab2 | remote_unauth | introduction/views.py | application data and system state | medium | almost_certain | unmitigated | none | introduction/views.py:584 [Image decompression bomb DoS in a9_lab2]; introduction/views.py:1200 [Unhandled KeyError DoS and missing response in auth_failure_lab3]; introduction/views.py:791 [Unhandled KeyError denial of service via missing User-Agent header] |

## 5. Deprioritized

None recorded by the deterministic floor. A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-pygoat
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history
- owner: unset
- enrichment: deterministic
- stored scan signals:
  - prefilter: .cerberus/realvuln-pygoat/signals/prefilter.txt (244 entries)
  - secrets: .cerberus/realvuln-pygoat/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-pygoat/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-pygoat/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-pygoat/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-pygoat/signals/routes.txt (40 entries)
## 8. Recommended mitigations

_unknown — owner to confirm (one class-level control per threat cluster; deterministic floor proposes none_).

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-pygoat).
Confirmed primary claims: 110.

By class: CWE-79 x14, CWE-798 x12, CWE-352 x10, CWE-327 x6, CWE-200 x6, CWE-639 x6, CWE-614 x6, CWE-94 x4, CWE-287 x4, CWE-306 x4, CWE-502 x3, CWE-78 x3, CWE-95 x3, CWE-22 x3, CWE-256 x3

Affected paths: introduction/views.py x49, dockerized_labs/broken_auth_lab/app.py x8, introduction/mitre.py x7, introduction/apis.py x4, dockerized_labs/sensitive_data_exposure/dataexposure/views.py x3, pygoat/settings.py x3, dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py x3, introduction/utility.py x2, introduction/templates/Lab/XSS/xss_lab_2.html x2, introduction/templates/Lab/XSS/xss_lab_3.html x2, introduction/templates/Lab/ssrf/ssrf_lab2.html x2, introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html x2, introduction/playground/ssrf/main.py x1, introduction/playground/A9/archive.py x1, dockerized_labs/insec_des_lab/main.py x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-117 x1, CWE-16 x1, CWE-200 x6, CWE-215 x3, CWE-22 x3, CWE-256 x3, CWE-287 x4, CWE-306 x4, CWE-312 x1, CWE-327 x6, CWE-328 x2, CWE-330 x2, CWE-338 x2, CWE-352 x10, CWE-400 x3, CWE-502 x3, CWE-532 x2, CWE-565 x1, CWE-611 x1, CWE-614 x6, CWE-639 x6, CWE-78 x3, CWE-79 x14, CWE-798 x12, CWE-862 x1, CWE-89 x2, CWE-918 x1, CWE-94 x4, CWE-95 x3

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x28 at dockerized_labs/broken_auth_lab/templates/reset.html, dockerized_labs/sensitive_data_exposure/templates/login.html, dockerized_labs/sensitive_data_exposure/templates/register.html, introduction/templates/Lab/A10/a10_lab.html, introduction/templates/Lab/A10/a10_lab2.html — heuristic: form + {{ }} co-occurrence | validator: dockerized_labs/broken_auth_lab/app.py:97-100 token must be in password_reset_tokens (md5 hex) before render_template reset.html:13,16; only allowlis
- CWE-798 x4 at introduction/mitre.py, introduction/static/js/a9.js, introduction/templates/mitre/mitre_top9.html, pygoat/settings.py — myHeaders.append("Cookie", "csrftoken=5fVOTXh2HNahtvJFJNRSrKkwPAgPM9YCHlrCGprAxhAAKOUWMxqMnWm8BUomv0Yd; jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjUzMzEzMDIxLCJpYXQiOjE2NTMzMDk0MjF
- CWE-78 x3 at introduction/lab_code/test.py, introduction/templates/Lab/XSS/xss_lab.html — process = subprocess.Popen( cmd_str, shell=True, | validator: introduction/lab_code/test.py:5 hardcodes cmd_str="pwd; ls" and test.py has no importers/routes; dead script not reachable | refute: not_r
- CWE-400 x3 at challenge/views.py, introduction/mitre.py, introduction/views.py — command = f"docker run -d -p {port}:{chal.docker_port} {chal.docker_image}" | validator: challenge/views.py:36-39 is_live early-return bounds concurrent spawn to 1 per user-challenge; challenge/views.
- CWE-306 x3 at challenge/views.py, introduction/apis.py — introduction/apis.py:93-94 defines A7_disscussion_api with @csrf_exempt and no is_authenticated check, unlike sibling ssrf_code_checker at introduction/apis.py:24 which gates on request.user.is_authen
- CWE-248 x2 at introduction/views.py — def error(request): | validator: introduction/views.py:403-404 def error(request): bare return None via introduction/urls.py:34 500error; single-request 500 functional bug with no principal/secret/res
- CWE-91 x1 at introduction/static/Lab/xss.js — xml="<?xml version='1.0'?>"+"<comm>"+"<text>"+comment+"</text>"+"</comm>"; | validator: introduction/static/Lab/xss.js:29-34 is client-side string concat; attacker already controls client, real XXE si
- CWE-532 x1 at dockerized_labs/sensitive_data_exposure/dataexposure/views.py — print(f"Creating missing user data for {request.user.username}") # debugging stuff | validator: dockerized_labs/sensitive_data_exposure/dataexposure/views.py:77 logs only request.user.username (non-se
- CWE-250 x1 at Dockerfile — FROM python:3.11.0b1-buster | validator: Dockerfile:1 FROM python:3.11.0b1-buster with no USER through Dockerfile:33; Dockerfiles/container build configs are out-of-scope per Exclusion Rules | refute:
- CWE-22 x1 at introduction/apis.py — outputs.append(main.ssrf_lab(inputs)) | validator: introduction/apis.py:36-42 ssrf_lab(inputs) outputs only compared to expected and never returned; introduction/playground/ssrf/main.py:5-9 file conte
- CWE-829 x1 at .github/workflows/flake8.yml — - uses: actions/checkout@v2 | validator: .github/workflows/flake8.yml:18 actions/checkout@v2 and :20 setup-python@v2; CI workflow manifests/pins are out-of-scope per Exclusion Rules | refute: exclusio
- CWE-200 x1 at introduction/apis.py — Credentials POSTed to introduction/playground/A9/api.py:14-17 are written via Log.info to test.log (introduction/playground/A9/archive.py:48 writes test.log), then returned unauthenticated by introduc
