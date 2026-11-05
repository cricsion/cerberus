# Cerberus Report

**Findings:** 110 actionable — 7 critical, 51 high, 46 medium, 6 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 49 false positives — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 7 | 0 / 7 (0%) | 7 |
| HIGH | 51 | 0 / 51 (0%) | 51 |
| MEDIUM | 46 | 0 / 46 (0%) | 46 |
| LOW | 6 | 0 / 6 (0%) | 6 |
| **TOTAL** | **110** | **0 / 110 (0%)** | **110** |

## Table of Contents

- [Confirmed (110)](#confirmed)
  - [CRITICAL: Pickle RCE in insec_des_lab deserialize_data (`dockerized_labs/insec_des_lab/main.py:38`)](#finding-1)
  - [CRITICAL: Code injection in mitre_lab_25_api via eval (`introduction/mitre.py:218`)](#finding-2)
  - [CRITICAL: Arbitrary file write RCE in log_function_checker (`introduction/apis.py:69`)](#finding-3)
  - [CRITICAL: Arbitrary file write in A6_disscussion_api_2 (`introduction/apis.py:131`)](#finding-4)
  - [CRITICAL: OS command injection in mitre_lab_17_api via nmap concatenation (`introduction/mitre.py:241`)](#finding-5)
  - [CRITICAL: Missing authentication on MITRE RCE APIs (eval and nmap) (`introduction/mitre.py:215`)](#finding-6)
  - [CRITICAL: Shell wrapper command_out executes caller string with shell=True (`introduction/mitre.py:233`)](#finding-7)
  - [HIGH: Unauthenticated bulk PII exposure in all_users_data_view (`dockerized_labs/sensitive_data_exposure/dataexposure/views.py:130`)](#finding-8)
  - [HIGH: Code injection in cmd_lab2 via eval (`introduction/views.py:460`)](#finding-9)
  - [HIGH: Hardcoded Django SECRET_KEY in pygoat settings (`pygoat/settings.py:25`)](#finding-10)
  - [HIGH: Insecure deserialization in insec_des_lab via pickle cookie (`introduction/views.py:214`)](#finding-11)
  - [HIGH: Plaintext password storage in auth_lab_signup (`introduction/views.py:286`)](#finding-12)
  - [HIGH: Authentication bypass in auth_lab_login via userid cookie (`introduction/views.py:302`)](#finding-13)
  - [HIGH: Broken access control in ba_lab via client-side admin cookie (`introduction/views.py:349`)](#finding-14)
  - [HIGH: Broken access control in a1_broken_access_lab_1 via admin cookie (`introduction/views.py:754`)](#finding-15)
  - [HIGH: Authorization bypass in a1_broken_access_lab_2 via User-Agent header (`introduction/views.py:794`)](#finding-16)
  - [HIGH: Missing authorization in a1_broken_access_lab3_secret (`introduction/views.py:837`)](#finding-17)
  - [HIGH: Path traversal file read in ssrf_lab (`introduction/views.py:927`)](#finding-18)
  - [HIGH: Unsigned cookie privilege escalation in crypto_failure_lab3 (`introduction/views.py:1065`)](#finding-19)
  - [HIGH: Hardcoded Flask secret_key in broken-auth lab (`dockerized_labs/broken_auth_lab/app.py:8`)](#finding-20)
  - [HIGH: Hardcoded weak default credentials in broken-auth lab (`dockerized_labs/broken_auth_lab/app.py:13`)](#finding-21)
  - [HIGH: Forgeable session token in broken_auth_lab login (`dockerized_labs/broken_auth_lab/app.py:42`)](#finding-22)
  - [HIGH: Plaintext password storage in broken-auth register (`dockerized_labs/broken_auth_lab/app.py:68`)](#finding-23)
  - [HIGH: Predictable reset token with disclosure in reset_password (`dockerized_labs/broken_auth_lab/app.py:84`)](#finding-24)
  - [HIGH: Authentication bypass in broken_auth_lab dashboard (`dockerized_labs/broken_auth_lab/app.py:112`)](#finding-25)
  - [HIGH: Plaintext PAN storage in UserData model (`dockerized_labs/sensitive_data_exposure/dataexposure/models.py:6`)](#finding-26)
  - [HIGH: Hardcoded Django SECRET_KEY in sensitive-data lab (`dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8`)](#finding-27)
  - [HIGH: Missing authentication on log_function_checker file-write API (`introduction/apis.py:61`)](#finding-28)
  - [HIGH: Missing authentication on A6_disscussion_api_2 arbitrary file-write (`introduction/apis.py:126`)](#finding-29)
  - [HIGH: Hardcoded JWT secret in csrf_lab_login (`introduction/mitre.py:169`)](#finding-30)
  - [HIGH: CSRF money transfer in csrf_transfer_monei_api via GET (`introduction/mitre.py:191`)](#finding-31)
  - [HIGH: Reflected XSS via |safe in xss_lab_2.html (`introduction/templates/Lab/XSS/xss_lab_2.html:20`)](#finding-32)
  - [HIGH: SQL injection in sql_lab via string-concatenated raw query (`introduction/views.py:158`)](#finding-33)
  - [HIGH: Missing authentication on xxe_parse endpoint (`introduction/views.py:256`)](#finding-34)
  - [HIGH: XXE in xxe_parse with external entities enabled (`introduction/views.py:258`)](#finding-35)
  - [HIGH: OS command injection in cmd_lab via shell=True (`introduction/views.py:430`)](#finding-36)
  - [HIGH: Predictable and disclosed OTP in Otp handler (`introduction/views.py:496`)](#finding-37)
  - [HIGH: Unsafe YAML deserialization in a9_lab via yaml.Loader (`introduction/views.py:560`)](#finding-38)
  - [HIGH: Hardcoded credentials in a1_broken_access_lab_3 (`introduction/views.py:831`)](#finding-39)
  - [HIGH: SQL injection in injection_sql_lab via raw query (`introduction/views.py:864`)](#finding-40)
  - [HIGH: SSRF in ssrf_lab2 via unchecked requests.get (`introduction/views.py:963`)](#finding-41)
  - [HIGH: Stored SSTI in ssti_lab via template file write (`introduction/views.py:995`)](#finding-42)
  - [HIGH: Hardcoded login in crypto_failure_lab3 (`introduction/views.py:1072`)](#finding-43)
  - [HIGH: Hardcoded JWT cookie signing key in settings (`pygoat/settings.py:171`)](#finding-44)
  - [HIGH: Code injection file write in ssrf_code_converter (`introduction/utility.py:35`)](#finding-45)
  - [HIGH: Path traversal in playground ssrf_lab (`introduction/playground/ssrf/main.py:8`)](#finding-46)
  - [HIGH: JS-context XSS via {{code}} in script block (`introduction/templates/Lab/XSS/xss_lab_3.html:20`)](#finding-47)
  - [HIGH: XSS via |safe rendering of SSRF response (`introduction/templates/Lab/ssrf/ssrf_lab2.html:23`)](#finding-48)
  - [HIGH: SSTI artifact discloses password hashes (`introduction/templates/Lab_2021/A3_Injection/Blogs/9d73d120683d.html:2`)](#finding-49)
  - [HIGH: SSTI artifact discloses SECRET_KEY (`introduction/templates/Lab_2021/A3_Injection/Blogs/a2538af1b5e4.html:1`)](#finding-50)
  - [HIGH: Reflected XSS via |safe username in A8 lab2 (`introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11`)](#finding-51)
  - [HIGH: Reflected XSS in xss_lab via q parameter (`introduction/views.py:101`)](#finding-52)
  - [HIGH: OTP verification bypass via admin-OTP OR condition (`introduction/views.py:514`)](#finding-53)
  - [HIGH: Code injection in a9_lab2 via ImageMath.eval (`introduction/views.py:588`)](#finding-54)
  - [HIGH: Plaintext credential comparison in a10_lab (`introduction/views.py:628`)](#finding-55)
  - [HIGH: Forgeable JWT in sec_misconfig_lab3 via hardcoded key (`introduction/views.py:1095`)](#finding-56)
  - [HIGH: Hardcoded admin password disclosed in code comment (`introduction/views.py:1119`)](#finding-57)
  - [HIGH: DOM XSS via innerHTML in a9.js (`introduction/static/js/a9.js:40`)](#finding-58)
  - [MEDIUM: Weak MD5 password hashing in crypto_failure_lab (`introduction/views.py:1026`)](#finding-59)
  - [MEDIUM: Flask debug mode enabled in broken-auth lab (`dockerized_labs/broken_auth_lab/app.py:123`)](#finding-60)
  - [MEDIUM: Plaintext credential logging in log_function_target (`introduction/playground/A9/archive.py:12`)](#finding-61)
  - [MEDIUM: Missing CSRF token in a9_lab2 form (`introduction/templates/Lab/A9/a9_lab2.html:21`)](#finding-62)
  - [MEDIUM: Missing CSRF token in cmd_lab form (`introduction/templates/Lab/CMD/cmd_lab.html:9`)](#finding-63)
  - [MEDIUM: Missing CSRF token in cmd_lab2 form (`introduction/templates/Lab/CMD/cmd_lab2.html:10`)](#finding-64)
  - [MEDIUM: template reflection surface (`introduction/templates/Lab/XSS/xss_lab.html:0`)](#finding-65)
  - [MEDIUM: template reflection surface (`introduction/templates/Lab/XSS/xss_lab_2.html:0`)](#finding-66)
  - [MEDIUM: Missing CSRF token in broken_access_lab_1 form (`introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html:11`)](#finding-67)
  - [MEDIUM: Missing CSRF token in broken_access_lab_2 form (`introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html:11`)](#finding-68)
  - [MEDIUM: template reflection surface (`introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:0`)](#finding-69)
  - [MEDIUM: Inadequate XSS filter in xss_lab2 (`introduction/views.py:111`)](#finding-70)
  - [MEDIUM: Header-spoof authorization in secret view (`introduction/views.py:537`)](#finding-71)
  - [MEDIUM: Reflected XSS in software_and_data_integrity_failure_lab2 (`introduction/views.py:1223`)](#finding-72)
  - [MEDIUM: Unmasked PII disclosure in api_data_view (`dockerized_labs/sensitive_data_exposure/dataexposure/views.py:109`)](#finding-73)
  - [MEDIUM: DEBUG True in sensitive-data lab settings (`dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:11`)](#finding-74)
  - [MEDIUM: Hardcoded demo credentials in login template (`dockerized_labs/sensitive_data_exposure/templates/login.html:73`)](#finding-75)
  - [MEDIUM: Full PII disclosure in HTML comment on profile page (`dockerized_labs/sensitive_data_exposure/templates/profile.html:128`)](#finding-76)
  - [MEDIUM: MD5 password hashing in csrf_lab_login (`introduction/mitre.py:161`)](#finding-77)
  - [MEDIUM: Missing CSRF token in a9_lab upload form (`introduction/templates/Lab/A9/a9_lab.html:10`)](#finding-78)
  - [MEDIUM: template reflection surface (`introduction/templates/Lab/XSS/xss_lab_3.html:0`)](#finding-79)
  - [MEDIUM: template reflection surface (`introduction/templates/Lab/ssrf/ssrf_lab2.html:0`)](#finding-80)
  - [MEDIUM: Weak reversible customHash primitive (SHA256 reversed) (`introduction/utility.py:58`)](#finding-81)
  - [MEDIUM: XSS bypass in xss_lab3 via alphanumeric strip (`introduction/views.py:129`)](#finding-82)
  - [MEDIUM: Insecure userid cookie flags in auth_lab_signup (`introduction/views.py:291`)](#finding-83)
  - [MEDIUM: Insecure userid cookie flags in auth_lab_login GET branch (`introduction/views.py:305`)](#finding-84)
  - [MEDIUM: Insecure userid cookie flags in auth_lab_login POST branch (`introduction/views.py:319`)](#finding-85)
  - [MEDIUM: Missing authorization on debug log disclosure (`introduction/views.py:636`)](#finding-86)
  - [MEDIUM: IP spoofing bypass in ssrf_target via X-Forwarded-For (`introduction/views.py:946`)](#finding-87)
  - [MEDIUM: Insecure custom hash in crypto_failure_lab2 (`introduction/views.py:1042`)](#finding-88)
  - [MEDIUM: Unsalted SHA256 password check in auth_failure_lab3 (`introduction/views.py:1194`)](#finding-89)
  - [MEDIUM: Django DEBUG enabled in production settings (`pygoat/settings.py:30`)](#finding-90)
  - [MEDIUM: Unsalted SHA256 flag hashing with prefix bypass in Challenge.save (`challenge/models.py:28`)](#finding-91)
  - [MEDIUM: Weak PRNG API key generation in generate_api_key (`dockerized_labs/sensitive_data_exposure/dataexposure/views.py:41`)](#finding-92)
  - [MEDIUM: Wildcard ALLOWED_HOSTS in sensitive-data lab (`dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:13`)](#finding-93)
  - [MEDIUM: Seeded MD5 hashes without salt (0017) (`introduction/migrations/0017_cf_user.py:21`)](#finding-94)
  - [MEDIUM: Seeded weak hashes without salt (0018) (`introduction/migrations/0018_cf_user_password2.py:21`)](#finding-95)
  - [MEDIUM: Hardcoded default credentials in log_function_target (`introduction/playground/A9/api.py:17`)](#finding-96)
  - [MEDIUM: Missing CSRF token in ba_lab form (`introduction/templates/Lab/BrokenAccess/ba_lab.html:11`)](#finding-97)
  - [MEDIUM: Missing CSRF token in otp form (`introduction/templates/Lab/BrokenAuth/otp.html:18`)](#finding-98)
  - [MEDIUM: Missing CSRF protection in XXE submission (`introduction/templates/Lab/XXE/xxe_lab.html:15`)](#finding-99)
  - [MEDIUM: Log injection via spoofable IP in a10_lab2 (`introduction/views.py:654`)](#finding-100)
  - [MEDIUM: Weak PRNG ticket codes in gentckt (`introduction/views.py:680`)](#finding-101)
  - [MEDIUM: IDOR in ssti_view_blog missing author check (`introduction/views.py:1003`)](#finding-102)
  - [MEDIUM: Template path traversal in ssti_view_blog (`introduction/views.py:1006`)](#finding-103)
  - [MEDIUM: Image decompression bomb DoS in a9_lab2 (`introduction/views.py:584`)](#finding-104)
  - [LOW: Insecure persistent session cookie without flags in broken-auth login (`dockerized_labs/broken_auth_lab/app.py:49`)](#finding-105)
  - [LOW: Version disclosure in get_version (`introduction/views.py:571`)](#finding-106)
  - [LOW: Unhandled KeyError denial of service via missing User-Agent header (`introduction/views.py:791`)](#finding-107)
  - [LOW: Insecure cookie flags in crypto_failure_lab3 (`introduction/views.py:1076`)](#finding-108)
  - [LOW: Unhandled KeyError DoS and missing response in auth_failure_lab3 (`introduction/views.py:1200`)](#finding-109)
  - [LOW: Insecure persistent session_id cookie in auth_failure_lab3 (`introduction/views.py:1204`)](#finding-110)

<a id="confirmed"></a>
## Confirmed (110)

<a id="finding-1"></a>
### CRITICAL Pickle RCE in insec_des_lab deserialize_data
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 0.98
- Location: `dockerized_labs/insec_des_lab/main.py:38-38`
- Vulnerable code (`dockerized_labs/insec_des_lab/main.py`):
```python
user = pickle.loads(decoded_data)
```
- Taint Flow:
  - **Source**: `POST serialized_data`
  - **Path**:
    - `dockerized_labs/insec_des_lab/main.py:33 POST serialized_data`
    - `dockerized_labs/insec_des_lab/main.py:38 pickle.loads`
  - **Sink**: `pickle deserialization`
- Evidence: user = pickle.loads(decoded_data)
  - Validation: dockerized_labs/insec_des_lab/main.py:33 request.form.get('serialized_data') flows to b64decode:34 then pickle.loads:38 with no allowlist on active POST /deserialize:30
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/insec_des_lab/main.py:33 request.form.get('serialized_data') flows to b64decode:34 then pickle.loads:38 with no allowlist on active POST /deserialize:30 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pickle,base64,os
class E:
 def __reduce__(self): return (os.system,('id',))
print(base64.b64encode(pickle.dumps(E())).decode())
```
- Patch:
  - **Summary**: Stop unpickling client data; use JSON/token with server-side session and HMAC, or allowlisted deserializer.

<a id="finding-2"></a>
### CRITICAL Code injection in mitre_lab_25_api via eval
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-95 | confidence: 0.98
- Location: `introduction/mitre.py:218-218`
- Vulnerable code (`introduction/mitre.py`):
```python
result = eval(expression)
```
- Taint Flow:
  - **Source**: `POST expression`
  - **Path**:
    - `introduction/mitre.py:217 POST expression`
    - `introduction/mitre.py:218 eval`
  - **Sink**: `eval of attacker string`
- Evidence: result = eval(expression)
  - Validation: introduction/mitre.py:217 POST expression passed directly to eval at mitre.py:218 with auth decorator commented out and csrf_exempt
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/mitre.py:217 POST expression passed directly to eval at mitre.py:218 with auth decorator commented out and csrf_exempt | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/mitre/25/lab/api -d 'expression=__import__("os").popen("id").read()'
```
- Patch:
  - **Summary**: Remove eval endpoint; use safe parser.

<a id="finding-3"></a>
### CRITICAL Arbitrary file write RCE in log_function_checker
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.97
- Location: `introduction/apis.py:69-75`
- Vulnerable code (`introduction/apis.py`):
```python
f = open(log_filename,"w")
```
- Taint Flow:
  - **Source**: `POST log_code/api_code`
  - **Path**:
    - `introduction/apis.py:64 POST log_code`
    - `introduction/apis.py:69 file write`
    - `introduction/apis.py:77 requests to target`
  - **Sink**: `Python file overwrite and execution`
- Evidence: f = open(log_filename,"w")
  - Validation: introduction/apis.py:64 POST log_code/api_code written to .py files at apis.py:69-75 via open(w), csrf_exempt with auth commented out
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/apis.py:64 POST log_code/api_code written to .py files at apis.py:69-75 via open(w), csrf_exempt with auth commented out | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:8000/2021/discussion/A9/api -d 'log_code=import os;os.system("id")' -d 'api_code=x' -d 'csrfmiddlewaretoken=x'
```
- Patch:
  - **Summary**: Remove arbitrary file-write API; require auth and never write .py from input.

<a id="finding-4"></a>
### CRITICAL Arbitrary file write in A6_disscussion_api_2
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.97
- Location: `introduction/apis.py:131-134`
- Vulnerable code (`introduction/apis.py`):
```python
f = open(filename,"w")
```
- Taint Flow:
  - **Source**: `POST code`
  - **Path**:
    - `introduction/apis.py:130 POST code`
    - `introduction/apis.py:131 file write`
  - **Sink**: `Python source overwrite`
- Evidence: f = open(filename,"w")
  - Validation: introduction/apis.py:130 POST code written to playground/A6/utility.py at apis.py:131-134, csrf_exempt with no auth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/apis.py:130 POST code written to playground/A6/utility.py at apis.py:131-134, csrf_exempt with no auth | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:8000/2021/discussion/A6/api2 -d 'code=import os;os.system("id")'
```
- Patch:
  - **Summary**: Remove file-overwrite endpoint; require auth and disallow code writes.

<a id="finding-5"></a>
### CRITICAL OS command injection in mitre_lab_17_api via nmap concatenation
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.97
- Location: `introduction/mitre.py:241-241`
- Vulnerable code (`introduction/mitre.py`):
```python
command = "nmap " + ip
```
- Taint Flow:
  - **Source**: `POST ip`
  - **Path**:
    - `introduction/mitre.py:240 POST ip`
    - `introduction/mitre.py:241 concat`
    - `introduction/mitre.py:233 shell exec`
  - **Sink**: `shell command execution`
- Evidence: command = "nmap " + ip
  - Validation: introduction/mitre.py:240 POST ip concatenated at mitre.py:241 into command_out Popen shell=True at mitre.py:233, csrf_exempt with no auth
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/mitre.py:240 POST ip concatenated at mitre.py:241 into command_out Popen shell=True at mitre.py:233, csrf_exempt with no auth | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/mitre/17/lab/api -d 'ip=127.0.0.1;id'
```
- Patch:
  - **Summary**: Avoid shell=True; validate IP and exec nmap via argv list.

<a id="finding-6"></a>
### CRITICAL Missing authentication on MITRE RCE APIs (eval and nmap)
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `introduction/mitre.py:215-215`
- Vulnerable code (`introduction/mitre.py`):
```python
def mitre_lab_25_api(request):
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP POST`
  - **Path**:
    - `introduction/urls.py:119 mitre/25/lab/api`
    - `introduction/mitre.py:215 no auth + eval`
  - **Sink**: `missing authentication on code/command execution APIs`
- Evidence: introduction/mitre.py:213 commented authentication_decorator + introduction/mitre.py:214 csrf_exempt + introduction/mitre.py:237 csrf_exempt with no auth, routes at introduction/urls.py:119 and :122
  - Validation: introduction/mitre.py:214-219 mitre_lab_25_api @csrf_exempt eval(expression) + mitre.py:237-243 mitre_lab_17_api @csrf_exempt nmap shell=True; routes introduction/urls.py:119,122 with no authentication_decorator
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/mitre.py:214-219 mitre_lab_25_api @csrf_exempt eval(expression) + mitre.py:237-243 mitre_lab_17_api @csrf_exempt nmap shell=True; routes introduction/urls.py:119,122 with no authentication_decorator | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication on both APIs, remove @csrf_exempt, and remove eval/shell=True (allowlist expression parser, avoid shell)

<a id="finding-7"></a>
### CRITICAL Shell wrapper command_out executes caller string with shell=True
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.95
- Location: `introduction/mitre.py:233-233`
- Vulnerable code (`introduction/mitre.py`):
```python
process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```
- Taint Flow:
  - **Source**: `POST ip via caller`
  - **Path**:
    - `introduction/mitre.py:240 POST ip`
    - `introduction/mitre.py:241 concat`
    - `introduction/mitre.py:233 shell exec`
  - **Sink**: `shell=True execution`
- Evidence: process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  - Validation: introduction/mitre.py:233 Popen(command, shell=True) reached by introduction/mitre.py:240-242 ip=request.POST.get(ip); command='nmap '+ip; mitre_lab_17_api has only @csrf_exempt with commented-out auth at line 236
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/mitre.py:233 Popen(command, shell=True) reached by introduction/mitre.py:240-242 ip=request.POST.get(ip); command='nmap '+ip; mitre_lab_17_api has only @csrf_exempt with commented-out auth at line 236 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Avoid shell=True; invoke nmap via argv list and validate ip with ipaddress module / allowlist.

<a id="finding-8"></a>
### HIGH Unauthenticated bulk PII exposure in all_users_data_view
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.98
- Location: `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:130-130`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/dataexposure/views.py`):
```python
return JsonResponse({'users': all_users_data})
```
- Taint Flow:
  - **Source**: `Unauthenticated request`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:112 unauth request`
    - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:118 DB all()`
  - **Sink**: `bulk PII JSON response`
- Evidence: return JsonResponse({'users': all_users_data})
  - Validation: dockerized_labs/sensitive_data_exposure/dataexposure/views.py:112 all_users_data_view has no login_required and iterates UserData.objects.all():118 returning credit_card/ssn/api_key:121-124 via JsonResponse:130, routed at dataexposure/urls.py:15 api/all-users/
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/dataexposure/views.py:112 all_users_data_view has no login_required and iterates UserData.objects.all():118 returning credit_card/ssn/api_key:121-124 via JsonResponse:130, routed at dataexposure/urls.py:15 api/all-users/ | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl http://localhost:8000/api/all-users/ # returns all credit_cards, SSNs, api_keys without auth
```
- Patch:
  - **Summary**: Require authentication+authorization and return only request.user data with masked secrets.

<a id="finding-9"></a>
### HIGH Code injection in cmd_lab2 via eval
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-95 | confidence: 0.98
- Location: `introduction/views.py:460-460`
- Vulnerable code (`introduction/views.py`):
```python
output = eval(val)
```
- Taint Flow:
  - **Source**: `POST val`
  - **Path**:
    - `introduction/views.py:456 POST val`
    - `introduction/views.py:460 eval`
  - **Sink**: `Python eval of attacker string`
- Evidence: output = eval(val)
  - Validation: introduction/views.py:456 POST val passed directly to eval at views.py:460
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:456 POST val passed directly to eval at views.py:460 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/cmd_lab2 -d 'val=__import__("os").popen("id").read()'
```
- Patch:
  - **Summary**: Remove eval; use safe expression parser or reject input.

<a id="finding-10"></a>
### HIGH Hardcoded Django SECRET_KEY in pygoat settings
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.98
- Location: `pygoat/settings.py:25-25`
- Vulnerable code (`pygoat/settings.py`):
```python
SECRET_KEY = 'lr66%-a!$km5ed@n5ug!tya5bv!0(yqwa1tn!q%0%3m2nh%oml'
```
- Taint Flow:
  - **Source**: `Committed configuration`
  - **Sink**: `hardcoded cryptographic secret`
- Evidence: SECRET_KEY = 'lr66%-a!$km5ed@n5ug!tya5bv!0(yqwa1tn!q%0%3m2nh%oml'
  - Validation: pygoat/settings.py:25 hardcodes SECRET_KEY='lr66%-a!$km5ed@n5ug!tya5bv!0(yqwa1tn!q%0%3m2nh%oml' with DEBUG=True:30 committed to repo
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: pygoat/settings.py:25 hardcodes SECRET_KEY='lr66%-a!$km5ed@n5ug!tya5bv!0(yqwa1tn!q%0%3m2nh%oml' with DEBUG=True:30 committed to repo | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
grep -r SECRET_KEY pygoat/settings.py # hardcoded Django secret enables session/JWT forgery
```
- Patch:
  - **Summary**: Load SECRET_KEY from env/secret manager, rotate exposed value, set DEBUG=False in production.

<a id="finding-11"></a>
### HIGH Insecure deserialization in insec_des_lab via pickle cookie
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 0.97
- Location: `introduction/views.py:214-214`
- Vulnerable code (`introduction/views.py`):
```python
admin = pickle.loads(token)
```
- Taint Flow:
  - **Source**: `Cookie token`
  - **Path**:
    - `introduction/views.py:209 request.COOKIES.get token`
    - `introduction/views.py:213 base64 decode`
    - `introduction/views.py:214 pickle.loads`
  - **Sink**: `pickle.loads attacker-controlled bytes`
- Evidence: admin = pickle.loads(token)
  - Validation: introduction/views.py:209 COOKIES token base64-decoded then pickle.loads at views.py:214 on attacker bytes
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:209 COOKIES token base64-decoded then pickle.loads at views.py:214 on attacker bytes | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import pickle,base64,os
class X:
 def __reduce__(self): return (os.system,('id',))
print(base64.b64encode(pickle.dumps(X())).decode())
```
- Patch:
  - **Summary**: Stop unpickling user cookies; use signed JSON session token.

<a id="finding-12"></a>
### HIGH Plaintext password storage in auth_lab_signup
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.97
- Location: `introduction/views.py:286-291`
- Vulnerable code (`introduction/views.py`):
```python
obj = authLogin.objects.create(name=name,username=user_name,password=passwd)
```
- Taint Flow:
  - **Source**: `POST pass`
  - **Path**:
    - `introduction/views.py:284 POST pass`
    - `introduction/views.py:286 DB save`
  - **Sink**: `plaintext password persistence`
- Evidence: obj = authLogin.objects.create(name=name,username=user_name,password=passwd)
  - Validation: introduction/views.py:284 POST pass stored verbatim via authLogin.objects.create(name=name,username=user_name,password=passwd):286 with plaintext CharField in introduction/models.py:30-34
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:284 POST pass stored verbatim via authLogin.objects.create(name=name,username=user_name,password=passwd):286 with plaintext CharField in introduction/models.py:30-34 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:8000/auth_lab/signup -d 'name=a&username=a&pass=secret123'; echo check DB authLogin password stored plaintext
```
- Patch:
  - **Summary**: Hash with PBKDF2/bcrypt via make_password and never store raw password.

<a id="finding-13"></a>
### HIGH Authentication bypass in auth_lab_login via userid cookie
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.97
- Location: `introduction/views.py:302-299`
- Vulnerable code (`introduction/views.py`):
```python
obj = authLogin.objects.filter(userid=request.COOKIES['userid'])[0]
```
- Taint Flow:
  - **Source**: `Cookie userid`
  - **Path**:
    - `introduction/views.py:302 COOKIES userid`
    - `introduction/views.py:302 DB lookup`
    - `introduction/views.py:305 set_cookie`
  - **Sink**: `authenticated session grant`
- Evidence: obj = authLogin.objects.filter(userid=request.COOKIES['userid'])[0]
  - Validation: introduction/views.py:299 GET auth_lab_login grants session solely on request.COOKIES['userid']:302 DB lookup with no password/signature, re-issues userid cookie:305
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:299 GET auth_lab_login grants session solely on request.COOKIES['userid']:302 DB lookup with no password/signature, re-issues userid cookie:305 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b 'userid=1' http://localhost:8000/auth_lab/login # gains victim session without password
```
- Patch:
  - **Summary**: Use server-side Django session auth; never trust client userid cookie, use signed session id.

<a id="finding-14"></a>
### HIGH Broken access control in ba_lab via client-side admin cookie
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.97
- Location: `introduction/views.py:349-350`
- Vulnerable code (`introduction/views.py`):
```python
if request.COOKIES.get('admin') == "1":
```
- Taint Flow:
  - **Source**: `Cookie admin`
  - **Path**:
    - `introduction/views.py:349 COOKIES admin`
    - `introduction/views.py:342 ba_lab handler`
  - **Sink**: `admin-only data disclosure`
- Evidence: if request.COOKIES.get('admin') == "1":
  - Validation: introduction/views.py:349 trusts request.COOKIES.get('admin')=="1" to render 0NLY_F0R_4DM1N5 in ba_lab:342 which only checks is_authenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:349 trusts request.COOKIES.get('admin')=="1" to render 0NLY_F0R_4DM1N5 in ba_lab:342 which only checks is_authenticated | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b 'sessionid=x; admin=1' -X POST http://localhost:8000/ba_lab -d 'name=a&pass=b' # reveals 0NLY_F0R_4DM1N5
```
- Patch:
  - **Summary**: Decide admin from server-side user/role, never from client cookie; sign/verify if cookie must carry role.

<a id="finding-15"></a>
### HIGH Broken access control in a1_broken_access_lab_1 via admin cookie
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.97
- Location: `introduction/views.py:754-754`
- Vulnerable code (`introduction/views.py`):
```python
if request.COOKIES.get('admin') == "1":
```
- Taint Flow:
  - **Source**: `Cookie admin`
  - **Path**:
    - `introduction/views.py:754 COOKIES admin`
    - `introduction/views.py:755 admin data render`
  - **Sink**: `admin secret disclosure`
- Evidence: if request.COOKIES.get('admin') == "1":
  - Validation: introduction/views.py:754 trusts request.COOKIES.get('admin')=="1" to disclose 0NLY_F0R_4DM1N5 in a1_broken_access_lab_1:741 gated only by is_authenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:754 trusts request.COOKIES.get('admin')=="1" to disclose 0NLY_F0R_4DM1N5 in a1_broken_access_lab_1:741 gated only by is_authenticated | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b 'sessionid=x; admin=1' -X POST http://localhost:8000/broken_access_lab_1 -d 'name=x&password=y'
```
- Patch:
  - **Summary**: Check server-side is_staff/role instead of client admin cookie.

<a id="finding-16"></a>
### HIGH Authorization bypass in a1_broken_access_lab_2 via User-Agent header
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-639 | confidence: 0.97
- Location: `introduction/views.py:794-794`
- Vulnerable code (`introduction/views.py`):
```python
if (user_agent == "pygoat_admin"):
```
- Taint Flow:
  - **Source**: `User-Agent header`
  - **Path**:
    - `introduction/views.py:789 HTTP_USER_AGENT`
    - `introduction/views.py:794 authorization check`
  - **Sink**: `admin data disclosure`
- Evidence: if (user_agent == "pygoat_admin"):
  - Validation: introduction/views.py:789 user_agent=request.META['HTTP_USER_AGENT'] grants admin at 794 if (user_agent=="pygoat_admin") attacker-controllable header in a1_broken_access_lab_2:778
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:789 user_agent=request.META['HTTP_USER_AGENT'] grants admin at 794 if (user_agent=="pygoat_admin") attacker-controllable header in a1_broken_access_lab_2:778 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -A 'pygoat_admin' -X POST http://localhost:8000/broken_access_lab_2 -d 'name=x&password=y'
```
- Patch:
  - **Summary**: Replace header check with server-side role check on authenticated user.

<a id="finding-17"></a>
### HIGH Missing authorization in a1_broken_access_lab3_secret
- CVSS: **7.4** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-862 | confidence: 0.97
- Location: `introduction/views.py:837-840`
- Vulnerable code (`introduction/views.py`):
```python
def a1_broken_access_lab3_secret(request):
```
- Taint Flow:
  - **Source**: `Authenticated request URL`
  - **Path**:
    - `introduction/views.py:837 secret endpoint`
    - `introduction/views.py:840 render secret.html`
  - **Sink**: `secret disclosure without authz`
- Evidence: def a1_broken_access_lab3_secret(request):
  - Validation: introduction/views.py:837 a1_broken_access_lab3_secret only checks is_authenticated:838 then renders secret.html:840 with explicit 'no checking applied here':839, routed at introduction/urls.py:63 broken_access_controle/secret
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:837 a1_broken_access_lab3_secret only checks is_authenticated:838 then renders secret.html:840 with explicit 'no checking applied here':839, routed at introduction/urls.py:63 broken_access_controle/secret | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x http://localhost:8000/broken_access_controle/secret # returns secret.html without role check
```
- Patch:
  - **Summary**: Add role/permission check (e.g. is_staff) before rendering secret.

<a id="finding-18"></a>
### HIGH Path traversal file read in ssrf_lab
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.96
- Location: `introduction/views.py:927-927`
- Vulnerable code (`introduction/views.py`):
```python
file = open(filename,"r")
```
- Taint Flow:
  - **Source**: `POST blog filename`
  - **Path**:
    - `introduction/views.py:924 POST blog`
    - `introduction/views.py:926 join`
    - `introduction/views.py:927 open`
  - **Sink**: `local file open/read`
- Evidence: file = open(filename,"r")
  - Validation: introduction/views.py:924 POST blog joined via os.path.join(dirname,file):926 then open(filename,"r"):927 with no normalization/allowlist in ssrf_lab:918 gated only by is_authenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:924 POST blog joined via os.path.join(dirname,file):926 then open(filename,"r"):927 with no normalization/allowlist in ssrf_lab:918 gated only by is_authenticated | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/ssrf_lab -d 'blog=../../etc/passwd'
```
- Patch:
  - **Summary**: Allowlist blog ids, canonicalize with abspath and enforce base-directory containment, or serve via id lookup.

<a id="finding-19"></a>
### HIGH Unsigned cookie privilege escalation in crypto_failure_lab3
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-565 | confidence: 0.96
- Location: `introduction/views.py:1065-1065`
- Vulnerable code (`introduction/views.py`):
```python
elif cookie.split('|')[0] == 'admin':
```
- Taint Flow:
  - **Source**: `Cookie value`
  - **Path**:
    - `introduction/views.py:1059 COOKIES cookie`
    - `introduction/views.py:1065 admin compare`
  - **Sink**: `privilege decision`
- Evidence: elif cookie.split('|')[0] == 'admin':
  - Validation: introduction/views.py:1065 elif cookie.split('|')[0]=='admin' trusts unsigned request.COOKIES["cookie"]:1062 issued as f"{username}|{expire}":1078 with no MAC, expiry parsed:1063-1064 but forgeable
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1065 elif cookie.split('|')[0]=='admin' trusts unsigned request.COOKIES["cookie"]:1062 issued as f"{username}|{expire}":1078 with no MAC, expiry parsed:1063-1064 but forgeable | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b 'cookie=admin|2099-01-01T00:00:00' -b sessionid=x http://localhost:8000/cryptographic_failure/lab3 # gains admin without password
```
- Patch:
  - **Summary**: Sign cookie with HMAC/SECRET_KEY (Django signed_cookies/session) and verify server-side.

<a id="finding-20"></a>
### HIGH Hardcoded Flask secret_key in broken-auth lab
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `dockerized_labs/broken_auth_lab/app.py:8-8`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
app.secret_key = 'your-secret-key-here'
```
- Taint Flow:
  - **Source**: `Committed Flask secret`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:8 hardcoded secret`
  - **Sink**: `Session cookie signing`
- Evidence: app.secret_key = 'your-secret-key-here'  # Vulnerable: Hardcoded secret key
  - Validation: dockerized_labs/broken_auth_lab/app.py:8 app.secret_key hardcoded signs Flask session cookies
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:8 app.secret_key hardcoded signs Flask session cookies | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Load Flask secret_key from environment/secret manager with strong random value.

<a id="finding-21"></a>
### HIGH Hardcoded weak default credentials in broken-auth lab
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `dockerized_labs/broken_auth_lab/app.py:13-13`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
'password': 'admin123'
```
- Taint Flow:
  - **Source**: `Hardcoded users dict`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:11 users dict`
    - `dockerized_labs/broken_auth_lab/app.py:41 password comparison`
  - **Sink**: `Login authentication decision`
- Evidence: 'password': 'admin123',  # Vulnerable: Weak password
  - Validation: dockerized_labs/broken_auth_lab/app.py:11-22 hardcoded users admin/admin123 checked at :41 plaintext comparison
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:11-22 hardcoded users admin/admin123 checked at :41 plaintext comparison | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove default accounts; require provisioned credentials with hashed passwords.

<a id="finding-22"></a>
### HIGH Forgeable session token in broken_auth_lab login
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.95
- Location: `dockerized_labs/broken_auth_lab/app.py:42-47`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
session_token = base64.b64encode(f"{username}:{datetime.now()}".encode()).decode()
```
- Taint Flow:
  - **Source**: `Username and forgeable cookie`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:36 POST username`
    - `dockerized_labs/broken_auth_lab/app.py:42 base64 token`
    - `dockerized_labs/broken_auth_lab/app.py:112 dashboard decode`
  - **Sink**: `session authentication decision`
- Evidence: session_token = base64.b64encode(f"{username}:{datetime.now()}".encode()).decode()
  - Validation: dockerized_labs/broken_auth_lab/app.py:42 unsigned base64 session_token issued; dashboard trusts it at app.py:112 via b64decode split without signature
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:42 unsigned base64 session_token issued; dashboard trusts it at app.py:112 via b64decode split without signature | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import base64; print(base64.b64encode(b'admin:2099-01-01').decode()) # set as session cookie to impersonate admin
```
- Patch:
  - **Summary**: Replace base64 cookie with Flask signed session or random unguessable token stored server-side and validated.

<a id="finding-23"></a>
### HIGH Plaintext password storage in broken-auth register
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.95
- Location: `dockerized_labs/broken_auth_lab/app.py:68-68`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
'password': password
```
- Taint Flow:
  - **Source**: `POST password`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:61 POST password`
    - `dockerized_labs/broken_auth_lab/app.py:68 plaintext store`
  - **Sink**: `Plaintext credential store`
- Evidence: 'password': password,  # Vulnerable: Storing plain text passwords
  - Validation: dockerized_labs/broken_auth_lab/app.py:61 POST password stored plaintext at :68 users[username] password
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:61 POST password stored plaintext at :68 users[username] password | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Hash passwords with bcrypt/argon2/scrypt before storage; compare hashes on login.

<a id="finding-24"></a>
### HIGH Predictable reset token with disclosure in reset_password
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-330 | confidence: 0.95
- Location: `dockerized_labs/broken_auth_lab/app.py:84-89`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
token = hashlib.md5(f"{email}:{datetime.now()}".encode()).hexdigest()
```
- Taint Flow:
  - **Source**: `POST email`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:80 POST email`
    - `dockerized_labs/broken_auth_lab/app.py:84 MD5 token`
    - `dockerized_labs/broken_auth_lab/app.py:88 flash disclosure`
  - **Sink**: `reset token generation and disclosure`
- Evidence: token = hashlib.md5(f"{email}:{datetime.now()}".encode()).hexdigest()
  - Validation: dockerized_labs/broken_auth_lab/app.py:84 MD5(email:datetime) predictable token; disclosed in flash at app.py:88
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:84 MD5(email:datetime) predictable token; disclosed in flash at app.py:88 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import hashlib; print(hashlib.md5(b'admin@example.com:now').hexdigest()) # predictable; token also flashed in response
```
- Patch:
  - **Summary**: Generate reset token with secrets.token_urlsafe(32), store hashed with expiry, and send via out-of-band channel not flash.

<a id="finding-25"></a>
### HIGH Authentication bypass in broken_auth_lab dashboard
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.95
- Location: `dockerized_labs/broken_auth_lab/app.py:112-113`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
username = base64.b64decode(session_token).decode().split(':')[0]
```
- Taint Flow:
  - **Source**: `Cookie session`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:105 COOKIES session`
    - `dockerized_labs/broken_auth_lab/app.py:112 decode`
  - **Sink**: `access control decision`
- Evidence: username = base64.b64decode(session_token).decode().split(':')[0]
  - Validation: dockerized_labs/broken_auth_lab/app.py:112 dashboard does b64decode(session).split(':')[0] and trusts username if in users, no signature/MAC
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:112 dashboard does b64decode(session).split(':')[0] and trusts username if in users, no signature/MAC | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b 'session= YWRtaW46MjAyNi0wMS0wMQ==' http://localhost:5000/dashboard # base64 admin forges login (strip space)
```
- Patch:
  - **Summary**: Validate session with server-side store or HMAC-signed token; reject forgeable client-supplied usernames.

<a id="finding-26"></a>
### HIGH Plaintext PAN storage in UserData model
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-312 | confidence: 0.95
- Location: `dockerized_labs/sensitive_data_exposure/dataexposure/models.py:6-6`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/dataexposure/models.py`):
```python
credit_card = models.CharField(max_length=16)  # probly should encrypt this lol
```
- Taint Flow:
  - **Source**: `Registered user PII`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/dataexposure/models.py:6 plaintext column`
  - **Sink**: `Plaintext DB column`
- Evidence: credit_card = models.CharField(max_length=16)  # probly should encrypt this lol
  - Validation: dockerized_labs/sensitive_data_exposure/dataexposure/models.py:6 credit_card CharField plaintext plus ssn/api_key at lines 7-8; seeded with real PAN at entrypoint.sh:11
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/dataexposure/models.py:6 credit_card CharField plaintext plus ssn/api_key at lines 7-8; seeded with real PAN at entrypoint.sh:11 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Encrypt PAN/SSN/API key at rest (field-level encryption/tokenization) and never store full PAN; mask on display.

<a id="finding-27"></a>
### HIGH Hardcoded Django SECRET_KEY in sensitive-data lab
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8-8`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py`):
```python
SECRET_KEY = 'django-insecure-key-for-demonstration-only'
```
- Taint Flow:
  - **Source**: `Committed settings file`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8 hardcoded key`
  - **Sink**: `Session/CSRF signing key`
- Evidence: SECRET_KEY = 'django-insecure-key-for-demonstration-only'
  - Validation: dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8 hardcoded SECRET_KEY signs sessions/CSRF
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8 hardcoded SECRET_KEY signs sessions/CSRF | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Load Django SECRET_KEY from environment/secret manager; rotate and never commit.

<a id="finding-28"></a>
### HIGH Missing authentication on log_function_checker file-write API
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `introduction/apis.py:61-61`
- Vulnerable code (`introduction/apis.py`):
```python
def log_function_checker(request):
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP POST`
  - **Path**:
    - `introduction/urls.py:83 2021/discussion/A9/api`
    - `introduction/apis.py:61 log_function_checker no auth`
  - **Sink**: `missing authentication on privileged file-write API`
- Evidence: introduction/apis.py:59 csrf_exempt + introduction/apis.py:61 def without authentication_decorator (commented out at line 60) reachable via introduction/urls.py:83
  - Validation: introduction/apis.py:59-61 @csrf_exempt log_function_checker with #@authentication_decorator commented, no is_authenticated check, writes POST log_code/api_code to playground/A9/main.py:65-72; route introduction/urls.py:83 2021/discussion/A9/api
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/apis.py:59-61 @csrf_exempt log_function_checker with #@authentication_decorator commented, no is_authenticated check, writes POST log_code/api_code to playground/A9/main.py:65-72; route introduction/urls.py:83 2021/discussion/A9/api | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Restore authentication_decorator/require login on log_function_checker and remove @csrf_exempt; restrict file-write to authenticated authorized users

<a id="finding-29"></a>
### HIGH Missing authentication on A6_disscussion_api_2 arbitrary file-write
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `introduction/apis.py:126-126`
- Vulnerable code (`introduction/apis.py`):
```python
def A6_disscussion_api_2(request):
```
- Taint Flow:
  - **Source**: `unauthenticated POST code parameter`
  - **Path**:
    - `introduction/urls.py:89 route api2`
    - `introduction/apis.py:130 code=POST.get('code')`
    - `introduction/apis.py:133 open(utility.py,"w").write(code)`
  - **Sink**: `arbitrary .py file overwrite leading to code execution`
- Evidence: Route introduction/urls.py:89 'path("2021/discussion/A6/api2",apis.A6_disscussion_api_2)' reaches apis.py:126 with only @csrf_exempt and no is_authenticated/authentication_decorator check, then writes request-controlled 'code' to playground/A6/utility.py at apis.py:131-134
  - Validation: introduction/apis.py:125-134 A6_disscussion_api_2 only @csrf_exempt, writes POST code to playground/A6/utility.py:131-134; route introduction/urls.py:89 2021/discussion/A6/api2 unauthenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/apis.py:125-134 A6_disscussion_api_2 only @csrf_exempt, writes POST code to playground/A6/utility.py:131-134; route introduction/urls.py:89 2021/discussion/A6/api2 unauthenticated | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication/authorization on A6_disscussion_api_2 and stop writing raw POST code to .py file

<a id="finding-30"></a>
### HIGH Hardcoded JWT secret in csrf_lab_login
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `introduction/mitre.py:169-169`
- Vulnerable code (`introduction/mitre.py`):
```python
cookie = jwt.encode(payload, 'csrf_vulneribility', algorithm='HS256')
```
- Taint Flow:
  - **Source**: `Hardcoded string secret`
  - **Sink**: `JWT signing with embedded secret`
- Evidence: cookie = jwt.encode(payload, 'csrf_vulneribility', algorithm='HS256')
  - Validation: introduction/mitre.py:169 jwt.encode(payload,'csrf_vulneribility') hardcoded; verified with same key at mitre.py:182 and csrf_transfer_monei_api
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/mitre.py:169 jwt.encode(payload,'csrf_vulneribility') hardcoded; verified with same key at mitre.py:182 and csrf_transfer_monei_api | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import jwt,datetime; print(jwt.encode({'username':'admin','exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=5)},'csrf_vulneribility',algorithm='HS256'))
```
- Patch:
  - **Summary**: Load JWT secret from env/secret manager, rotate, and validate; never hardcode signing key.

<a id="finding-31"></a>
### HIGH CSRF money transfer in csrf_transfer_monei_api via GET
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-352 | confidence: 0.95
- Location: `introduction/mitre.py:191-202`
- Vulnerable code (`introduction/mitre.py`):
```python
def csrf_transfer_monei_api(request,recipent,amount):
```
- Taint Flow:
  - **Source**: `Cross-site GET parameters`
  - **Path**:
    - `introduction/mitre.py:191 URL recipent/amount`
    - `introduction/mitre.py:202 balance update`
  - **Sink**: `money transfer state change`
- Evidence: def csrf_transfer_monei_api(request,recipent,amount):
  - Validation: introduction/mitre.py:191 csrf_transfer_monei_api mutates balances on GET:192-207 via URL recipent/amount:118 with cookie JWT only and no CSRF token/method guard
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/mitre.py:191 csrf_transfer_monei_api mutates balances on GET:192-207 via URL recipent/amount:118 with cookie JWT only and no CSRF token/method guard | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
<img src='http://target/mitre/9/lab/api/transfer/victim/100'> <!-- GET triggers transfer without CSRF token -->
```
- Patch:
  - **Summary**: Require POST with CSRF token, SameSite cookies, and re-auth/confirm for transfers; never mutate on GET.

<a id="finding-32"></a>
### HIGH Reflected XSS via |safe in xss_lab_2.html
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `introduction/templates/Lab/XSS/xss_lab_2.html:20-20`
- Vulnerable code (`introduction/templates/Lab/XSS/xss_lab_2.html`):
```html
<p>Hello, {{ username|safe }}</p>
```
- Taint Flow:
  - **Source**: `POST username`
  - **Path**:
    - `introduction/templates/Lab/XSS/xss_lab_2.html:20`
  - **Sink**: `{{ username|safe }}`
- Evidence: <p>Hello, {{ username|safe }}</p>
  - Validation: introduction/views.py:109 POST username flows to introduction/templates/Lab/XSS/xss_lab_2.html:20 {{username|safe}} via /xssL2; blacklist only strips <script> introduction/views.py:112
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:109 POST username flows to introduction/templates/Lab/XSS/xss_lab_2.html:20 {{username|safe}} via /xssL2; blacklist only strips <script> introduction/views.py:112 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe and properly encode username output.

<a id="finding-33"></a>
### HIGH SQL injection in sql_lab via string-concatenated raw query
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.95
- Location: `introduction/views.py:158-162`
- Vulnerable code (`introduction/views.py`):
```python
sql_query = "SELECT * FROM introduction_login WHERE user='"+name+"' AND password='"+password+"'"
```
- Taint Flow:
  - **Source**: `POST parameters name, pass`
  - **Path**:
    - `introduction/views.py:150 POST name/pass`
    - `introduction/views.py:158 string concat`
    - `introduction/views.py:162 objects.raw sink`
  - **Sink**: `login.objects.raw(sql_query) SQL execution`
- Evidence: sql_query = "SELECT * FROM introduction_login WHERE user='"+name+"' AND password='"+password+"'"
  - Validation: introduction/views.py:150 POST name/pass concatenated at views.py:158 into raw() sink at views.py:162 with no parameterization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:150 POST name/pass concatenated at views.py:158 into raw() sink at views.py:162 with no parameterization | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/sql_lab -d "name=' OR '1'='1&pass=' OR '1'='1"
```
- Patch:
  - **Summary**: Use parameterized ORM filter instead of string-concatenated raw SQL.

<a id="finding-34"></a>
### HIGH Missing authentication on xxe_parse endpoint
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.95
- Location: `introduction/views.py:256-256`
- Vulnerable code (`introduction/views.py`):
```python
def xxe_parse(request):
```
- Taint Flow:
  - **Source**: `Unauthenticated POST body`
  - **Path**:
    - `introduction/views.py:256 unguarded entry`
    - `introduction/views.py:260 parseString sink`
  - **Sink**: `XXE parse and DB update without auth`
- Evidence: def xxe_parse(request):
  - Validation: introduction/views.py:256 xxe_parse has only @csrf_exempt with no auth check vs siblings xxe_lab:233 and xxe_see:240 requiring is_authenticated; enables unauthenticated parseString at line 260 with feature_external_ges True at line 259, mounted at introduction/urls.py xx e_parse route
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:256 xxe_parse has only @csrf_exempt with no auth check vs siblings xxe_lab:233 and xxe_see:240 requiring is_authenticated; enables unauthenticated parseString at line 260 with feature_external_ges True at line 259, mounted at introduction/urls.py xx e_parse route | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication on xxe_parse and disable external general entities (setFeature False) / use defusedxml.

<a id="finding-35"></a>
### HIGH XXE in xxe_parse with external entities enabled
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-611 | confidence: 0.95
- Location: `introduction/views.py:258-260`
- Vulnerable code (`introduction/views.py`):
```python
parser.setFeature(feature_external_ges, True)
```
- Taint Flow:
  - **Source**: `Raw POST body XML`
  - **Path**:
    - `introduction/views.py:260 request.body`
    - `introduction/views.py:260 parseString sink`
  - **Sink**: `XML external entity expansion`
- Evidence: parser.setFeature(feature_external_ges, True)
  - Validation: introduction/views.py:258 setFeature external_ges True then parseString(request.body) at views.py:260 with no auth gate and csrf_exempt
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:258 setFeature external_ges True then parseString(request.body) at views.py:260 with no auth gate and csrf_exempt | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/xxe_parse -d '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><text>&xxe;</text></root>'
```
- Patch:
  - **Summary**: Disable external entities/DTD and use defusedxml parser.

<a id="finding-36"></a>
### HIGH OS command injection in cmd_lab via shell=True
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.95
- Location: `introduction/views.py:430-431`
- Vulnerable code (`introduction/views.py`):
```python
process = subprocess.Popen(
```
- Taint Flow:
  - **Source**: `POST domain`
  - **Path**:
    - `introduction/views.py:418 POST domain`
    - `introduction/views.py:425 format into command`
    - `introduction/views.py:430 Popen shell=True`
  - **Sink**: `shell command execution`
- Evidence: process = subprocess.Popen(
  - Validation: introduction/views.py:418 POST domain formatted at views.py:425 into Popen shell=True at views.py:430; re.sub only strips URL prefix
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:418 POST domain formatted at views.py:425 into Popen shell=True at views.py:430; re.sub only strips URL prefix | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/cmd_lab -d 'domain=example.com;id&os=linux'
```
- Patch:
  - **Summary**: Avoid shell=True; validate domain allowlist and use argv list.

<a id="finding-37"></a>
### HIGH Predictable and disclosed OTP in Otp handler
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-330 | confidence: 0.95
- Location: `introduction/views.py:496-497`
- Vulnerable code (`introduction/views.py`):
```python
otpN=randint(100,999)
```
- Taint Flow:
  - **Source**: `GET email parameter`
  - **Path**:
    - `introduction/views.py:496 predictable OTP`
    - `introduction/views.py:507 render OTP`
  - **Sink**: `OTP disclosure and weak generation`
- Evidence: otpN=randint(100,999)
  - Validation: introduction/views.py:496 otpN=randint(100,999) 900-value space with secrets-less random, reflected to non-admin via otp:507 and set via otp.objects.filter(id=1).update:504 enabling brute-force/auth bypass in Otp:491
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:496 otpN=randint(100,999) 900-value space with secrets-less random, reflected to non-admin via otp:507 and set via otp.objects.filter(id=1).update:504 enabling brute-force/auth bypass in Otp:491 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
for i in $(seq 100 999); do curl -b 'email=victim@x.com' -X POST http://localhost:8000/otp -d "otp=$i"; done # 900-space brute force, OTP reflected for non-admin
```
- Patch:
  - **Summary**: Use secrets CSPRNG 6+ digits, don't reflect OTP, add expiry/attempt limits and delivery out-of-band.

<a id="finding-38"></a>
### HIGH Unsafe YAML deserialization in a9_lab via yaml.Loader
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 0.95
- Location: `introduction/views.py:560-560`
- Vulnerable code (`introduction/views.py`):
```python
data = yaml.load(file,yaml.Loader)
```
- Taint Flow:
  - **Source**: `Uploaded YAML file`
  - **Path**:
    - `introduction/views.py:558 FILES file`
    - `introduction/views.py:560 yaml.load`
  - **Sink**: `unsafe YAML deserialization`
- Evidence: data = yaml.load(file,yaml.Loader)
  - Validation: introduction/views.py:558 FILES file passed to yaml.load with yaml.Loader at views.py:560
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:558 FILES file passed to yaml.load with yaml.Loader at views.py:560 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import yaml; print(yaml.load('!!python/object/apply:os.system ["id"]', yaml.Loader)) # upload as file to /a9_lab
```
- Patch:
  - **Summary**: Use yaml.safe_load instead of yaml.Loader.

<a id="finding-39"></a>
### HIGH Hardcoded credentials in a1_broken_access_lab_3
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `introduction/views.py:831-833`
- Vulnerable code (`introduction/views.py`):
```python
if username == 'John' and password == 'reaper':
```
- Taint Flow:
  - **Source**: `Hardcoded literals in source`
  - **Path**:
    - `introduction/views.py:831 hardcoded John`
    - `introduction/views.py:833 hardcoded admin`
  - **Sink**: `Authentication decision`
- Evidence: if username == 'John' and password == 'reaper':
  - Validation: introduction/views.py:831-833 hardcoded John/reaper and admin/admin_pass decide admin flag
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:831-833 hardcoded John/reaper and admin/admin_pass decide admin flag | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded credentials; authenticate against hashed user store with proper authorization.

<a id="finding-40"></a>
### HIGH SQL injection in injection_sql_lab via raw query
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 0.95
- Location: `introduction/views.py:864-864`
- Vulnerable code (`introduction/views.py`):
```python
sql_query = "SELECT * FROM introduction_sql_lab_table WHERE id='"+name+"'AND password='"+password+"'"
```
- Taint Flow:
  - **Source**: `POST name, pass`
  - **Path**:
    - `introduction/views.py:858 POST inputs`
    - `introduction/views.py:864 concat`
    - `introduction/views.py:878 raw()`
  - **Sink**: `raw SQL execution`
- Evidence: sql_query = "SELECT * FROM introduction_sql_lab_table WHERE id='"+name+"'AND password='"+password+"'"
  - Validation: introduction/views.py:858 POST name/pass concatenated at views.py:864 into objects.raw at views.py:878
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:858 POST name/pass concatenated at views.py:864 into objects.raw at views.py:878 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/injection_sql_lab -d "name=' OR '1'='1&pass=x"
```
- Patch:
  - **Summary**: Use parameterized queries/ORM filters instead of string concat.

<a id="finding-41"></a>
### HIGH SSRF in ssrf_lab2 via unchecked requests.get
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `introduction/views.py:963-963`
- Vulnerable code (`introduction/views.py`):
```python
response = requests.get(url)
```
- Taint Flow:
  - **Source**: `POST url`
  - **Path**:
    - `introduction/views.py:961 POST url`
    - `introduction/views.py:963 requests.get`
  - **Sink**: `outbound HTTP fetch`
- Evidence: response = requests.get(url)
  - Validation: introduction/views.py:961 POST url fetched unchecked via requests.get at views.py:963 with no allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:961 POST url fetched unchecked via requests.get at views.py:963 with no allowlist | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/ssrf_lab2 -d 'url=http://169.254.169.254/latest/meta-data/'
```
- Patch:
  - **Summary**: Enforce URL allowlist/egress deny and disable metadata access.

<a id="finding-42"></a>
### HIGH Stored SSTI in ssti_lab via template file write
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `introduction/views.py:995-995`
- Vulnerable code (`introduction/views.py`):
```python
file = open(filename, "w+")
```
- Taint Flow:
  - **Source**: `POST blog template code`
  - **Path**:
    - `introduction/views.py:980 POST blog`
    - `introduction/views.py:995 file write`
    - `introduction/views.py:1003 render template`
  - **Sink**: `template file creation and render`
- Evidence: file = open(filename, "w+")
  - Validation: introduction/views.py:980 POST blog via no-op filter_blog (utility.py:55 returns code) written to template file at views.py:995 and rendered at ssti_view_blog
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:980 POST blog via no-op filter_blog (utility.py:55 returns code) written to template file at views.py:995 and rendered at ssti_view_blog | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/ssti/lab -d 'blog={{ 7*7 }}' # then GET /ssti/blog/<id> renders 49
```
- Patch:
  - **Summary**: Do not write user input as template source; render as data only.

<a id="finding-43"></a>
### HIGH Hardcoded login in crypto_failure_lab3
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `introduction/views.py:1072-1072`
- Vulnerable code (`introduction/views.py`):
```python
if username == "User" and password == "P@$$w0rd":
```
- Taint Flow:
  - **Source**: `Hardcoded password literal`
  - **Path**:
    - `introduction/views.py:1072 hardcoded check`
    - `introduction/views.py:1074 cookie issue`
  - **Sink**: `Auth grant and cookie issue`
- Evidence: if username == "User" and password == "P@$$w0rd":
  - Validation: introduction/views.py:1072 hardcoded User/P@$$w0rd grants cookie at :1074-1077 tamperable to admin
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1072 hardcoded User/P@$$w0rd grants cookie at :1074-1077 tamperable to admin | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded credential; authenticate against hashed store and sign/encrypt auth cookie.

<a id="finding-44"></a>
### HIGH Hardcoded JWT cookie signing key in settings
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `pygoat/settings.py:171-171`
- Vulnerable code (`pygoat/settings.py`):
```python
SECRET_COOKIE_KEY = "PYGOAT"
```
- Taint Flow:
  - **Source**: `Committed short secret`
  - **Path**:
    - `pygoat/settings.py:171 hardcoded key`
    - `introduction/views.py:1095 jwt.decode`
  - **Sink**: `JWT HMAC verification key`
- Evidence: SECRET_COOKIE_KEY = "PYGOAT"
  - Validation: pygoat/settings.py:171 SECRET_COOKIE_KEY="PYGOAT" used as JWT HMAC key at introduction/views.py:1094 jwt.decode/1110 jwt.encode
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: pygoat/settings.py:171 SECRET_COOKIE_KEY="PYGOAT" used as JWT HMAC key at introduction/views.py:1094 jwt.decode/1110 jwt.encode | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Load JWT signing key from environment/secret manager with sufficient entropy; rotate key.

<a id="finding-45"></a>
### HIGH Code injection file write in ssrf_code_converter
- CVSS: **7.2** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.92
- Location: `introduction/utility.py:35-35`
- Vulnerable code (`introduction/utility.py`):
```python
f = open(filename,"w")
```
- Taint Flow:
  - **Source**: `POST python_code`
  - **Path**:
    - `introduction/apis.py:27 POST python_code`
    - `introduction/utility.py:35 file write`
    - `introduction/playground/ssrf/main.py:5 execution`
  - **Sink**: `server Python file overwrite`
- Evidence: f = open(filename,"w")
  - Validation: introduction/apis.py:27 POST python_code passed to ssrf_code_converter then introduction/utility.py:35 open(playground/ssrf/main.py,"w").write attacker-derived output_Code:36 with only line-slicing, no sandbox, reachable via introduction/urls.py:75 api/ssrf
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/apis.py:27 POST python_code passed to ssrf_code_converter then introduction/utility.py:35 open(playground/ssrf/main.py,"w").write attacker-derived output_Code:36 with only line-slicing, no sandbox, reachable via introduction/urls.py:75 api/ssrf | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/api/ssrf -d 'python_code=a\n\n\n\n\n\n\nimport os;os.system("id")' -d 'html_code=<input>'
```
- Patch:
  - **Summary**: Do not persist user code to executable .py; validate against allowlisted template, write outside import path with random name, or execute in sandbox.

<a id="finding-46"></a>
### HIGH Path traversal in playground ssrf_lab
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.9
- Location: `introduction/playground/ssrf/main.py:8-8`
- Vulnerable code (`introduction/playground/ssrf/main.py`):
```python
file = open(filename,"r")
```
- Taint Flow:
  - **Source**: `file parameter`
  - **Path**:
    - `introduction/playground/ssrf/main.py:5 file param`
    - `introduction/playground/ssrf/main.py:8 open`
  - **Sink**: `filesystem read`
- Evidence: file = open(filename,"r")
  - Validation: introduction/views.py:924 file=request.POST[blog] joined at views.py:926 and open(filename,"r") at views.py:927 with no normalization/allowlist; same pattern in playground/ssrf/main.py:8
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:924 file=request.POST[blog] joined at views.py:926 and open(filename,"r") at views.py:927 with no normalization/allowlist; same pattern in playground/ssrf/main.py:8 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/ssrf_lab -d 'blog=../../../../etc/passwd'
```
- Patch:
  - **Summary**: Allowlist blog names / safe_join under fixed dir and reject ../ and absolute paths.

<a id="finding-47"></a>
### HIGH JS-context XSS via {{code}} in script block
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `introduction/templates/Lab/XSS/xss_lab_3.html:20-22`
- Vulnerable code (`introduction/templates/Lab/XSS/xss_lab_3.html`):
```html
<script>
    // LAB 3 JS CODE
    {{code}}
```
- Taint Flow:
  - **Source**: `POST username`
  - **Path**:
    - `introduction/templates/Lab/XSS/xss_lab_3.html:22`
  - **Sink**: `{{code}} in script`
- Evidence: <script> // LAB 3 JS CODE {{code}}
  - Validation: introduction/views.py:125-131 POST username stripped of alphanumerics only then rendered unescaped in script block introduction/templates/Lab/XSS/xss_lab_3.html:22 {{code}} via /xssL3 allows JSFuck payload
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:125-131 POST username stripped of alphanumerics only then rendered unescaped in script block introduction/templates/Lab/XSS/xss_lab_3.html:22 {{code}} via /xssL3 allows JSFuck payload | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not reflect user input inside <script>; remove code reflection or JSON-encode with strict allowlist.

<a id="finding-48"></a>
### HIGH XSS via |safe rendering of SSRF response
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `introduction/templates/Lab/ssrf/ssrf_lab2.html:23-23`
- Vulnerable code (`introduction/templates/Lab/ssrf/ssrf_lab2.html`):
```html
<div style="width:70%;overflow:scroll;background-color:#000">{{response | safe}}<div>
```
- Taint Flow:
  - **Source**: `POST url / external body`
  - **Path**:
    - `introduction/templates/Lab/ssrf/ssrf_lab2.html:23`
  - **Sink**: `{{response | safe}}`
- Evidence: <div style="width:70%;overflow:scroll;background-color:#000">{{response | safe}}<div>
  - Validation: introduction/views.py:960-963 requests.get(url) unvalidated rendered as introduction/templates/Lab/ssrf/ssrf_lab2.html:23 {{response|safe}} via POST /ssrf_lab2
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:960-963 requests.get(url) unvalidated rendered as introduction/templates/Lab/ssrf/ssrf_lab2.html:23 {{response|safe}} via POST /ssrf_lab2 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Validate URL allowlist for SSRF and remove |safe so fetched body is HTML-escaped.

<a id="finding-49"></a>
### HIGH SSTI artifact discloses password hashes
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.9
- Location: `introduction/templates/Lab_2021/A3_Injection/Blogs/9d73d120683d.html:2-4`
- Vulnerable code (`introduction/templates/Lab_2021/A3_Injection/Blogs/9d73d120683d.html`):
```html
{% get_admin_log 5 as log %}
```
- Taint Flow:
  - **Source**: `attacker blog template`
  - **Path**:
    - `introduction/templates/Lab_2021/A3_Injection/Blogs/9d73d120683d.html:4`
  - **Sink**: `{{e.user.password}}`
- Evidence: {% get_admin_log 5 as log %}
  - Validation: introduction/views.py:975-1006 ssti_lab writes unsanitized blog (filter_blog no-op introduction/utility.py:55) and ssti_view_blog renders Blogs/9d73d120683d.html:4 {{e.user.password}} to any authenticated user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:975-1006 ssti_lab writes unsanitized blog (filter_blog no-op introduction/utility.py:55) and ssti_view_blog renders Blogs/9d73d120683d.html:4 {{e.user.password}} to any authenticated user | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Stop rendering user blog content as Django template; escape/store as plain text and enforce author-only read.

<a id="finding-50"></a>
### HIGH SSTI artifact discloses SECRET_KEY
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-200 | confidence: 0.9
- Location: `introduction/templates/Lab_2021/A3_Injection/Blogs/a2538af1b5e4.html:1-2`
- Vulnerable code (`introduction/templates/Lab_2021/A3_Injection/Blogs/a2538af1b5e4.html`):
```html
<h2> ip --> {{ip}} </h2>
```
- Taint Flow:
  - **Source**: `attacker template`
  - **Path**:
    - `introduction/templates/Lab_2021/A3_Injection/Blogs/a2538af1b5e4.html:2`
  - **Sink**: `{{settings.SECRET_KEY}}`
- Evidence: <h2> ip --> {{ip}} </h2>
  - Validation: introduction/views.py:975-1006 SSTI write+render reaches introduction/templates/Lab_2021/A3_Injection/Blogs/a2538af1b5e4.html:2 {{settings.SECRET_KEY}} exposed via /ssti/blog/<id>
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:975-1006 SSTI write+render reaches introduction/templates/Lab_2021/A3_Injection/Blogs/a2538af1b5e4.html:2 {{settings.SECRET_KEY}} exposed via /ssti/blog/<id> | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Stop rendering user blogs as templates; remove settings.SECRET_KEY from template context.

<a id="finding-51"></a>
### HIGH Reflected XSS via |safe username in A8 lab2
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11-11`
- Vulnerable code (`introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html`):
```html
<h1>Hey {{username | safe}},</h1>
```
- Taint Flow:
  - **Source**: `GET username`
  - **Path**:
    - `introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11`
  - **Sink**: `{{username | safe}}`
- Evidence: <h1>Hey {{username | safe}},</h1>
  - Validation: introduction/views.py:1223 GET username passed to introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11 {{username|safe}} via /2021/A8/lab2 with no encoding
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1223 GET username passed to introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11 {{username|safe}} via /2021/A8/lab2 with no encoding | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe and autoescape username parameter.

<a id="finding-52"></a>
### HIGH Reflected XSS in xss_lab via q parameter
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `introduction/views.py:101-101`
- Vulnerable code (`introduction/views.py`):
```python
return render(request,'Lab/XSS/xss_lab.html', {'query': q})
```
- Taint Flow:
  - **Source**: `GET q`
  - **Path**:
    - `introduction/views.py:95 GET q`
    - `introduction/views.py:101 render query`
  - **Sink**: `Template reflection of query`
- Evidence: return render(request,'Lab/XSS/xss_lab.html', {'query': q})
  - Validation: introduction/views.py:95 GET q flows to render at line 101 with query=q; template introduction/templates/Lab/XSS/xss_lab.html renders {{query|safe}} disabling autoescape
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:95 GET q flows to render at line 101 with query=q; template introduction/templates/Lab/XSS/xss_lab.html renders {{query|safe}} disabling autoescape | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe filter and rely on autoescaping / encode output.

<a id="finding-53"></a>
### HIGH OTP verification bypass via admin-OTP OR condition
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-287 | confidence: 0.9
- Location: `introduction/views.py:514-514`
- Vulnerable code (`introduction/views.py`):
```python
if otp.objects.filter(email=email,otp=otpR) or otp.objects.filter(id=2,otp=otpR):
```
- Taint Flow:
  - **Source**: `POST otp + Cookie email`
  - **Path**:
    - `introduction/views.py:512 POST otp`
    - `introduction/views.py:514 OR check`
  - **Sink**: `Auth decision with OR bypass`
- Evidence: if otp.objects.filter(email=email,otp=otpR) or otp.objects.filter(id=2,otp=otpR):
  - Validation: introduction/views.py:514 OR bypass allows any email cookie + admin id=2 OTP; introduction/views.py:488 randint(100,999) 900-space brute-forceable with no rate-limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:514 OR bypass allows any email cookie + admin id=2 OTP; introduction/views.py:488 randint(100,999) 900-space brute-forceable with no rate-limit | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require email binding on both branches (filter email=email AND otp=otpR only), remove id=2 OR clause, add rate-limit/lockout and constant-time compare.

<a id="finding-54"></a>
### HIGH Code injection in a9_lab2 via ImageMath.eval
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-95 | confidence: 0.9
- Location: `introduction/views.py:588-588`
- Vulnerable code (`introduction/views.py`):
```python
output = ImageMath.eval(function_str,img = img, b=b, r=r, g=g)
```
- Taint Flow:
  - **Source**: `POST function`
  - **Path**:
    - `introduction/views.py:583 POST function`
    - `introduction/views.py:588 ImageMath.eval`
  - **Sink**: `evaluated image expression`
- Evidence: output = ImageMath.eval(function_str,img = img, b=b, r=r, g=g)
  - Validation: introduction/views.py:583 POST function passed to ImageMath.eval at views.py:588 with no sanitization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:583 POST function passed to ImageMath.eval at views.py:588 with no sanitization | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/a9_lab2 -F 'function=exec("__import__(\"os\").system(\"id\")")' -F 'file=@img.jpg'
```
- Patch:
  - **Summary**: Remove ImageMath.eval on user input; restrict to allowlisted operations.

<a id="finding-55"></a>
### HIGH Plaintext credential comparison in a10_lab
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-256 | confidence: 0.9
- Location: `introduction/views.py:628-628`
- Vulnerable code (`introduction/views.py`):
```python
if login.objects.filter(user=user,password=password):
```
- Taint Flow:
  - **Source**: `POST name/pass`
  - **Path**:
    - `introduction/views.py:626 POST name/pass`
    - `introduction/views.py:628 plaintext filter`
  - **Sink**: `Plaintext password comparison`
- Evidence: if login.objects.filter(user=user,password=password):
  - Validation: introduction/views.py:628 login.objects.filter(user=user,password=password) plaintext comparison; introduction/models.py:20-23 login stores password CharField plaintext
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:628 login.objects.filter(user=user,password=password) plaintext comparison; introduction/models.py:20-23 login stores password CharField plaintext | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Store salted slow hashes (argon2/bcrypt) and verify via hash comparison, never plaintext filter.

<a id="finding-56"></a>
### HIGH Forgeable JWT in sec_misconfig_lab3 via hardcoded key
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.9
- Location: `introduction/views.py:1095-1095`
- Vulnerable code (`introduction/views.py`):
```python
payload = jwt.decode(cookie, SECRET_COOKIE_KEY, algorithms=['HS256'])
```
- Taint Flow:
  - **Source**: `Hardcoded secret plus attacker cookie`
  - **Path**:
    - `pygoat/settings.py:171 hardcoded key`
    - `introduction/views.py:1095 jwt.decode`
  - **Sink**: `JWT verification with known key`
- Evidence: payload = jwt.decode(cookie, SECRET_COOKIE_KEY, algorithms=['HS256'])
  - Validation: pygoat/settings.py:171 SECRET_COOKIE_KEY=PYGOAT hardcoded used in jwt.decode at introduction/views.py:1095 to grant admin
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: pygoat/settings.py:171 SECRET_COOKIE_KEY=PYGOAT hardcoded used in jwt.decode at introduction/views.py:1095 to grant admin | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import jwt,datetime; print(jwt.encode({'user':'admin'},'PYGOAT',algorithm='HS256'))
```
- Patch:
  - **Summary**: Load JWT key from secret env/random value, not hardcoded PYGOAT.

<a id="finding-57"></a>
### HIGH Hardcoded admin password disclosed in code comment
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.9
- Location: `introduction/views.py:1119-1119`
- Vulnerable code (`introduction/views.py`):
```python
## used admin password --> ***
```
- Evidence: introduction/views.py:1119 code comment discloses the live admin password for auth_failure_lab2 (password=*** redacted). No other finding reports this line; hardcoded logins reported at 831/833/1072 are different endpoints.
  - Validation: introduction/views.py:1119 comment discloses live admin password 2022_in_pygoat@pygoat.com used by auth_failure_lab2 at views.py:1122-1139 PasswordHasher.verify path
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1119 comment discloses live admin password 2022_in_pygoat@pygoat.com used by auth_failure_lab2 at views.py:1122-1139 PasswordHasher.verify path | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove password from code comment, rotate admin credential, and load secrets from environment/secret manager

<a id="finding-58"></a>
### HIGH DOM XSS via innerHTML in a9.js
- CVSS: **6.9** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.85
- Location: `introduction/static/js/a9.js:40-40`
- Vulnerable code (`introduction/static/js/a9.js`):
```javascript
li.innerHTML = data.logs[i];
```
- Taint Flow:
  - **Source**: `server JSON data.logs`
  - **Path**:
    - `introduction/static/js/a9.js:32`
    - `introduction/static/js/a9.js:40`
  - **Sink**: `li.innerHTML`
- Evidence: li.innerHTML = data.logs[i];
  - Validation: introduction/apis.py:59-84 log_function_checker accepts unauthenticated log_code/api_code to overwrite main.py and returns test.log lines rendered via introduction/static/js/a9.js:40 li.innerHTML without sanitization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/apis.py:59-84 log_function_checker accepts unauthenticated log_code/api_code to overwrite main.py and returns test.log lines rendered via introduction/static/js/a9.js:40 li.innerHTML without sanitization | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use textContent instead of innerHTML and sanitize log lines server-side.

<a id="finding-59"></a>
### MEDIUM Weak MD5 password hashing in crypto_failure_lab
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.96
- Location: `introduction/views.py:1026-1026`
- Vulnerable code (`introduction/views.py`):
```python
password = md5(password.encode()).hexdigest()
```
- Taint Flow:
  - **Source**: `POST password`
  - **Path**:
    - `introduction/views.py:1025 POST password`
    - `introduction/views.py:1026 md5`
  - **Sink**: `weak password hash`
- Evidence: password = md5(password.encode()).hexdigest()
  - Validation: introduction/views.py:1026 md5(password.encode()).hexdigest() unsalted fast hash for CF_user auth in crypto_failure_lab:1018
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1026 md5(password.encode()).hexdigest() unsalted fast hash for CF_user auth in crypto_failure_lab:1018 | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
echo -n password | md5sum # unsalted MD5 enables rainbow-table cracking of leaked CF_user passwords
```
- Patch:
  - **Summary**: Use PBKDF2/bcrypt/argon2 with salt via Django make_password/check_password.

<a id="finding-60"></a>
### MEDIUM Flask debug mode enabled in broken-auth lab
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-215 | confidence: 0.95
- Location: `dockerized_labs/broken_auth_lab/app.py:123-123`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
app.run(host='0.0.0.0', port=5000, debug=True)  # Vulnerable: Debug mode enabled in production
```
- Taint Flow:
  - **Source**: `Remote request triggering error`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:123 debug True`
  - **Sink**: `Debug traceback/console`
- Evidence: app.run(host='0.0.0.0', port=5000, debug=True)  # Vulnerable: Debug mode enabled in production
  - Validation: dockerized_labs/broken_auth_lab/app.py:123 app.run(host='0.0.0.0', debug=True); Dockerfile CMD runs app.py so debug ships in container
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:123 app.run(host='0.0.0.0', debug=True); Dockerfile CMD runs app.py so debug ships in container | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set debug=False in app.run and gate dev mode behind env var; never bind 0.0.0.0 with debugger in production.

<a id="finding-61"></a>
### MEDIUM Plaintext credential logging in log_function_target
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.95
- Location: `introduction/playground/A9/archive.py:12-12`
- Vulnerable code (`introduction/playground/A9/archive.py`):
```python
L.info(f"POST request with username {username} and password {password}")
```
- Taint Flow:
  - **Source**: `POST credentials`
  - **Path**:
    - `introduction/playground/A9/archive.py:10 POST username/password`
    - `introduction/playground/A9/archive.py:12 log write`
  - **Sink**: `plaintext credential log`
- Evidence: L.info(f"POST request with username {username} and password {password}")
  - Validation: introduction/playground/A9/archive.py:12 L.info(f"POST request with username {username} and password {password}") writes cleartext creds to test.log, reachable via introduction/urls.py target route
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/playground/A9/archive.py:12 L.info(f"POST request with username {username} and password {password}") writes cleartext creds to test.log, reachable via introduction/urls.py target route | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -X POST http://localhost:8000/2021/discussion/A9/target -d 'username=victim&password=secret123' # then read test.log for credentials
```
- Patch:
  - **Summary**: Never log passwords; redact credentials or log only username/result.

<a id="finding-62"></a>
### MEDIUM Missing CSRF token in a9_lab2 form
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.95
- Location: `introduction/templates/Lab/A9/a9_lab2.html:21-21`
- Vulnerable code (`introduction/templates/Lab/A9/a9_lab2.html`):
```html
<form enctype="multipart/form-data" id="a9_form2" method="POST" style="display: flex;flex-direction: column;align-items: center;margin-bottom: 50px;">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab/A9/a9_lab2.html:21`
  - **Sink**: `POST without token`
- Evidence: <form enctype="multipart/form-data" id="a9_form2" method="POST" style="display: flex;flex-direction: column;align-items: center;margin-bottom: 50px;">
  - Validation: introduction/templates/Lab/A9/a9_lab2.html:21 POST without token + introduction/views.py:573 @csrf_exempt on a9_lab2 + introduction/urls.py:46 route a9_lab2
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/A9/a9_lab2.html:21 POST without token + introduction/views.py:573 @csrf_exempt on a9_lab2 + introduction/urls.py:46 route a9_lab2 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt from a9_lab2 and add {% csrf_token %} to a9_lab2.html form

<a id="finding-63"></a>
### MEDIUM Missing CSRF token in cmd_lab form
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.95
- Location: `introduction/templates/Lab/CMD/cmd_lab.html:9-9`
- Vulnerable code (`introduction/templates/Lab/CMD/cmd_lab.html`):
```html
<form method="post" action="/cmd_lab">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab/CMD/cmd_lab.html:9`
  - **Sink**: `POST without token`
- Evidence: <form method="post" action="/cmd_lab">
  - Validation: introduction/templates/Lab/CMD/cmd_lab.html:9 POST form to /cmd_lab has no {% csrf_token %} and introduction/views.py:414 handler is @csrf_exempt on authenticated shell=True command execution
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/CMD/cmd_lab.html:9 POST form to /cmd_lab has no {% csrf_token %} and introduction/views.py:414 handler is @csrf_exempt on authenticated shell=True command execution | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt from cmd_lab, require {% csrf_token %} in form, and enforce SameSite/session CSRF checks.

<a id="finding-64"></a>
### MEDIUM Missing CSRF token in cmd_lab2 form
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.95
- Location: `introduction/templates/Lab/CMD/cmd_lab2.html:10-10`
- Vulnerable code (`introduction/templates/Lab/CMD/cmd_lab2.html`):
```html
<form method="post" action="/cmd_lab2">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab/CMD/cmd_lab2.html:10`
  - **Sink**: `POST without token`
- Evidence: <form method="post" action="/cmd_lab2">
  - Validation: introduction/templates/Lab/CMD/cmd_lab2.html:10 POST without token + introduction/views.py:452 @csrf_exempt on cmd_lab2 + introduction/urls.py:37 route cmd_lab2 reachable authenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/CMD/cmd_lab2.html:10 POST without token + introduction/views.py:452 @csrf_exempt on cmd_lab2 + introduction/urls.py:37 route cmd_lab2 reachable authenticated | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt from cmd_lab2 and add {% csrf_token %} to cmd_lab2.html form

<a id="finding-65"></a>
### MEDIUM template reflection surface
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.95
- Location: `introduction/templates/Lab/XSS/xss_lab.html:0-0`
- Vulnerable code (`introduction/templates/Lab/XSS/xss_lab.html`):
```html
form + {{ }} in template (verify server-side reflection)
```
- Taint Flow:
  - **Source**: `form input`
  - **Sink**: `template render`
- Evidence: heuristic: form + {{ }} co-occurrence
  - Validation: introduction/templates/Lab/XSS/xss_lab.html:27 {{query|safe}} disables escaping; introduction/views.py:94-101 passes request.GET q directly to query
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/XSS/xss_lab.html:27 {{query|safe}} disables escaping; introduction/views.py:94-101 passes request.GET q directly to query | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe filter so Django autoescapes query; render DB fields only.

<a id="finding-66"></a>
### MEDIUM template reflection surface
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.95
- Location: `introduction/templates/Lab/XSS/xss_lab_2.html:0-0`
- Vulnerable code (`introduction/templates/Lab/XSS/xss_lab_2.html`):
```html
form + {{ }} in template (verify server-side reflection)
```
- Taint Flow:
  - **Source**: `form input`
  - **Sink**: `template render`
- Evidence: heuristic: form + {{ }} co-occurrence
  - Validation: introduction/templates/Lab/XSS/xss_lab_2.html:20 {{username|safe}} disables escaping; introduction/views.py:109-114 only strips literal <script> so bypasses (case/event handlers) reflect unescaped
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/XSS/xss_lab_2.html:20 {{username|safe}} disables escaping; introduction/views.py:109-114 only strips literal <script> so bypasses (case/event handlers) reflect unescaped | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe and drop blacklist; rely on Django autoescaping for username.

<a id="finding-67"></a>
### MEDIUM Missing CSRF token in broken_access_lab_1 form
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.95
- Location: `introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html:11-11`
- Vulnerable code (`introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html`):
```html
<form method="post" action="/broken_access_lab_1">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html:11`
  - **Sink**: `POST without token`
- Evidence: <form method="post" action="/broken_access_lab_1">
  - Validation: introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html:11 POST without token + introduction/views.py:746 @csrf_exempt on a1_broken_access_lab_1
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html:11 POST without token + introduction/views.py:746 @csrf_exempt on a1_broken_access_lab_1 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt and add {% csrf_token %} to broken_access_lab_1.html form

<a id="finding-68"></a>
### MEDIUM Missing CSRF token in broken_access_lab_2 form
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.95
- Location: `introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html:11-11`
- Vulnerable code (`introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html`):
```html
<form method="post" action="/broken_access_lab_2">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html:11`
  - **Sink**: `POST without token`
- Evidence: <form method="post" action="/broken_access_lab_2">
  - Validation: introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html:11 POST without token + introduction/views.py:782 @csrf_exempt on a1_broken_access_lab_2
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html:11 POST without token + introduction/views.py:782 @csrf_exempt on a1_broken_access_lab_2 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt and add {% csrf_token %} to broken_access_lab_2.html form

<a id="finding-69"></a>
### MEDIUM template reflection surface
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.95
- Location: `introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:0-0`
- Vulnerable code (`introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html`):
```html
{{username | safe}}
```
- Taint Flow:
  - **Source**: `form input`
  - **Sink**: `template render`
- Evidence: heuristic: form + {{ }} co-occurrence | safe}} bypassing autoescape
  - Validation: introduction/views.py:1220-1225 GET username directly rendered at introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11 via {{username
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1220-1225 GET username directly rendered at introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11 via {{username | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe filter so {{username}} is autoescaped; validate username against allowlist.

<a id="finding-70"></a>
### MEDIUM Inadequate XSS filter in xss_lab2
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.95
- Location: `introduction/views.py:111-112`
- Vulnerable code (`introduction/views.py`):
```python
username = username.replace("<script>", "").replace("</script>", "")
```
- Taint Flow:
  - **Source**: `POST username`
  - **Path**:
    - `introduction/views.py:109 POST username`
    - `introduction/views.py:111 weak filter`
    - `introduction/views.py:116 render`
  - **Sink**: `template rendering of username`
- Evidence: username = username.replace("<script>", "").replace("</script>", "")
  - Validation: introduction/views.py:112 only strips <script> tags, rendered unescaped via introduction/templates/Lab/XSS/xss_lab_2.html:20 {{ username|safe }} allowing <img onerror> bypass
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:112 only strips <script> tags, rendered unescaped via introduction/templates/Lab/XSS/xss_lab_2.html:20 {{ username|safe }} allowing <img onerror> bypass | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/xssL2 -d 'username=<img src=x onerror=alert(1)>'
```
- Patch:
  - **Summary**: Remove |safe and rely on autoescaping plus context-aware output encoding.

<a id="finding-71"></a>
### MEDIUM Header-spoof authorization in secret view
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-639 | confidence: 0.95
- Location: `introduction/views.py:537-538`
- Vulnerable code (`introduction/views.py`):
```python
if(XHost == 'admin.localhost:8000'):
```
- Taint Flow:
  - **Source**: `X-Host header`
  - **Path**:
    - `introduction/views.py:536 X-Host header`
    - `introduction/views.py:537 check`
  - **Sink**: `secret disclosure`
- Evidence: if(XHost == 'admin.localhost:8000'):
  - Validation: introduction/views.py:536 XHost=request.headers.get(X-Host) grants S3CR37K3Y at views.py:537 if equal admin.localhost:8000, header is fully client-controlled
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:536 XHost=request.headers.get(X-Host) grants S3CR37K3Y at views.py:537 if equal admin.localhost:8000, header is fully client-controlled | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -H 'X-Host: admin.localhost:8000' http://localhost:8000/secret # discloses S3CR37K3Y
```
- Patch:
  - **Summary**: Do not authorize on client header; require authenticated session and server-side allowlist.

<a id="finding-72"></a>
### MEDIUM Reflected XSS in software_and_data_integrity_failure_lab2
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.95
- Location: `introduction/views.py:1223-1224`
- Vulnerable code (`introduction/views.py`):
```python
username = request.GET["username"] -> {{username | safe}}
```
- Taint Flow:
  - **Source**: `GET username`
  - **Path**:
    - `introduction/views.py:1223 GET username`
    - `introduction/views.py:1224 render`
  - **Sink**: `template reflection of username`
- Evidence: username = request.GET["username"]
  - Validation: introduction/views.py:1222 GET username rendered at :1224 into lab2.html:10 {{username|safe}} bypassing autoescape
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1222 GET username rendered at :1224 into lab2.html:10 {{username|safe}} bypassing autoescape | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x 'http://localhost:8000/2021/A8/lab2?username=<script>alert(1)</script>'
```
- Patch:
  - **Summary**: Remove |safe filter and rely on Django autoescaping for username.

<a id="finding-73"></a>
### MEDIUM Unmasked PII disclosure in api_data_view
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-200 | confidence: 0.9
- Location: `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:109-109`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/dataexposure/views.py`):
```python
return JsonResponse(data)
```
- Taint Flow:
  - **Source**: `Stored PAN/SSN/API key`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:91 DB UserData`
    - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:109 JsonResponse`
  - **Sink**: `PII JSON disclosure`
- Evidence: return JsonResponse(data)
  - Validation: dockerized_labs/sensitive_data_exposure/dataexposure/views.py:87 api_data_view returns full credit_card/ssn/api_key at views.py:109 via JsonResponse without masking, only login_required
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/dataexposure/views.py:87 api_data_view returns full credit_card/ssn/api_key at views.py:109 via JsonResponse without masking, only login_required | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x http://localhost:8000/api/user-data/ # returns full PAN, SSN, api_key unmasked
```
- Patch:
  - **Summary**: Mask PAN/SSN (last4 only), omit api_key or require re-auth/scope; add audit logging.

<a id="finding-74"></a>
### MEDIUM DEBUG True in sensitive-data lab settings
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-215 | confidence: 0.9
- Location: `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:11-11`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py`):
```python
DEBUG = True
```
- Taint Flow:
  - **Source**: `Erroneous request`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:11 DEBUG`
  - **Sink**: `Verbose error page`
- Evidence: DEBUG = True
  - Validation: dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:11 DEBUG=True with ALLOWED_HOSTS=*
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:11 DEBUG=True with ALLOWED_HOSTS=* | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set DEBUG=False in deployment; restrict ALLOWED_HOSTS and custom error pages.

<a id="finding-75"></a>
### MEDIUM Hardcoded demo credentials in login template
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-798 | confidence: 0.9
- Location: `dockerized_labs/sensitive_data_exposure/templates/login.html:73-74`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/templates/login.html`):
```html
Username: demo<br>
```
- Taint Flow:
  - **Source**: `Hardcoded template text`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/templates/login.html:73 demo disclosure`
  - **Sink**: `Public credential disclosure`
- Evidence: Username: demo<br>
  - Validation: dockerized_labs/sensitive_data_exposure/templates/login.html:73-74 discloses demo/demopass; entrypoint.sh:11 seeds working demo account with that password
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/templates/login.html:73-74 discloses demo/demopass; entrypoint.sh:11 seeds working demo account with that password | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded demo credentials from template/docs and disable or randomize seeded demo account in non-dev deployments.

<a id="finding-76"></a>
### MEDIUM Full PII disclosure in HTML comment on profile page
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-200 | confidence: 0.9
- Location: `dockerized_labs/sensitive_data_exposure/templates/profile.html:128-130`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/templates/profile.html`):
```html
User's full credit card: {{ user_data.credit_card }}
```
- Taint Flow:
  - **Source**: `Stored PAN/SSN/API key`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:84 profile_view`
    - `dockerized_labs/sensitive_data_exposure/templates/profile.html:128 comment disclosure`
  - **Sink**: `HTML comment reflection`
- Evidence: User's full credit card: {{ user_data.credit_card }}
  - Validation: dockerized_labs/sensitive_data_exposure/templates/profile.html:125-130 full credit_card/ssn/api_key in HTML comment served by profile_view
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/templates/profile.html:125-130 full credit_card/ssn/api_key in HTML comment served by profile_view | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove sensitive values from HTML comments; never render full PAN/SSN/API key to client.

<a id="finding-77"></a>
### MEDIUM MD5 password hashing in csrf_lab_login
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.9
- Location: `introduction/mitre.py:161-161`
- Vulnerable code (`introduction/mitre.py`):
```python
password = md5(password.encode()).hexdigest()
```
- Taint Flow:
  - **Source**: `POST password`
  - **Path**:
    - `introduction/mitre.py:159 POST password`
    - `introduction/mitre.py:161 MD5`
  - **Sink**: `MD5 hash for auth`
- Evidence: password = md5(password.encode()).hexdigest()
  - Validation: introduction/mitre.py:161 md5(password.encode()).hexdigest() for auth lookup at line 162
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/mitre.py:161 md5(password.encode()).hexdigest() for auth lookup at line 162 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace MD5 with salted slow hash (argon2/bcrypt).

<a id="finding-78"></a>
### MEDIUM Missing CSRF token in a9_lab upload form
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.9
- Location: `introduction/templates/Lab/A9/a9_lab.html:10-10`
- Vulnerable code (`introduction/templates/Lab/A9/a9_lab.html`):
```html
<form enctype="multipart/form-data" method="post" action="/a9_lab">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab/A9/a9_lab.html:10`
  - **Sink**: `upload without token`
- Evidence: <form enctype="multipart/form-data" method="post" action="/a9_lab">
  - Validation: introduction/templates/Lab/A9/a9_lab.html:10 POST without token + introduction/views.py:550 @csrf_exempt on a9_lab + introduction/urls.py:44 route a9_lab
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/A9/a9_lab.html:10 POST without token + introduction/views.py:550 @csrf_exempt on a9_lab + introduction/urls.py:44 route a9_lab | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt from a9_lab and add {% csrf_token %} to a9_lab.html form

<a id="finding-79"></a>
### MEDIUM template reflection surface
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `introduction/templates/Lab/XSS/xss_lab_3.html:0-0`
- Vulnerable code (`introduction/templates/Lab/XSS/xss_lab_3.html`):
```html
form + {{ }} in template (verify server-side reflection)
```
- Taint Flow:
  - **Source**: `form input`
  - **Sink**: `template render`
- Evidence: heuristic: form + {{ }} co-occurrence
  - Validation: introduction/templates/Lab/XSS/xss_lab_3.html:22 {{code}} inside <script> executes in JS context; introduction/views.py:122-131 strips alphanumerics leaving []()!+ JSFuck payload intact
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/XSS/xss_lab_3.html:22 {{code}} inside <script> executes in JS context; introduction/views.py:122-131 strips alphanumerics leaving []()!+ JSFuck payload intact | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not interpolate user input into <script>; use JSON-encoding or remove code sink.

<a id="finding-80"></a>
### MEDIUM template reflection surface
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `introduction/templates/Lab/ssrf/ssrf_lab2.html:0-0`
- Vulnerable code (`introduction/templates/Lab/ssrf/ssrf_lab2.html`):
```html
{{response | safe}}
```
- Taint Flow:
  - **Source**: `form input`
  - **Sink**: `template render`
- Evidence: heuristic: form + {{ }} co-occurrence | safe}} bypassing autoescape
  - Validation: introduction/views.py:956-965 POST url->requests.get->response.content.decode() rendered at introduction/templates/Lab/ssrf/ssrf_lab2.html:23 via {{response
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:956-965 POST url->requests.get->response.content.decode() rendered at introduction/templates/Lab/ssrf/ssrf_lab2.html:23 via {{response | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove |safe filter and rely on Django autoescaping; fetch/allowlist URLs and HTML-escape fetched content before render.

<a id="finding-81"></a>
### MEDIUM Weak reversible customHash primitive (SHA256 reversed)
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.9
- Location: `introduction/utility.py:58-59`
- Vulnerable code (`introduction/utility.py`):
```python
def customHash(password):
```
- Taint Flow:
  - **Source**: `User password`
  - **Path**:
    - `introduction/utility.py:58 customHash def`
  - **Sink**: `Weak custom hash`
- Evidence: def customHash(password):
  - Validation: introduction/utility.py:58-59 customHash is single-round unsalted SHA256 reversed; used for auth at introduction/views.py:1042
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/utility.py:58-59 customHash is single-round unsalted SHA256 reversed; used for auth at introduction/views.py:1042 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace customHash with argon2/bcrypt/scrypt with per-user salt.

<a id="finding-82"></a>
### MEDIUM XSS bypass in xss_lab3 via alphanumeric strip
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `introduction/views.py:129-129`
- Vulnerable code (`introduction/views.py`):
```python
result = re.sub(pattern, '', username)
```
- Taint Flow:
  - **Source**: `POST username`
  - **Path**:
    - `introduction/views.py:126 POST username`
    - `introduction/views.py:129 regex strip`
    - `introduction/views.py:130 render`
  - **Sink**: `reflected code rendering`
- Evidence: result = re.sub(pattern, '', username)
  - Validation: introduction/views.py:129 re.sub([a-zA-Z0-9],'',username) preserves symbols, rendered inside <script> at introduction/templates/Lab/XSS/xss_lab_3.html:24 {{code}} enabling symbol-only JS payload
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:129 re.sub([a-zA-Z0-9],'',username) preserves symbols, rendered inside <script> at introduction/templates/Lab/XSS/xss_lab_3.html:24 {{code}} enabling symbol-only JS payload | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x -X POST http://localhost:8000/xssL3 -d 'username=<svg/onload=alert(1)>' # alphanumerics stripped but payload survives
```
- Patch:
  - **Summary**: Stop blacklisting alphanumerics; output-encode and avoid injecting user input into script context.

<a id="finding-83"></a>
### MEDIUM Insecure userid cookie flags in auth_lab_signup
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `introduction/views.py:291-291`
- Vulnerable code (`introduction/views.py`):
```python
response.set_cookie('userid', obj.userid, max_age=31449600, samesite=None, secure=False)
```
- Taint Flow:
  - **Source**: `Signup auth grant`
  - **Path**:
    - `introduction/views.py:287 user create`
    - `introduction/views.py:291 set_cookie`
  - **Sink**: `Cookie without Secure/SameSite`
- Evidence: response.set_cookie('userid', obj.userid, max_age=31449600, samesite=None, secure=False)
  - Validation: introduction/views.py:291 set_cookie userid samesite=None secure=False max_age=31449600 missing Secure/HttpOnly
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:291 set_cookie userid samesite=None secure=False max_age=31449600 missing Secure/HttpOnly | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set auth cookie Secure=True HttpOnly=True SameSite=Lax/Strict; minimize max_age and sign value.

<a id="finding-84"></a>
### MEDIUM Insecure userid cookie flags in auth_lab_login GET branch
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `introduction/views.py:305-305`
- Vulnerable code (`introduction/views.py`):
```python
response.set_cookie('userid', obj.userid, max_age=31449600, samesite=None, secure=False)
```
- Taint Flow:
  - **Source**: `Cookie-based login`
  - **Path**:
    - `introduction/views.py:302 COOKIES userid`
    - `introduction/views.py:305 set_cookie`
  - **Sink**: `Reissued insecure cookie`
- Evidence: response.set_cookie('userid', obj.userid, max_age=31449600, samesite=None, secure=False)
  - Validation: introduction/views.py:305 set_cookie userid samesite=None secure=False reissued from COOKIES userid
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:305 set_cookie userid samesite=None secure=False reissued from COOKIES userid | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set auth cookie Secure=True HttpOnly=True SameSite=Lax/Strict; minimize max_age and sign value.

<a id="finding-85"></a>
### MEDIUM Insecure userid cookie flags in auth_lab_login POST branch
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `introduction/views.py:319-319`
- Vulnerable code (`introduction/views.py`):
```python
response.set_cookie('userid', obj.userid, max_age=31449600, samesite=None, secure=False)
```
- Taint Flow:
  - **Source**: `Password login success`
  - **Path**:
    - `introduction/views.py:315 credential check`
    - `introduction/views.py:319 set_cookie`
  - **Sink**: `Insecure persistent auth cookie`
- Evidence: response.set_cookie('userid', obj.userid, max_age=31449600, samesite=None, secure=False)
  - Validation: introduction/views.py:319 set_cookie userid samesite=None secure=False after password check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:319 set_cookie userid samesite=None secure=False after password check | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set auth cookie Secure=True HttpOnly=True SameSite=Lax/Strict; minimize max_age and sign value.

<a id="finding-86"></a>
### MEDIUM Missing authorization on debug log disclosure
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-532 | confidence: 0.9
- Location: `introduction/views.py:636-639`
- Vulnerable code (`introduction/views.py`):
```python
def debug(request):
```
- Taint Flow:
  - **Source**: `Unauthenticated HTTP request`
  - **Path**:
    - `introduction/views.py:636 debug entry`
    - `introduction/views.py:637 render debug.log`
  - **Sink**: `log file disclosure`
- Evidence: def debug(request):
  - Validation: introduction/views.py:636 debug() has no auth guard, mounted at introduction/urls.py:53 path(debug), renders introduction/templates/Lab/A10/debug.log with tracebacks/paths
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:636 debug() has no auth guard, mounted at introduction/urls.py:53 path(debug), renders introduction/templates/Lab/A10/debug.log with tracebacks/paths | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x http://localhost:8000/debug # returns debug.log without auth check in function body
```
- Patch:
  - **Summary**: Require staff auth for /debug or remove route; do not serve raw log file.

<a id="finding-87"></a>
### MEDIUM IP spoofing bypass in ssrf_target via X-Forwarded-For
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-639 | confidence: 0.9
- Location: `introduction/views.py:946-949`
- Vulnerable code (`introduction/views.py`):
```python
ip = x_forwarded_for.split(',')[0]
```
- Taint Flow:
  - **Source**: `X-Forwarded-For header`
  - **Path**:
    - `introduction/views.py:943 XFF header`
    - `introduction/views.py:951 IP check`
  - **Sink**: `access decision`
- Evidence: ip = x_forwarded_for.split(',')[0]
  - Validation: introduction/views.py:943 XFF trusted via split(',')[0] and loopback check at views.py:951 grants ssrf_target secret content, no auth gate
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:943 XFF trusted via split(',')[0] and loopback check at views.py:951 grants ssrf_target secret content, no auth gate | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -H 'X-Forwarded-For: 127.0.0.1' http://localhost:8000/ssrf_target # bypasses IP check
```
- Patch:
  - **Summary**: Use REMOTE_ADDR from trusted proxy config only; require auth and ignore spoofable X-Forwarded-For.

<a id="finding-88"></a>
### MEDIUM Insecure custom hash in crypto_failure_lab2
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.9
- Location: `introduction/views.py:1042-1042`
- Vulnerable code (`introduction/views.py`):
```python
password = customHash(password)
```
- Taint Flow:
  - **Source**: `POST password`
  - **Path**:
    - `introduction/views.py:1041 POST password`
    - `introduction/views.py:1042 customHash`
  - **Sink**: `custom weak hash`
- Evidence: password = customHash(password)
  - Validation: introduction/views.py:1042 password=customHash(password) where introduction/utility.py:58 customHash is SHA256 hexdigest reversed, unsalted single-round
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1042 password=customHash(password) where introduction/utility.py:58 customHash is SHA256 hexdigest reversed, unsalted single-round | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import hashlib; print(hashlib.sha256(b'pass').hexdigest()[::-1]) # custom reversible transform, no salt/iterations
```
- Patch:
  - **Summary**: Replace customHash with argon2/bcrypt/scrypt salted password hasher.

<a id="finding-89"></a>
### MEDIUM Unsalted SHA256 password check in auth_failure_lab3
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.9
- Location: `introduction/views.py:1194-1194`
- Vulnerable code (`introduction/views.py`):
```python
password = hashlib.sha256(password.encode()).hexdigest()
```
- Taint Flow:
  - **Source**: `POST password`
  - **Path**:
    - `introduction/views.py:1193 POST password`
    - `introduction/views.py:1194 SHA256`
  - **Sink**: `Weak hash comparison`
- Evidence: password = hashlib.sha256(password.encode()).hexdigest()
  - Validation: introduction/views.py:1194 hashlib.sha256(password.encode()).hexdigest() unsalted single-round compare at line 1200 against hardcoded USER_A7_LAB3 hashes at lines 1163-1166
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1194 hashlib.sha256(password.encode()).hexdigest() unsalted single-round compare at line 1200 against hardcoded USER_A7_LAB3 hashes at lines 1163-1166 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use salted slow password hash (argon2/bcrypt) with per-user salt.

<a id="finding-90"></a>
### MEDIUM Django DEBUG enabled in production settings
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-215 | confidence: 0.9
- Location: `pygoat/settings.py:30-30`
- Vulnerable code (`pygoat/settings.py`):
```python
DEBUG = True
```
- Taint Flow:
  - **Source**: `Remote request causing exception`
  - **Path**:
    - `pygoat/settings.py:30 DEBUG True`
  - **Sink**: `Debug traceback disclosure`
- Evidence: DEBUG = True
  - Validation: pygoat/settings.py:30 DEBUG=True enables verbose 500 tracebacks disclosing settings/secrets
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: pygoat/settings.py:30 DEBUG=True enables verbose 500 tracebacks disclosing settings/secrets | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set DEBUG=False in production via environment; use custom 500 handler without internals.

<a id="finding-91"></a>
### MEDIUM Unsalted SHA256 flag hashing with prefix bypass in Challenge.save
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.85
- Location: `challenge/models.py:28-28`
- Vulnerable code (`challenge/models.py`):
```python
self.flag = "hashed_" + hashlib.sha256(self.flag.encode('utf-8')).hexdigest()
```
- Taint Flow:
  - **Source**: `Admin-supplied flag`
  - **Path**:
    - `challenge/models.py:26 flag check`
    - `challenge/models.py:28 SHA256`
  - **Sink**: `Weak unsalted hash store`
- Evidence: self.flag = "hashed_" + hashlib.sha256(self.flag.encode('utf-8')).hexdigest()
  - Validation: challenge/models.py:28 hashed_+hashlib.sha256(flag) unsalted single-round with startswith prefix bypass at line 27
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: challenge/models.py:28 hashed_+hashlib.sha256(flag) unsalted single-round with startswith prefix bypass at line 27 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Store flags with salted slow hash or HMAC with secret; remove startswith bypass.

<a id="finding-92"></a>
### MEDIUM Weak PRNG API key generation in generate_api_key
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:41-41`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/dataexposure/views.py`):
```python
return ''.join(random.choices(chars, k=16))
```
- Taint Flow:
  - **Source**: `Weak PRNG`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:41 random.choices`
  - **Sink**: `API key generation`
- Evidence: return ''.join(random.choices(chars, k=16))
  - Validation: dockerized_labs/sensitive_data_exposure/dataexposure/views.py:41 return random.choices(chars,k=16) Mersenne Twister for api_key generation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/dataexposure/views.py:41 return random.choices(chars,k=16) Mersenne Twister for api_key generation | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
import random,string; print(''.join(random.choices(string.ascii_lowercase+string.digits,k=16))) # predictable Mersenne Twister, 16-char low entropy
```
- Patch:
  - **Summary**: Generate API keys with secrets.token_urlsafe/cSPRNG with sufficient entropy.

<a id="finding-93"></a>
### MEDIUM Wildcard ALLOWED_HOSTS in sensitive-data lab
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-16 | confidence: 0.85
- Location: `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:13-13`
- Vulnerable code (`dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py`):
```python
ALLOWED_HOSTS = ['*']
```
- Taint Flow:
  - **Source**: `Attacker Host header`
  - **Path**:
    - `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:13 wildcard`
  - **Sink**: `Trusted host validation disabled`
- Evidence: ALLOWED_HOSTS = ['*']
  - Validation: dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:13 ALLOWED_HOSTS=['*'] with DEBUG=True at line 11
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:13 ALLOWED_HOSTS=['*'] with DEBUG=True at line 11 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set ALLOWED_HOSTS to explicit hostnames and DEBUG=False in deployed settings.

<a id="finding-94"></a>
### MEDIUM Seeded MD5 hashes without salt (0017)
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-328 | confidence: 0.85
- Location: `introduction/migrations/0017_cf_user.py:21-24`
- Vulnerable code (`introduction/migrations/0017_cf_user.py`):
```python
migrations.RunSQL(
            "INSERT INTO introduction_cf_user (username, password) VALUES "
```
- Taint Flow:
  - **Source**: `hardcoded hashes`
  - **Path**:
    - `introduction/migrations/0017_cf_user.py:21`
  - **Sink**: `RunSQL seed`
- Evidence: migrations.RunSQL( "INSERT INTO introduction_cf_user (username, password) VALUES "
  - Validation: introduction/migrations/0017_cf_user.py:21 seeds unsalted MD5-equivalent passwords verified by md5() compare introduction/views.py:1026 CF_user lookup
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/migrations/0017_cf_user.py:21 seeds unsalted MD5-equivalent passwords verified by md5() compare introduction/views.py:1026 CF_user lookup | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Store salted stretched hashes (e.g. Django password hashers) instead of raw MD5.

<a id="finding-95"></a>
### MEDIUM Seeded weak hashes without salt (0018)
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-328 | confidence: 0.85
- Location: `introduction/migrations/0018_cf_user_password2.py:21-24`
- Vulnerable code (`introduction/migrations/0018_cf_user_password2.py`):
```python
migrations.RunSQL(
            "INSERT INTO introduction_cf_user (username, password, password2) VALUES "
```
- Taint Flow:
  - **Source**: `hardcoded hashes`
  - **Path**:
    - `introduction/migrations/0018_cf_user_password2.py:21`
  - **Sink**: `RunSQL seed`
- Evidence: migrations.RunSQL( "INSERT INTO introduction_cf_user (username, password, password2) VALUES "
  - Validation: introduction/migrations/0018_cf_user_password2.py:21 seeds unsalted fast hashes verified via customHash SHA256-reversed introduction/views.py:1041 without salt/stretching
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/migrations/0018_cf_user_password2.py:21 seeds unsalted fast hashes verified via customHash SHA256-reversed introduction/views.py:1041 without salt/stretching | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace fast unsalted hashes with salted password hasher and migrate stored values.

<a id="finding-96"></a>
### MEDIUM Hardcoded default credentials in log_function_target
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-798 | confidence: 0.85
- Location: `introduction/playground/A9/api.py:17-17`
- Vulnerable code (`introduction/playground/A9/api.py`):
```python
if username == "admin" and password == "admin":
```
- Taint Flow:
  - **Source**: `hardcoded default credentials in source`
  - **Sink**: `hardcoded credential check`
- Evidence: introduction/playground/A9/api.py:17 hardcoded default login + introduction/playground/A9/archive.py:17 same pattern
  - Validation: introduction/playground/A9/api.py:17 hardcoded admin/admin compare reachable via introduction/urls.py:84 with no auth gate (only DELETE at api.py:24 checks auth)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/playground/A9/api.py:17 hardcoded admin/admin compare reachable via introduction/urls.py:84 with no auth gate (only DELETE at api.py:24 checks auth) | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded admin/admin comparison; require proper authenticated session lookup instead of string literal check.

<a id="finding-97"></a>
### MEDIUM Missing CSRF token in ba_lab form
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `introduction/templates/Lab/BrokenAccess/ba_lab.html:11-11`
- Vulnerable code (`introduction/templates/Lab/BrokenAccess/ba_lab.html`):
```html
<form method="post" action="/ba_lab">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab/BrokenAccess/ba_lab.html:11`
  - **Sink**: `POST without token`
- Evidence: <form method="post" action="/ba_lab">
  - Validation: introduction/templates/Lab/BrokenAccess/ba_lab.html:11 POST form has no csrf_token and introduction/views.py:341 ba_lab is @csrf_exempt with state-changing cookie set
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/BrokenAccess/ba_lab.html:11 POST form has no csrf_token and introduction/views.py:341 ba_lab is @csrf_exempt with state-changing cookie set | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt from ba_lab and require {% csrf_token %} in the form.

<a id="finding-98"></a>
### MEDIUM Missing CSRF token in otp form
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `introduction/templates/Lab/BrokenAuth/otp.html:18-18`
- Vulnerable code (`introduction/templates/Lab/BrokenAuth/otp.html`):
```html
<form method="post" action="/otp">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab/BrokenAuth/otp.html:18`
  - **Sink**: `OTP POST without token`
- Evidence: <form method="post" action="/otp">
  - Validation: introduction/templates/Lab/BrokenAuth/otp.html:18 POST without token + introduction/views.py:492 @csrf_exempt on Otp allows cross-site OTP POST
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/BrokenAuth/otp.html:18 POST without token + introduction/views.py:492 @csrf_exempt on Otp allows cross-site OTP POST | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt from Otp and add {% csrf_token %} to otp.html POST form

<a id="finding-99"></a>
### MEDIUM Missing CSRF protection in XXE submission
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-352 | confidence: 0.85
- Location: `introduction/templates/Lab/XXE/xxe_lab.html:15-15`
- Vulnerable code (`introduction/templates/Lab/XXE/xxe_lab.html`):
```html
<form name="ajax" onsubmit="SendToServer()">
```
- Taint Flow:
  - **Source**: `cross-site request`
  - **Path**:
    - `introduction/templates/Lab/XXE/xxe_lab.html:15`
  - **Sink**: `XML POST without token`
- Evidence: <form name="ajax" onsubmit="SendToServer()">
  - Validation: introduction/templates/Lab/XXE/xxe_lab.html:15 form onsubmit SendToServer POSTs to xxe_parse + introduction/views.py:255 @csrf_exempt on xxe_parse with no token check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/templates/Lab/XXE/xxe_lab.html:15 form onsubmit SendToServer POSTs to xxe_parse + introduction/views.py:255 @csrf_exempt on xxe_parse with no token check | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove @csrf_exempt from xxe_parse/xxe_see and require CSRF token on XML POST

<a id="finding-100"></a>
### MEDIUM Log injection via spoofable IP in a10_lab2
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-117 | confidence: 0.85
- Location: `introduction/views.py:654-654`
- Vulnerable code (`introduction/views.py`):
```python
logging.info(f"{now}:{ip}:{user}")
```
- Taint Flow:
  - **Source**: `X-Forwarded-For / POST name`
  - **Path**:
    - `introduction/views.py:648 XFF source`
    - `introduction/views.py:654 log sink`
    - `introduction/views.py:636 debug disclosure`
  - **Sink**: `Log file write later disclosed`
- Evidence: logging.info(f"{now}:{ip}")
  - Validation: introduction/views.py:644-654 XFF split(',')[0] plus POST name flow into logging.info/error at introduction/views.py:654,658,663 with no CRLF/newline sanitization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:644-654 XFF split(',')[0] plus POST name flow into logging.info/error at introduction/views.py:654,658,663 with no CRLF/newline sanitization | consensus: 1/1 confirmed | triage: XFF+POST log injection later disclosed via unauth debug log
- Patch:
  - **Summary**: Sanitize XFF/user (strip \r\n, allow-list IP/hostname), prefer REMOTE_ADDR, use structured logging with newline removal.

<a id="finding-101"></a>
### MEDIUM Weak PRNG ticket codes in gentckt
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `introduction/views.py:680-680`
- Vulnerable code (`introduction/views.py`):
```python
return (''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=10)))
```
- Taint Flow:
  - **Source**: `Weak PRNG`
  - **Path**:
    - `introduction/views.py:680 random.choices`
  - **Sink**: `Security ticket generation`
- Evidence: return (''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=10)))
  - Validation: introduction/views.py:680 gentckt uses random.choices; consumed for security ticket codes at introduction/views.py:705
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:680 gentckt uses random.choices; consumed for security ticket codes at introduction/views.py:705 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use secrets.choice/token_urlsafe for ticket codes.

<a id="finding-102"></a>
### MEDIUM IDOR in ssti_view_blog missing author check
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-639 | confidence: 0.85
- Location: `introduction/views.py:1003-1006`
- Vulnerable code (`introduction/views.py`):
```python
def ssti_view_blog(request,blog_id):
```
- Taint Flow:
  - **Source**: `URL blog_id from different user`
  - **Path**:
    - `introduction/views.py:1003 URL blog_id`
    - `introduction/views.py:1006 render template without author check`
  - **Sink**: `unauthorized blog disclosure`
- Evidence: def ssti_view_blog(request,blog_id):
  - Validation: introduction/views.py:1003-1006 ssti_view_blog renders Blogs/{blog_id}.html with only is_authenticated, no author filter; sibling introduction/views.py:978 filters Blogs.objects.filter(author=request.user)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1003-1006 ssti_view_blog renders Blogs/{blog_id}.html with only is_authenticated, no author filter; sibling introduction/views.py:978 filters Blogs.objects.filter(author=request.user) | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Load via Blogs.objects.get(blog_id=blog_id, author=request.user) and 404 unless owner; validate blog_id format.

<a id="finding-103"></a>
### MEDIUM Template path traversal in ssti_view_blog
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-22 | confidence: 0.85
- Location: `introduction/views.py:1006-1006`
- Vulnerable code (`introduction/views.py`):
```python
return render(request,f"Lab_2021/A3_Injection/Blogs/{blog_id}.html")
```
- Taint Flow:
  - **Source**: `URL blog_id`
  - **Path**:
    - `introduction/views.py:1003 blog_id URL`
    - `introduction/views.py:1006 render`
  - **Sink**: `template path resolution`
- Evidence: return render(request,f"Lab_2021/A3_Injection/Blogs/{blog_id}.html")
  - Validation: introduction/views.py:1006 render(request,f"Lab_2021/A3_Injection/Blogs/{blog_id}.html") interpolates URL blog_id with only is_authenticated check, mounted at introduction/urls.py ssti/blog/<str:blog_id>
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1006 render(request,f"Lab_2021/A3_Injection/Blogs/{blog_id}.html") interpolates URL blog_id with only is_authenticated check, mounted at introduction/urls.py ssti/blog/<str:blog_id> | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Script (`poc.py`):
```python
curl -b sessionid=x http://localhost:8000/ssti/blog/../../settings # template path traversal attempt
```
- Patch:
  - **Summary**: Validate blog_id against UUID allowlist/DB lookup and use fixed template name.

<a id="finding-104"></a>
### MEDIUM Image decompression bomb DoS in a9_lab2
- CVSS: **4.4** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.75
- Location: `introduction/views.py:584-584`
- Vulnerable code (`introduction/views.py`):
```python
img  = Image.open(file)
```
- Taint Flow:
  - **Source**: `uploaded image file`
  - **Path**:
    - `introduction/views.py:582 FILES file`
    - `introduction/views.py:584 Image.open decode`
  - **Sink**: `image decompression resource exhaustion`
- Evidence: img  = Image.open(file)
  - Validation: introduction/views.py:582 FILES file then :584 Image.open(file) with :585-588 convert/split/ImageMath.eval and no size/pixel/count limit or MAX_IMAGE_PIXELS check
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:582 FILES file then :584 Image.open(file) with :585-588 convert/split/ImageMath.eval and no size/pixel/count limit or MAX_IMAGE_PIXELS check | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Enforce upload size/dimension limits, set Image.MAX_IMAGE_PIXELS, reject oversized images before convert/split/eval.

<a id="finding-105"></a>
### LOW Insecure persistent session cookie without flags in broken-auth login
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `dockerized_labs/broken_auth_lab/app.py:49-49`
- Vulnerable code (`dockerized_labs/broken_auth_lab/app.py`):
```python
response.set_cookie('session', session_token, max_age=30*24*60*60)
```
- Taint Flow:
  - **Source**: `Login remember_me flow`
  - **Path**:
    - `dockerized_labs/broken_auth_lab/app.py:39 remember_me`
    - `dockerized_labs/broken_auth_lab/app.py:49 set_cookie`
  - **Sink**: `Persistent cookie without flags`
- Evidence: response.set_cookie('session', session_token, max_age=30*24*60*60)
  - Validation: dockerized_labs/broken_auth_lab/app.py:49 set_cookie without httponly/secure/samesite; both branches at app.py:49 and app.py:51 lack flags
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dockerized_labs/broken_auth_lab/app.py:49 set_cookie without httponly/secure/samesite; both branches at app.py:49 and app.py:51 lack flags | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add httponly=True, secure=True, samesite='Lax' to both session set_cookie calls.

<a id="finding-106"></a>
### LOW Version disclosure in get_version
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-200 | confidence: 0.9
- Location: `introduction/views.py:571-571`
- Vulnerable code (`introduction/views.py`):
```python
return render(request,"Lab/A9/a9_lab.html",{"version":"pyyaml v5.1"})
```
- Taint Flow:
  - **Source**: `remote GET request`
  - **Path**:
    - `introduction/views.py:570 unauth entry`
    - `introduction/views.py:571 version render`
  - **Sink**: `software version disclosure`
- Evidence: return render(request,"Lab/A9/a9_lab.html",{"version":"pyyaml v5.1"})
  - Validation: introduction/views.py:570-571 get_version has no auth check and renders {"version":"pyyaml v5.1"}; introduction/urls.py get_version route unauth reachable
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:570-571 get_version has no auth check and renders {"version":"pyyaml v5.1"}; introduction/urls.py get_version route unauth reachable | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Require authentication for get_version and remove exact library version disclosure or gate behind admin.

<a id="finding-107"></a>
### LOW Unhandled KeyError denial of service via missing User-Agent header
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `introduction/views.py:791-791`
- Vulnerable code (`introduction/views.py`):
```python
user_agent = request.META['HTTP_USER_AGENT']
```
- Taint Flow:
  - **Source**: `HTTP request without User-Agent header`
  - **Path**:
    - `introduction/views.py:791 request.META header access`
  - **Sink**: `unhandled exception causing 500`
- Evidence: introduction/views.py:791 direct dict access to optional header with no .get default, unhandled KeyError -> 500
  - Validation: introduction/views.py:791 request.META['HTTP_USER_AGENT'] direct index with no .get/default; authenticated route at views.py:783-787 still 500s when header omitted
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:791 request.META['HTTP_USER_AGENT'] direct index with no .get/default; authenticated route at views.py:783-787 still 500s when header omitted | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use request.META.get('HTTP_USER_AGENT','') and handle missing header without exception.

<a id="finding-108"></a>
### LOW Insecure cookie flags in crypto_failure_lab3
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `introduction/views.py:1076-1076`
- Vulnerable code (`introduction/views.py`):
```python
response.set_cookie("cookie", cookie)
```
- Taint Flow:
  - **Source**: `server-issued privilege cookie`
  - **Path**:
    - `introduction/views.py:1074 cookie value build`
    - `introduction/views.py:1076 Set-Cookie sink`
  - **Sink**: `persistent auth cookie without flags`
- Evidence: response.set_cookie("cookie", cookie)
  - Validation: introduction/views.py:1074 cookie User|expire built unsigned then introduction/views.py:1076 response.set_cookie("cookie", cookie) with no HttpOnly/Secure/SameSite
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1074 cookie User|expire built unsigned then introduction/views.py:1076 response.set_cookie("cookie", cookie) with no HttpOnly/Secure/SameSite | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Sign/encrypt privilege cookie server-side and set httponly=True, secure=True, samesite='Lax/Strict' with expiry.

<a id="finding-109"></a>
### LOW Unhandled KeyError DoS and missing response in auth_failure_lab3
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `introduction/views.py:1200-1200`
- Vulnerable code (`introduction/views.py`):
```python
if USER_A7_LAB3[username]['password'] == password:
```
- Taint Flow:
  - **Source**: `unauthenticated POST username to auth_failure/lab3`
  - **Path**:
    - `introduction/views.py:1194 username=POST[username]`
    - `introduction/views.py:1200 USER_A7_LAB3[username]`
  - **Sink**: `unguarded dict access raising KeyError + implicit None return`
- Evidence: introduction/views.py:1200 'if USER_A7_LAB3[username]['password']' indexes attacker-controlled username with no validation and sits outside the try/except; unknown username raises KeyError -> 500. On password mismatch there is no else/return so view returns None -> Django ValueError.
  - Validation: introduction/views.py:1200 unguarded USER_A7_LAB3[username] outside try at views.py:1192-1197 raises KeyError; missing else at views.py:1200-1205 returns None; route at introduction/urls.py:89 requires auth via views.py:1177 but still reachable by authenticated user
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1200 unguarded USER_A7_LAB3[username] outside try at views.py:1192-1197 raises KeyError; missing else at views.py:1200-1205 returns None; route at introduction/urls.py:89 requires auth via views.py:1177 but still reachable by authenticated user | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Guard with 'if username in USER_A7_LAB3' and always return HttpResponse for mismatch/unknown user instead of falling through.

<a id="finding-110"></a>
### LOW Insecure persistent session_id cookie in auth_failure_lab3
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `introduction/views.py:1204-1204`
- Vulnerable code (`introduction/views.py`):
```python
response.set_cookie("session_id", token)
```
- Taint Flow:
  - **Source**: `server-generated session token`
  - **Path**:
    - `introduction/views.py:1190 token source`
    - `introduction/views.py:1204 Set-Cookie sink`
  - **Sink**: `session cookie without security flags`
- Evidence: response.set_cookie("session_id", token)
  - Validation: introduction/views.py:1190 uuid token then introduction/views.py:1204 response.set_cookie("session_id", token) with no HttpOnly/Secure/SameSite/expiry
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: introduction/views.py:1190 uuid token then introduction/views.py:1204 response.set_cookie("session_id", token) with no HttpOnly/Secure/SameSite/expiry | consensus: 1/1 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
- Patch:
  - **Summary**: Set session cookie with httponly=True, secure=True, samesite='Lax/Strict', max_age/expires and server-side expiry enforcement.
