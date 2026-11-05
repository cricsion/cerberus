# Cerberus Report

**Findings:** 103 actionable — 28 critical, 39 high, 24 medium, 12 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 34 false positives and 7 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 28 | 0 / 28 (0%) | 28 |
| HIGH | 39 | 0 / 39 (0%) | 39 |
| MEDIUM | 24 | 0 / 24 (0%) | 24 |
| LOW | 12 | 0 / 12 (0%) | 12 |
| **TOTAL** | **103** | **0 / 103 (0%)** | **103** |

## Table of Contents

- [Confirmed (103)](#confirmed)
  - [CRITICAL: Command injection in FastAPI cmdi route (`apps/fastapi_app.py:39`)](#finding-1)
  - [CRITICAL: OS command injection in do_os_system (`src/vulnpy/trigger/cmdi.py:5`)](#finding-2)
  - [CRITICAL: Shell injection in do_subprocess_popen (`src/vulnpy/trigger/cmdi.py:9`)](#finding-3)
  - [CRITICAL: Unsafe pickle.load in do_pickle_load (`src/vulnpy/trigger/deserialization.py:6`)](#finding-4)
  - [CRITICAL: Unsafe pickle.loads in do_pickle_loads (`src/vulnpy/trigger/deserialization.py:11`)](#finding-5)
  - [CRITICAL: Unsafe yaml.load in do_yaml_load (`src/vulnpy/trigger/deserialization.py:15`)](#finding-6)
  - [CRITICAL: Unsafe yaml.load_all in do_yaml_load_all (`src/vulnpy/trigger/deserialization.py:22`)](#finding-7)
  - [CRITICAL: Code injection via do_exec (`src/vulnpy/trigger/unsafe_code_exec.py:1`)](#finding-8)
  - [CRITICAL: Code injection via do_eval (`src/vulnpy/trigger/unsafe_code_exec.py:5`)](#finding-9)
  - [CRITICAL: Missing authentication on FastAPI /cmdi command-execution endpoint (`apps/fastapi_app.py:37`)](#finding-10)
  - [CRITICAL: Command injection via FastAPI file upload (`apps/fastapi_app.py:32`)](#finding-11)
  - [CRITICAL: Command injection via Quart file upload (`apps/quart_app.py:23`)](#finding-12)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in aiohttp get_trigger_view (`src/vulnpy/aiohttp/vulnerable_routes.py:23`)](#finding-13)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in Bottle get_trigger_view (`src/vulnpy/bottle/vulnerable_routes.py:34`)](#finding-14)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in Django get_trigger_view (`src/vulnpy/django/vulnerable.py:30`)](#finding-15)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in Django ASGI get_trigger_view (`src/vulnpy/django/vulnerable_asgi.py:49`)](#finding-16)
  - [CRITICAL: Reflected XSS in Falcon root view for xss (`src/vulnpy/falcon/vulnerable.py:42`)](#finding-17)
  - [CRITICAL: Trigger dispatch RCE in Falcon get_trigger_view (`src/vulnpy/falcon/vulnerable.py:71`)](#finding-18)
  - [CRITICAL: Reflected XSS in Falcon ASGI root view for xss (`src/vulnpy/falcon/vulnerable_asgi.py:42`)](#finding-19)
  - [CRITICAL: Trigger dispatch RCE in Falcon ASGI get_trigger_view (`src/vulnpy/falcon/vulnerable_asgi.py:71`)](#finding-20)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in FastAPI get_trigger_view (`src/vulnpy/fastapi/vulnerable.py:36`)](#finding-21)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in Flask get_trigger_view (`src/vulnpy/flask/blueprint.py:49`)](#finding-22)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in Pyramid get_trigger_view (`src/vulnpy/pyramid/vulnerable_routes.py:45`)](#finding-23)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in Quart get_trigger_view (`src/vulnpy/quart/blueprint.py:47`)](#finding-24)
  - [CRITICAL: Unauthenticated trigger dispatch RCE in WSGI vulnerable_app (`src/vulnpy/wsgi/app.py:22`)](#finding-25)
  - [CRITICAL: Command injection in Falcon FileUpload (`apps/falcon_app.py:28`)](#finding-26)
  - [CRITICAL: Header-trusted code input in Quart _get_user_input (`src/vulnpy/quart/blueprint.py:10`)](#finding-27)
  - [CRITICAL: Command injection in Falcon thread_function (`apps/falcon_app.py:63`)](#finding-28)
  - [HIGH: Reflected XSS in aiohttp get_trigger_view (`src/vulnpy/aiohttp/vulnerable_routes.py:28`)](#finding-29)
  - [HIGH: Reflected XSS in Bottle get_trigger_view (`src/vulnpy/bottle/vulnerable_routes.py:38`)](#finding-30)
  - [HIGH: Reflected XSS in Django get_trigger_view (`src/vulnpy/django/vulnerable.py:35`)](#finding-31)
  - [HIGH: Reflected XSS in Django ASGI get_trigger_view (`src/vulnpy/django/vulnerable_asgi.py:54`)](#finding-32)
  - [HIGH: Reflected XSS in Falcon _set_xss_response (`src/vulnpy/falcon/vulnerable.py:122`)](#finding-33)
  - [HIGH: Reflected XSS in Falcon ASGI _set_xss_response (`src/vulnpy/falcon/vulnerable_asgi.py:122`)](#finding-34)
  - [HIGH: Reflected XSS in FastAPI get_trigger_view (`src/vulnpy/fastapi/vulnerable.py:41`)](#finding-35)
  - [HIGH: Reflected XSS in Flask get_trigger_view (`src/vulnpy/flask/blueprint.py:54`)](#finding-36)
  - [HIGH: Path traversal in do_tarfile_bz2 (`src/vulnpy/trigger/pt.py:22`)](#finding-37)
  - [HIGH: Path traversal in do_bz2_class (`src/vulnpy/trigger/pt.py:30`)](#finding-38)
  - [HIGH: Path traversal in do_bz2_open (`src/vulnpy/trigger/pt.py:38`)](#finding-39)
  - [HIGH: Path traversal in do_io_open (`src/vulnpy/trigger/pt.py:46`)](#finding-40)
  - [HIGH: Path traversal in do_open (`src/vulnpy/trigger/pt.py:54`)](#finding-41)
  - [HIGH: SQL injection in do_sqlite3_execute (`src/vulnpy/trigger/sqli.py:34`)](#finding-42)
  - [HIGH: SQL injection in do_sqlite3_executemany (`src/vulnpy/trigger/sqli.py:45`)](#finding-43)
  - [HIGH: SQL script injection in do_sqlite3_executescript (`src/vulnpy/trigger/sqli.py:56`)](#finding-44)
  - [HIGH: Hardcoded Django SECRET_KEY (`apps/django_app.py:27`)](#finding-45)
  - [HIGH: Loop-amplified blocking execution DoS in FastAPI cmdi route (`apps/fastapi_app.py:41`)](#finding-46)
  - [HIGH: Unescaped output in jinja xss.html (`apps/templates/jinja/xss.html:28`)](#finding-47)
  - [HIGH: Reflected XSS in Pyramid get_trigger_view (`src/vulnpy/pyramid/vulnerable_routes.py:50`)](#finding-48)
  - [HIGH: Reflected XSS in Quart get_trigger_view (`src/vulnpy/quart/blueprint.py:52`)](#finding-49)
  - [HIGH: SSRF in do_urlopen_str (`src/vulnpy/trigger/ssrf.py:64`)](#finding-50)
  - [HIGH: SSRF via Request in do_urlopen_obj (`src/vulnpy/trigger/ssrf.py:72`)](#finding-51)
  - [HIGH: SSRF host-control sink in _request_init helper (`src/vulnpy/trigger/ssrf.py:136`)](#finding-52)
  - [HIGH: SSRF host control in do_httpconnection_init (`src/vulnpy/trigger/ssrf.py:143`)](#finding-53)
  - [HIGH: SSRF host control in do_httpsconnection_init (`src/vulnpy/trigger/ssrf.py:147`)](#finding-54)
  - [HIGH: XPath injection in do_lxml_etree_findall (`src/vulnpy/trigger/xpath.py:24`)](#finding-55)
  - [HIGH: XPath injection in do_lxml_etree_findtext (`src/vulnpy/trigger/xpath.py:28`)](#finding-56)
  - [HIGH: XPath injection in do_xml_etree_findall (`src/vulnpy/trigger/xpath.py:32`)](#finding-57)
  - [HIGH: Reflected XSS in WSGI vulnerable_app (`src/vulnpy/wsgi/app.py:25`)](#finding-58)
  - [HIGH: Jinja XSS sink in flask_app jinja_xss (`apps/flask_app.py:19`)](#finding-59)
  - [HIGH: Unbounded file read in Quart upload handler (`apps/quart_app.py:19`)](#finding-60)
  - [HIGH: Missing authentication/authorization on /vulnpy trigger routes (`src/vulnpy/flask/blueprint.py:61`)](#finding-61)
  - [HIGH: Path traversal in do_tarfile_open (`src/vulnpy/trigger/pt.py:6`)](#finding-62)
  - [HIGH: Path traversal in do_tarfile_class (`src/vulnpy/trigger/pt.py:14`)](#finding-63)
  - [HIGH: Central SSRF sink in _urlopen helper (`src/vulnpy/trigger/ssrf.py:51`)](#finding-64)
  - [HIGH: XXE in do_lxml_etree_fromstring (`src/vulnpy/trigger/xxe.py:7`)](#finding-65)
  - [HIGH: XXE in do_xml_dom_pulldom_parsestring (`src/vulnpy/trigger/xxe.py:11`)](#finding-66)
  - [HIGH: XXE in do_xml_sax_parsestring (`src/vulnpy/trigger/xxe.py:15`)](#finding-67)
  - [MEDIUM: ReDoS in do_re_sub (`src/vulnpy/trigger/redos.py:65`)](#finding-68)
  - [MEDIUM: ReDoS in do_re_sub_compiled (`src/vulnpy/trigger/redos.py:69`)](#finding-69)
  - [MEDIUM: ReDoS in do_re_subn (`src/vulnpy/trigger/redos.py:74`)](#finding-70)
  - [MEDIUM: ReDoS in do_re_subn_compiled (`src/vulnpy/trigger/redos.py:78`)](#finding-71)
  - [MEDIUM: ReDoS in do_re_split (`src/vulnpy/trigger/redos.py:83`)](#finding-72)
  - [MEDIUM: ReDoS in do_re_split_compiled (`src/vulnpy/trigger/redos.py:87`)](#finding-73)
  - [MEDIUM: SSRF in do_legacy_urlopen (`src/vulnpy/trigger/ssrf.py:56`)](#finding-74)
  - [MEDIUM: Insecure MD5 hash in do_hashlib_md5 (`src/vulnpy/trigger/hash.py:18`)](#finding-75)
  - [MEDIUM: Insecure SHA1 hash in do_hashlib_sha1 (`src/vulnpy/trigger/hash.py:23`)](#finding-76)
  - [MEDIUM: Insecure SHA1 via hashlib.new in do_hashlib_new (`src/vulnpy/trigger/hash.py:28`)](#finding-77)
  - [MEDIUM: Attacker-controlled PRNG seed in _seed (`src/vulnpy/trigger/rand.py:15`)](#finding-78)
  - [MEDIUM: Evil nested-quantifier regex definition PATTERN (`src/vulnpy/trigger/redos.py:3`)](#finding-79)
  - [MEDIUM: ReDoS in do_re_match (`src/vulnpy/trigger/redos.py:6`)](#finding-80)
  - [MEDIUM: ReDoS in do_re_match_compiled (`src/vulnpy/trigger/redos.py:12`)](#finding-81)
  - [MEDIUM: ReDoS in do_re_search (`src/vulnpy/trigger/redos.py:19`)](#finding-82)
  - [MEDIUM: ReDoS in do_re_search_compiled (`src/vulnpy/trigger/redos.py:25`)](#finding-83)
  - [MEDIUM: ReDoS in do_re_finditer (`src/vulnpy/trigger/redos.py:32`)](#finding-84)
  - [MEDIUM: ReDoS in do_re_finditer_compiled (`src/vulnpy/trigger/redos.py:37`)](#finding-85)
  - [MEDIUM: ReDoS in do_re_findall (`src/vulnpy/trigger/redos.py:43`)](#finding-86)
  - [MEDIUM: ReDoS in do_re_findall_compiled (`src/vulnpy/trigger/redos.py:47`)](#finding-87)
  - [MEDIUM: ReDoS in do_re_fullmatch (`src/vulnpy/trigger/redos.py:52`)](#finding-88)
  - [MEDIUM: ReDoS in do_re_fullmatch_compiled (`src/vulnpy/trigger/redos.py:58`)](#finding-89)
  - [MEDIUM: Event-loop blocking DoS in async_will_block (`apps/fastapi_app.py:51`)](#finding-90)
  - [MEDIUM: SSRF and method injection sink in _request helper (`src/vulnpy/trigger/ssrf.py:90`)](#finding-91)
  - [LOW: Insecure Jinja2 Environment without autoescape (`apps/flask_app.py:8`)](#finding-92)
  - [LOW: Insecure session cookie Secure flag (`apps/flask_app.py:29`)](#finding-93)
  - [LOW: Insecure session cookie HttpOnly flag (`apps/flask_app.py:30`)](#finding-94)
  - [LOW: Django DEBUG enabled (`apps/django_app.py:28`)](#finding-95)
  - [LOW: Unbounded file read in FastAPI upload handler (`apps/fastapi_app.py:31`)](#finding-96)
  - [LOW: Cacheable responses in WSGI app (`src/vulnpy/wsgi/app.py:33`)](#finding-97)
  - [LOW: Disabled XSS protection header in WSGI app (`src/vulnpy/wsgi/app.py:35`)](#finding-98)
  - [LOW: Disabled HSTS in WSGI app (`src/vulnpy/wsgi/app.py:36`)](#finding-99)
  - [LOW: Weak randomness in do_random (`src/vulnpy/trigger/rand.py:18`)](#finding-100)
  - [LOW: Weak randomness in do_randint (`src/vulnpy/trigger/rand.py:23`)](#finding-101)
  - [LOW: Weak randomness in do_randrange (`src/vulnpy/trigger/rand.py:28`)](#finding-102)
  - [LOW: Weak randomness in do_uniform (`src/vulnpy/trigger/rand.py:33`)](#finding-103)

<a id="confirmed"></a>
## Confirmed (103)

<a id="finding-1"></a>
### CRITICAL Command injection in FastAPI cmdi route
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 1.0
- Location: `apps/fastapi_app.py:39-43`
- Vulnerable code (`apps/fastapi_app.py`):
```python
cmd = "echo " + user_input + " this should be echoed"
        os.system(cmd)
```
- Taint Flow:
  - **Source**: `FastAPI user_input`
  - **Path**:
    - `user_input query -> cmd concat -> os.system`
  - **Sink**: `os.system(cmd)`
- Evidence: cmd = "echo " + user_input + " this should be echoed" os.system(cmd)
  - Validation: apps/fastapi_app.py:38-43 cmd = echo + user_input concat flows to os.system(cmd) with no quoting/sanitizer; unauth GET /cmdi at :37-38
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/fastapi_app.py:38-43 cmd = echo + user_input concat flows to os.system(cmd) with no quoting/sanitizer; unauth GET /cmdi at :37-38 | consensus: 1/1 confirmed | triage: Command injection in cmdi route
- Patch:
  - **Summary**: Remove os.system on user input; use safe API and shlex.quote/allowlist if shell needed.

<a id="finding-2"></a>
### CRITICAL OS command injection in do_os_system
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 1.0
- Location: `src/vulnpy/trigger/cmdi.py:5-6`
- Vulnerable code (`src/vulnpy/trigger/cmdi.py`):
```python
def do_os_system(command):
    return os.system(command)
```
- Taint Flow:
  - **Source**: `HTTP user_input parameter`
  - **Path**:
    - `framework user_input -> do_os_system(command) -> os.system`
  - **Sink**: `os.system(command)`
- Evidence: def do_os_system(command): return os.system(command)
  - Validation: src/vulnpy/trigger/cmdi.py:5-6 os.system(command) passes param unsanitized; reachable via src/vulnpy/flask/blueprint.py:38-43 user_input->get_trigger->trigger_func(user_input) and src/vulnpy/trigger/util.py:33-38 auto-mapped cmdi triggers
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/cmdi.py:5-6 os.system(command) passes param unsanitized; reachable via src/vulnpy/flask/blueprint.py:38-43 user_input->get_trigger->trigger_func(user_input) and src/vulnpy/trigger/util.py:33-38 auto-mapped cmdi triggers | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Avoid os.system with untrusted input; use subprocess without shell and fixed allow-listed args.
  - +1 duplicate(s): `src/vulnpy/trigger/cmdi.py:5`

<a id="finding-3"></a>
### CRITICAL Shell injection in do_subprocess_popen
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 1.0
- Location: `src/vulnpy/trigger/cmdi.py:9-12`
- Vulnerable code (`src/vulnpy/trigger/cmdi.py`):
```python
def do_subprocess_popen(command):
    process = subprocess.Popen(
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> do_subprocess_popen -> Popen shell=True`
  - **Sink**: `subprocess.Popen(..., shell=True)`
- Evidence: def do_subprocess_popen(command): process = subprocess.Popen(
  - Validation: src/vulnpy/trigger/cmdi.py:9-12 subprocess.Popen(command,...,shell=True) with raw param; reachable via src/vulnpy/flask/blueprint.py:38-43 with no sanitization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/cmdi.py:9-12 subprocess.Popen(command,...,shell=True) with raw param; reachable via src/vulnpy/flask/blueprint.py:38-43 with no sanitization | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove shell=True and pass argument list with allow-list validation.

<a id="finding-4"></a>
### CRITICAL Unsafe pickle.load in do_pickle_load
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 1.0
- Location: `src/vulnpy/trigger/deserialization.py:6-8`
- Vulnerable code (`src/vulnpy/trigger/deserialization.py`):
```python
def do_pickle_load(user_input):
    return pickle.load(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pickle.load`
  - **Sink**: `pickle.load`
- Evidence: def do_pickle_load(user_input): return pickle.load(user_input)
  - Validation: src/vulnpy/trigger/deserialization.py:6-8 pickle.load on attacker-derived BytesIO; reachable via src/vulnpy/flask/blueprint.py:38-43 with no allow-list
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/deserialization.py:6-8 pickle.load on attacker-derived BytesIO; reachable via src/vulnpy/flask/blueprint.py:38-43 with no allow-list | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not unpickle untrusted data; use JSON or allow-listed safe deserializer.

<a id="finding-5"></a>
### CRITICAL Unsafe pickle.loads in do_pickle_loads
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 1.0
- Location: `src/vulnpy/trigger/deserialization.py:11-12`
- Vulnerable code (`src/vulnpy/trigger/deserialization.py`):
```python
def do_pickle_loads(user_input):
    return pickle.loads(user_input.encode("utf-8"))
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pickle.loads`
  - **Sink**: `pickle.loads`
- Evidence: def do_pickle_loads(user_input): return pickle.loads(user_input.encode("utf-8"))
  - Validation: src/vulnpy/trigger/deserialization.py:11-12 pickle.loads(user_input.encode) with no guard; reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/deserialization.py:11-12 pickle.loads(user_input.encode) with no guard; reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed | triage: Unsafe pickle.loads RCE | triage: Unauth dispatch RCE in Django ASGI
- Patch:
  - **Summary**: Remove pickle.loads on untrusted input; use safe format.
  - +1 duplicate(s): `src/vulnpy/trigger/deserialization.py:11`

<a id="finding-6"></a>
### CRITICAL Unsafe yaml.load in do_yaml_load
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 1.0
- Location: `src/vulnpy/trigger/deserialization.py:15-17`
- Vulnerable code (`src/vulnpy/trigger/deserialization.py`):
```python
def do_yaml_load(user_input):
        return yaml.load(user_input, Loader=yaml.UnsafeLoader)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> yaml.load UnsafeLoader`
  - **Sink**: `yaml.load(..., UnsafeLoader)`
- Evidence: def do_yaml_load(user_input): return yaml.load(user_input, Loader=yaml.UnsafeLoader)
  - Validation: src/vulnpy/trigger/deserialization.py:15-17 yaml.load(user_input,Loader=yaml.UnsafeLoader) allows code execution; reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/deserialization.py:15-17 yaml.load(user_input,Loader=yaml.UnsafeLoader) allows code execution; reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use yaml.safe_load instead of UnsafeLoader.

<a id="finding-7"></a>
### CRITICAL Unsafe yaml.load_all in do_yaml_load_all
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 1.0
- Location: `src/vulnpy/trigger/deserialization.py:22-23`
- Vulnerable code (`src/vulnpy/trigger/deserialization.py`):
```python
def do_yaml_load_all(user_input):
    result = yaml.load_all(user_input, Loader=yaml.UnsafeLoader)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> yaml.load_all UnsafeLoader`
  - **Sink**: `yaml.load_all(..., UnsafeLoader)`
- Evidence: def do_yaml_load_all(user_input): result = yaml.load_all(user_input, Loader=yaml.UnsafeLoader)
  - Validation: src/vulnpy/trigger/deserialization.py:22-23 yaml.load_all(user_input,Loader=yaml.UnsafeLoader) then list(); reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/deserialization.py:22-23 yaml.load_all(user_input,Loader=yaml.UnsafeLoader) then list(); reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use yaml.safe_load_all or safe_load.

<a id="finding-8"></a>
### CRITICAL Code injection via do_exec
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 1.0
- Location: `src/vulnpy/trigger/unsafe_code_exec.py:1-2`
- Vulnerable code (`src/vulnpy/trigger/unsafe_code_exec.py`):
```python
def do_exec(code):
    exec(code)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> exec`
  - **Sink**: `exec(code)`
- Evidence: def do_exec(code): exec(code)
  - Validation: src/vulnpy/trigger/unsafe_code_exec.py:1-2 exec(code) with no sanitization; reachable via src/vulnpy/flask/blueprint.py:47-55 _get_user_input()->trigger_func(user_input) and src/vulnpy/trigger/util.py:34-62 trigger map
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/unsafe_code_exec.py:1-2 exec(code) with no sanitization; reachable via src/vulnpy/flask/blueprint.py:47-55 _get_user_input()->trigger_func(user_input) and src/vulnpy/trigger/util.py:34-62 trigger map | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove exec trigger; if needed, replace with allowlisted expression evaluator (e.g., ast.literal_eval).

<a id="finding-9"></a>
### CRITICAL Code injection via do_eval
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 1.0
- Location: `src/vulnpy/trigger/unsafe_code_exec.py:5-6`
- Vulnerable code (`src/vulnpy/trigger/unsafe_code_exec.py`):
```python
def do_eval(code):
    return eval(code)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> eval`
  - **Sink**: `eval(code)`
- Evidence: def do_eval(code): return eval(code)
  - Validation: src/vulnpy/trigger/unsafe_code_exec.py:5-6 return eval(code) unsanitized; reachable via src/vulnpy/flask/blueprint.py:47-55 user_input dispatch
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/unsafe_code_exec.py:5-6 return eval(code) unsanitized; reachable via src/vulnpy/flask/blueprint.py:47-55 user_input dispatch | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove eval trigger; replace with ast.literal_eval or strict allowlist.
  - +1 duplicate(s): `src/vulnpy/trigger/unsafe_code_exec.py:5`

<a id="finding-10"></a>
### CRITICAL Missing authentication on FastAPI /cmdi command-execution endpoint
- CVSS: **8.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.98
- Location: `apps/fastapi_app.py:37-43`
- Vulnerable code (`apps/fastapi_app.py`):
```python
cmd = "echo " + user_input + "..."; os.system(cmd)
```
- Taint Flow:
  - **Source**: `query param user_input at apps/fastapi_app.py:38 via GET /cmdi`
  - **Path**:
    - `apps/fastapi_app.py:38 user_input query param`
    - `apps/fastapi_app.py:39 cmd concatenation`
    - `apps/fastapi_app.py:43 os.system(cmd) in loop`
  - **Sink**: `os.system(cmd) at apps/fastapi_app.py:43`
- Evidence: Route def cmdi at apps/fastapi_app.py:37-38 takes attacker user_input with no auth decorator, Depends, API key, or session check and directly builds shell command at :39 and loops os.system(cmd)+sleep(3)x10 at :41-45
  - Validation: apps/fastapi_app.py:37-43 @app.get(/cmdi) def cmdi(user_input:str) builds cmd=echo+user_input at :39 and loops os.system(cmd) at :43 with no auth decorator, Depends, or sanitization
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/fastapi_app.py:37-43 @app.get(/cmdi) def cmdi(user_input:str) builds cmd=echo+user_input at :39 and loops os.system(cmd) at :43 with no auth decorator, Depends, or sanitization | consensus: 1/1 confirmed | triage: Missing auth on command-execution endpoint
- Patch:
  - **Summary**: Remove /cmdi shell endpoint or require authentication plus strict input validation and avoid os.system with shell=True; use subprocess without shell and allow-list.

<a id="finding-11"></a>
### CRITICAL Command injection via FastAPI file upload
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.95
- Location: `apps/fastapi_app.py:32-33`
- Vulnerable code (`apps/fastapi_app.py`):
```python
content = await file.read()
    do_os_system(content[:20])
```
- Taint Flow:
  - **Source**: `uploaded file content`
  - **Path**:
    - `UploadFile.read -> do_os_system -> os.system`
  - **Sink**: `do_os_system(content[:20])`
- Evidence: content = await file.read() do_os_system(content[:20])
  - Validation: apps/fastapi_app.py:31-33 await file.read() bytes sliced content[:20] passed to do_os_system (os.system at src/vulnpy/trigger/cmdi.py:5-6 accepts bytes); unauth POST /files/upload at :30 with no validation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/fastapi_app.py:31-33 await file.read() bytes sliced content[:20] passed to do_os_system (os.system at src/vulnpy/trigger/cmdi.py:5-6 accepts bytes); unauth POST /files/upload at :30 with no validation | consensus: 1/1 confirmed | triage: Command injection via FastAPI upload
- Patch:
  - **Summary**: Do not pass uploaded bytes to shell; reject/validate upload and use shell=False APIs.

<a id="finding-12"></a>
### CRITICAL Command injection via Quart file upload
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.95
- Location: `apps/quart_app.py:23-23`
- Vulnerable code (`apps/quart_app.py`):
```python
do_os_system(user_input[:20])
```
- Taint Flow:
  - **Source**: `uploaded file`
  - **Path**:
    - `request.files -> do_os_system`
  - **Sink**: `do_os_system(user_input[:20])`
- Evidence: do_os_system(user_input[:20])
  - Validation: apps/quart_app.py:18-23 files.get file stream.read() bytes [:20] to do_os_system (os.system at src/vulnpy/trigger/cmdi.py:5-6); unauth POST /files/upload at :17 with only ValueError catch, no sanitizer
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/quart_app.py:18-23 files.get file stream.read() bytes [:20] to do_os_system (os.system at src/vulnpy/trigger/cmdi.py:5-6); unauth POST /files/upload at :17 with only ValueError catch, no sanitizer | consensus: 1/1 confirmed | triage: Command injection via Quart upload
- Patch:
  - **Summary**: Do not pass uploaded bytes to shell; validate and avoid os.system.

<a id="finding-13"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in aiohttp get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/aiohttp/vulnerable_routes.py:23-24`
- Vulnerable code (`src/vulnpy/aiohttp/vulnerable_routes.py`):
```python
if trigger_func:
            trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `aiohttp query user_input`
  - **Path**:
    - `rel_url query -> trigger_func`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/aiohttp/vulnerable_routes.py:20 query user_input flows to trigger_func(user_input) at src/vulnpy/aiohttp/vulnerable_routes.py:23-24 with routes for every TRIGGER_MAP entry at src/vulnpy/aiohttp/vulnerable_routes.py:60-73
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/aiohttp/vulnerable_routes.py:20 query user_input flows to trigger_func(user_input) at src/vulnpy/aiohttp/vulnerable_routes.py:23-24 with routes for every TRIGGER_MAP entry at src/vulnpy/aiohttp/vulnerable_routes.py:60-73 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add auth and remove/neutralize code-exec triggers reachable via /vulnpy/<name>/<trigger>

<a id="finding-14"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in Bottle get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/bottle/vulnerable_routes.py:34-35`
- Vulnerable code (`src/vulnpy/bottle/vulnerable_routes.py`):
```python
if trigger_func:
            trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `Bottle user_input`
  - **Path**:
    - `request.GET/POST -> trigger_func`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/bottle/vulnerable_routes.py:31 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/bottle/vulnerable_routes.py:34-35 registered for all triggers at src/vulnpy/bottle/vulnerable_routes.py:53-58
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/bottle/vulnerable_routes.py:31 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/bottle/vulnerable_routes.py:34-35 registered for all triggers at src/vulnpy/bottle/vulnerable_routes.py:53-58 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Protect bottle trigger routes with auth and block raw input to os.system/eval triggers

<a id="finding-15"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in Django get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/django/vulnerable.py:30-31`
- Vulnerable code (`src/vulnpy/django/vulnerable.py`):
```python
if trigger_func:
            trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `Django request user_input`
  - **Path**:
    - `request.GET/POST user_input -> trigger_func`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/django/vulnerable.py:27 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/django/vulnerable.py:30-31; trigger resolves via TRIGGER_MAP built at src/vulnpy/trigger/util.py:22-38 to os.system at src/vulnpy/trigger/cmdi.py:6
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/django/vulnerable.py:27 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/django/vulnerable.py:30-31; trigger resolves via TRIGGER_MAP built at src/vulnpy/trigger/util.py:22-38 to os.system at src/vulnpy/trigger/cmdi.py:6 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Gate vulnerable_urlpatterns behind auth and remove raw user_input passthrough to code-exec triggers

<a id="finding-16"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in Django ASGI get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/django/vulnerable_asgi.py:49-50`
- Vulnerable code (`src/vulnpy/django/vulnerable_asgi.py`):
```python
if trigger_func:
            trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `Django ASGI user_input`
  - **Path**:
    - `await _get_user_input -> trigger_func`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/django/vulnerable_asgi.py:46 user_input=await _get_user_input flows to trigger_func(user_input) at src/vulnpy/django/vulnerable_asgi.py:49-50 reaching os.system at src/vulnpy/trigger/cmdi.py:6
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/django/vulnerable_asgi.py:46 user_input=await _get_user_input flows to trigger_func(user_input) at src/vulnpy/django/vulnerable_asgi.py:49-50 reaching os.system at src/vulnpy/trigger/cmdi.py:6 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require auth on async trigger views and stop dispatching unauthenticated input to exec/SQL/SSRF triggers
  - +1 duplicate(s): `src/vulnpy/trigger/deserialization.py:11`

<a id="finding-17"></a>
### CRITICAL Reflected XSS in Falcon root view for xss
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `src/vulnpy/falcon/vulnerable.py:42-43`
- Vulnerable code (`src/vulnpy/falcon/vulnerable.py`):
```python
if name == "xss":
                    _set_xss_response(resp, "{}.html".format(name), user_input)
```
- Taint Flow:
  - **Source**: `falcon query user_input`
  - **Path**:
    - `req.get_param user_input -> on_get root view -> _set_xss_response -> resp.text`
  - **Sink**: `resp.text = template + user_input`
- Evidence: if name == "xss": _set_xss_response(resp, "{}.html".format(name), user_input)
  - Validation: src/vulnpy/falcon/vulnerable.py:30 user_input=req.get_param + src/vulnpy/falcon/vulnerable.py:42-43 _set_xss_response + src/vulnpy/falcon/vulnerable.py:122-125 template+user_input to resp.text text/html unsanitized
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/falcon/vulnerable.py:30 user_input=req.get_param + src/vulnpy/falcon/vulnerable.py:42-43 _set_xss_response + src/vulnpy/falcon/vulnerable.py:122-125 template+user_input to resp.text text/html unsanitized | consensus: 1/1 confirmed | triage: Shell injection via Popen | triage: Reflected XSS in Falcon root view | triage: Unauth dispatch RCE in FastAPI
- Patch:
  - **Summary**: HTML-escape user_input (html.escape) before concatenation in _set_xss_response or set text/plain.

<a id="finding-18"></a>
### CRITICAL Trigger dispatch RCE in Falcon get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/falcon/vulnerable.py:71-72`
- Vulnerable code (`src/vulnpy/falcon/vulnerable.py`):
```python
if trigger_func:
                trigger_func(command)
```
- Taint Flow:
  - **Source**: `falcon user_input`
  - **Path**:
    - `req user_input -> trigger(command)`
  - **Sink**: `trigger_func(command)`
- Evidence: if trigger_func: trigger_func(command)
  - Validation: src/vulnpy/falcon/vulnerable.py:71-72 trigger_func(command) dispatches attacker req.get_param user_input from src/vulnpy/falcon/vulnerable.py:31 to exec/eval/system via src/vulnpy/trigger/util.py:50-62
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/falcon/vulnerable.py:71-72 trigger_func(command) dispatches attacker req.get_param user_input from src/vulnpy/falcon/vulnerable.py:31 to exec/eval/system via src/vulnpy/trigger/util.py:50-62 | consensus: 1/1 confirmed | triage: Dispatch RCE in Falcon
- Patch:
  - **Summary**: Remove unauthenticated trigger dispatch to code-exec triggers; require auth and disable exec/eval/system routes

<a id="finding-19"></a>
### CRITICAL Reflected XSS in Falcon ASGI root view for xss
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `src/vulnpy/falcon/vulnerable_asgi.py:42-43`
- Vulnerable code (`src/vulnpy/falcon/vulnerable_asgi.py`):
```python
if name == "xss":
                    _set_xss_response(resp, "{}.html".format(name), user_input)
```
- Taint Flow:
  - **Source**: `falcon ASGI query user_input`
  - **Path**:
    - `req.get_param user_input -> async on_get -> _set_xss_response`
  - **Sink**: `resp.text XSS concat`
- Evidence: if name == "xss": _set_xss_response(resp, "{}.html".format(name), user_input)
  - Validation: src/vulnpy/falcon/vulnerable_asgi.py:30 async user_input=req.get_param + src/vulnpy/falcon/vulnerable_asgi.py:42-43 _set_xss_response + src/vulnpy/falcon/vulnerable_asgi.py:122-125 unsanitized template+user_input to resp.text
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/falcon/vulnerable_asgi.py:30 async user_input=req.get_param + src/vulnpy/falcon/vulnerable_asgi.py:42-43 _set_xss_response + src/vulnpy/falcon/vulnerable_asgi.py:122-125 unsanitized template+user_input to resp.text | consensus: 1/1 confirmed | triage: Unsafe pickle.load RCE | triage: Reflected XSS in Falcon ASGI view | triage: Unauth dispatch RCE in Django
- Patch:
  - **Summary**: HTML-escape user_input before concatenation in _set_xss_response.

<a id="finding-20"></a>
### CRITICAL Trigger dispatch RCE in Falcon ASGI get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/falcon/vulnerable_asgi.py:71-72`
- Vulnerable code (`src/vulnpy/falcon/vulnerable_asgi.py`):
```python
if trigger_func:
                trigger_func(command)
```
- Taint Flow:
  - **Source**: `falcon ASGI user_input`
  - **Path**:
    - `user_input -> trigger(command)`
  - **Sink**: `trigger_func(command)`
- Evidence: if trigger_func: trigger_func(command)
  - Validation: src/vulnpy/falcon/vulnerable_asgi.py:31 user_input from req.get_param flows via self.trigger to src/vulnpy/falcon/vulnerable_asgi.py:71-72 trigger_func(command) with no sanitizer/auth; mounted at src/vulnpy/falcon/vulnerable_asgi.py:89-96 + apps/falcon_asgi_app.py:11
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/falcon/vulnerable_asgi.py:31 user_input from req.get_param flows via self.trigger to src/vulnpy/falcon/vulnerable_asgi.py:71-72 trigger_func(command) with no sanitizer/auth; mounted at src/vulnpy/falcon/vulnerable_asgi.py:89-96 + apps/falcon_asgi_app.py:11 | consensus: 1/1 confirmed | triage: Dispatch RCE in Falcon ASGI
- Patch:
  - **Summary**: Require auth and allowlist/validate trigger inputs; do not dispatch untrusted input to code-execution triggers (os.system/eval/pickle) and replace shell with safe APIs.

<a id="finding-21"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in FastAPI get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/fastapi/vulnerable.py:36-37`
- Vulnerable code (`src/vulnpy/fastapi/vulnerable.py`):
```python
if trigger_func:
            trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `FastAPI query user_input`
  - **Path**:
    - `query user_input -> trigger_func(user_input)`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/fastapi/vulnerable.py:33 async _view(user_input:str) flows to trigger_func(user_input) at src/vulnpy/fastapi/vulnerable.py:36-37; router mounted at apps/fastapi_app.py:8 and trigger resolves to os.system at src/vulnpy/trigger/cmdi.py:6
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/fastapi/vulnerable.py:33 async _view(user_input:str) flows to trigger_func(user_input) at src/vulnpy/fastapi/vulnerable.py:36-37; router mounted at apps/fastapi_app.py:8 and trigger resolves to os.system at src/vulnpy/trigger/cmdi.py:6 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authentication on /vulnpy trigger routes and disable code-execution triggers or stop passing raw user_input to exec sinks

<a id="finding-22"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in Flask get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/flask/blueprint.py:49-50`
- Vulnerable code (`src/vulnpy/flask/blueprint.py`):
```python
if trigger_func:
                trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `HTTP User-Input header / user_input query/form`
  - **Path**:
    - `_get_user_input -> user_input -> trigger_func(user_input) -> exec/eval/os.system/SQL/SSRF`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/flask/blueprint.py:43 user_input=_get_user_input() flows to trigger_func(user_input) at src/vulnpy/flask/blueprint.py:49-50; get_trigger resolves attacker-chosen cmdi/os-system to os.system at src/vulnpy/trigger/cmdi.py:6 and routes auto-generated for all TRIGGER_MAP at src/vulnpy/flask/blueprint.py:68-72
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/flask/blueprint.py:43 user_input=_get_user_input() flows to trigger_func(user_input) at src/vulnpy/flask/blueprint.py:49-50; get_trigger resolves attacker-chosen cmdi/os-system to os.system at src/vulnpy/trigger/cmdi.py:6 and routes auto-generated for all TRIGGER_MAP at src/vulnpy/flask/blueprint.py:68-72 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not expose code-exec triggers unauthenticated; require auth and remove/sandbox cmdi/unsafe_code_exec triggers or exec user input
  - +1 duplicate(s): `src/vulnpy/trigger/cmdi.py:5`

<a id="finding-23"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in Pyramid get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/pyramid/vulnerable_routes.py:45-46`
- Vulnerable code (`src/vulnpy/pyramid/vulnerable_routes.py`):
```python
if trigger_func:
            trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `Pyramid user_input`
  - **Path**:
    - `request.GET/POST -> trigger_func`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/pyramid/vulnerable_routes.py:42 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/pyramid/vulnerable_routes.py:45-46 with routes for all triggers via generate_trigger_urls at src/vulnpy/pyramid/vulnerable_routes.py:58-65
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/pyramid/vulnerable_routes.py:42 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/pyramid/vulnerable_routes.py:45-46 with routes for all triggers via generate_trigger_urls at src/vulnpy/pyramid/vulnerable_routes.py:58-65 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Require authorization on pyramid trigger views and disable code-exec triggers with raw user input

<a id="finding-24"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in Quart get_trigger_view
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/quart/blueprint.py:47-48`
- Vulnerable code (`src/vulnpy/quart/blueprint.py`):
```python
if trigger_func:
            trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `Quart user_input`
  - **Path**:
    - `User_Input header/args -> trigger_func`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: trigger_func(user_input)
  - Validation: src/vulnpy/quart/blueprint.py:44 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/quart/blueprint.py:47-48; routes auto-created for every TRIGGER_MAP entry at src/vulnpy/quart/blueprint.py:63-65
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/quart/blueprint.py:44 user_input=_get_user_input flows to trigger_func(user_input) at src/vulnpy/quart/blueprint.py:47-48; routes auto-created for every TRIGGER_MAP entry at src/vulnpy/quart/blueprint.py:63-65 | consensus: 1/1 confirmed | triage: Insecure SHA1 primitive reachable | triage: Unauth dispatch RCE in Quart
- Patch:
  - **Summary**: Enforce auth on quart trigger blueprint and eliminate unauthenticated exec of user_input

<a id="finding-25"></a>
### CRITICAL Unauthenticated trigger dispatch RCE in WSGI vulnerable_app
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `src/vulnpy/wsgi/app.py:22-24`
- Vulnerable code (`src/vulnpy/wsgi/app.py`):
```python
if trigger_func:
        user_input = _get_user_input(environ)
        trigger_func(user_input)
```
- Taint Flow:
  - **Source**: `WSGI QUERY_STRING user_input`
  - **Path**:
    - `QUERY_STRING user_input -> trigger_func`
  - **Sink**: `trigger_func(user_input)`
- Evidence: if trigger_func: user_input = _get_user_input(environ) trigger_func(user_input)
  - Validation: src/vulnpy/wsgi/app.py:22-24 user_input=_get_user_input(environ) from QUERY_STRING flows to trigger_func(user_input) with router _get_trigger_info at src/vulnpy/wsgi/app.py:66-90 resolving to os.system at src/vulnpy/trigger/cmdi.py:6
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/wsgi/app.py:22-24 user_input=_get_user_input(environ) from QUERY_STRING flows to trigger_func(user_input) with router _get_trigger_info at src/vulnpy/wsgi/app.py:66-90 resolving to os.system at src/vulnpy/trigger/cmdi.py:6 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Gate vulnerable_app trigger dispatch behind auth and do not pass query user_input to code-exec sinks

<a id="finding-26"></a>
### CRITICAL Command injection in Falcon FileUpload
- CVSS: **8.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.9
- Location: `apps/falcon_app.py:28-29`
- Vulnerable code (`apps/falcon_app.py`):
```python
cmd = "echo " + str(user_input[:10])
        os.system(cmd)
```
- Taint Flow:
  - **Source**: `uploaded file`
  - **Path**:
    - `upload file.read -> cmd -> os.system`
  - **Sink**: `os.system(cmd)`
- Evidence: cmd = "echo " + str(user_input[:10]) os.system(cmd)
  - Validation: apps/falcon_app.py:24 upload file.read() bytes sliced [:10] wrapped in str() at apps/falcon_app.py:28-29 cmd echo + str(...) to os.system; quoting via str(bytes) still allows $()/'' expansion inside double-quoted repr; unauth POST /file-upload at :82
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/falcon_app.py:24 upload file.read() bytes sliced [:10] wrapped in str() at apps/falcon_app.py:28-29 cmd echo + str(...) to os.system; quoting via str(bytes) still allows $()/'' expansion inside double-quoted repr; unauth POST /file-upload at :82 | consensus: 1/1 confirmed | triage: Command injection via Falcon upload
- Patch:
  - **Summary**: Remove os.system on upload data; handle uploads without shell.

<a id="finding-27"></a>
### CRITICAL Header-trusted code input in Quart _get_user_input
- CVSS: **8.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.9
- Location: `src/vulnpy/quart/blueprint.py:10-11`
- Vulnerable code (`src/vulnpy/quart/blueprint.py`):
```python
if request.headers.get("User_Input") is not None:
        return request.headers.get("User_Input")
```
- Taint Flow:
  - **Source**: `HTTP User_Input header`
  - **Path**:
    - `HTTP User_Input header -> _get_user_input -> trigger_func(user_input) -> RCE sinks`
  - **Sink**: `trust of header as code input + trigger dispatch`
- Evidence: if request.headers.get("User_Input") is not None: return request.headers.get("User_Input")
  - Validation: src/vulnpy/quart/blueprint.py:10-11 header User_Input source + src/vulnpy/quart/blueprint.py:42-48 trigger_func(user_input) reaching e.g. src/vulnpy/trigger/cmdi.py:5 os.system(command) unauthenticated
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/quart/blueprint.py:10-11 header User_Input source + src/vulnpy/quart/blueprint.py:42-48 trigger_func(user_input) reaching e.g. src/vulnpy/trigger/cmdi.py:5 os.system(command) unauthenticated | consensus: 1/1 confirmed | triage: Header input reaches RCE dispatch | triage: OS command injection in do_os_system | triage: Unauth dispatch RCE in Flask
- Patch:
  - **Summary**: Remove User_Input header source and parameterize/allowlist triggers; replace os.system shell with subprocess without shell=True.
  - +1 duplicate(s): `src/vulnpy/trigger/cmdi.py:5`

<a id="finding-28"></a>
### CRITICAL Command injection in Falcon thread_function
- CVSS: **8.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.85
- Location: `apps/falcon_app.py:63-64`
- Vulnerable code (`apps/falcon_app.py`):
```python
cmd = "echo " + str(user_input)
    os.system(cmd)
```
- Taint Flow:
  - **Source**: `falcon query user_input`
  - **Path**:
    - `user_input -> Thread -> os.system`
  - **Sink**: `os.system(cmd)`
- Evidence: cmd = "echo " + str(user_input) os.system(cmd)
  - Validation: apps/falcon_app.py:73 req.get_param user_input passed via Thread at :74 to thread_function at :35 which reaches apps/falcon_app.py:63-64 cmd echo + str(user_input) os.system; contrast-import early-return at :45-49 is not auth/sanitizer and is satisfied when contrast-agent installed (Dockerfile:5)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/falcon_app.py:73 req.get_param user_input passed via Thread at :74 to thread_function at :35 which reaches apps/falcon_app.py:63-64 cmd echo + str(user_input) os.system; contrast-import early-return at :45-49 is not auth/sanitizer and is satisfied when contrast-agent installed (Dockerfile:5) | consensus: 1/1 confirmed | triage: Command injection via thread_function
- Patch:
  - **Summary**: Remove os.system in thread_function; validate user_input and avoid shell.

<a id="finding-29"></a>
### HIGH Reflected XSS in aiohttp get_trigger_view
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/aiohttp/vulnerable_routes.py:28-29`
- Vulnerable code (`src/vulnpy/aiohttp/vulnerable_routes.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `aiohttp query user_input`
  - **Path**:
    - `rel_url query -> HTML`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/aiohttp/vulnerable_routes.py:29 raw user_input concatenated into web.Response text/html with no escaping, from src/vulnpy/aiohttp/vulnerable_routes.py:7-8
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/aiohttp/vulnerable_routes.py:29 raw user_input concatenated into web.Response text/html with no escaping, from src/vulnpy/aiohttp/vulnerable_routes.py:7-8 | consensus: 1/1 confirmed | triage: Reflected XSS in aiohttp
- Patch:
  - **Summary**: HTML-escape user_input with html.escape before concatenation

<a id="finding-30"></a>
### HIGH Reflected XSS in Bottle get_trigger_view
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/bottle/vulnerable_routes.py:38-39`
- Vulnerable code (`src/vulnpy/bottle/vulnerable_routes.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `bottle user_input`
  - **Path**:
    - `request.GET/POST -> HTML`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/bottle/vulnerable_routes.py:39 raw user_input concatenated into returned HTML with no escaping, from src/vulnpy/bottle/vulnerable_routes.py:7-10
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/bottle/vulnerable_routes.py:39 raw user_input concatenated into returned HTML with no escaping, from src/vulnpy/bottle/vulnerable_routes.py:7-10 | consensus: 1/1 confirmed | triage: Reflected XSS in Bottle
- Patch:
  - **Summary**: HTML-escape user_input before embedding in template string

<a id="finding-31"></a>
### HIGH Reflected XSS in Django get_trigger_view
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/django/vulnerable.py:35-36`
- Vulnerable code (`src/vulnpy/django/vulnerable.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `Django user_input`
  - **Path**:
    - `request.GET/POST -> HTML`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/django/vulnerable.py:36 raw user_input concatenated into HttpResponse HTML with no escaping, from src/vulnpy/django/vulnerable.py:13-16
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/django/vulnerable.py:36 raw user_input concatenated into HttpResponse HTML with no escaping, from src/vulnpy/django/vulnerable.py:13-16 | consensus: 1/1 confirmed | triage: Reflected XSS in Django
- Patch:
  - **Summary**: HTML-escape user_input via django.utils.html.escape before concatenation

<a id="finding-32"></a>
### HIGH Reflected XSS in Django ASGI get_trigger_view
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/django/vulnerable_asgi.py:54-55`
- Vulnerable code (`src/vulnpy/django/vulnerable_asgi.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `Django ASGI user_input`
  - **Path**:
    - `await _get_user_input -> HTML`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/django/vulnerable_asgi.py:55 raw user_input concatenated into HttpResponse HTML with no escaping, from await _get_user_input at src/vulnpy/django/vulnerable_asgi.py:43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/django/vulnerable_asgi.py:55 raw user_input concatenated into HttpResponse HTML with no escaping, from await _get_user_input at src/vulnpy/django/vulnerable_asgi.py:43 | consensus: 1/1 confirmed | triage: Reflected XSS in Django ASGI
- Patch:
  - **Summary**: HTML-escape user_input before embedding in response template

<a id="finding-33"></a>
### HIGH Reflected XSS in Falcon _set_xss_response
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/falcon/vulnerable.py:122-124`
- Vulnerable code (`src/vulnpy/falcon/vulnerable.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `falcon user_input param`
  - **Path**:
    - `req.get_param user_input -> _set_xss_response`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/falcon/vulnerable.py:123 raw user_input concatenated in _set_xss_response with text/html, from req.get_param at src/vulnpy/falcon/vulnerable.py:31
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/falcon/vulnerable.py:123 raw user_input concatenated in _set_xss_response with text/html, from req.get_param at src/vulnpy/falcon/vulnerable.py:31 | consensus: 1/1 confirmed | triage: Reflected XSS in Falcon helper
- Patch:
  - **Summary**: HTML-escape user_input before concatenation in _set_xss_response

<a id="finding-34"></a>
### HIGH Reflected XSS in Falcon ASGI _set_xss_response
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/falcon/vulnerable_asgi.py:122-124`
- Vulnerable code (`src/vulnpy/falcon/vulnerable_asgi.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `falcon ASGI user_input`
  - **Path**:
    - `req.get_param -> _set_xss_response`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/falcon/vulnerable_asgi.py:123 raw user_input concatenated in _set_xss_response with text/html, from req.get_param at src/vulnpy/falcon/vulnerable_asgi.py:31
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/falcon/vulnerable_asgi.py:123 raw user_input concatenated in _set_xss_response with text/html, from req.get_param at src/vulnpy/falcon/vulnerable_asgi.py:31 | consensus: 1/1 confirmed | triage: Reflected XSS in Falcon ASGI helper
- Patch:
  - **Summary**: HTML-escape user_input before concatenation in _set_xss_response

<a id="finding-35"></a>
### HIGH Reflected XSS in FastAPI get_trigger_view
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/fastapi/vulnerable.py:41-42`
- Vulnerable code (`src/vulnpy/fastapi/vulnerable.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `FastAPI query user_input`
  - **Path**:
    - `user_input query -> HTML concat`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/fastapi/vulnerable.py:42 raw user_input concatenated into HTMLResponse with no escaping, from query param at src/vulnpy/fastapi/vulnerable.py:32
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/fastapi/vulnerable.py:42 raw user_input concatenated into HTMLResponse with no escaping, from query param at src/vulnpy/fastapi/vulnerable.py:32 | consensus: 1/1 confirmed | triage: Reflected XSS in FastAPI
- Patch:
  - **Summary**: HTML-escape user_input before embedding in template response

<a id="finding-36"></a>
### HIGH Reflected XSS in Flask get_trigger_view
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 1.0
- Location: `src/vulnpy/flask/blueprint.py:54-55`
- Vulnerable code (`src/vulnpy/flask/blueprint.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `HTTP User-Input header / user_input`
  - **Path**:
    - `_get_user_input -> user_input -> HTML concat`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/flask/blueprint.py:55 raw user_input concatenated into HTML and returned with no escaping, from _get_user_input at src/vulnpy/flask/blueprint.py:9-15
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/flask/blueprint.py:55 raw user_input concatenated into HTML and returned with no escaping, from _get_user_input at src/vulnpy/flask/blueprint.py:9-15 | consensus: 1/1 confirmed | triage: Reflected XSS in Flask
- Patch:
  - **Summary**: HTML-escape user_input with html.escape before concatenation and set safe content handling

<a id="finding-37"></a>
### HIGH Path traversal in do_tarfile_bz2
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 1.0
- Location: `src/vulnpy/trigger/pt.py:22-25`
- Vulnerable code (`src/vulnpy/trigger/pt.py`):
```python
def do_tarfile_bz2(user_input):
        with tarfile.open(user_input, mode="r:bz2") as tf:
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> tarfile.open`
  - **Sink**: `tarfile.open(user_input)`
- Evidence: def do_tarfile_bz2(user_input): with tarfile.open(user_input, mode="r:bz2") as tf:
  - Validation: src/vulnpy/trigger/pt.py:24 tarfile.open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) from request input
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/pt.py:24 tarfile.open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) from request input | consensus: 1/1 confirmed | triage: Attacker path to tarfile.open
- Patch:
  - **Summary**: Reject path traversal: basename/allowlist filename to safe directory and deny absolute/.. paths before tarfile.open

<a id="finding-38"></a>
### HIGH Path traversal in do_bz2_class
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 1.0
- Location: `src/vulnpy/trigger/pt.py:30-33`
- Vulnerable code (`src/vulnpy/trigger/pt.py`):
```python
def do_bz2_class(user_input, size=0):
        with bz2.BZ2File(user_input) as bz2file:
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> BZ2File`
  - **Sink**: `BZ2File(user_input)`
- Evidence: def do_bz2_class(user_input, size=0): with bz2.BZ2File(user_input) as bz2file:
  - Validation: src/vulnpy/trigger/pt.py:32 bz2.BZ2File(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/pt.py:32 bz2.BZ2File(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Attacker path to BZ2File
- Patch:
  - **Summary**: Restrict filename to safe base directory, reject absolute paths and .. segments before BZ2File open

<a id="finding-39"></a>
### HIGH Path traversal in do_bz2_open
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 1.0
- Location: `src/vulnpy/trigger/pt.py:38-41`
- Vulnerable code (`src/vulnpy/trigger/pt.py`):
```python
def do_bz2_open(user_input, size=0):
        with bz2.open(user_input) as bz2file:
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> bz2.open`
  - **Sink**: `bz2.open(user_input)`
- Evidence: def do_bz2_open(user_input, size=0): with bz2.open(user_input) as bz2file:
  - Validation: src/vulnpy/trigger/pt.py:40 bz2.open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/pt.py:40 bz2.open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Attacker path to bz2.open
- Patch:
  - **Summary**: Canonicalize and confine path to allowed directory, deny .. and absolute paths before bz2.open

<a id="finding-40"></a>
### HIGH Path traversal in do_io_open
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 1.0
- Location: `src/vulnpy/trigger/pt.py:46-49`
- Vulnerable code (`src/vulnpy/trigger/pt.py`):
```python
def do_io_open(user_input):
        with io.open(user_input) as f:
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> io.open`
  - **Sink**: `io.open(user_input)`
- Evidence: def do_io_open(user_input): with io.open(user_input) as f:
  - Validation: src/vulnpy/trigger/pt.py:48 io.open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/pt.py:48 io.open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Attacker path to io.open
- Patch:
  - **Summary**: Allowlist/confine file path to safe directory and reject traversal before io.open

<a id="finding-41"></a>
### HIGH Path traversal in do_open
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 1.0
- Location: `src/vulnpy/trigger/pt.py:54-57`
- Vulnerable code (`src/vulnpy/trigger/pt.py`):
```python
def do_open(user_input):
        with open(user_input) as f:
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> open`
  - **Sink**: `open(user_input)`
- Evidence: def do_open(user_input): with open(user_input) as f:
  - Validation: src/vulnpy/trigger/pt.py:57 open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/pt.py:57 open(user_input) with no validation, reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Attacker path to open()
- Patch:
  - **Summary**: Validate filename against safe directory allowlist and block .. / absolute paths before open

<a id="finding-42"></a>
### HIGH SQL injection in do_sqlite3_execute
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 1.0
- Location: `src/vulnpy/trigger/sqli.py:34-37`
- Vulnerable code (`src/vulnpy/trigger/sqli.py`):
```python
def do_sqlite3_execute(user_input):
        sql = EXECUTE_QUERY_FMT.format(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> format -> cursor.execute`
  - **Sink**: `cursor.execute(sql)`
- Evidence: def do_sqlite3_execute(user_input): sql = EXECUTE_QUERY_FMT.format(user_input)
  - Validation: src/vulnpy/trigger/sqli.py:34-36 EXECUTE_QUERY_FMT.format(user_input)->cursor.execute(sql) with no parameterization; reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/sqli.py:34-36 EXECUTE_QUERY_FMT.format(user_input)->cursor.execute(sql) with no parameterization; reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use parameterized query cursor.execute with placeholders instead of format.
  - +1 duplicate(s): `src/vulnpy/trigger/sqli.py:36`

<a id="finding-43"></a>
### HIGH SQL injection in do_sqlite3_executemany
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 1.0
- Location: `src/vulnpy/trigger/sqli.py:45-48`
- Vulnerable code (`src/vulnpy/trigger/sqli.py`):
```python
def do_sqlite3_executemany(user_input):
        sql = EXECUTEMANY_QUERY_FMT.format(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> format -> executemany`
  - **Sink**: `cursor.executemany(sql,...)`
- Evidence: def do_sqlite3_executemany(user_input): sql = EXECUTEMANY_QUERY_FMT.format(user_input)
  - Validation: src/vulnpy/trigger/sqli.py:45-48 EXECUTEMANY_QUERY_FMT.format(user_input)->cursor.executemany(sql,...) injects into SQL text; reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/sqli.py:45-48 EXECUTEMANY_QUERY_FMT.format(user_input)->cursor.executemany(sql,...) injects into SQL text; reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use parameterized executemany without string formatting of SQL.

<a id="finding-44"></a>
### HIGH SQL script injection in do_sqlite3_executescript
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 1.0
- Location: `src/vulnpy/trigger/sqli.py:56-59`
- Vulnerable code (`src/vulnpy/trigger/sqli.py`):
```python
def do_sqlite3_executescript(user_input):
        return cursor.executescript(sql)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> format -> executescript`
  - **Sink**: `cursor.executescript(sql)`
- Evidence: def do_sqlite3_executescript(user_input): return cursor.executescript(sql)
  - Validation: src/vulnpy/trigger/sqli.py:56-59 EXECUTESCRIPT_QUERY_FMT.format(user_input)->cursor.executescript(sql) allows stacked SQL; reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/sqli.py:56-59 EXECUTESCRIPT_QUERY_FMT.format(user_input)->cursor.executescript(sql) allows stacked SQL; reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed | triage: SQLi via executescript | triage: Central SSRF sink
- Patch:
  - **Summary**: Remove executescript on formatted input; use parameterized single statements.

<a id="finding-45"></a>
### HIGH Hardcoded Django SECRET_KEY
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `apps/django_app.py:27-27`
- Vulnerable code (`apps/django_app.py`):
```python
"SECRET_KEY": "test_key",  # pragma: allowlist secret
```
- Taint Flow:
  - **Source**: `hardcoded credential`
  - **Sink**: `SECRET_KEY=test_key`
- Evidence: "SECRET_KEY": "test_key",  # pragma: allowlist secret
  - Validation: apps/django_app.py:27 hardcodes SECRET_KEY=test_key loaded into settings at apps/django_app.py:23-33
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/django_app.py:27 hardcodes SECRET_KEY=test_key loaded into settings at apps/django_app.py:23-33 | consensus: 1/1 confirmed | triage: Hardcoded SECRET_KEY
- Patch:
  - **Summary**: Load SECRET_KEY from environment/secret manager, never commit static value.

<a id="finding-46"></a>
### HIGH Loop-amplified blocking execution DoS in FastAPI cmdi route
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 0.95
- Location: `apps/fastapi_app.py:41-43`
- Vulnerable code (`apps/fastapi_app.py`):
```python
for i in range(10):
        print("will echo command")
        os.system(cmd)
```
- Taint Flow:
  - **Source**: `FastAPI query user_input`
  - **Path**:
    - `HTTP user_input -> cmd -> loop 10x os.system+sleep`
  - **Sink**: `amplified blocking execution`
- Evidence: for i in range(10): print("will echo command") os.system(cmd)
  - Validation: apps/fastapi_app.py:39-43 cmd='echo '+user_input then 10x os.system(cmd)+sleep(3) unauthenticated; injection + 30s blocking amplification
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/fastapi_app.py:39-43 cmd='echo '+user_input then 10x os.system(cmd)+sleep(3) unauthenticated; injection + 30s blocking amplification | consensus: 1/1 confirmed | triage: Attacker-controlled PRNG seed predicts output | triage: Same sink as cmdi injection, amplification view | triage: SQLi via execute
- Patch:
  - **Summary**: Remove os.system(shell) on user input (use allowlisted args without shell) and remove 10x loop + sleep(3).
  - +1 duplicate(s): `src/vulnpy/trigger/sqli.py:36`

<a id="finding-47"></a>
### HIGH Unescaped output in jinja xss.html
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `apps/templates/jinja/xss.html:28-28`
- Vulnerable code (`apps/templates/jinja/xss.html`):
```html
{{ user_input | safe }}
```
- Taint Flow:
  - **Source**: `Flask user_input`
  - **Path**:
    - `user_input -> safe filter`
  - **Sink**: `{{ user_input | safe }}`
- Evidence: {{ user_input | safe }} | safe }} disables escaping; rendered with attacker data at apps/flask_app.py:19-20 request.args user_input -> template.render; Environment at apps/flask_app.py:11 has autoescape off
  - Validation: apps/templates/jinja/xss.html:28 {{ user_input
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/templates/jinja/xss.html:28 {{ user_input | consensus: 1/1 confirmed | triage: Unescaped |safe output
- Patch:
  - **Summary**: Remove |safe filter and enable Jinja autoescape so user_input is escaped.
  - +2 duplicate(s): `apps/templates/jinja/xss.html:30`, `apps/templates/jinja/xss.html:0`

<a id="finding-48"></a>
### HIGH Reflected XSS in Pyramid get_trigger_view
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `src/vulnpy/pyramid/vulnerable_routes.py:50-51`
- Vulnerable code (`src/vulnpy/pyramid/vulnerable_routes.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `pyramid user_input`
  - **Path**:
    - `request.GET/POST -> HTML`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/pyramid/vulnerable_routes.py:7-10 _get_user_input from GET/POST concatenated unescaped at src/vulnpy/pyramid/vulnerable_routes.py:50-51 template += XSS user_input and returned via Response at :53; mounted at :66-73 + :93-98
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/pyramid/vulnerable_routes.py:7-10 _get_user_input from GET/POST concatenated unescaped at src/vulnpy/pyramid/vulnerable_routes.py:50-51 template += XSS user_input and returned via Response at :53; mounted at :66-73 + :93-98 | consensus: 1/1 confirmed | triage: Reflected XSS in Pyramid
- Patch:
  - **Summary**: HTML-escape user_input (html.escape) before concatenation and set explicit content-type; do not reflect raw input.

<a id="finding-49"></a>
### HIGH Reflected XSS in Quart get_trigger_view
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `src/vulnpy/quart/blueprint.py:52-53`
- Vulnerable code (`src/vulnpy/quart/blueprint.py`):
```python
template += "<p>XSS: " + user_input + "</p>"
```
- Taint Flow:
  - **Source**: `quart user_input`
  - **Path**:
    - `User_Input header/args -> HTML`
  - **Sink**: `template + user_input`
- Evidence: template += "<p>XSS: " + user_input + "</p>"
  - Validation: src/vulnpy/quart/blueprint.py:9-13 _get_user_input from header User_Input/args concatenated unescaped at src/vulnpy/quart/blueprint.py:52-53 and returned; routes mounted at :57-61 + registered in apps/quart_app.py:6
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/quart/blueprint.py:9-13 _get_user_input from header User_Input/args concatenated unescaped at src/vulnpy/quart/blueprint.py:52-53 and returned; routes mounted at :57-61 + registered in apps/quart_app.py:6 | consensus: 1/1 confirmed | triage: Reflected XSS in Quart
- Patch:
  - **Summary**: HTML-escape user_input before concatenation in xss/raw view.

<a id="finding-50"></a>
### HIGH SSRF in do_urlopen_str
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/vulnpy/trigger/ssrf.py:64-69`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
def do_urlopen_str(user_input):
    return _urlopen(urlopen, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> _urlopen`
  - **Sink**: `urlopen(user_input)`
- Evidence: def do_urlopen_str(user_input): return _urlopen(urlopen, user_input)
  - Validation: src/vulnpy/trigger/ssrf.py:64-69 do_urlopen_str passes full user_input to urlopen; reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:64-69 do_urlopen_str passes full user_input to urlopen; reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed | triage: SSRF via urlopen str | triage: SSRF host-control sink
- Patch:
  - **Summary**: Enforce URL allow-list for scheme/host before fetching.
  - +1 duplicate(s): `src/vulnpy/trigger/ssrf.py:64`

<a id="finding-51"></a>
### HIGH SSRF via Request in do_urlopen_obj
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/vulnpy/trigger/ssrf.py:72-79`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
def do_urlopen_obj(user_input):
        req = Request(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> Request -> urlopen`
  - **Sink**: `Request(user_input)`
- Evidence: def do_urlopen_obj(user_input): req = Request(user_input)
  - Validation: src/vulnpy/trigger/ssrf.py:72-79 Request(user_input)->urlopen(req) full URL attacker-controlled; reachable via src/vulnpy/flask/blueprint.py:38-43
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:72-79 Request(user_input)->urlopen(req) full URL attacker-controlled; reachable via src/vulnpy/flask/blueprint.py:38-43 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Validate Request URL host/scheme against allow-list.

<a id="finding-52"></a>
### HIGH SSRF host-control sink in _request_init helper
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/vulnpy/trigger/ssrf.py:136-136`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
c = connection_class(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input hostname`
  - **Path**:
    - `HTTP user_input -> connection_class(user_input)`
  - **Sink**: `HTTPConnection/HTTPSConnection(user_input)`
- Evidence: c = connection_class(user_input)
  - Validation: src/vulnpy/trigger/ssrf.py:136 c=connection_class(user_input) passes attacker host to HTTPConnection/HTTPSConnection, reachable via do_httpconnection_init/do_httpsconnection_init
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:136 c=connection_class(user_input) passes attacker host to HTTPConnection/HTTPSConnection, reachable via do_httpconnection_init/do_httpsconnection_init | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allow-list/validate host against TRUSTED_HOST; block private/link-local/metadata IPs before connecting.
  - +1 duplicate(s): `src/vulnpy/trigger/ssrf.py:64`

<a id="finding-53"></a>
### HIGH SSRF host control in do_httpconnection_init
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/vulnpy/trigger/ssrf.py:143-144`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
def do_httpconnection_init(user_input):
    return _request_init(user_input, HTTPConnection)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> HTTPConnection(user_input)`
  - **Sink**: `HTTPConnection(user_input)`
- Evidence: def do_httpconnection_init(user_input): return _request_init(user_input, HTTPConnection)
  - Validation: src/vulnpy/trigger/ssrf.py:133-140 _request_init does connection_class(user_input) with attacker host then c.request(TRUSTED_METHOD,TRUSTED_URL); reachable via src/vulnpy/flask/blueprint.py:47-55 _get_user_input->get_trigger dispatch and src/vulnpy/trigger/util.py:34-62 dynamic trigger map
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:133-140 _request_init does connection_class(user_input) with attacker host then c.request(TRUSTED_METHOD,TRUSTED_URL); reachable via src/vulnpy/flask/blueprint.py:47-55 _get_user_input->get_trigger dispatch and src/vulnpy/trigger/util.py:34-62 dynamic trigger map | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist/validate host against TRUSTED_HOST and block private-link-local/metadata IPs before HTTPConnection(user_input).

<a id="finding-54"></a>
### HIGH SSRF host control in do_httpsconnection_init
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/vulnpy/trigger/ssrf.py:147-148`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
def do_httpsconnection_init(user_input):
    return _request_init(user_input, HTTPSConnection)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> HTTPSConnection(user_input)`
  - **Sink**: `HTTPSConnection(user_input)`
- Evidence: def do_httpsconnection_init(user_input): return _request_init(user_input, HTTPSConnection)
  - Validation: src/vulnpy/trigger/ssrf.py:133-148 _request_init does HTTPSConnection(user_input) with full host control; reachable via src/vulnpy/flask/blueprint.py:47-55 user_input->get_trigger dispatch
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:133-148 _request_init does HTTPSConnection(user_input) with full host control; reachable via src/vulnpy/flask/blueprint.py:47-55 user_input->get_trigger dispatch | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist/validate host against TRUSTED_HOST and deny internal IPs before HTTPSConnection(user_input).

<a id="finding-55"></a>
### HIGH XPath injection in do_lxml_etree_findall
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-91 | confidence: 0.95
- Location: `src/vulnpy/trigger/xpath.py:24-25`
- Vulnerable code (`src/vulnpy/trigger/xpath.py`):
```python
def do_lxml_etree_findall(user_input):
    return root.findall(user_input)[0][0].text
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> findall`
  - **Sink**: `root.findall(user_input)`
- Evidence: def do_lxml_etree_findall(user_input): return root.findall(user_input)[0][0].text
  - Validation: src/vulnpy/trigger/xpath.py:24-25 root.findall(user_input) unsanitized XPath; reachable via src/vulnpy/flask/blueprint.py:47-55 dispatch
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/xpath.py:24-25 root.findall(user_input) unsanitized XPath; reachable via src/vulnpy/flask/blueprint.py:47-55 dispatch | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not interpolate user input into XPath; use parameterized XPath or allowlist element names.

<a id="finding-56"></a>
### HIGH XPath injection in do_lxml_etree_findtext
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-91 | confidence: 0.95
- Location: `src/vulnpy/trigger/xpath.py:28-29`
- Vulnerable code (`src/vulnpy/trigger/xpath.py`):
```python
def do_lxml_etree_findtext(user_input):
    return root.findtext(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> findtext`
  - **Sink**: `root.findtext(user_input)`
- Evidence: def do_lxml_etree_findtext(user_input): return root.findtext(user_input)
  - Validation: src/vulnpy/trigger/xpath.py:28-29 root.findtext(user_input) unsanitized XPath sink; reachable via src/vulnpy/flask/blueprint.py:47-55
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/xpath.py:28-29 root.findtext(user_input) unsanitized XPath sink; reachable via src/vulnpy/flask/blueprint.py:47-55 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist XPath expressions instead of passing user_input to findtext.

<a id="finding-57"></a>
### HIGH XPath injection in do_xml_etree_findall
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-91 | confidence: 0.95
- Location: `src/vulnpy/trigger/xpath.py:32-34`
- Vulnerable code (`src/vulnpy/trigger/xpath.py`):
```python
def do_xml_etree_elementtree_findall(user_input):
    node = ET.fromstring(xml)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> ET findall`
  - **Sink**: `node.findall(user_input)`
- Evidence: def do_xml_etree_elementtree_findall(user_input): node = ET.fromstring(xml)
  - Validation: src/vulnpy/trigger/xpath.py:32-34 ET.fromstring(xml) on trusted constant then node.findall(user_input) attacker XPath sink; reachable via src/vulnpy/flask/blueprint.py:47-55
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/xpath.py:32-34 ET.fromstring(xml) on trusted constant then node.findall(user_input) attacker XPath sink; reachable via src/vulnpy/flask/blueprint.py:47-55 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist XPath expressions instead of passing user_input to ET findall.

<a id="finding-58"></a>
### HIGH Reflected XSS in WSGI vulnerable_app
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `src/vulnpy/wsgi/app.py:25-26`
- Vulnerable code (`src/vulnpy/wsgi/app.py`):
```python
response.append("<p>XSS: {}</p>".format(user_input))
```
- Taint Flow:
  - **Source**: `WSGI QUERY_STRING`
  - **Path**:
    - `QUERY_STRING user_input -> format -> response`
  - **Sink**: `format(user_input) XSS`
- Evidence: response.append("<p>XSS: {}</p>".format(user_input))
  - Validation: src/vulnpy/wsgi/app.py:52-57 _get_user_input from QUERY_STRING flows to src/vulnpy/wsgi/app.py:25-26 format XSS sink when trigger is xss.do_raw with Content-Type text/html at :29; routed at :60-89
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/wsgi/app.py:52-57 _get_user_input from QUERY_STRING flows to src/vulnpy/wsgi/app.py:25-26 format XSS sink when trigger is xss.do_raw with Content-Type text/html at :29; routed at :60-89 | consensus: 1/1 confirmed | triage: Reflected XSS in WSGI
- Patch:
  - **Summary**: HTML-escape user_input before interpolation in WSGI XSS branch.

<a id="finding-59"></a>
### HIGH Jinja XSS sink in flask_app jinja_xss
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `apps/flask_app.py:19-21`
- Vulnerable code (`apps/flask_app.py`):
```python
return template.render(
        path="/template-xss/jinja", user_input=request.args.get("user_input", "")
```
- Taint Flow:
  - **Source**: `Flask query user_input`
  - **Path**:
    - `request.args user_input -> template.render`
  - **Sink**: `template.render(user_input)`
- Evidence: return template.render( path="/template-xss/jinja", user_input=request.args.get("user_input", "") | safe }} yielding unescaped output; route /template-xss/jinja at :16
  - Validation: apps/flask_app.py:19-20 request.args user_input passed to template.render at apps/flask_app.py:18-21; jinja Environment at :11 has no autoescape and apps/templates/jinja/xss.html:28 uses {{ user_input
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/flask_app.py:19-20 request.args user_input passed to template.render at apps/flask_app.py:18-21; jinja Environment at :11 has no autoescape and apps/templates/jinja/xss.html:28 uses {{ user_input | consensus: 1/1 confirmed | triage: Jinja XSS sink in flask_app
- Patch:
  - **Summary**: Enable Jinja autoescape (select_jinja_autoescape) and remove |safe; escape user_input.

<a id="finding-60"></a>
### HIGH Unbounded file read in Quart upload handler
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-400 | confidence: 0.9
- Location: `apps/quart_app.py:19-21`
- Vulnerable code (`apps/quart_app.py`):
```python
user_input = stream.read()
```
- Taint Flow:
  - **Source**: `uploaded file`
  - **Path**:
    - `multipart file -> stream.read()`
  - **Sink**: `stream.read() without limit`
- Evidence: files = await request.files stream = files.get("file")
  - Validation: apps/quart_app.py:22 stream.read() with no size limit on POST /files/upload, then do_os_system
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/quart_app.py:22 stream.read() with no size limit on POST /files/upload, then do_os_system | consensus: 1/1 confirmed | triage: Unbounded read enables DoS + injection | triage: SSRF host control via HTTP init
- Patch:
  - **Summary**: Enforce max upload size with bounded/chunked read and reject oversize uploads.

<a id="finding-61"></a>
### HIGH Missing authentication/authorization on /vulnpy trigger routes
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-306 | confidence: 0.9
- Location: `src/vulnpy/flask/blueprint.py:61-63`
- Vulnerable code (`src/vulnpy/flask/blueprint.py`):
```python
vulnerable_blueprint.add_url_rule(view_name, view_name, _view, methods=["GET", "POST"]) without auth
```
- Taint Flow:
  - **Source**: `unauthenticated HTTP GET/POST to /vulnpy/*/*/`
  - **Path**:
    - `src/vulnpy/flask/blueprint.py:61 route registration without guard`
    - `src/vulnpy/flask/blueprint.py:46 _get_user_input`
  - **Sink**: `trigger_func(user_input) reaching RCE/SQLi/XXE/SSRF sinks`
- Evidence: src/vulnpy/flask/blueprint.py:61 add_url_rule for every /vulnpy/<name>/<trigger>/ with methods GET,POST and no authentication, authorization, CSRF, or rate-limiting; same pattern in FastAPI/Django/Bottle/Quart/Pyramid/aiohttp/Falcon/WSGI generators
  - Validation: src/vulnpy/flask/blueprint.py:61 add_url_rule for every /vulnpy/<name>/<trigger>/ methods GET,POST with no auth decorator/guard; handler at :44-50 directly calls trigger_func(user_input) reaching RCE/SQLi sinks
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/flask/blueprint.py:61 add_url_rule for every /vulnpy/<name>/<trigger>/ methods GET,POST with no auth decorator/guard; handler at :44-50 directly calls trigger_func(user_input) reaching RCE/SQLi sinks | consensus: 1/1 confirmed | triage: Missing auth on all trigger routes enables unauth RCE
- Patch:
  - **Summary**: Add authentication/authorization gate before get_trigger_view dispatch or remove vulnerable routes from production; require login, role check, CSRF and rate-limit.

<a id="finding-62"></a>
### HIGH Path traversal in do_tarfile_open
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.9
- Location: `src/vulnpy/trigger/pt.py:6-9`
- Vulnerable code (`src/vulnpy/trigger/pt.py`):
```python
def do_tarfile_open(user_input):
        with tarfile.TarFile.open(user_input, mode="r:") as tf:
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> TarFile.open`
  - **Sink**: `TarFile.open(user_input)`
- Evidence: def do_tarfile_open(user_input): with tarfile.TarFile.open(user_input, mode="r:") as tf:
  - Validation: src/vulnpy/trigger/pt.py:6-9 TarFile.open(user_input,mode='r:') opens attacker-chosen filesystem path with no validation; reachable via src/vulnpy/flask/blueprint.py:47-55
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/pt.py:6-9 TarFile.open(user_input,mode='r:') opens attacker-chosen filesystem path with no validation; reachable via src/vulnpy/flask/blueprint.py:47-55 | consensus: 1/1 confirmed | triage: Attacker-controlled path to TarFile.open
- Patch:
  - **Summary**: Allowlist/basedir-canonicalize filename and verify tar members before open.

<a id="finding-63"></a>
### HIGH Path traversal in do_tarfile_class
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.9
- Location: `src/vulnpy/trigger/pt.py:14-16`
- Vulnerable code (`src/vulnpy/trigger/pt.py`):
```python
def do_tarfile_class(user_input):
        with tarfile.TarFile(user_input) as tf:
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> TarFile()`
  - **Sink**: `TarFile(user_input)`
- Evidence: def do_tarfile_class(user_input): with tarfile.TarFile(user_input) as tf:
  - Validation: src/vulnpy/trigger/pt.py:14-16 TarFile(user_input) attacker-controlled path with no validation; reachable via src/vulnpy/flask/blueprint.py:47-55
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/pt.py:14-16 TarFile(user_input) attacker-controlled path with no validation; reachable via src/vulnpy/flask/blueprint.py:47-55 | consensus: 1/1 confirmed | triage: Attacker path to TarFile constructor
- Patch:
  - **Summary**: Canonicalize and allowlist filename within safe directory before TarFile().

<a id="finding-64"></a>
### HIGH Central SSRF sink in _urlopen helper
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.9
- Location: `src/vulnpy/trigger/ssrf.py:51-51`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
return urlopen_func(arg).getcode()
```
- Taint Flow:
  - **Source**: `HTTP user_input URL`
  - **Path**:
    - `HTTP user_input -> _urlopen(arg) -> urlopen(arg)`
  - **Sink**: `urlopen_func(arg).getcode()`
- Evidence: return urlopen_func(arg).getcode()
  - Validation: src/vulnpy/trigger/ssrf.py:51 urlopen_func(arg).getcode() called with attacker user_input via do_urlopen_str at src/vulnpy/trigger/ssrf.py:65-69 with no allowlist; mock_connection only mocks socket for tests unless VULNPY_REAL_SSRF_REQUESTS is set
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:51 urlopen_func(arg).getcode() called with attacker user_input via do_urlopen_str at src/vulnpy/trigger/ssrf.py:65-69 with no allowlist; mock_connection only mocks socket for tests unless VULNPY_REAL_SSRF_REQUESTS is set | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Validate SSRF URL against allowlist, block private/metadata hosts, and disable follow of attacker URLs

<a id="finding-65"></a>
### HIGH XXE in do_lxml_etree_fromstring
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-611 | confidence: 0.9
- Location: `src/vulnpy/trigger/xxe.py:7-8`
- Vulnerable code (`src/vulnpy/trigger/xxe.py`):
```python
def do_lxml_etree_fromstring(user_input):
    return etree.fromstring(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> etree.fromstring`
  - **Sink**: `etree.fromstring(user_input)`
- Evidence: def do_lxml_etree_fromstring(user_input): return etree.fromstring(user_input)
  - Validation: src/vulnpy/trigger/xxe.py:7-8 etree.fromstring(user_input) with default parser (no resolve_entities=False/no_network) ; reachable via src/vulnpy/flask/blueprint.py:47-55
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/xxe.py:7-8 etree.fromstring(user_input) with default parser (no resolve_entities=False/no_network) ; reachable via src/vulnpy/flask/blueprint.py:47-55 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False) and defusedxml for untrusted XML.

<a id="finding-66"></a>
### HIGH XXE in do_xml_dom_pulldom_parsestring
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-611 | confidence: 0.9
- Location: `src/vulnpy/trigger/xxe.py:11-12`
- Vulnerable code (`src/vulnpy/trigger/xxe.py`):
```python
def do_xml_dom_pulldom_parsestring(user_input):
    return pulldom.parseString(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pulldom.parseString`
  - **Sink**: `pulldom.parseString(user_input)`
- Evidence: def do_xml_dom_pulldom_parsestring(user_input): return pulldom.parseString(user_input)
  - Validation: src/vulnpy/trigger/xxe.py:11-12 pulldom.parseString(user_input) with no entity-disabling/defusedxml; reachable via xxe trigger routes
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/xxe.py:11-12 pulldom.parseString(user_input) with no entity-disabling/defusedxml; reachable via xxe trigger routes | consensus: 1/1 confirmed | triage: XXE via pulldom
- Patch:
  - **Summary**: Use defusedxml or disable external entities/DTD and prohibit untrusted XML.

<a id="finding-67"></a>
### HIGH XXE in do_xml_sax_parsestring
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-611 | confidence: 0.9
- Location: `src/vulnpy/trigger/xxe.py:15-16`
- Vulnerable code (`src/vulnpy/trigger/xxe.py`):
```python
def do_xml_sax_parsestring(user_input):
    return sax.parseString(user_input, ContentHandler())
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> sax.parseString`
  - **Sink**: `sax.parseString(user_input,...)`
- Evidence: def do_xml_sax_parsestring(user_input): return sax.parseString(user_input, ContentHandler())
  - Validation: src/vulnpy/trigger/xxe.py:16 sax.parseString(user_input,ContentHandler()) passes raw input with no entity hardening; reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) from _get_user_input request data
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/xxe.py:16 sax.parseString(user_input,ContentHandler()) passes raw input with no entity hardening; reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) from _get_user_input request data | consensus: 1/1 confirmed | triage: XXE via sax
- Patch:
  - **Summary**: Use defusedxml.sax hardened parser or disable external entities/DTD; reject DOCTYPE.

<a id="finding-68"></a>
### MEDIUM ReDoS in do_re_sub
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `src/vulnpy/trigger/redos.py:65-66`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_sub(user_input):
    return re.sub(PATTERN, "anything", user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.sub`
  - **Sink**: `re.sub`
- Evidence: def do_re_sub(user_input): return re.sub(PATTERN, "anything", user_input)
  - Validation: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ with attacker input at src/vulnpy/trigger/redos.py:66 re.sub; reachable via TRIGGER_MAP src/vulnpy/trigger/util.py:27 and Flask view src/vulnpy/flask/blueprint.py:46-50
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ with attacker input at src/vulnpy/trigger/redos.py:66 re.sub; reachable via TRIGGER_MAP src/vulnpy/trigger/util.py:27 and Flask view src/vulnpy/flask/blueprint.py:46-50 | consensus: 1/1 confirmed | triage: ReDoS via sub
- Patch:
  - **Summary**: Replace nested-quantifier PATTERN with linear regex or enforce input length limit/timeout before re.sub.

<a id="finding-69"></a>
### MEDIUM ReDoS in do_re_sub_compiled
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `src/vulnpy/trigger/redos.py:69-70`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_sub_compiled(user_input):
    return pattern.sub("anything", user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.sub`
  - **Sink**: `pattern.sub`
- Evidence: def do_re_sub_compiled(user_input): return pattern.sub("anything", user_input)
  - Validation: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ compiled at src/vulnpy/trigger/redos.py:70 with attacker input at src/vulnpy/trigger/redos.py:71 pattern.sub; reachable via src/vulnpy/flask/blueprint.py:46-50
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ compiled at src/vulnpy/trigger/redos.py:70 with attacker input at src/vulnpy/trigger/redos.py:71 pattern.sub; reachable via src/vulnpy/flask/blueprint.py:46-50 | consensus: 1/1 confirmed | triage: ReDoS via compiled sub
- Patch:
  - **Summary**: Replace nested-quantifier PATTERN with linear regex or enforce input length limit/timeout before pattern.sub.

<a id="finding-70"></a>
### MEDIUM ReDoS in do_re_subn
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `src/vulnpy/trigger/redos.py:74-75`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_subn(user_input):
    return re.subn(PATTERN, "anything", user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.subn`
  - **Sink**: `re.subn`
- Evidence: def do_re_subn(user_input): return re.subn(PATTERN, "anything", user_input)
  - Validation: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ with attacker input at src/vulnpy/trigger/redos.py:75 re.subn; reachable via TRIGGER_MAP src/vulnpy/trigger/util.py:27 and Flask view src/vulnpy/flask/blueprint.py:46-50
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ with attacker input at src/vulnpy/trigger/redos.py:75 re.subn; reachable via TRIGGER_MAP src/vulnpy/trigger/util.py:27 and Flask view src/vulnpy/flask/blueprint.py:46-50 | consensus: 1/1 confirmed | triage: ReDoS via subn
- Patch:
  - **Summary**: Replace nested-quantifier PATTERN with linear regex or enforce input length limit/timeout before re.subn.

<a id="finding-71"></a>
### MEDIUM ReDoS in do_re_subn_compiled
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `src/vulnpy/trigger/redos.py:78-79`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_subn_compiled(user_input):
    return pattern.subn("anything", user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.subn`
  - **Sink**: `pattern.subn`
- Evidence: def do_re_subn_compiled(user_input): return pattern.subn("anything", user_input)
  - Validation: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ compiled at src/vulnpy/trigger/redos.py:79 with attacker input at src/vulnpy/trigger/redos.py:80 pattern.subn; reachable via src/vulnpy/flask/blueprint.py:46-50
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ compiled at src/vulnpy/trigger/redos.py:79 with attacker input at src/vulnpy/trigger/redos.py:80 pattern.subn; reachable via src/vulnpy/flask/blueprint.py:46-50 | consensus: 1/1 confirmed | triage: ReDoS via compiled subn
- Patch:
  - **Summary**: Replace nested-quantifier PATTERN with linear regex or enforce input length limit/timeout before pattern.subn.

<a id="finding-72"></a>
### MEDIUM ReDoS in do_re_split
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `src/vulnpy/trigger/redos.py:83-84`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_split(user_input):
    return re.split(PATTERN, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.split`
  - **Sink**: `re.split`
- Evidence: def do_re_split(user_input): return re.split(PATTERN, user_input)
  - Validation: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ with attacker input at src/vulnpy/trigger/redos.py:84 re.split; reachable via TRIGGER_MAP src/vulnpy/trigger/util.py:27 and Flask view src/vulnpy/flask/blueprint.py:46-50
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ with attacker input at src/vulnpy/trigger/redos.py:84 re.split; reachable via TRIGGER_MAP src/vulnpy/trigger/util.py:27 and Flask view src/vulnpy/flask/blueprint.py:46-50 | consensus: 1/1 confirmed | triage: ReDoS via split
- Patch:
  - **Summary**: Replace nested-quantifier PATTERN with linear regex or enforce input length limit/timeout before re.split.

<a id="finding-73"></a>
### MEDIUM ReDoS in do_re_split_compiled
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `src/vulnpy/trigger/redos.py:87-88`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_split_compiled(user_input):
    return pattern.split(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.split`
  - **Sink**: `pattern.split`
- Evidence: def do_re_split_compiled(user_input): return pattern.split(user_input)
  - Validation: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ compiled at src/vulnpy/trigger/redos.py:88 with attacker input at src/vulnpy/trigger/redos.py:89 pattern.split; reachable via src/vulnpy/flask/blueprint.py:46-50
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 evil pattern ((a)+)+ compiled at src/vulnpy/trigger/redos.py:88 with attacker input at src/vulnpy/trigger/redos.py:89 pattern.split; reachable via src/vulnpy/flask/blueprint.py:46-50 | consensus: 1/1 confirmed | triage: ReDoS via compiled split
- Patch:
  - **Summary**: Replace nested-quantifier PATTERN with linear regex or enforce input length limit/timeout before pattern.split.

<a id="finding-74"></a>
### MEDIUM SSRF in do_legacy_urlopen
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-918 | confidence: 0.95
- Location: `src/vulnpy/trigger/ssrf.py:56-61`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
def do_legacy_urlopen(user_input):
    return _urlopen(legacy_urlopen, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> _urlopen -> urlopen`
  - **Sink**: `urlopen(user_input)`
- Evidence: def do_legacy_urlopen(user_input): return _urlopen(legacy_urlopen, user_input)
  - Validation: src/vulnpy/trigger/ssrf.py:56-61 do_legacy_urlopen passes full user_input to urlopen via _urlopen; reachable via src/vulnpy/flask/blueprint.py:38-43 with no allow-list
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:56-61 do_legacy_urlopen passes full user_input to urlopen via _urlopen; reachable via src/vulnpy/flask/blueprint.py:38-43 with no allow-list | consensus: 1/1 confirmed | triage: SSRF via legacy urlopen | triage: SSRF/method sink in _request helper
- Patch:
  - **Summary**: Validate URL against allow-listed hosts/schemes before urlopen.

<a id="finding-75"></a>
### MEDIUM Insecure MD5 hash in do_hashlib_md5
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.9
- Location: `src/vulnpy/trigger/hash.py:18-20`
- Vulnerable code (`src/vulnpy/trigger/hash.py`):
```python
def do_hashlib_md5(user_input):
    h = hashlib.md5()
```
- Taint Flow:
  - **Source**: `intrinsic weak primitive`
  - **Sink**: `hashlib.md5()`
- Evidence: def do_hashlib_md5(user_input): h = hashlib.md5()
  - Validation: src/vulnpy/trigger/hash.py:18-20 do_hashlib_md5 uses hashlib.md5() with no secure alternative; reachable via TRIGGER_MAP cmdi/hash routes
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/hash.py:18-20 do_hashlib_md5 uses hashlib.md5() with no secure alternative; reachable via TRIGGER_MAP cmdi/hash routes | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace MD5 with SHA-256 or stronger and document no security use of broken hashes.

<a id="finding-76"></a>
### MEDIUM Insecure SHA1 hash in do_hashlib_sha1
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.9
- Location: `src/vulnpy/trigger/hash.py:23-25`
- Vulnerable code (`src/vulnpy/trigger/hash.py`):
```python
def do_hashlib_sha1(user_input):
    h = hashlib.sha1()
```
- Taint Flow:
  - **Source**: `intrinsic weak primitive`
  - **Sink**: `hashlib.sha1()`
- Evidence: def do_hashlib_sha1(user_input): h = hashlib.sha1()
  - Validation: src/vulnpy/trigger/hash.py:23-25 do_hashlib_sha1 uses hashlib.sha1() with no secure alternative
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/hash.py:23-25 do_hashlib_sha1 uses hashlib.sha1() with no secure alternative | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace SHA1 with SHA-256 or stronger.

<a id="finding-77"></a>
### MEDIUM Insecure SHA1 via hashlib.new in do_hashlib_new
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-327 | confidence: 0.9
- Location: `src/vulnpy/trigger/hash.py:28-30`
- Vulnerable code (`src/vulnpy/trigger/hash.py`):
```python
def do_hashlib_new(user_input):
    h = hashlib.new("SHA1")
```
- Taint Flow:
  - **Source**: `intrinsic weak primitive`
  - **Sink**: `hashlib.new("SHA1")`
- Evidence: def do_hashlib_new(user_input): h = hashlib.new("SHA1")
  - Validation: src/vulnpy/trigger/hash.py:28-30 do_hashlib_new uses hashlib.new(SHA1) weak primitive
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/hash.py:28-30 do_hashlib_new uses hashlib.new(SHA1) weak primitive | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace hashlib.new(SHA1) with SHA-256 or stronger.

<a id="finding-78"></a>
### MEDIUM Attacker-controlled PRNG seed in _seed
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.9
- Location: `src/vulnpy/trigger/rand.py:15-15`
- Vulnerable code (`src/vulnpy/trigger/rand.py`):
```python
random.seed(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input seed`
  - **Path**:
    - `HTTP user_input -> _seed -> random.seed`
  - **Sink**: `random.seed(user_input)`
- Evidence: random.seed(user_input)
  - Validation: src/vulnpy/trigger/rand.py:15 random.seed(user_input) with attacker-controlled seed then do_random at src/vulnpy/trigger/rand.py:18-20 returns predictable random.random() output
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/rand.py:15 random.seed(user_input) with attacker-controlled seed then do_random at src/vulnpy/trigger/rand.py:18-20 returns predictable random.random() output | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not seed PRNG with attacker input and use secrets module for security-sensitive randomness
  - +1 duplicate(s): `src/vulnpy/trigger/sqli.py:36`

<a id="finding-79"></a>
### MEDIUM Evil nested-quantifier regex definition PATTERN
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-1333 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:3-3`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
PATTERN = r"((a)+)+"
```
- Taint Flow:
  - **Source**: `intrinsic vulnerable primitive`
  - **Sink**: `evil regex definition ((a)+)+`
- Evidence: PATTERN = r"((a)+)+"
  - Validation: src/vulnpy/trigger/redos.py:3 PATTERN=r'((a)+)+' matched against attacker user_input in re.match at src/vulnpy/trigger/redos.py:6-9 and 13+ variants, reachable via redos trigger routes
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 PATTERN=r'((a)+)+' matched against attacker user_input in re.match at src/vulnpy/trigger/redos.py:6-9 and 13+ variants, reachable via redos trigger routes | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace nested-quantifier pattern with linear-time regex and add input length/timeout limits

<a id="finding-80"></a>
### MEDIUM ReDoS in do_re_match
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:6-7`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_match(user_input):
    match = re.match(PATTERN, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.match(PATTERN)`
  - **Sink**: `re.match(((a)+)+)`
- Evidence: def do_re_match(user_input): match = re.match(PATTERN, user_input)
  - Validation: src/vulnpy/trigger/redos.py:3 PATTERN=((a)+)+ nested quantifier with src/vulnpy/trigger/redos.py:7 re.match(PATTERN,user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no length limit/timeout
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:3 PATTERN=((a)+)+ nested quantifier with src/vulnpy/trigger/redos.py:7 re.match(PATTERN,user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no length limit/timeout | consensus: 1/1 confirmed | triage: ReDoS via re.match
- Patch:
  - **Summary**: Rewrite regex to linear form (e.g. a+) and enforce input length limit/timeout.

<a id="finding-81"></a>
### MEDIUM ReDoS in do_re_match_compiled
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:12-14`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_match_compiled(user_input):
    match = pattern.match(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.match`
  - **Sink**: `pattern.match`
- Evidence: def do_re_match_compiled(user_input): match = pattern.match(user_input)
  - Validation: src/vulnpy/trigger/redos.py:13-14 re.compile(PATTERN) then pattern.match(user_input) on evil nested quantifier; reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:13-14 re.compile(PATTERN) then pattern.match(user_input) on evil nested quantifier; reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via compiled match
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-82"></a>
### MEDIUM ReDoS in do_re_search
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:19-20`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_search(user_input):
    match = re.search(PATTERN, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.search`
  - **Sink**: `re.search(((a)+)+)`
- Evidence: def do_re_search(user_input): match = re.search(PATTERN, user_input)
  - Validation: src/vulnpy/trigger/redos.py:20 re.search(PATTERN,user_input) on PATTERN=((a)+)+; reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:20 re.search(PATTERN,user_input) on PATTERN=((a)+)+; reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via re.search
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-83"></a>
### MEDIUM ReDoS in do_re_search_compiled
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:25-27`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_search_compiled(user_input):
    match = pattern.search(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.search`
  - **Sink**: `pattern.search`
- Evidence: def do_re_search_compiled(user_input): match = pattern.search(user_input)
  - Validation: src/vulnpy/trigger/redos.py:26-27 re.compile(PATTERN) then pattern.search(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:26-27 re.compile(PATTERN) then pattern.search(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via compiled search
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-84"></a>
### MEDIUM ReDoS in do_re_finditer
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:32-33`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_finditer(user_input):
    for match in re.finditer(PATTERN, user_input):
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.finditer`
  - **Sink**: `re.finditer`
- Evidence: def do_re_finditer(user_input): for match in re.finditer(PATTERN, user_input):
  - Validation: src/vulnpy/trigger/redos.py:33 re.finditer(PATTERN,user_input) on evil pattern; reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:33 re.finditer(PATTERN,user_input) on evil pattern; reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via finditer
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-85"></a>
### MEDIUM ReDoS in do_re_finditer_compiled
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:37-39`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_finditer_compiled(user_input):
    for match in pattern.finditer(user_input):
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.finditer`
  - **Sink**: `pattern.finditer`
- Evidence: def do_re_finditer_compiled(user_input): for match in pattern.finditer(user_input):
  - Validation: src/vulnpy/trigger/redos.py:38-39 re.compile(PATTERN) then pattern.finditer(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:38-39 re.compile(PATTERN) then pattern.finditer(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via compiled finditer
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-86"></a>
### MEDIUM ReDoS in do_re_findall
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:43-44`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_findall(user_input):
    return re.findall(PATTERN, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.findall`
  - **Sink**: `re.findall`
- Evidence: def do_re_findall(user_input): return re.findall(PATTERN, user_input)
  - Validation: src/vulnpy/trigger/redos.py:44 re.findall(PATTERN,user_input) on evil pattern; reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:44 re.findall(PATTERN,user_input) on evil pattern; reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via findall
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-87"></a>
### MEDIUM ReDoS in do_re_findall_compiled
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:47-49`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_findall_compiled(user_input):
    return pattern.findall(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.findall`
  - **Sink**: `pattern.findall`
- Evidence: def do_re_findall_compiled(user_input): return pattern.findall(user_input)
  - Validation: src/vulnpy/trigger/redos.py:48-49 re.compile(PATTERN) then pattern.findall(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:48-49 re.compile(PATTERN) then pattern.findall(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via compiled findall
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-88"></a>
### MEDIUM ReDoS in do_re_fullmatch
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:52-53`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_fullmatch(user_input):
    match = re.fullmatch(PATTERN, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> re.fullmatch`
  - **Sink**: `re.fullmatch`
- Evidence: def do_re_fullmatch(user_input): match = re.fullmatch(PATTERN, user_input)
  - Validation: src/vulnpy/trigger/redos.py:53 re.fullmatch(PATTERN,user_input) on evil pattern; reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:53 re.fullmatch(PATTERN,user_input) on evil pattern; reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via fullmatch
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-89"></a>
### MEDIUM ReDoS in do_re_fullmatch_compiled
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `src/vulnpy/trigger/redos.py:58-60`
- Vulnerable code (`src/vulnpy/trigger/redos.py`):
```python
def do_re_fullmatch_compiled(user_input):
    match = pattern.fullmatch(user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `user_input -> pattern.fullmatch`
  - **Sink**: `pattern.fullmatch`
- Evidence: def do_re_fullmatch_compiled(user_input): match = pattern.fullmatch(user_input)
  - Validation: src/vulnpy/trigger/redos.py:59-60 re.compile(PATTERN) then pattern.fullmatch(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/redos.py:59-60 re.compile(PATTERN) then pattern.fullmatch(user_input); reachable via src/vulnpy/flask/blueprint.py:47 with no limit | consensus: 1/1 confirmed | triage: ReDoS via compiled fullmatch
- Patch:
  - **Summary**: Rewrite regex to linear form and enforce input length limit/timeout.

<a id="finding-90"></a>
### MEDIUM Event-loop blocking DoS in async_will_block
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.85
- Location: `apps/fastapi_app.py:51-57`
- Vulnerable code (`apps/fastapi_app.py`):
```python
async def async_will_block():
    sleep(10)
```
- Taint Flow:
  - **Source**: `HTTP request`
  - **Path**:
    - `request -> sleep(10) on loop`
  - **Sink**: `time.sleep in async`
- Evidence: async def async_will_block(): sleep(10)
  - Validation: apps/fastapi_app.py:51 @app.get('/async_will_block') exposes async def async_will_block at apps/fastapi_app.py:52-57 calling blocking sleep(10) with comments stating main thread will stall and all other requests blocked
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/fastapi_app.py:51 @app.get('/async_will_block') exposes async def async_will_block at apps/fastapi_app.py:52-57 calling blocking sleep(10) with comments stating main thread will stall and all other requests blocked | consensus: 1/1 confirmed | triage: Event-loop blocking sleep DoS
- Patch:
  - **Summary**: Replace time.sleep(10) with await asyncio.sleep(10) or move blocking work to threadpool so event loop is not stalled

<a id="finding-91"></a>
### MEDIUM SSRF and method injection sink in _request helper
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-918 | confidence: 0.85
- Location: `src/vulnpy/trigger/ssrf.py:90-92`
- Vulnerable code (`src/vulnpy/trigger/ssrf.py`):
```python
request_method(TRUSTED_METHOD, user_input)
```
- Taint Flow:
  - **Source**: `HTTP user_input`
  - **Path**:
    - `HTTP user_input -> _request -> HTTPConnection.request`
  - **Sink**: `request_method(user_input/TRUSTED_URL or TRUSTED_METHOD/user_input)`
- Evidence: request_method(TRUSTED_METHOD, user_input)
  - Validation: src/vulnpy/trigger/ssrf.py:86 host fixed to TRUSTED_HOST but src/vulnpy/trigger/ssrf.py:90-92 passes untrusted user_input as URL path and as HTTP method to HTTPConnection.request, reachable via do_* wrappers
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/ssrf.py:86 host fixed to TRUSTED_HOST but src/vulnpy/trigger/ssrf.py:90-92 passes untrusted user_input as URL path and as HTTP method to HTTPConnection.request, reachable via do_* wrappers | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Validate/allow-list URL path and HTTP method; do not pass raw user_input to HTTPConnection.request.

<a id="finding-92"></a>
### LOW Insecure Jinja2 Environment without autoescape
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.95
- Location: `apps/flask_app.py:8-9`
- Vulnerable code (`apps/flask_app.py`):
```python
environment = Environment(loader=loader)
```
- Taint Flow:
  - **Source**: `query user_input`
  - **Path**:
    - `request.args user_input -> template.render -> |safe`
  - **Sink**: `Environment without autoescape`
- Evidence: loader = FileSystemLoader(Path(__file__).parent / "templates" / "jinja") | safe }} renders request.args user_input unescaped at apps/flask_app.py:20-23
  - Validation: apps/flask_app.py:9 Environment(loader=loader) without autoescape plus apps/templates/jinja/xss.html:28 {{ user_input
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/flask_app.py:9 Environment(loader=loader) without autoescape plus apps/templates/jinja/xss.html:28 {{ user_input | consensus: 1/1 confirmed | triage: Insecure Jinja env enables XSS | triage: HTTPS putrequest path not SSRF
- Patch:
  - **Summary**: Enable autoescape=True and remove |safe; escape user_input on render.

<a id="finding-93"></a>
### LOW Insecure session cookie Secure flag
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.95
- Location: `apps/flask_app.py:29-29`
- Vulnerable code (`apps/flask_app.py`):
```python
app.config["SESSION_COOKIE_SECURE"] = False
```
- Taint Flow:
  - **Source**: `intrinsic cookie misconfig`
  - **Sink**: `SESSION_COOKIE_SECURE=False`
- Evidence: app.config["SESSION_COOKIE_SECURE"] = False
  - Validation: apps/flask_app.py:29 SESSION_COOKIE_SECURE=False on live Flask app registered with vulnerable_blueprint at apps/flask_app.py:25
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/flask_app.py:29 SESSION_COOKIE_SECURE=False on live Flask app registered with vulnerable_blueprint at apps/flask_app.py:25 | consensus: 1/1 confirmed | triage: Insecure Secure flag low-impact hardening
- Patch:
  - **Summary**: Set SESSION_COOKIE_SECURE=True.

<a id="finding-94"></a>
### LOW Insecure session cookie HttpOnly flag
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-1004 | confidence: 0.95
- Location: `apps/flask_app.py:30-30`
- Vulnerable code (`apps/flask_app.py`):
```python
app.config["SESSION_COOKIE_HTTPONLY"] = False
```
- Taint Flow:
  - **Source**: `intrinsic cookie misconfig`
  - **Sink**: `SESSION_COOKIE_HTTPONLY=False`
- Evidence: app.config["SESSION_COOKIE_HTTPONLY"] = False
  - Validation: apps/flask_app.py:30 SESSION_COOKIE_HTTPONLY=False on live Flask app registered with vulnerable_blueprint at apps/flask_app.py:25
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/flask_app.py:30 SESSION_COOKIE_HTTPONLY=False on live Flask app registered with vulnerable_blueprint at apps/flask_app.py:25 | consensus: 1/1 confirmed | triage: HttpOnly=False confirmed on live app; low-impact cookie hardening
- Patch:
  - **Summary**: Set SESSION_COOKIE_HTTPONLY=True.

<a id="finding-95"></a>
### LOW Django DEBUG enabled
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-489 | confidence: 0.9
- Location: `apps/django_app.py:28-28`
- Vulnerable code (`apps/django_app.py`):
```python
"DEBUG": True,
```
- Taint Flow:
  - **Source**: `intrinsic debug exposure`
  - **Sink**: `DEBUG=True`
- Evidence: "DEBUG": True,
  - Validation: apps/django_app.py:28 DEBUG=True loaded into settings at apps/django_app.py:23-33
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/django_app.py:28 DEBUG=True loaded into settings at apps/django_app.py:23-33 | consensus: 1/1 confirmed | triage: DEBUG enabled leaks internals
- Patch:
  - **Summary**: Set DEBUG=False for any network-reachable deployment; gate debug tracebacks.

<a id="finding-96"></a>
### LOW Unbounded file read in FastAPI upload handler
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `apps/fastapi_app.py:31-32`
- Vulnerable code (`apps/fastapi_app.py`):
```python
content = await file.read()
```
- Taint Flow:
  - **Source**: `multipart uploaded file`
  - **Path**:
    - `uploaded file -> file.read() unbounded`
  - **Sink**: `await file.read() without limit`
- Evidence: async def upload_return_large_file(file: UploadFile = File(...)):
  - Validation: apps/fastapi_app.py:32 content=await file.read() with no size limit on POST /files/upload, then os.system
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: apps/fastapi_app.py:32 content=await file.read() with no size limit on POST /files/upload, then os.system | consensus: 1/1 confirmed | triage: Unbounded file read enables memory DoS + RCE chain | triage: HTTPS putrequest method not SSRF
- Patch:
  - **Summary**: Enforce max upload size (chunked read with limit) and reject oversize files before read().

<a id="finding-97"></a>
### LOW Cacheable responses in WSGI app
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-614 | confidence: 0.9
- Location: `src/vulnpy/wsgi/app.py:33-33`
- Vulnerable code (`src/vulnpy/wsgi/app.py`):
```python
headers.append(("Cache-Control", "public"))
```
- Taint Flow:
  - **Source**: `intrinsic header misconfig`
  - **Sink**: `Cache-Control: public`
- Evidence: headers.append(("Cache-Control", "public"))
  - Validation: src/vulnpy/wsgi/app.py:33 sets Cache-Control: public on all vulnerable_app responses; mounted via apps/wsgi_app.py:27
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/wsgi/app.py:33 sets Cache-Control: public on all vulnerable_app responses; mounted via apps/wsgi_app.py:27 | consensus: 1/1 confirmed | triage: Cacheable responses low-impact
- Patch:
  - **Summary**: Set Cache-Control: no-store, no-cache on vulnerable_app responses.

<a id="finding-98"></a>
### LOW Disabled XSS protection header in WSGI app
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-693 | confidence: 0.9
- Location: `src/vulnpy/wsgi/app.py:35-35`
- Vulnerable code (`src/vulnpy/wsgi/app.py`):
```python
headers.append(("X-XSS-Protection", "0"))
```
- Taint Flow:
  - **Source**: `intrinsic header misconfig`
  - **Sink**: `X-XSS-Protection: 0`
- Evidence: headers.append(("X-XSS-Protection", "0"))
  - Validation: src/vulnpy/wsgi/app.py:35 sets X-XSS-Protection: 0 on all vulnerable_app responses; mounted via apps/wsgi_app.py:27
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/wsgi/app.py:35 sets X-XSS-Protection: 0 on all vulnerable_app responses; mounted via apps/wsgi_app.py:27 | consensus: 1/1 confirmed | triage: Disabled XSS header low-impact
- Patch:
  - **Summary**: Remove X-XSS-Protection: 0 header; rely on Content-Security-Policy and output encoding.

<a id="finding-99"></a>
### LOW Disabled HSTS in WSGI app
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-319 | confidence: 0.9
- Location: `src/vulnpy/wsgi/app.py:36-36`
- Vulnerable code (`src/vulnpy/wsgi/app.py`):
```python
headers.append(("Strict-Transport-Security", "max-age=0"))
```
- Taint Flow:
  - **Source**: `intrinsic header misconfig`
  - **Sink**: `HSTS max-age=0`
- Evidence: headers.append(("Strict-Transport-Security", "max-age=0"))
  - Validation: src/vulnpy/wsgi/app.py:36 sets Strict-Transport-Security: max-age=0 disabling HSTS; mounted via apps/wsgi_app.py:27
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/wsgi/app.py:36 sets Strict-Transport-Security: max-age=0 disabling HSTS; mounted via apps/wsgi_app.py:27 | consensus: 1/1 confirmed | triage: Disabled HSTS is low-impact transport hardening
- Patch:
  - **Summary**: Set Strict-Transport-Security: max-age=31536000; includeSubDomains when served over HTTPS.

<a id="finding-100"></a>
### LOW Weak randomness in do_random
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `src/vulnpy/trigger/rand.py:18-20`
- Vulnerable code (`src/vulnpy/trigger/rand.py`):
```python
def do_random(user_input):
    return str(random.random())
```
- Taint Flow:
  - **Source**: `weak PRNG`
  - **Sink**: `random.random()`
- Evidence: def do_random(user_input): return str(random.random())
  - Validation: src/vulnpy/trigger/rand.py:18-20 do_random seeds random with user input then str(random.random()); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/rand.py:18-20 do_random seeds random with user input then str(random.random()); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Weak randomness low impact without token use
- Patch:
  - **Summary**: Use secrets module (secrets.randbits/SystemRandom) for security contexts; do not use random.

<a id="finding-101"></a>
### LOW Weak randomness in do_randint
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `src/vulnpy/trigger/rand.py:23-25`
- Vulnerable code (`src/vulnpy/trigger/rand.py`):
```python
def do_randint(user_input):
    return str(random.randint(0, 100))
```
- Taint Flow:
  - **Source**: `weak PRNG`
  - **Sink**: `random.randint`
- Evidence: def do_randint(user_input): return str(random.randint(0, 100))
  - Validation: src/vulnpy/trigger/rand.py:23-25 do_randint seeds then random.randint(0,100); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/rand.py:23-25 do_randint seeds then random.randint(0,100); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Weak randint low impact
- Patch:
  - **Summary**: Use secrets.randbelow/secrets.choice for security-sensitive randomness.

<a id="finding-102"></a>
### LOW Weak randomness in do_randrange
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `src/vulnpy/trigger/rand.py:28-30`
- Vulnerable code (`src/vulnpy/trigger/rand.py`):
```python
def do_randrange(user_input):
    return str(random.randrange(0, 101, 5))
```
- Taint Flow:
  - **Source**: `weak PRNG`
  - **Sink**: `random.randrange`
- Evidence: def do_randrange(user_input): return str(random.randrange(0, 101, 5))
  - Validation: src/vulnpy/trigger/rand.py:28-30 do_randrange seeds then random.randrange(0,101,5); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/rand.py:28-30 do_randrange seeds then random.randrange(0,101,5); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Weak randrange low impact
- Patch:
  - **Summary**: Use secrets module for unpredictable values.

<a id="finding-103"></a>
### LOW Weak randomness in do_uniform
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-338 | confidence: 0.85
- Location: `src/vulnpy/trigger/rand.py:33-35`
- Vulnerable code (`src/vulnpy/trigger/rand.py`):
```python
def do_uniform(user_input):
    return str(random.uniform(5.5, 7.5))
```
- Taint Flow:
  - **Source**: `weak PRNG`
  - **Sink**: `random.uniform`
- Evidence: def do_uniform(user_input): return str(random.uniform(5.5, 7.5))
  - Validation: src/vulnpy/trigger/rand.py:33-35 do_uniform seeds then random.uniform(5.5,7.5); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input)
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: src/vulnpy/trigger/rand.py:33-35 do_uniform seeds then random.uniform(5.5,7.5); reachable via src/vulnpy/flask/blueprint.py:47 trigger_func(user_input) | consensus: 1/1 confirmed | triage: Weak uniform low impact
- Patch:
  - **Summary**: Use secrets.SystemRandom for security contexts instead of random.
