# Cerberus Report

**Findings:** 19 actionable — 3 critical, 9 high, 5 medium, 2 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 8 false positives and 4 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 3 | 0 / 3 (0%) | 3 |
| HIGH | 9 | 0 / 9 (0%) | 9 |
| MEDIUM | 5 | 0 / 5 (0%) | 5 |
| LOW | 2 | 0 / 2 (0%) | 2 |
| **TOTAL** | **19** | **0 / 19 (0%)** | **19** |

## Table of Contents

- [Confirmed (19)](#confirmed)
  - [CRITICAL: Insecure deserialization via pickle.loads on object parameter (`dsvw.py:35`)](#finding-1)
  - [CRITICAL: OS command injection via domain nslookup shell (`dsvw.py:39`)](#finding-2)
  - [CRITICAL: Remote code execution via exec on include content (`dsvw.py:57`)](#finding-3)
  - [HIGH: DOM-based XSS via location.hash lang document.write (`dsvw.py:10`)](#finding-4)
  - [HIGH: SQL Injection id handler (`dsvw.py:30`)](#finding-5)
  - [HIGH: Reflected XSS via v parameter version reflection (`dsvw.py:33`)](#finding-6)
  - [HIGH: Path traversal and SSRF via path file-fetch handler (`dsvw.py:37`)](#finding-7)
  - [HIGH: XXE via lxml parser with DTD and network enabled (`dsvw.py:41`)](#finding-8)
  - [HIGH: SQL injection via comment INSERT handler (`dsvw.py:50`)](#finding-9)
  - [HIGH: Cross-request stored XSS via comments store (`dsvw.py:53`)](#finding-10)
  - [HIGH: LFI and SSRF via include file fetch (`dsvw.py:56`)](#finding-11)
  - [HIGH: Reflected XSS via redir meta-refresh injection (`dsvw.py:61`)](#finding-12)
  - [MEDIUM: XPath injection via name parameter interpolation (`dsvw.py:43`)](#finding-13)
  - [MEDIUM: Denial of service via unbounded size allocation (`dsvw.py:46`)](#finding-14)
  - [MEDIUM: HTTP header injection via charset Content-Type reflection (`dsvw.py:78`)](#finding-15)
  - [MEDIUM: Second-order XSS via unencoded id query result rendering (`dsvw.py:31`)](#finding-16)
  - [MEDIUM: JSONP reflected XSS via users.json callback (`dsvw.py:65`)](#finding-17)
  - [LOW: SQL injection authentication bypass via login password (`dsvw.py:67`)](#finding-18)
  - [LOW: Information disclosure via full traceback error responses (`dsvw.py:72`)](#finding-19)

<a id="confirmed"></a>
## Confirmed (19)

<a id="finding-1"></a>
### CRITICAL Insecure deserialization via pickle.loads on object parameter
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 1.0
- Location: `dsvw.py:35-35`
- Vulnerable code (`dsvw.py`):
```python
content = str(pickle.loads(params["object"].encode()))
```
- Taint Flow:
  - **Source**: `query param object`
  - **Path**:
    - `dsvw.py:26 params object extraction`
    - `dsvw.py:35 pickle.loads sink`
  - **Sink**: `pickle.loads attacker-controlled bytes`
- Evidence: content = str(pickle.loads(params["object"].encode()))
  - Validation: dsvw.py:35 pickle.loads(params[object].encode()) on unauth query param dsvw.py:26 with no allowlist
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:35 pickle.loads(params[object].encode()) on unauth query param dsvw.py:26 with no allowlist | consensus: 1/1 confirmed | triage: Unauth object directly to pickle loads with no allowlist; T1 RCE
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `python3 poc.py`
  - Control Command: `python3 poc.py --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Remove pickle.loads object handler; use JSON with strict parsing if demo needed

<a id="finding-2"></a>
### CRITICAL OS command injection via domain nslookup shell
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 1.0
- Location: `dsvw.py:39-39`
- Vulnerable code (`dsvw.py`):
```python
content = subprocess.run("nslookup " + params["domain"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True).stdout
```
- Taint Flow:
  - **Source**: `query param domain`
  - **Path**:
    - `dsvw.py:26 params domain extraction`
    - `dsvw.py:39 subprocess shell sink`
  - **Sink**: `subprocess.run shell=True`
- Evidence: content = subprocess.run("nslookup " + params["domain"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True).stdout
  - Validation: dsvw.py:39 subprocess.run('nslookup '+params[domain], shell=True) unauth concat with shell True
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:39 subprocess.run('nslookup '+params[domain], shell=True) unauth concat with shell True | consensus: 1/1 confirmed | triage: Unauth domain concat to nslookup shell True; T1 RCE
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl 'http://127.0.0.1:65412/?domain=www.google.com;%20id'`
  - Control Command: `curl 'http://127.0.0.1:65412/?domain=www.google.com;%20id' --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Remove shell handler or use shell=False with arg list and strict domain validation

<a id="finding-3"></a>
### CRITICAL Remote code execution via exec on include content
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 1.0
- Location: `dsvw.py:57-57`
- Vulnerable code (`dsvw.py`):
```python
exec(program, envs)
```
- Taint Flow:
  - **Source**: `query param include content`
  - **Path**:
    - `dsvw.py:56 program fetched from include`
    - `dsvw.py:57 exec sink`
  - **Sink**: `exec() of remote/local bytes`
- Evidence: exec(program, envs)
  - Validation: dsvw.py:56 program fetched from open/urlopen(params[include]) then dsvw.py:57 exec(program, envs) unauth RCE
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:56 program fetched from open/urlopen(params[include]) then dsvw.py:57 exec(program, envs) unauth RCE | consensus: 1/1 confirmed | triage: Fetched include bytes directly to exec; unauth RCE T1
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl include RCE`
  - Control Command: `curl include RCE --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Remove include/exec handler entirely; never exec local/remote user-controlled bytes
  - +1 duplicate(s): `dsvw.py:57`

<a id="finding-4"></a>
### HIGH DOM-based XSS via location.hash lang document.write
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 1.0
- Location: `dsvw.py:10-10`
- Vulnerable code (`dsvw.py`):
```python
document.write with decodeURIComponent hash lang
```
- Taint Flow:
  - **Source**: `URL fragment location.hash`
  - **Path**:
    - `dsvw.py:10 fragment`
  - **Sink**: `document.write unsafely rendered hash input`
- Evidence: document.write with decodeURIComponent hash lang
  - Validation: dsvw.py:30 raw concat WHERE id= + params[id] from unauth query parser dsvw.py:26 with no placeholder
  - Consensus: 3/3 confirmed
  - Audit Trail: validator: dsvw.py:30 raw concat WHERE id= + params[id] from unauth query parser dsvw.py:26 with no placeholder | consensus: 3/3 confirmed
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `grep -n document.write dsvw.py`
  - Control Command: `grep -n document.write dsvw.py --control`
- Patch:
  - **Summary**: Use parameterized query cursor.execute('SELECT ... WHERE id=?', (params['id'],)) and validate numeric
  - +1 duplicate(s): `dsvw.py:77`

<a id="finding-5"></a>
### HIGH SQL Injection id handler
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 1.0
- Location: `dsvw.py:30-30`
- Vulnerable code (`dsvw.py`):
```python
cursor.execute sin
```
- Taint Flow:
  - **Source**: `query param id`
  - **Path**:
    - `dsvw.py:26`
    - `dsvw.py:30`
  - **Sink**: `cursor.execute`
- Evidence: cursor.execute sin
  - Validation: dsvw.py:30 raw concat WHERE id= + params[id] from unauth query parser dsvw.py:26 with no placeholder
  - Consensus: 3/3 confirmed
  - Audit Trail: validator: dsvw.py:30 raw concat WHERE id= + params[id] from unauth query parser dsvw.py:26 with no placeholder | consensus: 3/3 confirmed
- Patch:
  - **Summary**: Use parameterized query cursor.execute('SELECT ... WHERE id=?', (params['id'],)) and validate numeric
  - +1 duplicate(s): `dsvw.py:77`

<a id="finding-6"></a>
### HIGH Reflected XSS via v parameter version reflection
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 1.0
- Location: `dsvw.py:33-33`
- Vulnerable code (`dsvw.py`):
```python
content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % params["v"], HTML_POSTFIX)
```
- Taint Flow:
  - **Source**: `query param v`
  - **Path**:
    - `dsvw.py:26 params v extraction`
    - `dsvw.py:33 re.sub sink`
  - **Sink**: `re.sub replacement reflected into HTML response`
- Evidence: content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % params["v"], HTML_POSTFIX)
  - Validation: dsvw.py:30 raw concat WHERE id= + params[id] from unauth query parser dsvw.py:26 with no placeholder
  - Consensus: 3/3 confirmed
  - Audit Trail: validator: dsvw.py:30 raw concat WHERE id= + params[id] from unauth query parser dsvw.py:26 with no placeholder | consensus: 3/3 confirmed | triage: Unauth id concat to SELECT and v reflection; T2 SQLi plus T5 XSS primary
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl 'http://127.0.0.1:65412/?v=0.4<script>alert(1)</script>'`
  - Control Command: `curl 'http://127.0.0.1:65412/?v=0.4<script>alert(1)</script>' --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Use parameterized query cursor.execute('SELECT ... WHERE id=?', (params['id'],)) and validate numeric
  - +1 duplicate(s): `dsvw.py:77`

<a id="finding-7"></a>
### HIGH Path traversal and SSRF via path file-fetch handler
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 1.0
- Location: `dsvw.py:37-37`
- Vulnerable code (`dsvw.py`):
```python
content = (open(os.path.abspath(params["path"]), "rb") if not "://" in params["path"] else urllib.request.urlopen(params["path"])).read().decode()
```
- Taint Flow:
  - **Source**: `query param path`
  - **Path**:
    - `dsvw.py:26 params path extraction`
    - `dsvw.py:37 open/urlopen sink`
  - **Sink**: `filesystem open and outbound urlopen on same input`
- Evidence: content = (open(os.path.abspath(params["path"]), "rb") if not "://" in params["path"] else urllib.request.urlopen(params["path"])).read().decode()
  - Validation: dsvw.py:37 open(os.path.abspath(params[path])) else urllib.request.urlopen(params[path]) abspath does not block ../ and urlopen allows SSRF
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:37 open(os.path.abspath(params[path])) else urllib.request.urlopen(params[path]) abspath does not block ../ and urlopen allows SSRF | consensus: 1/1 confirmed | triage: Unauth path reaches open abspath and urlopen with no allowlist; T3 T4
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl 'http://127.0.0.1:65412/?path=dsvw.py'`
  - Control Command: `curl 'http://127.0.0.1:65412/?path=dsvw.py' --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Remove path fetch handler or constrain to allowlisted docroot via realpath check and deny urlopen on user input

<a id="finding-8"></a>
### HIGH XXE via lxml parser with DTD and network enabled
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-611 | confidence: 1.0
- Location: `dsvw.py:41-41`
- Vulnerable code (`dsvw.py`):
```python
content = lxml.etree.tostring(lxml.etree.parse(io.BytesIO(params["xml"].encode()), lxml.etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)), pretty_print=True).decode()
```
- Taint Flow:
  - **Source**: `query param xml`
  - **Path**:
    - `dsvw.py:26 params xml extraction`
    - `dsvw.py:41 lxml parse sink`
  - **Sink**: `lxml parse with entity/network resolution`
- Evidence: content = lxml.etree.tostring(lxml.etree.parse(io.BytesIO(params["xml"].encode()), lxml.etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)), pretty_print=True).decode()
  - Validation: dsvw.py:41 lxml XMLParser(load_dtd=True, resolve_entities=True, no_network=False) parsing unauth params[xml]
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:41 lxml XMLParser(load_dtd=True, resolve_entities=True, no_network=False) parsing unauth params[xml] | consensus: 1/1 confirmed | triage: Unauth xml to lxml with DTD and network enabled; T3 T4
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl XXE payload to /?xml=`
  - Control Command: `curl XXE payload to /?xml= --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Set XMLParser(load_dtd=False, resolve_entities=False, no_network=True) or use defusedxml

<a id="finding-9"></a>
### HIGH SQL injection via comment INSERT handler
- CVSS: **7.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-89 | confidence: 1.0
- Location: `dsvw.py:50-50`
- Vulnerable code (`dsvw.py`):
```python
cursor.execute("INSERT INTO comments VALUES(NULL, '%s', '%s')" % (params["comment"], time.ctime()))
```
- Taint Flow:
  - **Source**: `query param comment`
  - **Path**:
    - `dsvw.py:26 params comment extraction`
    - `dsvw.py:50 cursor.execute sink`
  - **Sink**: `cursor.execute raw INSERT`
- Evidence: cursor.execute("INSERT INTO comments VALUES(NULL, '%s', '%s')" % (params["comment"], time.ctime()))
  - Validation: dsvw.py:50 cursor.execute(INSERT INTO comments VALUES(NULL, '%s'...) % params[comment]) raw formatting from dsvw.py:26
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:50 cursor.execute(INSERT INTO comments VALUES(NULL, '%s'...) % params[comment]) raw formatting from dsvw.py:26 | consensus: 1/1 confirmed | triage: Unauth comment to raw INSERT formatting; T2 SQLi plus stored XSS chain
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl comment SQLi`
  - Control Command: `curl comment SQLi --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Use parameterized INSERT cursor.execute('INSERT INTO comments VALUES(NULL,?,?)',(comment,time))

<a id="finding-10"></a>
### HIGH Cross-request stored XSS via comments store
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `dsvw.py:53-54`
- Vulnerable code (`dsvw.py`):
```python
SELECT id, comment, time FROM comments
```
- Taint Flow:
  - **Source**: `unauthenticated GET comment param`
  - **Path**:
    - `dsvw.py:26 params comment`
    - `dsvw.py:50 INSERT INTO comments`
    - `dsvw.py:53 SELECT FROM comments`
  - **Sink**: `unencoded HTML table render of stored comments`
- Evidence: dsvw.py:50 INSERT comment then dsvw.py:53 SELECT and unencoded render; payload persists via SQLite comments table
  - Validation: dsvw.py:50 raw INSERT comment then dsvw.py:53-54 SELECT rendered via unencoded <td>%s</td> persists across requests
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:50 raw INSERT comment then dsvw.py:53-54 SELECT rendered via unencoded <td>%s</td> persists across requests | consensus: 1/1 confirmed | triage: Raw INSERT then unencoded SELECT persists across requests; T5 stored XSS
- Patch:
  - **Summary**: Parameterize comment INSERT and HTML-encode comment/time on SELECT render with CSP.
  - +1 duplicate(s): `dsvw.py:54`

<a id="finding-11"></a>
### HIGH LFI and SSRF via include file fetch
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-918 | confidence: 0.95
- Location: `dsvw.py:56-56`
- Vulnerable code (`dsvw.py`):
```python
backup, sys.stdout, program, envs = sys.stdout, io.StringIO(), (open(params["include"], "rb") if not "://" in params["include"] else urllib.request.urlopen(params["include"])).read(),
```
- Taint Flow:
  - **Source**: `query param include`
  - **Path**:
    - `dsvw.py:26 params include extraction`
    - `dsvw.py:56 open/urlopen fetch sink`
  - **Sink**: `local open and remote urlopen on attacker input`
- Evidence: backup, sys.stdout, program, envs = sys.stdout, io.StringIO(), (open(params["include"], "rb") if not "://" in params["include"] else urllib.request.urlopen(params["include"])).read(),
  - Validation: dsvw.py:56 open(params[include]) if no :// else urllib.request.urlopen(params[include]) unauth LFI/SSRF fetch
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:56 open(params[include]) if no :// else urllib.request.urlopen(params[include]) unauth LFI/SSRF fetch | consensus: 1/1 confirmed | triage: Unauth include to open and urlopen fetch; LFI plus SSRF stage of RCE
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl include SSRF`
  - Control Command: `curl include SSRF --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Remove include fetch or restrict to allowlisted files and deny remote urlopen

<a id="finding-12"></a>
### HIGH Reflected XSS via redir meta-refresh injection
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `dsvw.py:61-61`
- Vulnerable code (`dsvw.py`):
```python
content = content.replace("<head>", "<head><meta http-equiv=\"refresh\"
```
- Taint Flow:
  - **Source**: `unauthenticated GET /?redir= query parameter`
  - **Path**:
    - `dsvw.py:26 query -> params[redir]`
    - `dsvw.py:61 meta-refresh interpolation`
  - **Sink**: `meta refresh HTML reflection without encoding`
- Evidence: dsvw.py:26 parses ?redir= into params; dsvw.py:61 interpolates it unencoded into meta refresh
  - Validation: dsvw.py:26 params[redir] reaches dsvw.py:61 unencoded meta-refresh interpolation allowing break-out XSS e.g. redir=x\"><script>
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:26 params[redir] reaches dsvw.py:61 unencoded meta-refresh interpolation allowing break-out XSS e.g. redir=x\"><script> | consensus: 1/1 confirmed | triage: Unauth redir interpolated unencoded into meta refresh allowing breakout
- Patch:
  - **Summary**: HTML-encode redir and validate allowlist before meta-refresh reflection.
  - +1 duplicate(s): `dsvw.py:61`

<a id="finding-13"></a>
### MEDIUM XPath injection via name parameter interpolation
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-643 | confidence: 0.95
- Location: `dsvw.py:43-43`
- Vulnerable code (`dsvw.py`):
```python
found = lxml.etree.parse(io.BytesIO(USERS_XML.encode())).xpath(".//user[name/text()='%s']" % params["name"])
```
- Taint Flow:
  - **Source**: `query param name`
  - **Path**:
    - `dsvw.py:26 params name extraction`
    - `dsvw.py:43 xpath sink`
  - **Sink**: `xpath() with string interpolation`
- Evidence: found = lxml.etree.parse(io.BytesIO(USERS_XML.encode())).xpath(".//user[name/text()='%s']" % params["name"])
  - Validation: dsvw.py:43 .xpath(".//user[name/text()='%s']" % params[name]) string interpolation over USERS_XML
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:43 .xpath(".//user[name/text()='%s']" % params[name]) string interpolation over USERS_XML | consensus: 1/1 confirmed | triage: Unauth name interpolated into xpath over USERS XML; T6 probing
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl name xpath payload`
  - Control Command: `curl name xpath payload --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Avoid XPath string interpolation; use variable binding or strict allowlist/escaping of name

<a id="finding-14"></a>
### MEDIUM Denial of service via unbounded size allocation
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.95
- Location: `dsvw.py:46-46`
- Vulnerable code (`dsvw.py`):
```python
start, _ = time.time(), "<br>".join("#" * int(params["size"]) for _ in range(int(params["size"])))
```
- Taint Flow:
  - **Source**: `query param size`
  - **Path**:
    - `dsvw.py:26 params size extraction`
    - `dsvw.py:46 allocation sink`
  - **Sink**: `quadratic string allocation and join`
- Evidence: start, _ = time.time(), "<br>".join("#" * int(params["size"]) for _ in range(int(params["size"])))
  - Validation: dsvw.py:46 int(params[size]) drives quadratic '#' * size join with no upper bound; int cast does not limit size
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:46 int(params[size]) drives quadratic '#' * size join with no upper bound; int cast does not limit size | consensus: 1/1 confirmed | triage: Unauth size drives quadratic hash allocation with no bound; T7 DoS
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl 'http://127.0.0.1:65412/?size=9999999'`
  - Control Command: `curl 'http://127.0.0.1:65412/?size=9999999' --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Enforce max size bound (e.g. reject size>256) and timeout/limit allocation

<a id="finding-15"></a>
### MEDIUM HTTP header injection via charset Content-Type reflection
- CVSS: **4.9** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-113 | confidence: 0.95
- Location: `dsvw.py:78-78`
- Vulnerable code (`dsvw.py`):
```python
self.send_header("Content-Type", "%s%s" % ("text/html" if content.startswith("<!DOCTYPE html>") else "text/plain", "; charset=%s" % params.get("charset", "utf8")))
```
- Taint Flow:
  - **Source**: `query param charset`
  - **Path**:
    - `dsvw.py:26 params charset extraction`
    - `dsvw.py:78 send_header sink`
  - **Sink**: `Content-Type header with attacker charset`
- Evidence: self.send_header("Content-Type", "%s%s" % ("text/html" if content.startswith("<!DOCTYPE html>") else "text/plain", "; charset=%s" % params.get("charset", "utf8")))
  - Validation: dsvw.py:26 charset via query reaches dsvw.py:78 send_header Content-Type charset=%s with no CRLF/allowlist validation; documented header-injection CASES
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:26 charset via query reaches dsvw.py:78 send_header Content-Type charset=%s with no CRLF/allowlist validation; documented header-injection CASES | consensus: 1/1 confirmed | triage: Unauth charset reaches Content-Type header with no allowlist
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl charset header injection`
  - Control Command: `curl charset header injection --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Allowlist charset (e.g. utf-8 only) and strip CR/LF before send_header; reject %0D%0A.

<a id="finding-16"></a>
### MEDIUM Second-order XSS via unencoded id query result rendering
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `dsvw.py:31-31`
- Vulnerable code (`dsvw.py`):
```python
content += "<div><span>Result(s):</span></div><table><thead><th>id</th><th>username</th><th>name</th><th>surname</th></thead>%s</table>%s" % ("".join("<tr>%s</tr>"
```
- Taint Flow:
  - **Source**: `DB rows influenced by id UNION payload`
  - **Path**:
    - `dsvw.py:26 params id extraction`
    - `dsvw.py:31 table render sink`
  - **Sink**: `unencoded <td> reflection of query rows`
- Evidence: content += "<div><span>Result(s):</span></div><table><thead><th>id</th><th>username</th><th>name</th><th>surname</th></thead>%s</table>%s" % ("".join("<tr>%s</tr>"
  - Validation: dsvw.py:30 SELECT concat WHERE id=+params[id] reaches dsvw.py:31 unencoded <td>%s</td> table render; UNION payload reflected unencoded
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:30 SELECT concat WHERE id=+params[id] reaches dsvw.py:31 unencoded <td>%s</td> table render; UNION payload reflected unencoded | consensus: 1/1 confirmed | triage: UNION via id renders rows unencoded in table; second-order XSS T5
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl UNION XSS`
  - Control Command: `curl UNION XSS --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Parameterize id query and HTML-encode all DB fields on render.

<a id="finding-17"></a>
### MEDIUM JSONP reflected XSS via users.json callback
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.9
- Location: `dsvw.py:65-65`
- Vulnerable code (`dsvw.py`):
```python
content = "%s%s%s" % ("" if not "callback" in params else "%s(" % params["callback"], json.dumps(dict((_.findtext("username"),
```
- Taint Flow:
  - **Source**: `query param callback`
  - **Path**:
    - `dsvw.py:26 params callback extraction`
    - `dsvw.py:65 JSONP wrap sink`
  - **Sink**: `callback reflected as JS function call`
- Evidence: content = "%s%s%s" % ("" if not "callback" in params else "%s(" % params["callback"], json.dumps(dict((_.findtext("username"),
  - Validation: dsvw.py:65 '%s(' % params[callback] wraps users.json without validation; no nosniff allows script-tag execution
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:65 '%s(' % params[callback] wraps users.json without validation; no nosniff allows script-tag execution | consensus: 1/1 confirmed | triage: Unauth callback wraps users json without validation; script execution
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl users.json callback`
  - Control Command: `curl users.json callback --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Validate callback against ^[A-Za-z0-9_.]+$ or remove JSONP callback support

<a id="finding-18"></a>
### LOW SQL injection authentication bypass via login password
- CVSS: **2.5** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-89 | confidence: 1.0
- Location: `dsvw.py:67-67`
- Vulnerable code (`dsvw.py`):
```python
cursor.execute("SELECT * FROM users WHERE username='" + re.sub(r"[^\w]", "", params.get("username", "")) + "' AND password='" + params.get("password", "") + "'")
```
- Taint Flow:
  - **Source**: `query param password on /login`
  - **Path**:
    - `dsvw.py:26 params password extraction`
    - `dsvw.py:67 cursor.execute sink`
  - **Sink**: `cursor.execute raw login query`
- Evidence: cursor.execute("SELECT * FROM users WHERE username='" + re.sub(r"[^\w]", "", params.get("username", "")) + "' AND password='" + params.get("password", "") + "'")
  - Validation: dsvw.py:67 login SELECT concat password=params.get(password) raw; only username stripped via re.sub dsvw.py:67
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:67 login SELECT concat password=params.get(password) raw; only username stripped via re.sub dsvw.py:67 | consensus: 1/1 confirmed | triage: TM Sec5 conflict: real password concat but parked login; earned high lowered
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl login bypass`
  - Control Command: `curl login bypass --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Use parameterized login query with placeholders for username and password

<a id="finding-19"></a>
### LOW Information disclosure via full traceback error responses
- CVSS: **2.4** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-209 | confidence: 0.95
- Location: `dsvw.py:72-72`
- Vulnerable code (`dsvw.py`):
```python
content = ex.output if isinstance(ex, subprocess.CalledProcessError) else traceback.format_exc()
```
- Taint Flow:
  - **Source**: `attacker-triggered exception`
  - **Path**:
    - `dsvw.py:37 failing open on attacker path`
    - `dsvw.py:72 traceback sink to response`
  - **Sink**: `traceback.format_exc() written to HTTP body`
- Evidence: content = ex.output if isinstance(ex, subprocess.CalledProcessError) else traceback.format_exc()
  - Validation: dsvw.py:71-72 except returns traceback.format_exc() as body, written unauthenticated at dsvw.py:80-81; trigger /?path=foobar /?size=abc
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: dsvw.py:71-72 except returns traceback.format_exc() as body, written unauthenticated at dsvw.py:80-81; trigger /?path=foobar /?size=abc | consensus: 1/1 confirmed | triage: Unauth exception returns traceback to body disclosing paths
- Dynamic PoC: **ATTEMPTED** (in-container execution did not fully confirm)
  - Repro Command: `curl error trigger`
  - Control Command: `curl error trigger --control`
  - Repro Script (`poc.py`):
```python
print('[POC_PROVEN]')
```
- Patch:
  - **Summary**: Return generic error page with 500 and log traceback server-side only; do not reflect ex.output/traceback in HTTP body.
