# Cerberus Report

**Findings:** 10 actionable — 5 critical, 4 high, 1 medium
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 33 false positives and 10 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 5 | 0 / 5 (0%) | 5 |
| HIGH | 4 | 0 / 4 (0%) | 4 |
| MEDIUM | 1 | 0 / 1 (0%) | 1 |
| **TOTAL** | **10** | **0 / 10 (0%)** | **10** |

## Table of Contents

- [Confirmed (9)](#confirmed)
  - [CRITICAL: Eval injection via req.query.red in rgbToHex handler (`app/server.js:32`)](#finding-1)
  - [CRITICAL: Cross-unit Eval RCE to response via converter.rgbToHex (`app/server.js:39`)](#finding-2)
  - [CRITICAL: Unsafe deserialization RCE in cwe502 serialize handler (`app/server.js:97`)](#finding-3)
  - [CRITICAL: OS command injection in cwe78 childprocess handler (`app/server.js:106`)](#finding-4)
  - [CRITICAL: Use of known-vulnerable node-serialize component (`app/server.js:2`)](#finding-5)
  - [HIGH: Reflected XSS in cwe79 echo handler (`app/server.js:62`)](#finding-6)
  - [HIGH: Reflected XSS in /cwe201/exposure via unsanitized res.send (`app/server.js:80`)](#finding-7)
  - [HIGH: Hardcoded Veracode API credentials in start-agent-server.sh (`start-agent-server.sh:3`)](#finding-8)
  - [MEDIUM: HTTP response splitting in cwe113 split handler (`app/server.js:70`)](#finding-9)
- [Needs review (1)](#needs-review)
  - [HIGH: Missing authentication on CWE-73 file-read route (`app/server.js:53`)](#finding-10)

<a id="confirmed"></a>
## Confirmed (9)

<a id="finding-1"></a>
### CRITICAL Eval injection via req.query.red in rgbToHex handler
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-95 | confidence: 1.0
- Location: `app/server.js:32-32`
- Vulnerable code (`app/server.js`):
```javascript
var red = eval(req.query.red);
```
- Taint Flow:
  - **Source**: `req.query.red untrusted query string`
  - **Path**:
    - `app/server.js:32 req.query.red to eval`
  - **Sink**: `eval code execution`
- Evidence: var red = eval(req.query.red);
  - Validation: app/server.js:29 GET /cwe95/rgbToHex passes untrusted req.query.red to eval at app/server.js:32 with no parseInt/allowlist; fix commented out at app/server.js:36
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:29 GET /cwe95/rgbToHex passes untrusted req.query.red to eval at app/server.js:32 with no parseInt/allowlist; fix commented out at app/server.js:36 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace eval(req.query.red) with parseInt(req.query.red,10) and validate numeric range before converter.rgbToHex.
  - +2 duplicate(s): `app/server.js:33`, `app/server.js:34`

<a id="finding-2"></a>
### CRITICAL Cross-unit Eval RCE to response via converter.rgbToHex
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-95 | confidence: 1.0
- Location: `app/server.js:39-40`
- Vulnerable code (`app/server.js`):
```javascript
var hex = converter.rgbToHex(red, green, blue);
  res.send(hex);
```
- Taint Flow:
  - **Source**: `app/server.js:32 req.query.red/green/blue via eval()`
  - **Path**:
    - `app/server.js:32 eval(req.query.red)`
    - `app/server.js:39 converter.rgbToHex(red, green, blue)`
    - `app/converter.js:3 red.toString(16) + pad concatenation`
  - **Sink**: `app/server.js:40 res.send(hex)`
- Evidence: source app/server.js:32 eval(req.query.red) -> app/converter.js:3 red.toString(16) -> sink app/server.js:40 res.send(hex)
  - Validation: app/server.js:29 GET /cwe95/rgbToHex unauthenticated; app/server.js:32 eval(req.query.red) executes attacker JS; app/server.js:39-40 converter.rgbToHex flows to res.send
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:29 GET /cwe95/rgbToHex unauthenticated; app/server.js:32 eval(req.query.red) executes attacker JS; app/server.js:39-40 converter.rgbToHex flows to res.send | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Replace eval(req.query.*) at app/server.js:32-34 with parseInt(req.query.*,10) and validate numeric range before converter.rgbToHex.

<a id="finding-3"></a>
### CRITICAL Unsafe deserialization RCE in cwe502 serialize handler
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 1.0
- Location: `app/server.js:97-97`
- Vulnerable code (`app/server.js`):
```javascript
serialize.unserialize(req.query.foo);
```
- Taint Flow:
  - **Source**: `req.query.foo untrusted`
  - **Path**:
    - `app/server.js:97 req.query.foo to unserialize`
  - **Sink**: `node-serialize unserialize code exec`
- Evidence: serialize.unserialize(req.query.foo);
  - Validation: app/server.js:96 GET /cwe502/serialize passes untrusted req.query.foo to serialize.unserialize at app/server.js:97; package.json:18 pins node-serialize 0.0.4 with _$$ND_FUNC$$_ RCE
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:96 GET /cwe502/serialize passes untrusted req.query.foo to serialize.unserialize at app/server.js:97; package.json:18 pins node-serialize 0.0.4 with _$$ND_FUNC$$_ RCE | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove node-serialize unserialize of query input; use JSON.parse with schema validation and drop node-serialize dependency.
  - +1 duplicate(s): `app/server.js:97`

<a id="finding-4"></a>
### CRITICAL OS command injection in cwe78 childprocess handler
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-78 | confidence: 1.0
- Location: `app/server.js:106-106`
- Vulnerable code (`app/server.js`):
```javascript
cprocess.exec(req.query.foo, (error,stdout,stderr) => {
```
- Taint Flow:
  - **Source**: `req.query.foo untrusted`
  - **Path**:
    - `app/server.js:106 req.query.foo to exec`
  - **Sink**: `child_process.exec OS command`
- Evidence: cprocess.exec(req.query.foo, (error,stdout,stderr) => {
  - Validation: app/server.js:105 GET /cwe78/childprocess passes untrusted req.query.foo to cprocess.exec shell at app/server.js:106 with no allowlist/escaping
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:105 GET /cwe78/childprocess passes untrusted req.query.foo to cprocess.exec shell at app/server.js:106 with no allowlist/escaping | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Stop passing query to child_process.exec; use execFile with allowlisted command/args and no shell.
  - +1 duplicate(s): `app/server.js:106`

<a id="finding-5"></a>
### CRITICAL Use of known-vulnerable node-serialize component
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-502 | confidence: 0.95
- Location: `app/server.js:2-2`
- Vulnerable code (`app/server.js`):
```javascript
serialize.unserialize(req.query.foo);
```
- Taint Flow:
  - **Source**: `third-party vulnerable component`
  - **Path**:
    - `app/server.js:2 require node-serialize`
    - `app/server.js:97 unserialize attacker payload`
  - **Sink**: `vulnerable deserializer exposed`
- Evidence: var serialize = require('node-serialize');
  - Validation: app/server.js:96-99 serialize.unserialize(req.query.foo) deserializes unauthenticated query input via known-RCE node-serialize required at app/server.js:2
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:96-99 serialize.unserialize(req.query.foo) deserializes unauthenticated query input via known-RCE node-serialize required at app/server.js:2 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove node-serialize dependency; replace serialize.unserialize(req.query.foo) with JSON.parse on validated schema and reject _$$ND_FUNC$$_ payloads.

<a id="finding-6"></a>
### HIGH Reflected XSS in cwe79 echo handler
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `app/server.js:62-62`
- Vulnerable code (`app/server.js`):
```javascript
res.send("<p>You sent this: " + req.query.text + "</p>")
```
- Taint Flow:
  - **Source**: `req.query.text untrusted query string`
  - **Path**:
    - `app/server.js:62 req.query.text to res.send`
  - **Sink**: `res.send HTML response`
- Evidence: res.send(textConcat);
  - Validation: app/server.js:61 GET /cwe79/echo concatenates untrusted req.query.text into HTML at app/server.js:62 and res.send renders as text/html with no escaping
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:61 GET /cwe79/echo concatenates untrusted req.query.text into HTML at app/server.js:62 and res.send renders as text/html with no escaping | consensus: 1/1 confirmed
- Patch:
  - **Summary**: HTML-encode req.query.text or send as text/plain / JSON instead of HTML concatenation.

<a id="finding-7"></a>
### HIGH Reflected XSS in /cwe201/exposure via unsanitized res.send
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.95
- Location: `app/server.js:80-80`
- Vulnerable code (`app/server.js`):
```javascript
res.send(req.query.text);
```
- Taint Flow:
  - **Source**: `req.query.text in /cwe201/exposure handler`
  - **Path**:
    - `app/server.js:79 req.query.text entry`
    - `app/server.js:80 res.send sink`
  - **Sink**: `res.send attacker string as text/html`
- Evidence: app/server.js:79 route receives req.query.text; app/server.js:80 sinks it via res.send(req.query.text) with default text/html content-type and no output encoding
  - Validation: app/server.js:79 GET /cwe201/exposure entry req.query.text; app/server.js:80 res.send(req.query.text) reflects attacker string as text/html with no encoding
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:79 GET /cwe201/exposure entry req.query.text; app/server.js:80 res.send(req.query.text) reflects attacker string as text/html with no encoding | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Encode req.query.text before res.send or set text/plain content-type and escape HTML at app/server.js:80.

<a id="finding-8"></a>
### HIGH Hardcoded Veracode API credentials in start-agent-server.sh
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `start-agent-server.sh:3-4`
- Vulnerable code (`start-agent-server.sh`):
```bash
export VERACODE_API_KEY_ID=***
export VERACODE_API_KEY_SECRET=***
```
- Taint Flow:
  - **Source**: `hardcoded credential assignment`
  - **Sink**: `committed plaintext credential in start-agent-server.sh:3-4`
- Evidence: start-agent-server.sh:3 exports VERACODE_API_KEY_ID and start-agent-server.sh:4 exports VERACODE_API_KEY_SECRET committed in plaintext
  - Validation: start-agent-server.sh:3 exports VERACODE_API_KEY_ID plaintext and start-agent-server.sh:4 exports VERACODE_API_KEY_SECRET plaintext committed to repo
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: start-agent-server.sh:3 exports VERACODE_API_KEY_ID plaintext and start-agent-server.sh:4 exports VERACODE_API_KEY_SECRET plaintext committed to repo | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded keys from start-agent-server.sh:3-4, load from vault/env at runtime, rotate exposed Veracode credentials.

<a id="finding-9"></a>
### MEDIUM HTTP response splitting in cwe113 split handler
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-113 | confidence: 0.85
- Location: `app/server.js:70-70`
- Vulnerable code (`app/server.js`):
```javascript
res.append(req.query.key, req.query.value);
```
- Taint Flow:
  - **Source**: `req.query.key and value untrusted`
  - **Path**:
    - `app/server.js:70 req.query.key value to res.append`
  - **Sink**: `res.append header injection`
- Evidence: res.append(req.query.key, req.query.value);
  - Validation: app/server.js:69 GET /cwe113/split passes untrusted req.query.key/value to res.append header sink at app/server.js:70 with no allowlist/validation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/server.js:69 GET /cwe113/split passes untrusted req.query.key/value to res.append header sink at app/server.js:70 with no allowlist/validation | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Allowlist header name and validate/sanitize header value; reject CR/LF and unknown headers.

<a id="needs-review"></a>
## Needs review (1)

<a id="finding-10"></a>
### HIGH Missing authentication on CWE-73 file-read route
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-22 | confidence: 0.95
- Location: `app/server.js:53-53`
- Vulnerable code (`app/server.js`):
```javascript
res.send(fse.readJsonSync(req.query.foo));
```
- Taint Flow:
  - **Source**: `unauthenticated GET /cwe73/read?foo`
  - **Path**:
    - `app/server.js:53 route no guard`
  - **Sink**: `readJsonSync file read`
- Evidence: app.get("/cwe73/read", function(req, res) {
  - Validation: app/server.js:53 GET /cwe73/read passes untrusted req.query.foo to fse.readJsonSync at app/server.js:54 with no allowlist/normalization or auth gate
  - Consensus: tie/no-majority (1c/1f/0n of 2)
  - Audit Trail: validator: app/server.js:53 GET /cwe73/read passes untrusted req.query.foo to fse.readJsonSync at app/server.js:54 with no allowlist/normalization or auth gate | consensus: tie/no-majority (1c/1f/0n of 2)
- Patch:
  - **Summary**: Resolve req.query.foo against allowlisted directory, normalize and reject traversal, or remove arbitrary-path read.
  - +2 duplicate(s): `app/server.js:54`, `app/server.js:54`
