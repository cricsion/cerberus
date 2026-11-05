# Cerberus Report

**Findings:** 12 actionable — 3 critical, 2 high, 6 medium, 1 low
- Order: confirmed → needs-review, then severity, then confidence
- Omitted: 8 false positives and 8 duplicates — full triage record in `findings.json`

| Severity | Count | Proven PoCs | Patched |
| :--- | :---: | :---: | :---: |
| CRITICAL | 3 | 0 / 3 (0%) | 3 |
| HIGH | 2 | 0 / 2 (0%) | 2 |
| MEDIUM | 6 | 0 / 6 (0%) | 6 |
| LOW | 1 | 0 / 1 (0%) | 1 |
| **TOTAL** | **12** | **0 / 12 (0%)** | **12** |

## Table of Contents

- [Confirmed (12)](#confirmed)
  - [CRITICAL: Hardcoded SUPER_SECRET_NAME credential in config (`app/config.py:13`)](#finding-1)
  - [CRITICAL: SSTI test (`app/main.py:38`)](#finding-2)
  - [CRITICAL: Critical SSTI/RCE: unauthenticated ?name= rendered as Jinja2 template source (`app/main.py:41`)](#finding-3)
  - [HIGH: Hardcoded application secrets baked into source defaults (`app/config.py:13`)](#finding-4)
  - [HIGH: Reflected XSS via unescaped name interpolation into HTML (`app/main.py:38`)](#finding-5)
  - [MEDIUM: Production debug mode wired from env into FastAPI debug flag (`app/main.py:14`)](#finding-6)
  - [MEDIUM: Sensitive default query value discloses baked-in secret in responses and OpenAPI (`app/main.py:19`)](#finding-7)
  - [MEDIUM: Outbound fetch without timeout enables worker exhaustion DoS (`app/main.py:31`)](#finding-8)
  - [MEDIUM: Coraza WAF engine disabled leaving SSTI/XSS rules non-enforcing (`caddy/Caddyfile:13`)](#finding-9)
  - [MEDIUM: Blocking synchronous requests call inside async handler starves event loop (`app/main.py:29`)](#finding-10)
  - [MEDIUM: Unescaped external IP-service body reflected into HTML enables XSS (`app/main.py:36`)](#finding-11)
  - [LOW: FastAPI interactive docs/OpenAPI left enabled on unauthenticated edge (`app/main.py:10`)](#finding-12)

<a id="confirmed"></a>
## Confirmed (12)

<a id="finding-1"></a>
### CRITICAL Hardcoded SUPER_SECRET_NAME credential in config
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 1.0
- Location: `app/config.py:13-13`
- Vulnerable code (`app/config.py`):
```python
return Template(content).render()
```
- Taint Flow:
  - **Source**: `hardcoded literal in app/config.py`
  - **Path**:
    - `app/config.py:13`
    - `app/main.py:19`
  - **Sink**: `default query param and greeting body in app/main.py try_hack_me`
- Evidence: SUPER_SECRET_NAME = "John Ripper"  # FIXME: os.getenv("SUPER_SECRET_NAME")
  - Validation: Unauth ?name= at app/main.py:19 flows via f-string app/main.py:38 into Template().render() at app/main.py:41 with no sanitization; WAF disabled caddy/Caddyfile:12 SecRuleEngine Off
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: Unauth ?name= at app/main.py:19 flows via f-string app/main.py:38 into Template().render() at app/main.py:41 with no sanitization; WAF disabled caddy/Caddyfile:12 SecRuleEngine Off | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Stop rendering user input as template source; use static Jinja file with autoescape and return HTMLResponse(content) with escaping.

<a id="finding-2"></a>
### CRITICAL SSTI test
- CVSS: **9.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 1.0
- Location: `app/main.py:38-38`
- Vulnerable code (`app/main.py`):
```python
return Template(content).render()
```
- Taint Flow:
  - **Source**: `query param`
  - **Sink**: `Template render`
- Evidence: return Template(content).render()
  - Validation: Unauth ?name= at app/main.py:19 flows via f-string app/main.py:38 into Template().render() at app/main.py:41 with no sanitization; WAF disabled caddy/Caddyfile:12 SecRuleEngine Off
  - Consensus: 2/2 confirmed
  - Audit Trail: validator: Unauth ?name= at app/main.py:19 flows via f-string app/main.py:38 into Template().render() at app/main.py:41 with no sanitization; WAF disabled caddy/Caddyfile:12 SecRuleEngine Off | consensus: 2/2 confirmed
- Patch:
  - **Summary**: Stop rendering user input as template source; use static Jinja file with autoescape and return HTMLResponse(content) with escaping.

<a id="finding-3"></a>
### CRITICAL Critical SSTI/RCE: unauthenticated ?name= rendered as Jinja2 template source
- CVSS: **8.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-94 | confidence: 0.95
- Location: `app/main.py:41-41`
- Vulnerable code (`app/main.py`):
```python
return Template(content).render()
```
- Taint Flow:
  - **Source**: `HTTP GET / ?name= unauthenticated query string (app/main.py:19)`
  - **Path**:
    - `app/main.py:19 unauthenticated name param`
    - `app/main.py:37 name fallback to SUPER_SECRET_NAME`
    - `app/main.py:38 f-string builds template source from name+public_ip`
    - `app/main.py:41 Template(content).render() executes it`
  - **Sink**: `jinja2 Template(content).render() server-side template execution (app/main.py:41)`
- Evidence: app/main.py:19 defines unauthenticated 'name' query param defaulting to config.SUPER_SECRET_NAME; app/main.py:38 interpolates 'name' and SSRF-derived 'public_ip' into 'content' via f-string; app/main.py:41 executes 'Template(content).render()' where 'content' is attacker-controlled template source
  - Validation: app/main.py:19 ?name= unauthenticated input flows via app/main.py:38 f-string into template source executed at app/main.py:41 Template(content).render() with no sandbox/validation
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/main.py:19 ?name= unauthenticated input flows via app/main.py:38 f-string into template source executed at app/main.py:41 Template(content).render() with no sandbox/validation | consensus: 1/1 confirmed | triage: Unauth name into Template source enables RCE
- Patch:
  - **Summary**: Stop rendering user input as template source: return static HTMLResponse with autoescaped template/file and never interpolate name/public_ip into Template().

<a id="finding-4"></a>
### HIGH Hardcoded application secrets baked into source defaults
- CVSS: **7.3** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-798 | confidence: 0.95
- Location: `app/config.py:13-15`
- Vulnerable code (`app/config.py`):
```python
SUPER_SECRET_NAME = "***"  # FIXME: os.getenv("SUPER_SECRET_NAME")
```
- Taint Flow:
  - **Source**: `hardcoded literal defaults in app/config.py`
  - **Path**:
    - `app/config.py:13 hardcoded default`
    - `app/main.py:19 default query value`
    - `app/main.py:37 fallback or-branch`
  - **Sink**: `default greeting response and OpenAPI schema disclosure + repo/image leak`
- Evidence: Hardcoded fallback credentials baked into source at app/config.py:13 and app/config.py:15; same values published as example config in README.md:83-84; imported as defaults by app/main.py:19 and app/main.py:37 so they ship in repo and image layers
  - Validation: app/config.py:13 SUPER_SECRET_NAME="John Ripper" and app/config.py:15 SUPER_SECRET_TOKEN hardcoded literals shipped in repo/image and published in README.md:83-84
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/config.py:13 SUPER_SECRET_NAME="John Ripper" and app/config.py:15 SUPER_SECRET_TOKEN hardcoded literals shipped in repo/image and published in README.md:83-84 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove hardcoded defaults, load secrets only from vault/mounted env at runtime, rotate exposed values, add secret-scan gate.
  - +1 duplicate(s): `app/config.py:14`

<a id="finding-5"></a>
### HIGH Reflected XSS via unescaped name interpolation into HTML
- CVSS: **7.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | CWE: CWE-79 | confidence: 0.9
- Location: `app/main.py:38-38`
- Vulnerable code (`app/main.py`):
```python
content = f"<h1>Hello, {name}!</h1><h2>Public IP: <code>{public_ip}</code></h2>"
```
- Taint Flow:
  - **Source**: `query param name (app/main.py:19)`
  - **Path**:
    - `app/main.py:19`
    - `app/main.py:38`
  - **Sink**: `HTML body construction without escaping`
- Evidence: content = f"<h1>Hello, {name}!</h1><h2>Public IP: <code>{public_ip}</code></h2>"
  - Validation: Untrusted name at app/main.py:19 interpolated unescaped into HTML at app/main.py:38 with autoescape disabled via Template() at app/main.py:41
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Untrusted name at app/main.py:19 interpolated unescaped into HTML at app/main.py:38 with autoescape disabled via Template() at app/main.py:41 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: HTML-escape name/ip, enable Jinja autoescape, and validate/length-limit name.
  - +1 duplicate(s): `app/main.py:38`

<a id="finding-6"></a>
### MEDIUM Production debug mode wired from env into FastAPI debug flag
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-215 | confidence: 0.9
- Location: `app/main.py:14-14`
- Vulnerable code (`app/main.py`):
```python
debug=config.DEBUG,
```
- Taint Flow:
  - **Source**: `DEBUG env via app/config.py:9`
  - **Path**:
    - `app/config.py:9`
    - `app/main.py:14`
  - **Sink**: `FastAPI(debug=config.DEBUG)`
- Evidence: debug=config.DEBUG,
  - Validation: Env-driven DEBUG at app/config.py:9 wired to FastAPI(debug=) at app/main.py:14 with DEBUG=True in .env_temp:3 and passthrough in docker-compose.yaml:8
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: Env-driven DEBUG at app/config.py:9 wired to FastAPI(debug=) at app/main.py:14 with DEBUG=True in .env_temp:3 and passthrough in docker-compose.yaml:8 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Do not wire env DEBUG to production; force debug=False in prod and remove DEBUG from compose passthrough.
  - +1 duplicate(s): `app/main.py:14`

<a id="finding-7"></a>
### MEDIUM Sensitive default query value discloses baked-in secret in responses and OpenAPI
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-200 | confidence: 0.9
- Location: `app/main.py:19-19`
- Vulnerable code (`app/main.py`):
```python
async def try_hack_me(name: str = config.SUPER_SECRET_NAME):
```
- Taint Flow:
  - **Source**: `SUPER_SECRET_NAME default query parameter`
  - **Path**:
    - `app/config.py:13 hardcoded secret`
    - `app/main.py:19 default param`
    - `app/main.py:37 or-fallback`
    - `app/main.py:38 HTML response`
  - **Sink**: `unauthenticated greeting body + OpenAPI default value`
- Evidence: app/main.py:19 default name=config.SUPER_SECRET_NAME exposes baked-in secret in OpenAPI schema and default GET / response; fallback at app/main.py:37 re-discloses it on empty input; test at tests/test_main.py:20 asserts default body contains it
  - Validation: app/main.py:19 default name=config.SUPER_SECRET_NAME from app/config.py:13 plus app/main.py:37 or-fallback re-discloses secret in default GET / body and OpenAPI default
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/main.py:19 default name=config.SUPER_SECRET_NAME from app/config.py:13 plus app/main.py:37 or-fallback re-discloses secret in default GET / body and OpenAPI default | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Remove secret as default query value; use non-sensitive default (e.g. World) and do not fall back to secrets.
  - +1 duplicate(s): `app/main.py:19`

<a id="finding-8"></a>
### MEDIUM Outbound fetch without timeout enables worker exhaustion DoS
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.9
- Location: `app/main.py:31-31`
- Vulnerable code (`app/main.py`):
```python
public_ip_response = requests.get(config.PUBLIC_IP_SERVICE_URL)
```
- Taint Flow:
  - **Source**: `HTTP GET / triggers outbound fetch on every request`
  - **Sink**: `requests.get without timeout (availability sink)`
- Evidence: app/main.py:31 calls requests.get(config.PUBLIC_IP_SERVICE_URL) with no timeout=; repo-wide grep for timeout finds zero hits, so slow/hung IP service blocks worker indefinitely
  - Validation: app/main.py:31 requests.get(config.PUBLIC_IP_SERVICE_URL) has no timeout= and repo grep for timeout shows zero app-code hits so hung upstream blocks worker
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/main.py:31 requests.get(config.PUBLIC_IP_SERVICE_URL) has no timeout= and repo grep for timeout shows zero app-code hits so hung upstream blocks worker | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Add short timeout (e.g. timeout=3) plus size cap to outbound fetch and handle Timeout exception with fallback.
  - +1 duplicate(s): `app/main.py:32`

<a id="finding-9"></a>
### MEDIUM Coraza WAF engine disabled leaving SSTI/XSS rules non-enforcing
- CVSS: **4.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-693 | confidence: 0.9
- Location: `caddy/Caddyfile:13-13`
- Vulnerable code (`caddy/Caddyfile`):
```caddy/cadd
SecRuleEngine Off
```
- Taint Flow:
  - **Source**: `internet -> Caddy :80/:443/:1337`
  - **Sink**: `reverse_proxy app:1337 without WAF enforcement`
- Evidence: caddy/Caddyfile:13 SecRuleEngine Off with SSTI/XSS/SQLi/traversal SecRules at :17-20 present but non-enforcing; both localhost and :1337 routes import waf_rules so edge is unprotected
  - Validation: caddy/Caddyfile:13 SecRuleEngine Off leaves SSTI/XSS/SQLi rules at caddy/Caddyfile:17-20 non-enforcing on both routes importing waf_rules
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: caddy/Caddyfile:13 SecRuleEngine Off leaves SSTI/XSS/SQLi rules at caddy/Caddyfile:17-20 non-enforcing on both routes importing waf_rules | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Set SecRuleEngine On with tested SSTI/XSS rules, or remove stub rules if Caddy is not the enforcement point.

<a id="finding-10"></a>
### MEDIUM Blocking synchronous requests call inside async handler starves event loop
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-400 | confidence: 0.85
- Location: `app/main.py:29-31`
- Vulnerable code (`app/main.py`):
```python
public_ip_response = requests.get(config.PUBLIC_IP_SERVICE_URL)
```
- Taint Flow:
  - **Source**: `unauthenticated GET / handler try_hack_me`
  - **Sink**: `blocking socket I/O in async event loop`
- Evidence: app/main.py:19 async def try_hack_me blocks event loop at app/main.py:31 with synchronous requests.get; no httpx/aiohttp/AsyncClient usage found in app/
  - Validation: app/main.py:19 async def try_hack_me blocks event loop at app/main.py:31 synchronous requests.get with no async client in app/
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/main.py:19 async def try_hack_me blocks event loop at app/main.py:31 synchronous requests.get with no async client in app/ | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Use async HTTP client (httpx.AsyncClient) with timeout or run sync fetch in threadpool to avoid event-loop starvation.

<a id="finding-11"></a>
### MEDIUM Unescaped external IP-service body reflected into HTML enables XSS
- CVSS: **4.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | CWE: CWE-79 | confidence: 0.85
- Location: `app/main.py:36-36`
- Vulnerable code (`app/main.py`):
```python
public_ip = public_ip_response.text
```
- Taint Flow:
  - **Source**: `external HTTP response text`
  - **Path**:
    - `app/main.py:31`
    - `app/main.py:36`
  - **Sink**: `HTML interpolation without escaping or size cap`
- Evidence: public_ip = public_ip_response.text
  - Validation: External response text assigned unbounded at app/main.py:36 and interpolated unescaped into HTML at app/main.py:38
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: External response text assigned unbounded at app/main.py:36 and interpolated unescaped into HTML at app/main.py:38 | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Escape/size-cap upstream body before HTML interpolation; treat external text as untrusted.

<a id="finding-12"></a>
### LOW FastAPI interactive docs/OpenAPI left enabled on unauthenticated edge
- CVSS: **2.3** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N`) | CWE: CWE-200 | confidence: 0.85
- Location: `app/main.py:10-15`
- Vulnerable code (`app/main.py`):
```python
app = FastAPI(
```
- Taint Flow:
  - **Source**: `default FastAPI docs enabled on public app`
  - **Sink**: `/docs /redoc /openapi.json exposure`
- Evidence: app/main.py:10 FastAPI(...) sets title/description/version/debug but never docs_url=None/redoc_url=None/openapi_url=None, so /docs /redoc /openapi.json are exposed on unauthenticated edge
  - Validation: app/main.py:10 FastAPI(...) sets title/debug but never docs_url=None/redoc_url=None/openapi_url=None so /docs/openapi.json exposed with secret default
  - Consensus: 1/1 confirmed
  - Audit Trail: validator: app/main.py:10 FastAPI(...) sets title/debug but never docs_url=None/redoc_url=None/openapi_url=None so /docs/openapi.json exposed with secret default | consensus: 1/1 confirmed
- Patch:
  - **Summary**: Disable docs/redoc/openapi on public deployment (docs_url=None etc.) or gate behind auth.
