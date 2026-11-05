# Threat Model: realvuln-vulnpy

## 1. System context

Repo: realvuln-vulnpy. Threat model for realvuln-vulnpy | stack: unknown stack | entry points: ~5 routes | prefilter signal classes: sqli-cursor, shell-true, eval-exec, jinja-render, pickle-loads, yaml-load, ssrf-requests, redos-regex, xpath-xml, md5-sha1, path-open-join, tpl-xss, weak-random, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): sqli-cursor, shell-true, eval-exec, jinja-render, pickle-loads, yaml-load, ssrf-requests, redos-regex, xpath-xml, md5-sha1, path-open-join, tpl-xss, weak-random, tpl-form-reflect.

Day-one docs read: README.md.

## 2. Assets

| source code integrity | .github (1 files), apps (15 files), root (2 files), src (69 files), tests (39 files) | high |
| data assets | _unknown — owner to confirm_ | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP request handlers (5 routes detected) | Web and REST API endpoints (~5 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~5 framework routes:*

- `GET /` (`apps/bottle_app.py:11`)
- *(and ~4 additional route handlers)*

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Internal service access and cloud metadata exposure via Server-Side Request Forgery (SSRF) | remote_unauth | src/vulnpy/trigger/ssrf.py | application data and system state | high | almost_certain | unmitigated | none | src/vulnpy/trigger/ssrf.py:143 [SSRF host control in do_httpconnection_init]; src/vulnpy/trigger/ssrf.py:147 [SSRF host control in do_httpsconnection_init]; src/vulnpy/trigger/ssrf.py:51 [Central SSRF sink in _urlopen helper]; src/vulnpy/trigger/ssrf.py:90 [SSRF and method injection sink in _request helper]; src/vulnpy/trigger/ssrf.py:136 [SSRF host-control sink in _request_init helper]; src/vulnpy/trigger/ssrf.py:56 [SSRF in do_legacy_urlopen]; src/vulnpy/trigger/ssrf.py:64 [SSRF in do_urlopen_str]; src/vulnpy/trigger/ssrf.py:72 [SSRF via Request in do_urlopen_obj] |
| T2 | Arbitrary code execution via dynamic code evaluation | remote_unauth | src/vulnpy/aiohttp/vulnerable_routes.py, src/vulnpy/bottle/vulnerable_routes.py, src/vulnpy/django/vulnerable.py | application data and system state | critical | almost_certain | unmitigated | none | src/vulnpy/trigger/unsafe_code_exec.py:1 [Code injection via do_exec]; src/vulnpy/trigger/unsafe_code_exec.py:5 [Code injection via do_eval]; src/vulnpy/falcon/vulnerable_asgi.py:71 [Trigger dispatch RCE in Falcon ASGI get_trigger_view]; src/vulnpy/falcon/vulnerable.py:71 [Trigger dispatch RCE in Falcon get_trigger_view]; src/vulnpy/flask/blueprint.py:49 [Unauthenticated trigger dispatch RCE in Flask get_trigger_view]; src/vulnpy/fastapi/vulnerable.py:36 [Unauthenticated trigger dispatch RCE in FastAPI get_trigger_view]; src/vulnpy/django/vulnerable.py:30 [Unauthenticated trigger dispatch RCE in Django get_trigger_view]; src/vulnpy/django/vulnerable_asgi.py:49 [Unauthenticated trigger dispatch RCE in Django ASGI get_trigger_view]; src/vulnpy/aiohttp/vulnerable_routes.py:23 [Unauthenticated |
| T3 | Security compromise via XPath injection in do_lxml_etree_findall | remote_unauth | src/vulnpy/trigger/xpath.py | application data and system state | high | almost_certain | unmitigated | none | src/vulnpy/trigger/xpath.py:24 [XPath injection in do_lxml_etree_findall]; src/vulnpy/trigger/xpath.py:28 [XPath injection in do_lxml_etree_findtext]; src/vulnpy/trigger/xpath.py:32 [XPath injection in do_xml_etree_findall] |
| T4 | Arbitrary file disclosure via XML External Entity (XXE) injection | remote_unauth | src/vulnpy/trigger/xxe.py | application data and system state | high | almost_certain | unmitigated | none | src/vulnpy/trigger/xxe.py:7 [XXE in do_lxml_etree_fromstring]; src/vulnpy/trigger/xxe.py:15 [XXE in do_xml_sax_parsestring]; src/vulnpy/trigger/xxe.py:11 [XXE in do_xml_dom_pulldom_parsestring] |
| T5 | Arbitrary file disclosure or tampering via path traversal | remote_unauth | src/vulnpy/trigger/pt.py | application data and system state | high | almost_certain | unmitigated | none | src/vulnpy/trigger/pt.py:6 [Path traversal in do_tarfile_open]; src/vulnpy/trigger/pt.py:14 [Path traversal in do_tarfile_class]; src/vulnpy/trigger/pt.py:22 [Path traversal in do_tarfile_bz2]; src/vulnpy/trigger/pt.py:30 [Path traversal in do_bz2_class]; src/vulnpy/trigger/pt.py:38 [Path traversal in do_bz2_open]; src/vulnpy/trigger/pt.py:46 [Path traversal in do_io_open]; src/vulnpy/trigger/pt.py:54 [Path traversal in do_open] |
| T6 | Security compromise via Weak randomness in do_random | remote_unauth | src/vulnpy/trigger/rand.py | application data and system state | medium | almost_certain | unmitigated | none | src/vulnpy/trigger/rand.py:18 [Weak randomness in do_random]; src/vulnpy/trigger/rand.py:23 [Weak randomness in do_randint]; src/vulnpy/trigger/rand.py:28 [Weak randomness in do_randrange]; src/vulnpy/trigger/rand.py:33 [Weak randomness in do_uniform]; src/vulnpy/trigger/rand.py:15 [Attacker-controlled PRNG seed in _seed] |
| T7 | Security compromise via ReDoS in do_re_match | remote_unauth | apps/fastapi_app.py, apps/quart_app.py, src/vulnpy/trigger/redos.py | application data and system state | high | almost_certain | unmitigated | none | src/vulnpy/trigger/redos.py:6 [ReDoS in do_re_match]; src/vulnpy/trigger/redos.py:12 [ReDoS in do_re_match_compiled]; src/vulnpy/trigger/redos.py:19 [ReDoS in do_re_search]; src/vulnpy/trigger/redos.py:25 [ReDoS in do_re_search_compiled]; src/vulnpy/trigger/redos.py:32 [ReDoS in do_re_finditer]; src/vulnpy/trigger/redos.py:37 [ReDoS in do_re_finditer_compiled]; src/vulnpy/trigger/redos.py:43 [ReDoS in do_re_findall]; src/vulnpy/trigger/redos.py:47 [ReDoS in do_re_findall_compiled]; src/vulnpy/trigger/redos.py:52 [ReDoS in do_re_fullmatch]; src/vulnpy/trigger/redos.py:58 [ReDoS in do_re_fullmatch_compiled]; src/vulnpy/trigger/redos.py:65 [ReDoS in do_re_sub]; src/vulnpy/trigger/redos.py:69 [ReDoS in do_re_sub_compiled]; src/vulnpy/trigger/redos.py:74 [ReDoS in do_re_subn]; src/vulnpy/trigge |
| T8 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | apps/flask_app.py, apps/templates/jinja/xss.html, src/vulnpy/aiohttp/vulnerable_routes.py | application data and system state | critical | almost_certain | unmitigated | none | src/vulnpy/pyramid/vulnerable_routes.py:50 [Reflected XSS in Pyramid get_trigger_view]; src/vulnpy/quart/blueprint.py:52 [Reflected XSS in Quart get_trigger_view]; src/vulnpy/wsgi/app.py:25 [Reflected XSS in WSGI vulnerable_app]; apps/flask_app.py:19 [Jinja XSS sink in flask_app jinja_xss]; apps/templates/jinja/xss.html:28 [Unescaped output in jinja xss.html]; src/vulnpy/flask/blueprint.py:54 [Reflected XSS in Flask get_trigger_view]; src/vulnpy/fastapi/vulnerable.py:41 [Reflected XSS in FastAPI get_trigger_view]; src/vulnpy/django/vulnerable.py:35 [Reflected XSS in Django get_trigger_view]; src/vulnpy/django/vulnerable_asgi.py:54 [Reflected XSS in Django ASGI get_trigger_view]; src/vulnpy/aiohttp/vulnerable_routes.py:28 [Reflected XSS in aiohttp get_trigger_view]; src/vulnpy/bottle/vulner |
| T9 | Remote code execution via untrusted operating system command injection | remote_unauth | apps/falcon_app.py, apps/fastapi_app.py, apps/quart_app.py | application data and system state | critical | almost_certain | unmitigated | none | apps/fastapi_app.py:32 [Command injection via FastAPI file upload]; apps/fastapi_app.py:39 [Command injection in FastAPI cmdi route]; apps/falcon_app.py:28 [Command injection in Falcon FileUpload]; apps/falcon_app.py:63 [Command injection in Falcon thread_function]; apps/quart_app.py:23 [Command injection via Quart file upload]; src/vulnpy/trigger/cmdi.py:5 [OS command injection in do_os_system]; src/vulnpy/trigger/cmdi.py:9 [Shell injection in do_subprocess_popen]; src/vulnpy/quart/blueprint.py:10 [Header-trusted code input in Quart _get_user_input]; apps/fastapi_app.py:41 [Loop-amplified blocking execution DoS in FastAPI cmdi route]; apps/fastapi_app.py:37 [Missing authentication on FastAPI /cmdi command-execution endpoint] |
| T10 | Security compromise via Insecure MD5 hash in do_hashlib_md5 | remote_unauth | src/vulnpy/trigger/hash.py | application data and system state | medium | almost_certain | unmitigated | none | src/vulnpy/trigger/hash.py:18 [Insecure MD5 hash in do_hashlib_md5]; src/vulnpy/trigger/hash.py:23 [Insecure SHA1 hash in do_hashlib_sha1]; src/vulnpy/trigger/hash.py:28 [Insecure SHA1 via hashlib.new in do_hashlib_new] |
| T11 | Security compromise via Cacheable responses in WSGI app | remote_unauth | apps/flask_app.py, src/vulnpy/wsgi/app.py | application data and system state | medium | almost_certain | unmitigated | none | src/vulnpy/wsgi/app.py:33 [Cacheable responses in WSGI app]; apps/flask_app.py:29 [Insecure session cookie Secure flag] |
| T12 | Security compromise via Disabled XSS protection header in WSGI app | remote_unauth | src/vulnpy/wsgi/app.py | application data and system state | medium | almost_certain | unmitigated | none | src/vulnpy/wsgi/app.py:35 [Disabled XSS protection header in WSGI app] |
| T13 | Security compromise via Disabled HSTS in WSGI app | remote_unauth | src/vulnpy/wsgi/app.py | application data and system state | medium | almost_certain | unmitigated | none | src/vulnpy/wsgi/app.py:36 [Disabled HSTS in WSGI app] |
| T14 | Security compromise via Insecure session cookie HttpOnly flag | remote_unauth | apps/flask_app.py | application data and system state | medium | almost_certain | unmitigated | none | apps/flask_app.py:30 [Insecure session cookie HttpOnly flag] |
| T15 | Security compromise via Hardcoded Django SECRET_KEY | remote_unauth | apps/django_app.py | application data and system state | high | almost_certain | unmitigated | none | apps/django_app.py:27 [Hardcoded Django SECRET_KEY] |
| T16 | Security compromise via Django DEBUG enabled | remote_unauth | apps/django_app.py | application data and system state | medium | almost_certain | unmitigated | none | apps/django_app.py:28 [Django DEBUG enabled] |
| T17 | Security compromise via Evil nested-quantifier regex definition PATTERN | remote_unauth | src/vulnpy/trigger/redos.py | application data and system state | medium | almost_certain | unmitigated | none | src/vulnpy/trigger/redos.py:3 [Evil nested-quantifier regex definition PATTERN] |
| T18 | Remote code execution via untrusted object deserialization | remote_unauth | src/vulnpy/trigger/deserialization.py | application data and system state | critical | almost_certain | unmitigated | none | src/vulnpy/trigger/deserialization.py:6 [Unsafe pickle.load in do_pickle_load]; src/vulnpy/trigger/deserialization.py:11 [Unsafe pickle.loads in do_pickle_loads]; src/vulnpy/trigger/deserialization.py:15 [Unsafe yaml.load in do_yaml_load]; src/vulnpy/trigger/deserialization.py:22 [Unsafe yaml.load_all in do_yaml_load_all] |
| T19 | Database compromise and sensitive data exfiltration via SQL injection | remote_unauth | src/vulnpy/trigger/sqli.py | application data and system state | high | almost_certain | unmitigated | none | src/vulnpy/trigger/sqli.py:34 [SQL injection in do_sqlite3_execute]; src/vulnpy/trigger/sqli.py:45 [SQL injection in do_sqlite3_executemany]; src/vulnpy/trigger/sqli.py:56 [SQL script injection in do_sqlite3_executescript] |
| T20 | Security compromise via Missing authentication/authorization on /vulnpy trigger routes | remote_unauth | src/vulnpy/flask/blueprint.py | application data and system state | high | almost_certain | unmitigated | none | src/vulnpy/flask/blueprint.py:61 [Missing authentication/authorization on /vulnpy trigger routes] |

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
- target: realvuln-vulnpy
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history
- owner: unset
- enrichment: deterministic
- stored scan signals:
  - prefilter: .cerberus/realvuln-vulnpy/signals/prefilter.txt (91 entries)
  - secrets: .cerberus/realvuln-vulnpy/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-vulnpy/signals/sca.json (1 entries)
  - iac: .cerberus/realvuln-vulnpy/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-vulnpy/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-vulnpy/signals/routes.txt (5 entries)
## 8. Recommended mitigations

_unknown — owner to confirm (one class-level control per threat cluster; deterministic floor proposes none_).

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-vulnpy).
Confirmed primary claims: 103.

By class: CWE-400 x19, CWE-79 x16, CWE-94 x13, CWE-78 x10, CWE-918 x8, CWE-22 x7, CWE-338 x5, CWE-502 x4, CWE-91 x3, CWE-611 x3, CWE-327 x3, CWE-89 x3, CWE-614 x2, CWE-693 x1, CWE-319 x1

Affected paths: src/vulnpy/trigger/redos.py x17, src/vulnpy/trigger/ssrf.py x8, src/vulnpy/trigger/pt.py x7, apps/fastapi_app.py x6, src/vulnpy/trigger/rand.py x5, src/vulnpy/wsgi/app.py x5, apps/flask_app.py x4, src/vulnpy/trigger/deserialization.py x4, src/vulnpy/trigger/xpath.py x3, src/vulnpy/trigger/xxe.py x3, src/vulnpy/falcon/vulnerable_asgi.py x3, src/vulnpy/quart/blueprint.py x3, src/vulnpy/trigger/hash.py x3, src/vulnpy/flask/blueprint.py x3, src/vulnpy/falcon/vulnerable.py x3

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-1004 x1, CWE-1333 x1, CWE-22 x7, CWE-306 x1, CWE-319 x1, CWE-327 x3, CWE-338 x5, CWE-400 x19, CWE-489 x1, CWE-502 x4, CWE-611 x3, CWE-614 x2, CWE-693 x1, CWE-78 x10, CWE-79 x16, CWE-798 x1, CWE-89 x3, CWE-91 x3, CWE-918 x8, CWE-94 x13

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-918 x8 at src/vulnpy/trigger/ssrf.py — def do_httpconnection_putrequest_method(user_input): return _request(user_input, HTTPConnection, "putrequest", False) | validator: src/vulnpy/trigger/ssrf.py:79-93 _request fixes c=connection_class(TR
- CWE-94 x4 at src/vulnpy/trigger/pt.py, src/vulnpy/trigger/unsafe_code_exec.py, src/vulnpy/trigger/util.py — def do_compile(code): return compile(code, "vulnpy.py", "exec") | validator: src/vulnpy/trigger/unsafe_code_exec.py:10 compile() only compiles, never executes; callers discard return src/vulnpy/flask/
- CWE-400 x4 at apps/falcon_app.py, apps/fastapi_app.py, src/vulnpy/common/templating.py, src/vulnpy/wsgi/app.py — threading.Thread(target=thread_function, args=(user_input,)).start() | validator: apps/falcon_app.py:72-74 ThreadView spawns exactly one short-lived thread per request; user_input only sets thread arg
- CWE-20 x3 at apps/falcon_app.py, src/vulnpy/django/vulnerable_asgi.py, src/vulnpy/flask/blueprint.py — if request.headers.get("User-Input") is not None: | validator: src/vulnpy/flask/blueprint.py:10-15 User-Input header is just alternate untrusted source flowing to same trigger_func at :50 as query/for
- CWE-390 x3 at src/vulnpy/falcon/vulnerable.py, src/vulnpy/falcon/vulnerable_asgi.py, src/vulnpy/trigger/sqli.py — try: self.trigger(user_input) except Exception: | validator: src/vulnpy/falcon/vulnerable.py:29-37 catch_exception only gates try/except:pass around self.trigger; no auth/data disclosure, intended tes
- CWE-252 x3 at apps/quart_app.py, src/vulnpy/django/vulnerable_asgi.py, src/vulnpy/utils/utils_string.py — stream = files.get("file") user_input = stream.read() | validator: apps/quart_app.py:20-21 files.get('file').read() None deref only yields request-scoped 500, no process crash or resource exhaustion |
- CWE-22 x1 at src/vulnpy/common/templating.py — filename = os.path.join(TEMPLATES_LOCATION, path) with open(filename, "r") as f: | validator: src/vulnpy/common/templating.py:26-27 sink but all callers pass static '{}.html'.format(name) e.g. src/vul
- CWE-327 x1 at apps/falcon_app.py — digest = hexlify(md5(user_input).digest()).decode("utf8") | validator: apps/falcon_app.py:26 md5(user_input) used only as file-upload checksum returned as JSON md5 field, no password/token/auth integr
- CWE-250 x1 at Dockerfile — ENV HOST="0.0.0.0" | validator: Dockerfile:15 ENV HOST="0.0.0.0" and missing USER is container/build config explicitly excluded (Infrastructure & build configurations) | refute: exclusion_rule | conse
- CWE-1104 x1 at Dockerfile — FROM python:${PYTHON_VERSION}-slim | validator: Dockerfile:2 FROM python:${PYTHON_VERSION}-slim is base-image pin/build config explicitly excluded | refute: exclusion_rule | consensus: 1/1 fp | triage
- CWE-732 x1 at .github/workflows/main.yml — on: [push] | validator: .github/workflows/main.yml:3 on:[push] with no permissions block is CI workflow config explicitly excluded | refute: exclusion_rule | consensus: 1/1 fp | triage: GITHUB_TOKEN p
- CWE-829 x1 at src/vulnpy/templates/fragments/base.html — <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.8.2/css/bulma.min.css"> | validator: src/vulnpy/templates/fragments/base.html:4 hardcoded bulma CDN stylesheet URL; missing SRI alone 
- CWE-200 x1 at src/vulnpy/templates/fragments/parameter_pollution.frag.html — <form name="Polluted Form" method="POST" autocomplete="on"> | validator: src/vulnpy/templates/fragments/parameter_pollution.frag.html:5 autocomplete=on on non-sensitive foo field; default browser beha
- CWE-759 x1 at src/vulnpy/trigger/hash.py — def _hash(hasher, user_input): b = ensure_binary(user_input, errors="ignore") hasher.update(b) return hasher.hexdigest() | validator: src/vulnpy/trigger/hash.py:12-15 _hash just hexdigests user_input;
- CWE-209 x1 at src/vulnpy/trigger/util.py — print("Cannot find function {} in module {}", func_name, module.__name__) | validator: src/vulnpy/trigger/util.py:61 print() to stdout not HTTP response, and names are public TRIGGER_MAP values; no se
