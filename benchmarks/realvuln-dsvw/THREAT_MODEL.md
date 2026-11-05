# Threat Model: realvuln-dsvw

## 1. System context

Damn Small Vulnerable Web (DSVW) v0.4 is a deliberately vulnerable teaching web application in a single ~100-line Python file (dsvw.py, Unlicense). It runs a threaded BaseHTTPRequestHandler server bound to loopback by default (rewritten to 0.0.0.0 in Dockerfile/docker-compose) with an in-memory SQLite users/comments database seeded from hardcoded USERS_XML, exposing / , /users.json and /login plus documented attack links with inline CASES payloads. Users are security learners running it locally or via the provided Dockerfile/docker-compose; the only hard requirement is lxml for the XXE/XPath cases. README declares it deliberately vulnerable with no security claims, no SECURITY.md/CHANGELOG, and the only in-code mitigations are html.escape on the app name and an alphanumeric strip on the login username.

Repo: realvuln-dsvw. Threat model for realvuln-dsvw | stack: unknown stack | entry points: ~0 routes | prefilter signal classes: hardcoded-secret, sqli-cursor, shell-true, eval-exec, pickle-loads, ssrf-requests, redos-regex, xpath-xml, path-open-join, ldap-xpath | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, sqli-cursor, shell-true, eval-exec, pickle-loads, ssrf-requests, redos-regex, xpath-xml, path-open-join, ldap-xpath.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| Server process integrity and OS command execution | Python process running dsvw.py; RCE via pickle.loads, nslookup shell=True, exec() of local/remote include gives OS command execution | critical |
| Host/container filesystem contents | Files readable via path traversal/LFI and XXE local entities e.g. /etc/passwd, dsvw.py source disclosure, full-path disclosure on error | high |
| Server-side network fetch capability (SSRF/RFI) | Outbound fetch via urllib.request.urlopen(path) and XXE remote entities / remote file inclusion of arbitrary URLs to internal services | high |
| Demo user table (usernames, names, surnames, passwords) | In-memory SQLite users table seeded from hardcoded USERS_XML for admin/dricci/amason/svargas; fixture credentials | medium |
| Service availability (single ThreadingServer) | Single threaded server with unbounded allocations via size parameter and expensive XML/pickle/SSRF handlers | medium |
| User-supplied comments store and rendered HTML | In-memory SQLite comments table re-rendered without encoding; stored/reflected XSS delivery to later viewers | low |
| Ephemeral session identifier randomness (SESSIONID on /login) | SESSIONID emitted via meta refresh on /login; weak predictability enables session fixation/spoofing in lab | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP GET /?id= (SQL injection) | Query string id crosses regex query parser into raw string-concatenated SELECT FROM users WHERE id= ; returns rows as HTML table. Blind-boolean, time and UNION payloads documented in CASES. dsvw.py:45, dsvw.py:50 [refs: `dsvw.py:45`, `dsvw.py:50`] | unauthenticated remote HTTP client -> in-memory SQLite query | Demo user table (usernames, names, surnames, passwords) |
| HTTP GET /?comment= (stored XSS / SQL insert) | comment value crosses query parser into raw INSERT INTO comments VALUES and later SELECT re-rendered without encoding; empty ?comment= lists all comments. Stored XSS plus SQL injection. dsvw.py:63 [refs: `dsvw.py:63`] | unauthenticated remote HTTP client -> SQLite comments store -> later victims viewing /?comment= | User-supplied comments store and rendered HTML, Demo user table (usernames, names, surnames, passwords) |
| HTTP GET /?v= (reflected XSS / frame injection) | v value crosses into re.sub replacement of version string in HTML_POSTFIX without encoding; abused for iframe/div injection, phishing, clickjacking and CSRF-link payloads. dsvw.py:52 [refs: `dsvw.py:52`] | unauthenticated remote HTTP client -> reflected HTML response -> victim browser | User-supplied comments store and rendered HTML |
| HTTP GET /?object= (pickle deserialization) | URL-decoded object string .encode() crosses into pickle.loads() and str() of result; CASES advertises cos/system payload with ping. Remote code execution sink. dsvw.py:53 [refs: `dsvw.py:53`] | unauthenticated remote HTTP client -> Python unpickler / process memory | Server process integrity and OS command execution |
| HTTP GET /?path= (path traversal / LFI / SSRF) | path value crosses os.path.abspath+open(rb) when no :// substring else urllib.request.urlopen(path); response decoded and returned. Absolute-path read, ../ traversal, dsvw.py source disclosure, full-path disclosure, and SSRF. dsvw.py:54 [refs: `dsvw.py:54`] | unauthenticated remote HTTP client -> filesystem read and outbound HTTP client | Host/container filesystem contents, Server-side network fetch capability (SSRF/RFI) |
| HTTP GET /?domain= (OS command injection) | domain value string-concatenated to nslookup +domain and run via subprocess.run(shell=True) with captured stdout returned. CASES advertises ;ifconfig chaining. dsvw.py:56 [refs: `dsvw.py:56`] | unauthenticated remote HTTP client -> shell -> OS process | Server process integrity and OS command execution |
| HTTP GET /?xml= (XXE local + remote) | xml value crosses lxml.etree.parse(BytesIO) with XMLParser(load_dtd=True, resolve_entities=True, no_network=False) and re-serialized. Local file:///etc/passwd and remote httpbin entity payloads. dsvw.py:58 [refs: `dsvw.py:58`] | unauthenticated remote HTTP client -> lxml parser with DTD/entities/network enabled -> filesystem and outbound HTTP | Host/container filesystem contents, Server-side network fetch capability (SSRF/RFI) |
| HTTP GET /?name= (XPath injection) | name value interpolated into .xpath(.//user[name/text()='%s']) over parsed USERS_XML; last match surname reflected. Boolean substring(password) probing. dsvw.py:60 [refs: `dsvw.py:60`] | unauthenticated remote HTTP client -> XPath evaluator over embedded credential store | Demo user table (usernames, names, surnames, passwords) |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker executes arbitrary OS commands via pickle deserialization and shell command injection | remote_unauth | HTTP GET /?object= (pickle deserialization), HTTP GET /?domain= (OS command injection) | Server process integrity and OS command execution | critical | almost_certain | unmitigated | Container runs as non-root USER dsvw with chown -R dsvw:dsvw /dsvw (limits host impact, does not prevent RCE) | dsvw.py:53 (pickle.loads), dsvw.py:56 (subprocess.run shell=True nslookup); dsvw.py:35 [Insecure deserialization via pickle.loads on object parameter]; dsvw.py:39 [OS command injection via domain nslookup shell] |
| T2 | Attacker exfiltrates or corrupts demo credentials via SQL injection in query and comment handlers | remote_unauth | HTTP GET /?id= (SQL injection), HTTP GET /?comment= (stored XSS / SQL insert) | Demo user table (usernames, names, surnames, passwords) | high | almost_certain | unmitigated | none | dsvw.py:45, dsvw.py:50 (raw SELECT string concat on id), dsvw.py:63 (raw INSERT/SELECT on comment); dsvw.py:30 [SQL Injection id handler]; dsvw.py:10 [DOM-based XSS via location.hash lang document.write]; dsvw.py:67 [SQL injection authentication bypass via login password]; dsvw.py:33 [Reflected XSS via v parameter version reflection]; dsvw.py:31 [Second-order XSS via unencoded id query result rendering]; dsvw.py:61 [Reflected XSS via redir meta-refresh injection] |
| T3 | Attacker forces server to fetch internal or remote URLs via SSRF file-fetch and XXE remote entities | remote_unauth | HTTP GET /?path= (path traversal / LFI / SSRF), HTTP GET /?xml= (XXE local + remote) | Server-side network fetch capability (SSRF/RFI) | critical | almost_certain | unmitigated | none | dsvw.py:54 (urllib.request.urlopen(path) branch), dsvw.py:58 (lxml no_network=False remote entities); dsvw.py:41 [XXE via lxml parser with DTD and network enabled]; dsvw.py:57 [Remote code execution via exec on include content]; dsvw.py:56 [LFI and SSRF via include file fetch] |
| T4 | Attacker reads arbitrary host files via traversal/LFI and XXE local file disclosure | remote_unauth | HTTP GET /?path= (path traversal / LFI / SSRF), HTTP GET /?xml= (XXE local + remote) | Host/container filesystem contents | high | almost_certain | unmitigated | none | dsvw.py:54 (os.path.abspath+open(rb)), dsvw.py:58 (load_dtd=True resolve_entities=True file:///etc/passwd); dsvw.py:37 [Path traversal and SSRF via path file-fetch handler] |
| T5 | Attacker injects stored and reflected scripts and frames to hijack learner browsers and phish via crafted links | remote_unauth | HTTP GET /?comment= (stored XSS / SQL insert), HTTP GET /?v= (reflected XSS / frame injection) | User-supplied comments store and rendered HTML | high | almost_certain | unmitigated | none | dsvw.py:63 (unencoded comment re-render), dsvw.py:52 (unencoded v reflection and frame injection); dsvw.py:65 [JSONP reflected XSS via users.json callback]; dsvw.py:53 [Cross-request stored XSS via comments store] |
| T6 | Attacker probes embedded credential store passwords via boolean XPath injection | remote_unauth | HTTP GET /?name= (XPath injection) | Demo user table (usernames, names, surnames, passwords) | medium | almost_certain | unmitigated | none | dsvw.py:60 (.xpath interpolation over USERS_XML); dsvw.py:43 [XPath injection via name parameter interpolation] |
| T7 | Attacker exhausts CPU, memory, or connections via expensive parses, fetches, and unbounded allocations to deny lab service | remote_unauth | HTTP GET /?path= (path traversal / LFI / SSRF), HTTP GET /?xml= (XXE local + remote), HTTP GET /?object= (pickle deserialization), HTTP GET /?domain= (OS command injection) | Service availability (single ThreadingServer) | medium | almost_certain | unmitigated | none | dsvw.py:46 [Denial of service via unbounded size allocation] |
| T8 | Security compromise via Information disclosure via full traceback error responses | remote_unauth | dsvw.py | application data and system state | medium | almost_certain | unmitigated | none | dsvw.py:72 [Information disclosure via full traceback error responses] |
| T9 | Security compromise via HTTP header injection via charset Content-Type reflection | remote_unauth | dsvw.py | application data and system state | medium | almost_certain | unmitigated | none | dsvw.py:78 [HTTP header injection via charset Content-Type reflection] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Elevation via IDOR/authz bypass on demo login/users.json | No authentication, authorization, or session enforcement to defeat by design; login is a demo vector for sqli/auth-bypass teaching. No privilege boundary exists to elevate across beyond already-modeled RCE. |
| Repudiation via absence of audit logging allowing undetected exploitation of all parameters | Parked, not excluded: application emits no access/audit logging by design so repudiation is total, but it adds no distinct class beyond enabling all other classes undetected; revisit if logging is ever added as a control. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- Is any instance network-reachable beyond loopback? Dockerfile seds bind to 0.0.0.0 and compose publishes 65412:65412 - owner to confirm intended exposure.
- Who supplies inputs to each query parameter and is there any upstream WAF, auth gateway, size limit, or egress filter? None found in tree.
- Which controls bound the exec/include and urlopen SSRF/RFI paths (allowlist, sandbox, no-new-privs)? None found beyond USER dsvw.
- Are hardcoded USERS_XML passwords live credentials in any deployment, or fixtures only? Treat as medium fixture secrets pending confirmation.
- No SECURITY.md, CHANGELOG, docs/, CI workflows, Terraform, K8s manifests, or IAM/ACL files found - owner to confirm out-of-tree access grants or credentials surviving migration/teardown.

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-dsvw
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-dsvw/signals/prefilter.txt (43 entries)
  - secrets: .cerberus/realvuln-dsvw/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-dsvw/signals/sca.json (1 entries)
  - iac: .cerberus/realvuln-dsvw/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-dsvw/signals/codegraph-index.txt (1 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Remove unauthenticated code-execution sinks: delete pickle.loads(object), shell=True nslookup, and exec()/include of local/remote content; if demo needed isolate in disabled-by-default flag with sandbox | T1 | yes | M |
| Disable server-side fetch and external entities: deny urlopen on user input, set lxml no_network=True resolve_entities=False load_dtd=False, and allowlist any required outbound hosts with egress filtering | T3 | yes | M |
| Constrain file access to an allowlisted document root: canonicalize with realpath, reject ../ and absolute paths, and return generic errors without full-path disclosure | T4 | yes | M |
| Parameterize all data access everywhere: use SQLite placeholders and parameterized XPath/XQuery (no string interpolation) for id, comment, and name handlers | T2,T6 | yes | M |
| Context-encode all reflection: HTML-encode comment, v, id, name outputs, set Content-Security-Policy and X-Frame-Options, and separate data API from HTML rendering | T5 | yes | M |
| Bound resource consumption and add minimal accountability: enforce size/count/timeout limits, request throttling, generic error pages, and access logging for teaching-lab containment | T7 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-dsvw).
Confirmed primary claims: 19.

By class: CWE-89 x5, CWE-79 x4, CWE-502 x1, CWE-22 x1, CWE-78 x1, CWE-611 x1, CWE-94 x1, CWE-643 x1, CWE-400 x1, CWE-918 x1, CWE-209 x1, CWE-113 x1

Affected paths: dsvw.py x19

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-113 x1, CWE-209 x1, CWE-22 x1, CWE-400 x1, CWE-502 x1, CWE-611 x1, CWE-643 x1, CWE-78 x1, CWE-79 x4, CWE-89 x5, CWE-918 x1, CWE-94 x1

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-798 x1 at dsvw.py — USERS_XML = """<?xml version="1.0" encoding="utf-8"?><users><user id="0"><username>admin</username><name>admin</name><surname>admin</surname><password>7en8aiDoh!</password></user> | validator: dsvw.py
- CWE-338 x1 at dsvw.py — content += "Welcome <b>%s</b><meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=%s; path=/\"><meta http-equiv=\"refresh\" content=\"1; url=/\"/>" % (re.sub(r"[^\w]", "", params.get("username", "")), 
- CWE-693 x1 at dsvw.py — self.send_header("X-XSS-Protection", "0") | validator: dsvw.py:77 X-XSS-Protection: 0 is recommended hardening; deprecated auditor disabled introduces no boundary violation | refute: not_a_vulnerabili
- CWE-362 x1 at dsvw.py — connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False) | validator: dsvw.py:17 shared :memory: connection with ThreadingServer dsvw.py:84-86 causes only robustness err
- CWE-1333 x1 at dsvw.py — code, content, params, cursor = http.client.OK, HTML_PREFIX, dict((match.group("parameter"), urllib.parse.unquote(','.join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % match.group("parameter"), query)))) | v
- CWE-352 x1 at dsvw.py — dsvw.py:48-50 state-changing INSERT via GET comment param with no CSRF token, no auth | validator: dsvw.py:50 INSERT via GET has no session/auth anywhere (dsvw.py:67-68 SESSIONID never validated); att
- CWE-200 x1 at dsvw.py — dsvw.py:64-65 users.json returns username to surname map with no authentication check | validator: dsvw.py:64-65 users.json returns only username->surname (no passwords from dsvw.py:11); intentionally
- CWE-307 x1 at dsvw.py — dsvw.py:66-68 login performs check with no rate limiting, lockout, or throttling | validator: dsvw.py:66-68 demo login intentionally bypassable via SQLi password concat; no privileged accounts/session
