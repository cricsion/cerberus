# Threat Model: realvuln-python-insecure-app

## 1. System context

Deliberately-vulnerable FastAPI demo (python-insecure-app) used for training and shift-left tooling demos. A single greeting handler takes an unauthenticated ?name= parameter, fetches the host public IP via requests, and renders both into HTML with jinja2 Template().render(). Secrets SUPER_SECRET_NAME/TOKEN are baked in as defaults with dotenv-driven config including DEBUG wired to FastAPI(debug=). It runs as app:1337 behind a Caddy+Coraza reverse proxy via docker-compose with multiple image variants and pip-audit/bandit/trivy/schemathesis/ZAP demo tooling, but no coordinated-disclosure scope.

Repo: realvuln-python-insecure-app. Threat model for realvuln-python-insecure-app | stack: unknown stack | entry points: ~1 routes | prefilter signal classes: hardcoded-secret, jinja-render, ssrf-requests | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, jinja-render, ssrf-requests.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| Server process integrity (Python/FastAPI runtime — SSTI/RCE target) | FastAPI Python process executing attacker-influenced Jinja template; RCE gives code execution in container | critical |
| Hardcoded application secrets SUPER_SECRET_NAME and SUPER_SECRET_TOKEN in source | Demo credentials baked into source/env template; disclose via greeting page, debug pages, or repo leak | high |
| Container/host isolation and image integrity (Debian/Alpine/distroless/Wolfi variants) | Container filesystem and host isolation built from Dockerfiles, pip requirements, and xcaddy builder | high |
| Outbound public-IP response body rendered into HTML (integrity/availability of greeting page) | External IP-service response embedded into greeting HTML; tampering or failure defaces page or blocks render | medium |
| Service availability of app (port 1337) behind Caddy reverse proxy (ports 80/443/1337) | Greeting page and /health served through Caddy reverse_proxy; unauthenticated and DEBUG-enabled | medium |
| application data assets | user records, processed inputs, and runtime application state | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP GET / ?name= | Unauthenticated query parameter name: str (defaults to SUPER_SECRET_NAME) flows into f-string HTML then jinja2 Template(content).render(); attacker string controls template source [refs: `app/main.py:18`, `app/main.py:35`, `app/main.py:38`] | untrusted network/client query string -> application logic/template engine | Server process integrity (Python/FastAPI runtime — SSTI/RCE target), Hardcoded application secrets SUPER_SECRET_NAME and SUPER_SECRET_TOKEN in source, Outbound public-IP response body rendered into HTML (integrity/availability of greeting page) |
| Outbound SSRF fetch requests.get(PUBLIC_IP_SERVICE_URL) | URL taken from env config PUBLIC_IP_SERVICE_URL fetched with requests.get without allowlist, timeout, or scheme/host validation; response text embedded in HTML with only raise_for_status fallback to Unknown [refs: `app/main.py:28`, `app/config.py:11`, `.env_temp:5`] | application server -> attacker-influenced external URL / network | Outbound public-IP response body rendered into HTML (integrity/availability of greeting page), Service availability of app (port 1337) behind Caddy reverse proxy (ports 80/443/1337) |
| Env/config ingestion via os.getenv + dotenv | DEBUG, PUBLIC_IP_SERVICE_URL (and intended SUPER_SECRET_NAME/TOKEN) read via os.getenv; load_dotenv(find_dotenv()) loads nearest .env into process env, wiring DEBUG into FastAPI(debug=) [refs: `app/config.py:7`, `app/config.py:9`, `app/config.py:11`, `app/main.py:14`] | operator env / .env file -> configuration parser / process env | Service availability of app (port 1337) behind Caddy reverse proxy (ports 80/443/1337), Hardcoded application secrets SUPER_SECRET_NAME and SUPER_SECRET_TOKEN in source |
| Caddy reverse-proxy edge + /health | Caddy listens on 80/443/1337, reverse_proxies to app:1337, exposes unauthenticated /health -> OK; Coraza rule stubs for SSTI/SQLi/XSS/traversal present but SecRuleEngine Off so not enforcing [refs: `caddy/Caddyfile:9`, `caddy/Caddyfile:27`, `caddy/Caddyfile:35`, `docker-compose.yaml:8`] | untrusted internet -> Caddy -> container network app:1337 | Service availability of app (port 1337) behind Caddy reverse proxy (ports 80/443/1337), Container/host isolation and image integrity (Debian/Alpine/distroless/Wolfi variants) |
| Supply-chain: Dockerfiles + requirements + xcaddy build | Image build pulls base python image, pip/uv requirements, and (caddy builder) floating go install xcaddy@latest plus coraza-caddy plugin; only *.in requirements found, no compiled lockfile with hashes checked in [refs: `Dockerfile:3`, `Dockerfile:14`, `caddy/Dockerfile:5`, `caddy/Dockerfile:6`, `requirements/base.in`, `requirements/common.in`] | upstream registry / PyPI / Go module -> build-time image/filesystem | Container/host isolation and image integrity (Debian/Alpine/distroless/Wolfi variants), Server process integrity (Python/FastAPI runtime — SSTI/RCE target) |
| HTTP request handlers (1 routes detected) | Web and REST API endpoints (~1 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| container build and runtime configuration | Dockerfile, container images, and runtime deployment manifests | untrusted base images / container host runtime → container namespace | container isolation, host process integrity |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~1 framework routes:*

- `GET /` (`app/main.py:18`)

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker executes arbitrary Python in the server process by submitting Jinja payloads in ?name= rendered as template source | remote_unauth | HTTP GET / ?name= traversing Caddy reverse-proxy edge + /health to jinja2 Template().render() | Server process integrity (Python/FastAPI runtime — SSTI/RCE target) | critical | almost_certain | unmitigated | Dockerfile runs as non-root USER $NONROOT; Coraza SSTI rule stubs present but SecRuleEngine Off so not enforcing | app/main.py:18, app/main.py:35, app/main.py:38; app/config.py:13 [Hardcoded SUPER_SECRET_NAME credential in config]; app/main.py:41 [Critical SSTI/RCE: unauthenticated ?name= rendered as Jinja2 template source] |
| T2 | Attacker harvests baked-in secrets disclosed as default greeting values, debug/stacktrace pages, or repo/image leaks | remote_unauth | HTTP GET / ?name= and Env/config ingestion via os.getenv + dotenv | Hardcoded application secrets SUPER_SECRET_NAME and SUPER_SECRET_TOKEN in source | high | almost_certain | unmitigated | none | app/main.py:35, app/config.py:7, app/config.py:9; app/main.py:14 [Production debug mode wired from env into FastAPI debug flag]; app/config.py:13 [Hardcoded application secrets baked into source defaults]; app/main.py:19 [Sensitive default query value discloses baked-in secret in responses and OpenAPI]; app/main.py:10 [FastAPI interactive docs/OpenAPI left enabled on unauthenticated edge] |
| T3 | Attacker backdoors the deployed container by compromising floating base images, PyPI packages, or xcaddy@latest builder plugin | supply_chain | Supply-chain: Dockerfiles + requirements + xcaddy build | Container/host isolation and image integrity (Debian/Alpine/distroless/Wolfi variants) | high | possible | partially_mitigated | Dockerfile pins base image by digest; pip installs with --no-cache-dir and venv; requirements compiled with --generate-hashes per Makefile but no lockfile checked in | Dockerfile:3, Dockerfile:14, caddy/Dockerfile:5, caddy/Dockerfile:6 |
| T4 | Attacker pivots the unrestricted outbound fetch to internal metadata or attacker hosts by influencing PUBLIC_IP_SERVICE_URL or DNS | remote_unauth | Outbound SSRF fetch requests.get(PUBLIC_IP_SERVICE_URL) triggered by HTTP GET / ?name= | Outbound public-IP response body rendered into HTML (integrity/availability of greeting page) | high | possible | unmitigated | Limited exception handling around fetch: raise_for_status plus fallback public_ip=Unknown on HTTPError/InvalidSchema | app/main.py:28, app/config.py:11 |
| T5 | Attacker injects reflected script/HTML that executes in victims browsers via unencoded name and IP bodies | remote_unauth | HTTP GET / ?name= and Outbound SSRF fetch requests.get(PUBLIC_IP_SERVICE_URL) | Outbound public-IP response body rendered into HTML (integrity/availability of greeting page) | high | almost_certain | unmitigated | none | app/main.py:35, app/main.py:38; app/main.py:36 [Unescaped external IP-service body reflected into HTML enables XSS] |
| T6 | Attacker probes and exploits the unauthenticated edge without attribution due to missing access/audit logging and disabled WAF enforcement | remote_unauth | Caddy reverse-proxy edge + /health and HTTP GET / ?name= | Service availability of app (port 1337) behind Caddy reverse proxy (ports 80/443/1337) | medium | likely | unmitigated | none |  |
| T7 | Attacker exhausts worker connections or CPU by forcing slow unbounded outbound fetches and DEBUG error handling with no timeouts or throttling | remote_unauth | HTTP GET / ?name= via Caddy reverse-proxy edge + /health and Outbound SSRF fetch requests.get(PUBLIC_IP_SERVICE_URL) plus Env/config ingestion via os.getenv + dotenv (DEBUG) | Service availability of app (port 1337) behind Caddy reverse proxy (ports 80/443/1337) | medium | almost_certain | unmitigated | Caddy reverse_proxy with /health and healthcheck plus non-root runtime; no timeouts, size caps, or rate limits found | app/main.py:28, caddy/Caddyfile:9, docker-compose.yaml:8; app/main.py:31 [Outbound fetch without timeout enables worker exhaustion DoS] |
| T8 | Security compromise via Coraza WAF engine disabled leaving SSTI/XSS rules non-enforcing | remote_unauth | caddy/Caddyfile | application data and system state | medium | almost_certain | unmitigated | none | caddy/Caddyfile:13 [Coraza WAF engine disabled leaving SSTI/XSS rules non-enforcing] |
| T9 | Security compromise via Blocking synchronous requests call inside async handler starves event loop | remote_unauth | app/main.py | application data and system state | medium | almost_certain | unmitigated | none | app/main.py:29 [Blocking synchronous requests call inside async handler starves event loop] |

## 5. Deprioritized

| threat | reason |
|---|---|
| SQL injection / path traversal via greeting handler | No database, ORM, session store, or file-upload handling found; Coraza stubs mention SQLi/traversal but no sink exists to exploit. |
| IDOR / authz bypass across user objects | No authenticated users, roles, or object IDs exist; single anonymous route means no horizontal/vertical authz boundary to bypass yet. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- No SECURITY.md/CHANGELOG/docs found (only README.md); is there a published scope or coordinated-disclosure policy? Owner to confirm.
- Who controls PUBLIC_IP_SERVICE_URL and .env in deployed environments — can a lower-trust actor influence the SSRF URL, and is DEBUG=True (.env_temp:3) carried to production?
- Caddyfile sets SecRuleEngine Off — is the Coraza WAF intentionally disabled for demo, or is it expected to enforce SSTI/XSS/SQLi/traversal rules?
- Do SUPER_SECRET_NAME/TOKEN exist as real credentials outside this demo (env, vault, Caddy/compose env passthrough), and do they survive migration/teardown?
- No auth middleware, input validation, output encoding, timeouts, or size caps found — are any upstream controls (WAF, ingress, sandbox) intended?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-python-insecure-app
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-python-insecure-app/signals/prefilter.txt (8 entries)
  - secrets: .cerberus/realvuln-python-insecure-app/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-python-insecure-app/signals/sca.json (1 entries)
  - iac: .cerberus/realvuln-python-insecure-app/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-python-insecure-app/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-python-insecure-app/signals/routes.txt (1 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Eliminate server-side template injection by never rendering user input as template source — use static Jinja file with autoescape plus framework response models | T1,T2 | yes | M |
| Encode all reflected output, set Content-Security-Policy and X-Content-Type-Options, and validate/length-limit name parameter | T2 | partial | M |
| Harden outbound fetch with allowlisted https hosts, scheme/host validation, short timeout, size cap, and no cloud-metadata access | T4,T5 | partial | M |
| Remove hardcoded secrets from source and images — load from vault/mounted secrets, rotate any exposed values, and gate merges on secret scanning | T3 | yes | M |
| Pin all build inputs by digest/hash with generated lockfiles, verify signatures, and rebuild on CVE signals | T7 | partial | M |
| Harden edge and runtime: enable Coraza engine with SSTI/XSS rules, enforce rate limits and request caps, disable DEBUG in prod, and emit structured access/audit logs | T5,T6 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-python-insecure-app).
Confirmed primary claims: 12.

By class: CWE-94 x3, CWE-79 x2, CWE-400 x2, CWE-200 x2, CWE-215 x1, CWE-798 x1, CWE-693 x1

Affected paths: app/main.py x9, app/config.py x2, caddy/Caddyfile x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-200 x2, CWE-215 x1, CWE-400 x2, CWE-693 x1, CWE-79 x2, CWE-798 x1, CWE-94 x3

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-918 x2 at app/main.py — public_ip_response = requests.get(config.PUBLIC_IP_SERVICE_URL) | validator: Sink app/main.py:31 uses operator-env URL from app/config.py:11; ?name= at app/main.py:19 never flows into URL so remote at
- CWE-390 x2 at app/main.py — except (requests.HTTPError, requests.exceptions.InvalidSchema): | validator: Narrow except at app/main.py:33 only affects HTTP status code path; unhandled errors return generic 500 via FastAPI with no
- CWE-20 x2 at app/config.py, app/main.py — PUBLIC_IP_SERVICE_URL = os.getenv("PUBLIC_IP_SERVICE_URL") | validator: URL source app/config.py:11 is operator env (trusted by default); remote ?name= cannot set it, so arbitrary-URL requires operato
- CWE-807 x2 at app/config.py — load_dotenv(find_dotenv()) | validator: Dotenv load at app/config.py:7 requires local filesystem write to plant .env; not reachable from unauth network GET / at app/main.py:18 | refute: not_reachable 
- CWE-1088 x1 at app/main.py — try: | validator: Sync requests.get at app/main.py:31 inside async def at app/main.py:19 is performance anti-pattern; availability impact already covered as timeout issue with no distinct privilege/da
- CWE-306 x1 at app/main.py — @app.get("/", response_class=HTMLResponse) | validator: Public greeting route at app/main.py:18 is intentionally anonymous demo with no users/roles/object IDs in repo; no auth boundary exists to bypas
- CWE-770 x1 at app/main.py — app/main.py:18 @app.get("/") unauthenticated handler triggers SSRF fetch + Jinja render per request; repo grep for ratelimit/rate_limit/slowapi/throttle/limiter finds zero hits in py/Caddyfile/yaml, a
