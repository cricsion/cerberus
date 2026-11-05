# Threat Model: realvuln-node-api-goat

## 1. System context

Repo: realvuln-node-api-goat. Threat model for realvuln-node-api-goat | stack: unknown stack | entry points: ~9 routes | prefilter signal classes: js-exec | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): js-exec.

Day-one docs read: README.md.

## 2. Assets

| source code integrity | .github (1 files), app (2 files), root (2 files), test (2 files) | high |
| data assets | _unknown — owner to confirm_ | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| HTTP request handlers (9 routes detected) | Web and REST API endpoints (~9 routes detected) processing external requests | untrusted network / client → application logic | application data, session state, process integrity |
| CI workflow definitions | Automation pipelines (.github/workflows) triggered on pull requests and commits | untrusted pull requests / external action runners → CI runner environment | source code integrity, CI secrets & deployment credentials |
| parsed configuration and data files | Structured configuration and data files (JSON, YAML, TOML, INI) parsed at startup/runtime | untrusted configuration files → configuration parser | application configuration state, runtime logic |

### Key Detected Endpoints
*Detected ~9 framework routes:*

- `GET /cwe95/rgbToHex` (`app/server.js:29`)
- `GET /hexToRgb` (`app/server.js:43`)
- `GET /cwe73/read` (`app/server.js:53`)
- `GET /cwe79/echo` (`app/server.js:61`)
- `GET /cwe113/split` (`app/server.js:69`)
- `GET /cwe201/exposure` (`app/server.js:79`)
- `GET /cwe601/redirect` (`app/server.js:88`)
- `GET /cwe502/serialize` (`app/server.js:96`)
- `GET /cwe78/childprocess` (`app/server.js:105`)

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Security compromise via Eval injection via req.query.red in rgbToHex handler | remote_unauth | app/server.js | application data and system state | critical | almost_certain | unmitigated | none | app/server.js:32 [Eval injection via req.query.red in rgbToHex handler]; app/server.js:39 [Cross-unit Eval RCE to response via converter.rgbToHex] |
| T2 | Remote code execution via untrusted object deserialization | remote_unauth | app/server.js | application data and system state | critical | almost_certain | unmitigated | none | app/server.js:97 [Unsafe deserialization RCE in cwe502 serialize handler]; app/server.js:2 [Use of known-vulnerable node-serialize component] |
| T3 | Remote code execution via untrusted operating system command injection | remote_unauth | app/server.js | application data and system state | critical | almost_certain | unmitigated | none | app/server.js:106 [OS command injection in cwe78 childprocess handler] |
| T4 | Client-side session hijacking or defacement via cross-site scripting (XSS) | remote_unauth | app/server.js | application data and system state | high | almost_certain | unmitigated | none | app/server.js:62 [Reflected XSS in cwe79 echo handler]; app/server.js:80 [Reflected XSS in /cwe201/exposure via unsanitized res.send] |
| T5 | Security compromise via HTTP response splitting in cwe113 split handler | remote_unauth | app/server.js | application data and system state | medium | almost_certain | unmitigated | none | app/server.js:70 [HTTP response splitting in cwe113 split handler] |
| T6 | Security compromise via Hardcoded Veracode API credentials in start-agent-server.sh | remote_unauth | start-agent-server.sh | application data and system state | high | almost_certain | unmitigated | none | start-agent-server.sh:3 [Hardcoded Veracode API credentials in start-agent-server.sh] |

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
- target: realvuln-node-api-goat
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history
- owner: unset
- enrichment: deterministic
- stored scan signals:
  - prefilter: .cerberus/realvuln-node-api-goat/signals/prefilter.txt (9 entries)
  - secrets: .cerberus/realvuln-node-api-goat/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-node-api-goat/signals/sca.json (2 entries)
  - iac: .cerberus/realvuln-node-api-goat/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-node-api-goat/signals/codegraph-index.txt (1 entries)
  - routes: .cerberus/realvuln-node-api-goat/signals/routes.txt (9 entries)
## 8. Recommended mitigations

_unknown — owner to confirm (one class-level control per threat cluster; deterministic floor proposes none_).

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-node-api-goat).
Confirmed primary claims: 9.

By class: CWE-95 x2, CWE-502 x2, CWE-79 x2, CWE-78 x1, CWE-113 x1, CWE-798 x1

Affected paths: app/server.js x8, start-agent-server.sh x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-113 x1, CWE-502 x2, CWE-78 x1, CWE-79 x2, CWE-798 x1, CWE-95 x2

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-20 x10 at app/converter.js, app/server.js — var greenHex = green.toString(16); | validator: No security boundary: app/converter.js:4 green.toString throws per-request 500 only, app/server.js:121-124 process stays listening, no crash/DoS demonst
- CWE-306 x8 at app/server.js — app.get("/cwe502/serialize", function(req, res) { | validator: No auth model in app: app/server.js:1-8 imports only express/serialize/child_process/fs-extra with zero auth middleware, so app/server.js
- CWE-297 x3 at azure-pipelines-1.yml — status_code=`curl --write-out "%{http_code}" --silent --output /dev/null --insecure $(AGENT_SERVER_URL)` | validator: CI config excluded: azure-pipelines-1.yml:11-21 defines pool/resources IAST sideca
- CWE-829 x3 at .github/workflows/semgrep.yml, azure-pipelines-1.yml — image: returntocorp/semgrep | validator: .github/workflows/semgrep.yml:19 container image in CI workflow manifest is out-of-scope per exclusion rules | refute: exclusion_rule | consensus: 1/1 fp
- CWE-400 x2 at app/server.js — var hex = req.query.hex; | validator: app/server.js:43-45 /hexToRgb with missing hex yields per-request TypeError/500 via Express sync-error handling; no process crash or resource exhaustion shown | r
- CWE-201 x1 at app/server.js — res.send(req.query.text); | validator: app/server.js:79-80 res.send(req.query.text) reflects only attacker-supplied query value; no server secret, file, or store read at that sink | refute: not_a_vuln
- CWE-601 x1 at app/server.js — res.redirect(redirectTarget); | validator: app/server.js:88-89 redirect Location hardcoded to http://localhost:3001/echo?text= + req.query.text; attacker controls only query suffix, not host/scheme | 
- CWE-494 x1 at azure-pipelines-1.yml — curl --silent --insecure ${AGENT_SERVER_URL}/downloads | sh | validator: azure-pipelines-1.yml:52 curl --insecure ${AGENT_SERVER_URL}/downloads | sh is CI/CD pipeline config, excluded as infrastructur
- CWE-693 x1 at app/server.js — var app = express(); | validator: app/server.js:8 bare express() is generic hardening absence with no demonstrated principal/resource violation | refute: not_a_vulnerability | consensus: 1/1 fp
- CWE-319 x1 at app/server.js — var server = app.listen(3001, function () { | validator: app/server.js:122 app.listen(3001) plain HTTP is local dev listener; TLS is deployment concern with no secret flow demonstrated in code | refut
- CWE-117 x1 at app/server.js — console.log(`Error executing endpoint /cwe78/childprocess: ${error}`); | validator: app/server.js:108 console.log to local stdout has no log-integrity boundary; underlying risk is the CWE-78 exec at a
- CWE-209 x1 at app/server.js — res.send(JSON.stringify(rgb)); | validator: app/server.js:43-46 JSON NaN reflection with 200 is functional correctness, no secret or error-leak boundary crossed | refute: not_a_vulnerability | consens
- CWE-248 x1 at app/server.js — process.exit(); | validator: app/server.js:12-21 process.exit only on local SIGTERM/SIGINT gracefulShutdown, not reachable from untrusted network input | refute: not_reachable | consensus: 1/1 fp
- CWE-532 x1 at azure-pipelines-1.yml — echo Using session_id: $SESSION_ID | validator: azure-pipelines-1.yml:48 echo in CI build script is build-configuration logging out-of-scope per exclusion rules | refute: exclusion_rule | consensus: 1
- CWE-1104 x1 at azure-pipelines.yml — versionSpec: '8.x' | validator: azure-pipelines.yml:15 Node versionSpec is CI toolchain pin out-of-scope per infrastructure/build exclusion rules | refute: exclusion_rule | consensus: 1/1 fp
