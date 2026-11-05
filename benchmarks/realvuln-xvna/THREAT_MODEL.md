# Threat Model: realvuln-xvna

## 1. System context

XVNA (Extreme Vulnerable Node Application) is an intentionally vulnerable OWASP Top-10 2017 training app: an Express 4 backend in a single index.js file with an AngularJS frontend under public/app served as static content, backed by a local unauthenticated MongoDB xvna database seeded from checked-in collection/*.json files with plaintext credentials. It implements login, NoSQL lookups, bank-account lookup, ping, reflected search, eval, and deserialization demos using default credential admin@xvna.com/password. README states it must run only on localhost:3000 and must never face the internet; no production manifests, IAM, logging, or security policy ship in-repo.

Repo: realvuln-xvna. Threat model for realvuln-xvna | stack: unknown stack | entry points: ~0 routes | prefilter signal classes: hardcoded-secret, js-exec, js-ssrf, log-inject, weak-random, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect | STRIDE focus: spoofing (auth), tampering (injection), repudiation (logging), info-disclosure (secrets/XSS), DoS (eval/exec), elevation (authz/IDOR). No published dependency security policy found in-repo (checked SECURITY*/docs) — owner to confirm.

Detector coverage (regex prefilter rules that fired; this is what our tooling can match, not what is in scope): hardcoded-secret, js-exec, js-ssrf, log-inject, weak-random, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect, tpl-form-reflect.

Day-one docs read: README.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| source code integrity | code the system runs from; tampering changes behavior for every user | high |
| Login credentials (login collection: email + plaintext password) | Auth database with plaintext passwords and default admin@xvna.com/password | critical |
| User PII records (users collection: name, password, age, id) | Queryable user records with passwords and age | high |
| Bank account records (a5_insecure_dor: name, accountno, accounttype) | Financial account objects accessed without ownership check | high |
| Shopping-cart records (cart collection queried by name) | Cart records used in XSS and deserialization flows | medium |
| Session integrity + session secret ('Your secret key') | Express-session state protecting login status | high |
| Server process integrity (Node.js code execution via exec/eval/deserialize) | Full Node process compromise via injection primitives | critical |
| Service availability (Node on :3000 + MongoDB xvna) | Local Express + MongoDB availability | medium |
| Hardcoded/default secrets (eval secret 'impraveensingh', default admin@xvna.com/password) | In-code secrets and default credentials enabling spoofing | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| POST /api/users (login) | JSON body email/password; password containing '{' is JSON.parse'd into object and passed as Mongo find selector -> NoSQL operator injection with file_refs index.js:24 [refs: `index.js:24`] | unauthenticated network client -> Express handler -> MongoDB query | Login credentials (login collection: email + plaintext password), Session integrity + session secret ('Your secret key') |
| GET /getdata?id= | Query id JSON.parse'd then used as {id:id} selector on users collection -> NoSQL/JS-operator injection with file_refs index.js:77 [refs: `index.js:77`] | unauthenticated network client -> Express handler -> MongoDB query | User PII records (users collection: name, password, age, id) |
| GET /a3sensitive?id= | Query id parseInt'd then find({id}) on users, result echoed as {cmd, search:id} -> sensitive-data exposure with file_refs index.js:95 [refs: `index.js:95`] | unauthenticated network client -> Express handler -> MongoDB | User PII records (users collection: name, password, age, id) |
| GET /a3sensitive_header | No input; handler serializes full req.headers to response body -> header/cookie/session disclosure with file_refs index.js:110 [refs: `index.js:110`] | unauthenticated network client -> Express handler (request metadata becomes response) | Session integrity + session secret ('Your secret key') |
| GET /a4xxe?id= | Query id accepted but currently ignored; handler parses hardcoded XML with xmldom/xpath.js -> stubbed XXE/XPath surface with file_refs index.js:114 [refs: `index.js:114`] | unauthenticated network client -> XML parser (xmldom/xpath.js) | Server process integrity (Node.js code execution via exec/eval/deserialize) |
| POST /insecure_dor | Body accountno used verbatim as {accountno:accno} selector, no ownership check -> IDOR / NoSQL injection across accounts with file_refs index.js:133 [refs: `index.js:133`] | unauthenticated network client -> Express handler -> MongoDB (cross-user object access) | Bank account records (a5_insecure_dor: name, accountno, accounttype) |
| GET /ping?id= | Query id string-concatenated into 'ping '+id passed to child_process.exec -> OS command injection, stdout+stderr reflected with file_refs index.js:147 [refs: `index.js:147`] | unauthenticated network client -> Node process -> OS shell | Server process integrity (Node.js code execution via exec/eval/deserialize), Service availability (Node on :3000 + MongoDB xvna) |
| GET /xss_r?id= | Query id used as {name:id} cart lookup and echoed as search:id; Angular controller renders search via $sce.trustAsHtml -> reflected XSS with file_refs index.js:158 [refs: `index.js:158`] | unauthenticated network client -> Express+Mongo -> browser DOM (explicit trustAsHtml bypasses escaping) | Shopping-cart records (cart collection queried by name), Session integrity + session secret ('Your secret key') |
| POST /a6_misconfig | Body accountno JSON.parse'd then used as selector -> NoSQL operator injection, errors echoed as JSON with file_refs index.js:174 [refs: `index.js:174`] | unauthenticated network client -> JSON.parse -> MongoDB query | Bank account records (a5_insecure_dor: name, accountno, accounttype) |
| GET /eval?id=&id2= | Query id+id2 concatenated and passed to eval(); result echoed as {cmd}; function-scope secret variable present -> server-side JS injection with file_refs index.js:194 [refs: `index.js:194`] | unauthenticated network client -> Node eval runtime | Server process integrity (Node.js code execution via exec/eval/deserialize), Hardcoded/default secrets (eval secret 'impraveensingh', default admin@xvna.com/password) |
| POST /insecure_deserialization | Body userid stringified into object, serialize.serialize then serialize.unserialize (node-serialize 0.0.4) + cart lookup -> insecure deserialization RCE with file_refs index.js:203 [refs: `index.js:203`] | unauthenticated network client -> node-serialize deserializer -> MongoDB | Server process integrity (Node.js code execution via exec/eval/deserialize), Shopping-cart records (cart collection queried by name) |
| POST /service_logout + POST /service_login | Session destroy + redirect; reads req.session.user with no authz check with file_refs index.js:55, index.js:66 [refs: `index.js:55`, `index.js:66`] | authenticated/unauthenticated client -> session store | Session integrity + session secret ('Your secret key') |
| GET * catch-all + express.static | Catch-all returns static string for any unmatched GET; static middleware serves public/ frontend with file_refs index.js:5, index.js:236 [refs: `index.js:5`, `index.js:236`] | network client -> Express router | Service availability (Node on :3000 + MongoDB xvna) |
| Supply chain: package.json dependencies | No lockfile; loose ranges (^) plus pinned-vulnerable node-serialize 0.0.4, mongoose 4.x, xmldom/xpath libs; install-time code execution and known-vuln deps with file_refs package.json:11 [refs: `package.json:11`] | upstream npm registry / vendored code -> build/install -> runtime | Server process integrity (Node.js code execution via exec/eval/deserialize) |
| Supply chain / data seed: MongoDB + collection/*.json | Local unauthenticated MongoDB mongodb://localhost:27017/xvna seeded from checked-in JSON dumps containing plaintext passwords and account numbers with file_refs index.js:7, collection/login.json:1 [refs: `index.js:7`, `collection/login.json:1`] | checked-in seed files + local DB -> application trust (no DB auth) | Login credentials (login collection: email + plaintext password), User PII records (users collection: name, password, age, id), Bank account records (a5_insecure_dor: name, accountno, accounttype) |
| server-side template rendering | Template engine evaluating dynamic views with server and user variables | untrusted template variables → template engine runtime | server process integrity, application data |

### Trust Boundaries & Assumptions

Trust defaults (deterministic):
- **UNTRUSTED**: Network input, HTTP request bodies/parameters, query strings, headers, file uploads, and template variables rendered from user data.
- **TRUSTED (by default)**: Authenticated administrative clients, local configuration files, and vendored dependencies unless explicitly modeled as an attack surface.

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker compromises the server via known-vulnerable dependencies or checked-in plaintext seed credentials to gain pre-auth control | supply_chain | Supply chain: package.json dependencies, Supply chain / data seed: MongoDB + collection/*.json | Server process integrity (Node.js code execution via exec/eval/deserialize), Login credentials (login collection: email + plaintext password) | critical | almost_certain | unmitigated | none | collection/login.json:3 [Default hardcoded admin credentials in seed data]; index.js:40 [Plaintext credentials written to logs in login handler] |
| T2 | Attacker executes arbitrary OS commands via shell-concatenated ping input to take over the Node process | remote_unauth | GET /ping?id= | Server process integrity (Node.js code execution via exec/eval/deserialize), Service availability (Node on :3000 + MongoDB xvna) | critical | almost_certain | unmitigated | none | index.js:152 [Missing authentication on GET /ping (pre-auth command execution)] |
| T3 | Attacker executes arbitrary server-side JavaScript via eval concatenation or node-serialize deserialization to take over the process | remote_unauth | GET /eval?id=&id2=, POST /insecure_deserialization | Server process integrity (Node.js code execution via exec/eval/deserialize), Hardcoded/default secrets (eval secret 'impraveensingh', default admin@xvna.com/password) | critical | almost_certain | unmitigated | none | index.js:202 [Server-side JavaScript injection (eval) RCE via /eval]; index.js:207 [Missing authentication on POST /insecure_deserialization (pre-auth deserialization)]; index.js:218 [Insecure deserialization RCE via node-serialize] |
| T4 | Attacker injects MongoDB query operators via login and account lookup inputs to bypass authentication and read arbitrary records | remote_unauth | POST /api/users (login), GET /getdata?id=, POST /insecure_dor, POST /a6_misconfig | Login credentials (login collection: email + plaintext password), User PII records (users collection: name, password, age, id), Bank account records (a5_insecure_dor: name, accountno, accounttype) | critical | almost_certain | unmitigated | none | index.js:44 [NoSQL injection login bypass]; index.js:81 [Missing authentication on GET /getdata user lookup]; index.js:198 [Missing authentication on GET /eval (pre-auth code execution)] |
| T5 | Attacker hijacks sessions via reflected XSS with explicit trustAsHtml and header/cookie echo to steal credentials | remote_unauth | GET /xss_r?id=, GET /a3sensitive_header | Session integrity + session secret ('Your secret key'), Shopping-cart records (cart collection queried by name) | high | almost_certain | unmitigated | none | public/app/js/controllers/a7_xss_reflected.js:10 [Reflected XSS via /xss_r echoed search + explicit trustAsHtml bypass]; index.js:48 [Session fixation: no session regeneration after login] |
| T6 | Attacker reads or traverses other users bank and PII records by bypassing missing ownership and authorization checks | remote_unauth | GET /a3sensitive?id=, POST /insecure_dor, POST /service_logout + POST /service_login | User PII records (users collection: name, password, age, id), Bank account records (a5_insecure_dor: name, accountno, accounttype), Session integrity + session secret ('Your secret key') | high | almost_certain | unmitigated | parseInt(id) coercion in GET /a3sensitive before Mongo find (index.js:~102) — limits but does not eliminate injection | index.js:142 [Missing authorization (IDOR) on POST /insecure_dor bank lookup] |
| T7 | Attacker abuses XML/XPath parsing via XXE input to exfiltrate files or exhaust the parser | remote_unauth | GET /a4xxe?id= | Server process integrity (Node.js code execution via exec/eval/deserialize) | high | rare | unmitigated | none |  |
| T8 | Attacker exhausts server resources or acts without attribution via unauthenticated endpoints with no logging, limits, or session protections | remote_unauth | GET * catch-all + express.static, Supply chain / data seed: MongoDB + collection/*.json, POST /service_logout + POST /service_login | Service availability (Node on :3000 + MongoDB xvna), Session integrity + session secret ('Your secret key') | medium | possible | unmitigated | express-session session cookie set on successful POST /api/users with hardcoded secret 'Your secret key'; no audit logging |  |
| T9 | Security compromise via Denial of service via hanging GET /a4xxe handler (no response sent) | remote_unauth | index.js | application data and system state | medium | almost_certain | unmitigated | none | index.js:119 [Denial of service via hanging GET /a4xxe handler (no response sent)] |
| T10 | Security compromise via NoSQL operator injection in GET /getdata via JSON.parse | remote_unauth | index.js | application data and system state | critical | almost_certain | unmitigated | none | index.js:83 [NoSQL operator injection in GET /getdata via JSON.parse]; index.js:179 [NoSQL injection + verbose error disclosure in POST /a6_misconfig] |
| T11 | Information disclosure of sensitive application or configuration data | remote_unauth | index.js | application data and system state | high | almost_certain | unmitigated | none | index.js:106 [Sensitive data exposure (plaintext passwords) in GET /a3sensitive] |
| T12 | Security compromise via Uncaught JSON.parse exception enables DoS in login handler | remote_unauth | index.js | application data and system state | medium | almost_certain | unmitigated | none | index.js:31 [Uncaught JSON.parse exception enables DoS in login handler] |

## 5. Deprioritized

| threat | reason |
|---|---|
| Full XXE file exfiltration via attacker-controlled XML upload | Functionality is stubbed in current code (hardcoded XML, id parameter ignored at index.js:114); retained as low-likelihood parser-hardening concern but parked behind active RCE and injection classes. |
| Path traversal via catch-all/static middleware to read server files | Catch-all returns a static string and express.static serves only public/ frontend; no directory traversal primitive found in code, so parked behind active injection/RCE. |

A threat model prioritizes, it never excludes: a parked row is not a scope decision, and absence from section 4 is never grounds to skip a class.

## 6. Open questions

- Is this deployment network-reachable, and by whom?
- Who supplies the inputs each entry point receives?
- Which controls (WAF, sandbox, size limits, authz) sit upstream?
- Which threats should be parked in section 5, and why (a threat model prioritizes, it never excludes)?
- No Dockerfile, k8s manifests, Terraform, or CI workflows found in-repo: what is the production hosting/identity model and is MongoDB auth/network isolation provided externally?
- Session management: where is session store (default MemoryStore?) and session-cookie flags (HttpOnly/Secure/SameSite) — none set in index.js?
- Is /a4xxe intentionally stubbed (hardcoded XML, id unused) or is the vulnerable XXE path in git history / another branch?
- How are MongoDB credentials/access controlled — connection string is unauthenticated localhost; who can reach :27017?
- Is there any supported-deployment scope, given README explicitly warns not to host online and no SECURITY.md exists?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-04
- target: realvuln-xvna
- inputs: indexer signals (routes/prefilter) + day-one docs + git fix history + swarm research (surfaces/assets/controls) + git-history classification
- owner: unset
- enrichment: llm-swarm
- stored scan signals:
  - prefilter: .cerberus/realvuln-xvna/signals/prefilter.txt (54 entries)
  - secrets: .cerberus/realvuln-xvna/signals/secrets.json (1 entries)
  - sca: .cerberus/realvuln-xvna/signals/sca.json (1 entries)
  - iac: .cerberus/realvuln-xvna/signals/iac.json (1 entries)
  - codegraph-index: .cerberus/realvuln-xvna/signals/codegraph-index.txt (1 entries)
## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Enforce parameterized/typed Mongo queries everywhere: forbid JSON.parse of input into selectors and reject objects containing $ / operators | T4,T6 | yes | M |
| Remove shell, eval, and unsafe deserialization primitives: replace exec with execFile allowlist, delete eval endpoint, replace node-serialize with JSON | T2,T3 | yes | M |
| Enforce output encoding and session hardening: remove trustAsHtml, set HttpOnly/Secure/SameSite cookies, rotate strong session secret, add ownership checks | T1,T6 | partial | M |
| Pin, lock, and upgrade dependencies and isolate datastore: add lockfile, remove node-serialize/xmldom vuln versions, require MongoDB auth and remove plaintext seed secrets | T5,T7 | partial | M |
| Add authenticated logging, rate-limiting, and resource caps: structured audit log for auth/data access, throttling on ping/eval/deserialize paths | T2,T3,T8 | partial | M |

## Observed findings

Last validator-confirmed scan: 2026-11-04 (realvuln-xvna).
Confirmed primary claims: 17.

By class: CWE-306 x4, CWE-943 x3, CWE-94 x1, CWE-639 x1, CWE-798 x1, CWE-400 x1, CWE-79 x1, CWE-200 x1, CWE-532 x1, CWE-502 x1, CWE-248 x1, CWE-384 x1

Affected paths: index.js x15, collection/login.json x1, public/app/js/controllers/a7_xss_reflected.js x1

## Scope proposals

Machine-generated candidates from verified findings — promote by adding a threat row above; scans never apply these themselves.

Consider adding a threat row for: CWE-200 x1, CWE-248 x1, CWE-306 x4, CWE-384 x1, CWE-400 x1, CWE-502 x1, CWE-532 x1, CWE-639 x1, CWE-79 x1, CWE-798 x1, CWE-94 x1, CWE-943 x3

## Known false positives

Disproven in past scans — do not re-report without new evidence.

- CWE-79 x9 at public/app/partials/a1_injection.html, public/app/partials/a1_injection_sql.html, public/app/partials/a3_sensitive.html, public/app/partials/a4_xxe.html, public/app/partials/ui-login.html — heuristic: form + {{ }} co-occurrence | validator: public/app/partials/a1_injection.html:24 {{alldata}} is client-side Angular interpolation; index.js:5 serves public/ via express.static with no view 
- CWE-200 x1 at index.js — index.js:114-116 app.get('/a3sensitive_header') does res.send(JSON.stringify(req.headers)) with no auth; reflects cookies, authorization headers, session IDs to any caller | validator: index.js:116 re
- CWE-798 x1 at index.js — index.js:199 declares function-scope secret assigned string literal in GET /eval handler; reachable and visible in source; combined with eval RCE allows secret theft | validator: index.js:199 secret="
- CWE-352 x1 at index.js — index.js:1-22 shows no csurf/csrf middleware, no SameSite/secure cookie flags; index.js:72 handler destroys session on cross-site cookie-authenticated POST with no token check; login sets req.session.
