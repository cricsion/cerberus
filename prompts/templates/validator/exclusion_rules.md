---
role: validator
module: harness.prompts.validation
---
EXCLUSION RULES (mark status='fp' citing the rule number if any apply):
1. Test-only scaffolding, fixtures, dead code, or crashes with no security impact. Do not exclude a build, CI, IaC, or release path when it crosses an in-scope security boundary. In benchmark repositories or intentionally vulnerable demo suites, the triggers and routes being evaluated are in scope.
2. Intended application design or documentation examples. (Note: do NOT use rule 2 to dismiss purposely-vulnerable benchmark modules, demo apps, or test cases being evaluated).
3. Memory-safety concerns in memory-safe languages outside unsafe/FFI blocks.
4. SSRF where the attacker only controls URL path/query parameters, not host or protocol.
5. Operator-controlled inputs (env vars, CLI flags) unless environment specifies untrusted. (Note: mock wrappers like @mock_connection used to prevent outbound test traffic are test scaffolding, not sanitizers; evaluate whether the underlying function sink is vulnerable).
6. Client-side code flagged for server-side vulnerability classes.
7. Outdated dependency versions (SCA concern, not source vulnerability).
8. Weak randomness used for non-security purposes (UUIDv4, jitter, UI colors, math). In benchmark targets where PRNG weaknesses are under test, flag the weak primitive.
9. XSS in frameworks with context-aware auto-escaping (React/Angular/Vue/Jinja2 autoescape=on) without raw HTML escape hatches.
10. Unguessable identifiers (UUIDv4, 128-bit cryptographic tokens) flagged as predictable.
11. Purely theoretical race conditions / TOCTOU with no realistic race window.
12. Purely static/hardcoded string literals, constants, or internal demo data with no untrusted external source reaching the sink. Mark status='fp' with refute_reason='not_a_vulnerability' (e.g., dangerouslySetInnerHTML, innerHTML, or eval() receiving a hardcoded string literal alert('...') with no attacker input).
13. Architectural best-practice gaps or defense-in-depth observations without a concrete, viable exploit primitive or attacker-controlled entry point (e.g., missing React error boundaries [CWE-248], missing generic CSP headers [CWE-1021], storing non-sensitive session flags in localStorage [CWE-922] without XSS, unhandled generic runtime exceptions causing client-only reload). Mark status='fp' with refute_reason='not_a_vulnerability' or downgrade severity to 'info'.
