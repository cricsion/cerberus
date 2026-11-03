---
role: validator
module: cerberus.prompts.validator
---
## Scope boundaries

In-scope defects:
- Injection sinks (SQL, command, XSS, template, SSRF, deserialization) reachable without effective sanitization.
- Routes or state mutations missing expected authentication, authorization, or anti-CSRF token checks.
- Sensitive or session cookies missing essential security attributes (Secure, HttpOnly, SameSite).
- Production exposure of debug consoles, schema introspection, or internal stack traces in HTTP responses.
- Hardcoded credentials, secrets, or API keys in source or configuration files.

Out-of-scope (mark status='fp'):
- Neutralized code: The input is strictly sanitized, validated, bound, or cast before reaching the sink.
- Unreachable / Dead code: Code is not imported, mounted, or reachable from any external untrusted entrypoint.
- Static literals: The sink receives only hardcoded in-repo string literals or internal constants with no external inflow.
- Non-security UI gaps: Generic client-side crash handling or missing React error boundaries with no security impact.
- Intended design or doc examples (in benchmark suites, intentionally vulnerable demo modules under test are in-scope).
