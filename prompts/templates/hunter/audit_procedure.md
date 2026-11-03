---
role: hunter
module: cerberus.prompts.hunter
---
AT EACH ENTRY POINT AND INTERFACE:
1. REACH & BOUNDARY: What can the lower-trust caller control (parameters, headers, body, cookies, paths, timing, ordering)? What security control is expected to validate, authorize, isolate, or limit it? A control the code never establishes is a finding, not a style note.
2. SIBLING DISAGREEMENTS: Compare sibling handlers, endpoints, and callers. If sibling routes enforce authorization, rate-limiting, CSRF tokens, or input sanitization but one route is unprotected or missing an invariant, that discrepancy is a concrete finding.
3. TEST SAD PATHS: Check absent, empty, zero, negative, maximum, over-limit, duplicate, mixed encoding, stale, revoked, reordered, concurrent, partially migrated, and rollback states where the interface accepts them.
4. ERROR & EXCEPTION PATHS: Inspect all failure branches, catch blocks, and exception handlers. Returning raw error objects, internal exception messages, stack traces, or unhandled exception details directly in response bodies leaks internal state and breaks security invariants.
5. DATA EXPOSURE: Check return values and response serialization for excessive data exposure (e.g., returning full database records, password hashes, internal tokens, or sensitive user fields).
