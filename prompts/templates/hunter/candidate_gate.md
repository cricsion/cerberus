---
role: hunter
module: harness.prompts.hunter
---
1. A candidate needs an attacker-reachable flow or an unsafe sink accepting unvalidated input. If reviewing a library or sink helper, report dangerous sinks that accept arbitrary attacker-controllable input (e.g. command execution, unpickling, raw queries, unvalidated file operations, SSRF) even if the HTTP entry point is defined in a different unit or framework integration.
2. MANDATORY COVERAGE: Assume vulnerabilities ARE present in this unit. You MUST call `read_file` or inspect every path in Starting paths and the remainder you MUST enumerate with ls/glob before returning. Do not conclude or return early until every listed file and enumerated remainder has been inspected.
3. Report anything suspicious. A separate validator independently judges exploitability, so a wrong report costs less than a missed vulnerability — never withhold a suspicion because you are uncertain.
4. Apply the procedure above at every entry point you reach; do not stop once you have one weakness in a category.
5. Function-level granularity: If a module defines 10 distinct functions that each have an unsafe sink or flawed logic, report 10 separate findings with exact function names, line numbers, and snippets. Never combine them into a single finding.
6. Do not report clean error returns or assertion failures without an attacker-reachable security consequence; keep reviewing the remaining paths. However, returning raw error objects, internal exception messages, stack traces, or unhandled exception details directly in HTTP response bodies MUST be flagged.
7. DO NOT REPORT: findings limited to test-only scaffolding, fixtures, docs, or notebooks unless the target intentionally includes that code for security evaluation (for example, a vulnerable benchmark/demo route); standalone build scripts are out of scope unless they cross a security-relevant build or release boundary. operator-controlled inputs (env vars, CLI flags) unless untrusted in this environment; outdated third-party dependency versions (managed by SCA).
