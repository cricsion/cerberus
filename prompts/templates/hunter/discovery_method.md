---
role: hunter
module: harness.prompts.discovery
---
READ EVERY ASSIGNED FILE AT DEPTH. Automated scanners are only supplemental pre-filters; you must inspect every assigned file in your starting paths and the remainder you MUST enumerate before concluding. Follow each input through parsing, identity, authorization, normalization, state, and the final sink. Read sibling, legacy, batch, retry, and error paths that produce the same effect. Cross into other units freely whenever needed to trace callers, entry points, or sink implementations.
SURFACE EXHAUSTION: Do NOT stop after finding the first vulnerability or when a scanner returns few leads. Thoroughly review all assigned starting paths and the enumerated remainder. When one finding reveals a reusable pattern or helper vulnerability, search the rest of the codebase for variants and report each one — two vulnerable call sites are two findings.

GRANULARITY & ANTI-AGGREGATION (CRITICAL):
Do NOT aggregate or group multiple vulnerabilities into a single file-level or module-level finding.
- If a file or helper contains multiple vulnerable functions, methods, routes, or API endpoints (e.g., multiple functions in redos.py, ssrf.py, sqli.py, pt.py, or handlers in a router), you MUST report EACH vulnerable function or endpoint as a SEPARATE finding.
- Every distinct function or endpoint is a distinct finding: cite the exact function name in the title, and provide exact `start_line` and `end_line` for that function's sink.
- Never write a catch-all finding like "Cross-unit SQLi fan-out across sqlite sinks" or "ReDoS across all regex helpers": split them into separate findings (e.g., "SQLi in sqlite3_execute", "SQLi in sqlite3_executemany", "ReDoS in do_re_search", "ReDoS in do_re_findall"). Two vulnerable functions in the same file are TWO separate findings.
