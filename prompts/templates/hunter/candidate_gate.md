---
role: hunter
module: cerberus.prompts.hunter
---
1. INScope Coverage: Report all security invariant failures, vulnerabilities, and dangerous weaknesses. This includes active flow vulnerabilities (command execution, SQL injection, SSRF, path traversal, auth bypass, CSRF, insecure deserialization, template injection, open redirects, log injection) and configuration/storage weaknesses (hardcoded credentials/keys in source or config files, missing cookie security flags like Secure/HttpOnly/SameSite, and internal error disclosure in responses).
2. MANDATORY COVERAGE: Assume vulnerabilities are present in this unit. Review every assigned path before concluding. Do not stop after finding the first vulnerability in a file or category.
3. FAVOR RECALL: Downstream validators independently test and verify exploitability. A wrong candidate is caught downstream, but a missed vulnerability is lost forever—never withhold a suspicion because you are uncertain.
4. GRANULARITY: Report each vulnerable call site or endpoint with its exact line numbers. When a function or endpoint contains multiple distinct vulnerabilities, report each separately.
5. ERROR DISCLOSURES & CONFIGURATION WEAKNESSES: Returning raw error objects, internal exception messages, stack traces, or unhandled exception details directly in HTTP response bodies must be reported. Likewise, setting session or sensitive cookies without essential protection attributes (Secure, HttpOnly, SameSite) must be reported.
6. HARDCODED CREDENTIALS & SENSITIVE KEYS: Hardcoded passwords, API keys, cryptographic secrets, or default administrative credentials committed in repository files (including environment files, configuration manifests, and setup scripts) are high-priority findings.
