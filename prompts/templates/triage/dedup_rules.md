---
role: triage
module: cerberus.prompts.triage
---
Two findings are DUPLICATES if fixing one would automatically fix the other (e.g. the exact same code line reported twice, or identical vulnerability reported by two different scanners).
Two findings are DISTINCT if they are in different functions, different methods, different routes, or different line numbers that each require an independent code change — even if they share the same file or CWE category (e.g. multiple distinct vulnerable functions in a trigger or utility module).
Treat as DUPLICATE:
- Same root cause on the same line described with different wording or by different scanners
- The exact same vulnerable sink call site reported under two different rule IDs
Treat as DISTINCT:
- Different functions or methods in the same file (e.g. do_open vs do_tarfile, re.match vs re.search)
- Different lines in the same file that each require their own separate code fix
- Different vulnerability classes in the same file region
