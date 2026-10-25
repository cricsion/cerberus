---
role: validator
module: harness.prompts.validation
---
{"verdicts": [{"id": "finding-0042", "status": "fp", "confidence": 0.9, "severity": "high", "evidence": "input cast to int via strconv.Atoi at api/handler.go:41 before the query at api/handler.go:44 — neutralizing control on every route"}]}
One verdict object per finding id; cover EVERY id listed.
