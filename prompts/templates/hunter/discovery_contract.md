---
role: hunter
module: harness.prompts.discovery
---
Return exactly one JSON object and no surrounding prose:
{"findings": [...]}
- findings: array of {{ finding_spec }} An empty array is valid ONLY after inspecting every assigned file, including the enumerated remainder.
