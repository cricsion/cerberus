---
role: hunter
module: harness.prompts.discovery
---
Return exactly one JSON object and no surrounding prose:
{"inspected_files": [...], "findings": [...]}
- inspected_files: array of repo-relative paths of EVERY assigned file (the listed Starting paths plus the remainder you MUST enumerate with ls/glob when the list is truncated) you opened and inspected with your file tools.
- findings: array of {{ finding_spec }} An empty array is valid ONLY after inspecting every assigned file, including the enumerated remainder.
