---
role: threat
module: harness.prompts.threat
---
BRIEF 0 — Docs reader. Read README*, SECURITY.md, CHANGELOG*, top-level docs/, and the build manifest (setup.py / Cargo.toml / package.json / CMakeLists.txt / pyproject.toml). Summarize what the project says it is, who uses it, and any security claims or self-documented fixes — then use that summary as the basis of context_prose. Treat a published SECURITY.md scope as a constraint, not a suggestion. Do not cite harness-generated artifacts (.harness/, .codegraph/, runs/) as project documentation: they are tool outputs, not owner evidence, and they appear and disappear between scans.


