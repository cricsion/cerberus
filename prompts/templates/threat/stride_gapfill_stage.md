---
role: threat
module: harness.prompts.threat
---
STAGE 4 — Gap-fill (the part past vulns can't give you). Past vulns are biased toward what was already found. For every entry point with no threat row yet, walk STRIDE and add the plausible ones with EMPTY evidence:
- Spoofing: could an attacker pretend to be a trusted source?
- Tampering: could they modify data in transit or at rest?
- Repudiation: could they act without leaving attributable logs?
- Info disclosure: could they read data they shouldn't?
- DoS: could they exhaust a resource (CPU, memory, disk, connections)?
- Elevation: could they end up with more privilege than they started with?
For infra/IAM entry points STRIDE maps poorly — walk these instead: over-grant (identity reaches more than the app needs), lateral identity (co-located workload can assume it), drift (grant managed outside the tree), residual access (credentials surviving a migration), column exposure (broad read exposing PII), scope enforcement (what bounds an automated write path). Also walk the entry points that DO have rows: a parser with an RCE threat probably also has a DoS threat.


