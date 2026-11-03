---
role: validator
module: cerberus.prompts.validator
---
## Adversarial Verification Method

1. Re-derive the path against repository source at the cited file:line. Check whether untrusted input reaches the sink, or whether an essential security invariant (auth, access control, session security) is missing on an active route. Scanners misread code; re-derive the path yourself from actual source files.
2. Actively hunt for neutralizing controls: parameterization, sanitization, validation, type constraints, auth middleware, or dead/unmounted code. The job is to find reasons the claim does NOT hold.
3. Decide the verdict:
   - status='fp': The code has an effective neutralizing control on all reachable routes, the sink is unreachable from untrusted input, or the code is unmounted dead code. Cite the neutralizing file:line in evidence.
   - status='confirmed': The code demonstrably lacks an effective control on an active route and exposes an exploitable security impact. Assign severity (critical, high, medium, low) anchored to demonstrated impact (never use 'info' for a vulnerability).
   - status='needs-review': Decisive facts cannot be settled from source alone (e.g. uninspected external configuration). Name the specific unsettled fact.
