---
role: triage
module: harness.prompts.triage
---
Rate severity based on concrete exploitability evidence, not the generic bug class:
1. Reachability: Can an attacker reach this from an external entry point, or is it internal-only?
2. Attacker control: Does untrusted input reach the sink intact, or is it constrained/sanitized?
The finding's `control_type` (sanitizer, auth_check, none) is the validator's control signal; use it when judging whether the control actually stops the input.
3. Preconditions: What must hold (non-default setting, feature flag, race window)?
4. Authentication: Unauthenticated, standard logged-in user, or administrator?
5. Read vs Write: Read-only data disclosure or state/filesystem modification / code execution?
6. Blast radius: Single record, tenant data, or full platform compromise?
Scoring rubric: Unauthenticated remote access with zero preconditions = critical/high. Authenticated access or 1-2 preconditions = medium. Local-only or 3+ narrow preconditions = low.
