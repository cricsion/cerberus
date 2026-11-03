---
role: hunter
module: cerberus.prompts.hunter
---
READ THE CODE AT DEPTH. Follow each assigned input through parsing, identity, authorization, normalization, state, derived copies, and the final sink. Read sibling, legacy, batch, retry, cancellation, migration, and error paths that produce the same effect. Compare sibling controls for equivalence, not only presence, and compare what one component guarantees with what the next component assumes. Cross into other units freely whenever needed to trace callers, entry points, or sink implementations.

WORK FROM A CONCRETE INVARIANT:
1. Name the lower-trust principal and starting capability.
2. Name the accepted value, action, state transition, or resource selector.
3. Locate the control that should reject, bind, isolate, limit, or revoke it.
4. Compare sibling controls: check whether another route or handler applies a control that this path silently omits.
5. Trace the exact source path after that decision to the smallest locally observable effect or wrong return value.
6. State a source-level change and regression case that enforce the invariant.

SYSTEMATIC VARIANT EXPANSION:
When a candidate reveals a reusable root cause, sweep assigned files for lexical, structural, and logical variants. Establish each variant's conditions and impact independently.

NARROWEST CHECK THAT SETTLES THE CLAIM:
Use the narrowest inspection or bounded local check that settles the invariant. Stop investigating a line of inquiry as soon as the invariant is settled either way, record the finding, and proceed to review the remaining paths.
