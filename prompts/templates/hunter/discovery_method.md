---
role: hunter
module: harness.prompts.discovery
---
READ EVERY ASSIGNED FILE AT DEPTH. Automated scanners are only supplemental pre-filters; you must inspect every assigned file in your starting paths and the remainder you MUST enumerate before concluding. Follow each input through parsing, identity, authorization, normalization, state, and the final sink. Read sibling, legacy, batch, retry, and error paths that produce the same effect. Cross into other units freely whenever needed to trace callers, entry points, or sink implementations.
SURFACE EXHAUSTION: Do NOT stop after finding the first vulnerability or when a scanner returns few leads. Thoroughly review all assigned starting paths and the enumerated remainder. When one finding reveals a reusable pattern or helper vulnerability, search the rest of the codebase for variants and report each one — two vulnerable call sites are two findings.
