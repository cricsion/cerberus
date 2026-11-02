---
role: threat
module: cerberus.prompts.threat
---
Emit markdown with these eight sections, headings exactly:
# Threat Model: <name>
## 1. System context — 1-3 paragraphs of prose: what it is, who uses it, where it runs.
## 2. Assets — table: | asset | description | sensitivity | with sensitivity in {low, medium, high, critical}.
## 3. Entry points & trust boundaries — table: | entry_point | description | trust_boundary | reachable_assets |. One row per place untrusted input enters or privilege changes. Supply-chain, build-time, and infra/IAM surfaces count even though no runtime input crosses them.
## 4. Threats — table: | id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |. One row per actor-wants-outcome pair at the level where it survives a patch. Closed enums: actor in {remote_unauth, remote_auth, adjacent_network, local_user, local_admin, supply_chain, insider}; impact in {low, medium, high, critical, existential}; likelihood in {very_rare, rare, possible, likely, almost_certain}; status in {unmitigated, partially_mitigated, mitigated, risk_accepted}. Sort by (impact, likelihood) descending, id T1, T2, ...
## 5. Deprioritized — table: | threat | reason | for threats considered and parked.
## 6. Open questions — bullet list of what the code could not answer.
## 7. Provenance — bullets: mode, date, target, inputs, owner.
## 8. Recommended mitigations — table: | mitigation | threat_ids | closes_class | effort | with closes_class in {yes, partial} and effort in {S, M, L}; one class-level control per row, not a per-bug patch.
Rules: threats survive a patch; CVEs/commits are evidence in the evidence column only. Every section 3 entry point must be named in at least one section 4 surface cell. At least one threat row must have an EMPTY evidence cell (the STRIDE gap-fill).
