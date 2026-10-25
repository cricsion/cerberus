---
role: partition
module: harness.partitioning.prompts
---
## Goal
Partition this repository into cohesive, independently reviewable units for parallel security hunters. Keep files together when they implement the same capability or connected trust-sensitive flow, even when they sit in different directories. Separate distinct capabilities or input subsystems when different hunters can review them without repeatedly covering the same code.

## Evidence and boundary choices
Use the supplied inventory and metadata first, and use your tools to inspect files and graph relationships where ownership is ambiguous. Prefer explicit service, package, route, protocol-dispatch, and deployment boundaries; then use graph/coupling and shared-domain clues; use directory names only as a fallback.
Keep related entry points, handlers, services, and persistence paths for one feature together. Do not split a feature into generic controller, service, and model layers. Auth, admin, parsers, and APIs can be valid units when they form distinct capabilities or trust boundaries. Treat migrations, IaC, CI, and build/release files as security-relevant: attach them to their owning feature when clear, otherwise group them into a named infrastructure or release unit when they define a distinct boundary. Attach tests, fixtures, docs, and ordinary support files to the feature they describe; do not create a generic docs-only unit.

Prefer broader feature domains over fine-grained micro-units. Never create units with fewer than 5 files unless the entire repository has fewer than 5 files. Merge tiny shards directly into the nearest owning feature unit.

## Coverage and size
Assign every listed path to exactly one unit. Use only exact paths from the inventory; do not invent, omit, or duplicate paths. For a file with unclear ownership, choose its closest feature or a clearly named shared support unit and explain the choice briefly. Avoid both one-unit-per-file fragmentation and catch-all units that mix unrelated capabilities. Do not exceed {{ max_units }} units, but do not force a minimum count or split coherent features to reach a target. If the cap requires combining boundaries, combine the most closely related ones and state the tradeoff in the rationale. Deterministic code will enforce final coverage and size limits, but your proposal should already cover the inventory.

## Repository inventory and signals
{{ ctx }}

## Output
Return exactly this JSON shape, with no prose or markdown fences: {"units": [{"name": "short-kebab-name", "files": ["exact paths from the list above"], "rationale": "one sentence citing the structural clues for this grouping"}]}
