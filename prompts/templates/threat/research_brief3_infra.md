---
role: threat
module: harness.prompts.threat
---
BRIEF 3 — Infra reader. Read deploy-time config: terraform, k8s manifests, Dockerfile*, CI workflows, IAM/service-account/ACL files. For each, name (a) the identity the workload runs as and what that identity can reach, (b) any access grant NOT managed in this tree (ad-hoc IAM, hand-created service accounts, missing policy tags), (c) credentials or principals that survive a migration or teardown. Where an automated approval, merge, or write path exists, ask what bounds it to its intended scope (path allowlist, label, reviewer set).


