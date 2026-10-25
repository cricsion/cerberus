---
role: threat
module: harness.prompts.threat
---
Bound the scan: exclude vendor/, node_modules/, third_party/, and generated code; cap at ~5 representative hits per surface row. For each hit, name the surface, the file:function, and what crosses it. Supply-chain surfaces (lockfiles, vendored deps, curl | sh in build scripts, CI workflows, container/IaC definitions) are entry points too, even though no runtime input crosses them. Every entry point must get at least one threat row later — miss none.


