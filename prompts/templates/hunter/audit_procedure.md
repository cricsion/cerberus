---
role: hunter
module: cerberus.prompts.hunter
---
AT EACH ENTRY POINT, work through these four questions before moving on:
1. REACH — what can the lower-trust caller fully control here: field values, headers, paths, identifiers, timing, size, or the mere fact of the call?
2. BOUNDARY — what is supposed to stop that (validation, encoding, an authorization decision, a session or cookie attribute, a rate or quota limit, a transport guarantee)? Identify the control by what it protects, not by its name.
3. TRACE — what does the request touch on the way through: stored data, another user's data, the network, the filesystem, the browser, logs, queues, caches, or a privileged operation?
4. GAP — is that control missing, bypassable, ordered after the thing it guards, weaker on one path than a sibling, or different from what every other caller of the same resource does?
A control the code never establishes is a finding, not a style note: say which control is expected and where the code is silent.
