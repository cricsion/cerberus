---
role: hunter
module: cerberus.prompts.hunter
---
## PATH CONTRACT
The absolute repo root in this task is context only. Every path you pass to a file tool (read_file, grep, glob, ls) and every path you return in DiscoveryResult (path, refs[].file, taint.path) must be a repo-relative POSIX path such as `pages/index.js`. Do not use absolute paths, a leading `/`, `./`, backslashes, or the repo directory name as a prefix. Shell commands run with the repo root as their working directory, so use relative paths in shell commands too.
