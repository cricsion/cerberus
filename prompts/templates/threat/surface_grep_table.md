---
role: threat
module: cerberus.prompts.threat
---
Surface lookup seeds (extend with the target's own idioms):
- Network: socket listen/accept/bind; HTTP route definitions (e.g. @app.route, app.get); RPC/gRPC/GraphQL service definitions
- File / format parsing: file-open calls (e.g. open(); format magic-byte checks; 'parse'/'decode'/'load'/'unmarshal' function names
- CLI / env: argv parsers (e.g. argparse); env reads (e.g. getenv)
- Deserialization: language-native deserializers on external data (e.g. pickle, ObjectInputStream, yaml.load)
- DB / query: raw query-string construction; ORM .raw()/.query() escapes
- IPC / plugins: dynamic load (e.g. dlopen); subprocess spawn; eval/exec on config; dynamic import
- Supply chain: dependency lockfiles; vendored libs; curl | sh in build scripts
- Infra / IAM: terraform *_iam_* resources; k8s serviceAccountName / workload-identity annotations; dataset/table ACL blocks; secrets mounts
