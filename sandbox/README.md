# Scan sandbox backends (operator setup)

Set `sandbox.backend` in `config/default.yaml` (or `SANDBOX_BACKEND`) to pick
the execution environment for hunter agents. All modes keep the same harness
posture: no subagent recursion, no `write_file`/`edit_file`/`delete`,
file tools confined to the target repo, and the shell (when it exists) is
the only extra capability.

| mode | file tools | shell | boundary |
|---|---|---|---|
| `local` (resolver fallback) | in-process, repo-confined | none | path containment |
| `docker` (app-config default) | in-process, repo-confined | `execute` | one network-full container per run |
| `sbx` | in-process, repo-confined | `execute` | one microVM per run |

## local

No setup.

## docker

Build the scan-toolchain image (pins live in `versions.env`):

```bash
cp docker/versions.env.example docker/versions.env   # fill versions + sha256s
./docker/build.sh cyber-sandbox:local
```

Requires Docker Desktop running. The repo is bind-mounted **read-only** at
its absolute path; the container gets no host mounts and no host env. Only
paths under Docker Desktop's file sharing work.

### Scan toolchain (image contents)

Everything below is **image-only**: never installed on the host, so there is
no host-side wrapper to keep in sync and no binary the agent cannot reach.
The agent runs them through `execute`; usage is documented in the skills at
`/opt/harness-skills/<name>/SKILL.md`, served to the agent by the skills
route on its backend (`harness/agents/deep.py`). Pins and per-arch
sha256s live in `docker/versions.env` and are verified at build (a mismatch
fails the build).

| tool | role | engine lineage |
|---|---|---|
| `semgrep` | pattern + taint rules | Semgrep Inc., upstream |
| `opengrep` | pattern + taint rules (same rule format) | fork of Semgrep 1.100.0 |
| `bandit` | Python-specific AST checks | pip |
| `gosec` | Go security specialist | static binary |
| `njsscan` | Node/JS-specific rules | pip (bundles semgrep) |
| `flawfinder` | C/C++ pattern checks, CWE-tagged | pip |
| `bearer` | dataflow + privacy/PII flows | static binary |
| `trufflehog` | verified secrets (current tree, `--no-update`) | static binary |
| `atheris` | Python fuzzing — **proves** a finding, not a scanner | pip |
| `gitleaks` | fast secret regex (indexer path, host-side wrapper) | — |
| `osv-scanner` | dependency vulns (needs osv.dev egress) | google |
| `checkov` | IaC (indexer path, host-side wrapper) | bridgecrew |

The first nine are **agent-driven** (run per unit via `execute`, one skill
each under `harness/skills/`); the last three are indexer wrappers that run
in the harness process on the host and degrade gracefully when their binary
is absent. `bandit`/`njsscan`/`atheris`/`flawfinder` ride the pip line with
`semgrep`/`checkov`; `gosec`/`bearer`/`trufflehog` are release binaries with
per-arch sha256 verification.

Considered and deliberately **not** shipped: `weggli` and KICS (no release
binaries/assets to sha256-verify — a Rust toolchain or a Docker-only
distribution would be required), and the language tools that would need
their runtime added to the image (brakeman/Ruby, psalm/PHP,
spotbugs/JVM, security-code-scan/.NET). Re-add is one ARG block + one
versions.env pin each if a target mix demands them.

### Network egress (`sandbox.network`)

| value | posture |
|---|---|
| `bridge` (default) | full egress: pip/npm/git fetch, semgrep registry packs, uploads |
| `none` | no egress at all: only the preinstalled toolchain |

`host` is refused: it would join the host's network namespace.

**With egress on, treat everything the agent can read as exfiltrable** — the
repo, and any credential file inside it (a target repo that is the harness
checkout exposes its own `.env` with the live API key). The command deny-list
does not hold this boundary (`python -c 'import socket...'` fetches with the
same bytes curl would). Set `sandbox.network: none` when that is not
acceptable. Unknown commands are passed to the sandbox without a quick
refusal; the sandbox provides containment.

**Credential files are masked, not just noticed**: Docker places a read-only
`/dev/null` bind over each detected file's in-repo resolved target, so a
credential-named symlink does not expose its destination. Reads return EOF;
writes fail on the read-only bind. Only Docker can mask paths this way — sbx
mounts the workspace whole and can only warn. The mask cannot be a tmpfs:
tmpfs mounts onto directories only, and Docker refuses the whole container
("not a directory") when a plain-file credential is masked.

### Orphans from a killed run

A harness that EXITS reaps its sandbox (CLI `finally`, `atexit`, SIGTERM). A
harness that is **SIGKILL'd** — `kill -9`, a host OOM-kill, power loss — runs
none of that, so its sandbox outlives it: a container nobody uses, or an idle
microVM costing host CPU. Local sandboxes never expire on their own
(`sbx settings list` has no TTL — that is cloud-only), so something has to reap.

**The operator's answer is `sbx prune`**, which the CLI documents as *"safe to
run habitually"* because it only ever removes **stopped** sandboxes (idle
sandboxes auto-stop, and the next `sbx exec` restarts one in under a second):

```bash
sbx prune --filter until=168h     # remove anything stopped over a week ago
sbx prune --dry-run               # see what it would take first
```

Docker has no equivalent for a *running* container, so the label is the
operator's handle there:

```bash
docker ps --filter label=cyber.agent.sandbox=run
docker rm -f <name>
```

**The harness's own sweep** runs at scan start (`sandbox.sweep_orphans`,
default on) and is name-scoped, so it never touches a sandbox this harness did
not create. It also spares any run still alive on this machine — any harness
process, not just this one — and both backends establish that from what their
daemon already publishes, because both publish it:

| | liveness signal | query |
|---|---|---|
| `sbx` | `last_used_at` per sandbox (advances on every exec) | `sbx ls --json` |
| `docker` | `exec_start` events, one per command the daemon ran | `docker events --filter container=NAME` |

So the rule is the same on both: our name pattern, not one this process owns
(that is what protects a concurrent scan — the registry, checked before any
age), and idle past `ORPHAN_IDLE_SECONDS` (6h — longer than any live run's
quiet gap, and a false positive self-heals because the sandbox is recreated on
the next command). A container or sandbox whose history the daemon can no
longer report is left alone rather than removed: never delete what you cannot
measure.

There is no harness-side liveness state anywhere — nothing to write, nothing
to forge, and nothing to lose when the harness is SIGKILL'd, which is the
whole point, since the process that would have maintained it is exactly the one
that died. The name pattern is also the only thing keeping the sweep off a
sandbox this harness did not create, so it is not a security boundary either.

**What a SIGKILL'd run leaves, and where it goes:** `sbx rm` deletes a
sandbox's state, Git worktrees and scoped secrets, but never the throwaway
workspace on the host — so a killed run leaks a pair. The sweep takes both:
each workspace is named after its sandbox, so removing a dead sandbox removes
`cyber-sbx-primary-<same id>` with it. A graceful run already removes its own
(close → `_after_close`), which is why only the kill -9 case needs this.

### One container per run, shared by every agent

Hunter units, validators, triage and the partitioner all execute inside the
**same** container: it starts on the first agent command and is removed at
scan teardown (`shutdown_run_sandbox()`, from the CLI's `finally` and an
atexit hook). Nothing per-agent survives after the run, and nothing is
carried between scans.

Shared vs per-agent:

| shared | per-agent |
|---|---|
| the container, `--memory` / `--cpus` / `--pids-limit` budget | `HOME` (`/work/agent-<agent-id>`) and `TMPDIR` (`/tmp/agent-<agent-id>`) scratch |
| the read-only repo mount | `pip install`s, temp files |
| image start / teardown | pycache: `/work/agent-<id>/.pyc` |
| package **download** caches: `/work/_shared/pip`, `/work/_shared/npm` | `close_backend()` (ends one agent's session) |

Every per-agent path is prefixed `agent-`, and that prefix is what the
best-effort phase cleanup below matches. The download caches are shared
writable directories: agents avoid duplicate downloads, while installs still
land in the installing agent's `HOME`. All agents share the same runtime
identity and can access each other's paths.

Consequences to plan for:

* `memory`, `cpus` and `pids_limit` now bound the **whole run** — 30 parallel
  agents (default `concurrency`) share one 2g budget. Raise
  `sandbox.memory` if agents thrash.
* a runaway agent (memory, pids, a stray `rm -rf` in the shared tmpfs,
  a background process) degrades **every** agent in the run; the container
  is reaped only at scan end.
* if the harness CLI is SIGKILLed, atexit does not run and the container
  leaks: sweep stale ones with
  `docker ps --filter label=cyber.agent.sandbox=run`.

### Phase reset: scratch hygiene

Between the hunter phase and the verifier phase the harness wipes the per-agent
scratchpads — and nothing else. One exec inside the same container:

```bash
rm -rf /work/agent-* /tmp/agent-*   # then exit 0
```

The shared package caches under `/work/_shared` are deliberately **kept**: they
hold wheels, not reasoning, and wiping them would only cost every later agent a
re-download.

The reset reduces accidental carryover from ordinary tool use. It removes only
the named scratch directories; it does not stop background processes or prevent
an agent with shell access from writing elsewhere in the shared container. It
is not a verifier-isolation guarantee. Strong phase separation would require a
fresh sandbox for the verifier.

Knob: `sandbox.reset_agent_scratch` (`SANDBOX_RESET_AGENT_SCRATCH`, default
on). It is a **no-op in `local` mode**, where there is no sandbox to reset.

## sbx (Docker Sandboxes)

One **microVM** per run (own kernel, own Docker daemon inside, no path to the
host), shared by every agent. Design + validated CLI facts:
`sbx-sandbox-design.md`.

Setup (once per machine):

```bash
brew install docker/tap/sbx && sbx login
sbx policy init balanced          # egress: package managers/registries allowed
docker image save cyber-sandbox:local -o /tmp/t.tar && sbx template load /tmp/t.tar
```

Then `sandbox.backend: sbx` (or `SANDBOX_BACKEND=sbx`).

What the backend guarantees:

| property | how |
|---|---|
| repo read-only | sbx refuses `:ro` on the primary workspace, so the repo is attached as an extra `<repo>:ro` workspace and every exec runs with `--workdir <repo>` |
| one sandbox per run | created on the first agent command, removed at scan teardown (`shutdown_run_sandbox()`, CLI `finally` + atexit) |
| per-agent scratch | `HOME=/work/agent-<agent-id>`, `TMPDIR=/tmp/agent-<agent-id>`, pycache per agent (the `agent-` prefix is what the phase reset above matches) |
| shared package caches | `/work/_shared/pip`, `/work/_shared/npm` (downloads shared, installs per-agent) |
| egress | the machine policy (`balanced`); the harness **never** mutates global policy — only per-sandbox `--deny-network` hosts from `sandbox.sbx.deny_network` |

Accepted deltas vs the docker backend: **no** `--cap-drop`/seccomp/
`--read-only`/`--pids-limit` (the microVM replaces them); the toolchain image
must be loaded into the *sandbox runtime* with `sbx template load` (it does
not share your host Docker image store); VM disk persists until `sbx rm`.

Hardening the operator should apply once (the harness cannot):
`sbx settings set ssh.agentForwardingEnabled false && sbx daemon restart` —
sandbox processes can otherwise ask your host SSH agent to sign, which the
scan agents never need.

## Code layout

The two sandbox backends are deliberately thin: they differ in *which CLI*
they drive and nothing else, so everything they share lives in its own
module and each backend supplies argv.

| module | owns |
|---|---|
| `local_backend.py` | `RepoLocalBackend`: read-only, repo-confined file tools (the base of all three modes, and local mode itself) |
| `cli_utils.py` | the two subprocess seams (bounded / fixed output), the exec tag, the agent-id slug — one monkeypatch point for both backends |
| `command_policy.py` | a deny-only prefilter for obvious host/runtime commands. Not the boundary; see the docker section |
| `validation.py` | setting validators that fail at construction, before any container or VM exists |
| `run_base.py` | `RunSandboxBase`: the whole run-sandbox lifecycle (create-once, per-agent env, phase reset, mark-dead, remove) + `RunRegistry` (one sandbox per repo per process, atexit + SIGTERM reaping) + the shared orphan-sweep rules (name pattern, idle threshold, target selection) |
| `backend_base.py` | `SandboxShellBackend`: the per-agent session (close = session only) and the `execute` contract, with hooks for the two recovery paths that genuinely differ |
| `docker_backend.py` / `sbx_backend.py` | the CLI argv, the create failure advice, and each backend's recovery hook |

Adding a third backend means one `RunSandboxBase` subclass, one
`SandboxShellBackend` subclass, and a registry line — no copy-pasted
lifecycle.


## Run-sandbox filesystem continuity

A `docker` or `sbx` run shares one sandboxed filesystem across all agents of
the scan: writes to sandbox scratch survive from one agent to the next until
scan teardown. That state is **shared and mutable run state**, not durable
agent memory. It never becomes LangGraph checkpointer/store state, thread
context, or long-term memory; each invocation remains ephemeral at the agent
framework level. At scan teardown the run registry shuts the sandbox down and
that scratch state is discarded. Do not design agents to rely on files
persisting beyond a single scan, and do not treat sandbox scratch as an
audit trail.
