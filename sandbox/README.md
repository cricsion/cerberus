# Scan sandbox backends (operator setup)

Set `sandbox.backend` in `harness/config/default.yaml` (or `SANDBOX_BACKEND`) to pick
the execution environment for every agent in a scan (hunters, validators,
triage, partitioner). All modes keep the same harness
posture: no subagent recursion, no `delete`; `write_file`/`edit_file` are
confined to the state scratch route; target-repo file tools are read-only;
the shell (when it exists) is the only extra capability.

| mode | repo file tools | scratch writes | shell | boundary |
|---|---|---|---|---|
| `local` (default, resolver fallback) | read-only, in-process | `write_file`/`edit_file` in `/.cerberus/scratch/` | none | path containment |
| `docker` (opt-in) | read-only, in-process | same | `execute` | one container per run, egress per `sandbox.network` (default `bridge`) |

## local

No setup.

## docker

Build the scan-toolchain image (pins live in `versions.env`):

```bash
cp docker/versions.env.example docker/versions.env
./docker/build.sh cerberus-sandbox:local
```

Requires Docker Desktop running. The repo is bind-mounted **read-only** at
its absolute path; the container gets no host mounts and no host env. Only
paths under Docker Desktop's file sharing work.

### Scan toolchain (image contents)

Everything below is **image-only**: never installed on the host, so there is
no host toolchain to provision and no binary the agent cannot reach. The host
indexer wrappers are thin `subprocess` calls that run only when the host
happens to have the binary; the agent always uses the image.
The agent runs them through `execute`; usage is documented in the skills at
`/opt/cerberus-skills/<name>/SKILL.md`, served to the agent by the skills
route on its backend (`harness/agents/deep.py`). Pins and per-arch
sha256s live in `docker/versions.env` and are verified at build (a mismatch
fails the build).

| tool | role | engine lineage |
|---|---|---|
| `semgrep` | pattern + taint rules | Semgrep Inc., upstream |
| `opengrep` | pattern + taint rules (same rule format) | fork of Semgrep 1.100.0 |
| `bandit` | Python-specific AST checks | pip |
| `gosec` | Go security specialist | static binary |
| `njsscan` | Node/JS-specific rules | pip (shares the pinned semgrep) |
| `flawfinder` | C/C++ pattern checks, CWE-tagged | pip |
| `bearer` | dataflow + privacy/PII flows | static binary |
| `trufflehog` | verified secrets (current tree, `--no-update`) | static binary |
| `atheris` | Python fuzzing — **proves** a finding, not a scanner | pip |
| `gitleaks` | fast secret regex (in-container via `execute`, plus indexer wrapper) | — |
| `osv-scanner` | dependency vulns (needs osv.dev egress; plus indexer wrapper) | google |
| `checkov` | IaC (in-container via `execute`, plus indexer wrapper) | bridgecrew |

All image scanners are **agent-driven** (run per unit via `execute`, one skill
each under `harness/skills/`); the indexer path additionally calls the
`gitleaks`/`osv-scanner`/`checkov` wrappers in the harness process on the
host, degrading gracefully when a binary is absent.
`bandit`/`njsscan`/`atheris`/`flawfinder` ride the pip line with
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
repo, including any `.env`, key, or other credential file in it. These files
are readable like any other repo file (a target repo that is the harness
checkout exposes its own `.env` with the live API key). The default is
`sandbox.network: bridge`; switch to `none` for untrusted targets or scans that
do not need egress. The agent has full control inside the sandbox; containment
is the sandbox itself.

### Orphans from a killed run

A harness that EXITS reaps its sandbox (CLI `finally`, `atexit`, SIGTERM). A
harness that is **SIGKILL'd** — `kill -9`, a host OOM-kill, power loss — runs
```bash
docker ps --filter label=cerberus.agent.sandbox=run
docker rm -f <name>
```

**The harness's own sweep** runs at scan start (`sandbox.sweep_orphans`,
default on) and is name-scoped, so it never touches a sandbox this harness did
not create. It also spares any run still alive on this machine — any harness
process, not just this one — established from what the Docker daemon already
publishes:

| liveness signal | query |
|---|---|
| `exec_start` events, one per command the daemon ran | `docker events --filter container=NAME` |
| the container's `Created` birth stamp, when there is no exec history at all | `docker ps` (epoch field, read via the SDK listing) |

So the rule: our name pattern, not one this process owns
(that is what protects a concurrent scan — the registry, checked before any
age), and idle past `ORPHAN_IDLE_SECONDS` (6h — longer than any live run's
quiet gap, and a false positive self-heals because the sandbox is recreated on
the next command). The birth stamp closes the one hole the events log alone
had: a container created and never exec'ed (killed between create and the
first command) has no `exec_start` history to measure, so its `Created` age
decides — young means kept (and recreated on the next command anyway), old
means swept. A container whose history the daemon can report nothing about —
no events it can serve AND no listing row — is left alone rather than
removed: never delete what you cannot measure.

That contract is also why the sweep does not use the SDK's one-call bulk
API, `client.containers.prune(filters={"label": ...})` (docker-py docs,
containers.prune; Engine API `Container/Prune`): prune is
delete-what-matches — a label filter in, one summary count out, and every
match gone unconditionally. The sweep's rule is the inverse shape: it decides
KEEP vs REMOVE one container at a time from evidence prune has no slot for
(per-container exec history and birth stamps on the keep side; a per-refusal
"not removed" verdict on the remove side so the next scan re-sweeps). The
list → age → remove loop is the contract, not a legacy habit — deliberately
not switched, per the note in `docker_backend.sweep_orphans`.

There is no harness-side liveness state anywhere — nothing to write, nothing
to forge, and nothing to lose when the harness is SIGKILL'd, which is the
whole point, since the process that would have maintained it is exactly the one
that died. The name pattern is also the only thing keeping the sweep off a
sandbox this harness did not create, so it is not a security boundary either.

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

* `memory`, `cpus` and `pids_limit` now bound the **whole run** — 8 parallel
  agents (default `concurrency`) share one 2g budget. Raise
  `sandbox.memory` if agents thrash.
* a runaway agent (memory, pids, a stray `rm -rf` in the shared tmpfs,
  a background process) degrades **every** agent in the run; the container
  is reaped only at scan end.
* if the harness CLI is SIGKILLed, atexit does not run and the container
  leaks: sweep stale ones with
  `docker ps --filter label=cerberus.agent.sandbox=run`.

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

## Code layout

A sandbox backend is deliberately thin: it supplies the container it drives
(the SDK channel call) and the confinement kwargs, while everything the
backends share lives in its own module.

| module | owns |
|---|---|
| `local_backend.py` | `RepoLocalBackend`: read-only, repo-confined file tools (the base of both modes, and local mode itself) |
| `cli_utils.py` | the byte-bounded separated-streams subprocess seam, the exec tag, the byte-cap factor, the agent-id slug — one monkeypatch point for the shell backend |
| `validation.py` | setting validators that fail at construction, before any container exists |
| `docker_channel.py` | the one docker-py transport: confined `containers.create`, bounded demuxed execs (client deadline + watchdog pkill), the tar transfer plane, and the sweep's daemon-published liveness sources |
| `run_base.py` | `RunSandboxBase`: the run-sandbox lifecycle (create-once, mark-dead, remove, close) + `RunRegistry` (one sandbox per repo per process, atexit + SIGTERM reaping) + the shared orphan-sweep rules (name pattern, idle threshold, target selection) |
| `backend_base.py` | `SandboxShellBackend`: the per-agent session (close = session only) and the `execute` contract, with hooks for the two recovery paths that genuinely differ |
| `docker_backend.py` | the docker settings surface, the create failure advice, its recovery hook, and the `BaseSandbox` adapter (FS ops confined, then delegated into the container) |
| `system_exec.py` | the system lane: harness-owned commands (scanners, indexers) run in the sandbox on the same channel, with a local subprocess fallback |

Adding another backend means one `RunSandboxBase` subclass, one
`SandboxShellBackend` subclass, and a registry line — no copy-pasted
lifecycle.


## Run-sandbox filesystem continuity

A `docker` run shares one sandboxed filesystem across all agents of
the scan: writes to sandbox scratch survive from one agent to the next until
scan teardown. That state is **shared and mutable run state**, not durable
agent memory. It never becomes LangGraph checkpointer/store state, thread
context, or long-term memory; each invocation remains ephemeral at the agent
framework level. At scan teardown the run registry shuts the sandbox down and
that scratch state is discarded. Do not design agents to rely on files
persisting beyond a single scan, and do not treat sandbox scratch as an
audit trail.

## Coverage gaps

Per hunter unit, the assigned files that were never listed as inspected are
recorded as **coverage gaps**: the per-unit notes ride `hunter_coverage` in
`scan_meta.json`, appear in `report.md` under `## Coverage gaps`, and are
logged per unit to stderr as
`[hunters] unit-<name> coverage: k/n listed; missing: …`. Gaps are reported,
never turned into findings — an unlisted file is a signal, not a finding.
