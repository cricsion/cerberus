from pydantic import BaseModel, Field


# Output contract for both swarm stages and the synthesizer; mirrors the threat-model skill's schema contract.
SCHEMA_CONTRACT = (
    "Emit markdown with these eight sections, headings exactly:\n"
    "# Threat Model: <name>\n"
    "## 1. System context — 1-3 paragraphs of prose: what it is, who uses it, "
    "where it runs.\n"
    "## 2. Assets — table: | asset | description | sensitivity | with "
    "sensitivity in {low, medium, high, critical}.\n"
    "## 3. Entry points & trust boundaries — table: | entry_point | "
    "description | trust_boundary | reachable_assets |. One row per place "
    "untrusted input enters or privilege changes. Supply-chain, build-time, "
    "and infra/IAM surfaces count even though no runtime input crosses them.\n"
    "## 4. Threats — table: | id | threat | actor | surface | asset | impact "
    "| likelihood | status | controls | evidence |. One row per "
    "actor-wants-outcome pair at the level where it survives a patch. Closed "
    "enums: actor in {remote_unauth, remote_auth, adjacent_network, local_user, "
    "local_admin, supply_chain, insider}; impact in {low, medium, high, "
    "critical, existential}; likelihood in {very_rare, rare, possible, likely, "
    "almost_certain}; status in {unmitigated, partially_mitigated, mitigated, "
    "risk_accepted}. Sort by (impact, likelihood) descending, id T1, T2, ...\n"
    "## 5. Deprioritized — table: | threat | reason | for threats considered "
    "and parked.\n"
    "## 6. Open questions — bullet list of what the code could not answer.\n"
    "## 7. Provenance — bullets: mode, date, target, inputs, owner.\n"
    "## 8. Recommended mitigations — table: | mitigation | threat_ids | "
    "closes_class | effort | with closes_class in {yes, partial} and effort in "
    "{S, M, L}; one class-level control per row, not a per-bug patch.\n"
    "Rules: threats survive a patch; CVEs/commits are evidence in the evidence "
    "column only. Every section 3 entry point must be named in at least one "
    "section 4 surface cell. At least one threat row must have an EMPTY "
    "evidence cell (the STRIDE gap-fill)."
)


class SwarmEntryPoint(BaseModel):
    """One place untrusted input enters or privilege changes."""

    entry_point: str = Field(default="", description="Short name, e.g. 'HTTP route POST /login', 'file input argv[1]'")
    description: str = Field(default="", description="What crosses it, with file:refs")
    trust_boundary: str = Field(default="", description="The crossing, e.g. 'untrusted file → process memory'")
    reachable_assets: list[str] = Field(default_factory=list, description="Asset names from section 2 this entry point can reach")
    file_refs: list[str] = Field(default_factory=list, description="file:line refs")


class SwarmAsset(BaseModel):
    """One thing worth protecting."""

    asset: str = Field(default="")
    description: str = Field(default="")
    sensitivity: str = Field(default="medium", description="low|medium|high|critical")


class SwarmResearch(BaseModel):
    """Surface-mapper + asset-finder return: entry points, assets, controls."""

    system_context: str = Field(default="", description="1-3 paragraphs: what this system is, who uses it, where it runs")
    entry_points: list[SwarmEntryPoint] = Field(default_factory=list)
    assets: list[SwarmAsset] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list, description="Mitigations found in code/config")
    open_questions: list[str] = Field(default_factory=list)


class SwarmVuln(BaseModel):
    """One past-vulnerability row mined from history."""

    id: str = Field(default="", description="Commit sha or CVE/GHSA id")
    title: str = Field(default="")
    component: str = Field(default="", description="File/module it lived in")
    vclass: str = Field(default="", description="Bug class, e.g. sql-injection")
    vector: str = Field(default="", description="How it was reached (which surface)")


class SwarmHistory(BaseModel):
    """Git-history miner return: past vulns as threat evidence candidates."""

    vulns: list[SwarmVuln] = Field(default_factory=list)


# No `id` field: code assigns T1..Tn after sorting by (impact, likelihood).


class SwarmThreat(BaseModel):
    """One threat row: class-level, survives a patch."""

    threat: str = Field(default="", description="One sentence, active voice, names the outcome")
    actor: str = Field(default="", description="remote_unauth|remote_auth|adjacent_network|local_user|local_admin|supply_chain|insider")
    surface: str = Field(default="", description="Which section 3 entry point(s) this traverses, naming them")
    asset: str = Field(default="", description="Which section 2 asset(s) this compromises")
    impact: str = Field(default="", description="low|medium|high|critical|existential")
    likelihood: str = Field(default="", description="very_rare|rare|possible|likely|almost_certain (residual, after controls)")
    status: str = Field(default="", description="unmitigated|partially_mitigated|mitigated|risk_accepted")
    controls: str = Field(default="none", description="Mitigations actually found, or 'none'")
    evidence: str = Field(default="", description="CVE/commit ids or file:refs that instantiate this; EMPTY for gap-fill rows")


class SwarmParked(BaseModel):
    """One considered-and-ruled-out threat (section 5)."""

    threat: str = Field(default="")
    reason: str = Field(default="")


class SwarmMitigation(BaseModel):
    """One class-level control (section 8)."""

    mitigation: str = Field(default="", description="Imperative, one line, closes a class not an instance")
    threat_numbers: list[int] = Field(default_factory=list, description="1-based positions in YOUR threats list this covers")
    closes_class: str = Field(default="partial", description="yes|partial")
    effort: str = Field(default="M", description="S|M|L")


class SwarmPlan(BaseModel):
    """Synthesis payload: everything judgment-shaped, nothing mechanical."""

    context_prose: str = Field(default="", description="1-3 paragraphs: what the system is, who uses it, where it runs")
    entry_points: list[SwarmEntryPoint] = Field(default_factory=list)
    assets: list[SwarmAsset] = Field(default_factory=list)
    threats: list[SwarmThreat] = Field(default_factory=list)
    deprioritized: list[SwarmParked] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    mitigations: list[SwarmMitigation] = Field(default_factory=list)


class QuestionList(BaseModel):
    """Structured-output contract for the interview-question stage."""
    questions: list[str] = Field(
        default_factory=list,
        description="Follow-up threat-model questions; empty means nothing "
                    "material is left open.")


# Filesystem tools are confined to the target repo; local mode has no shell; `execute` (Docker) runs inside the sandbox only.
READ_ONLY_NOTE = (
    "The filesystem tools (read_file/grep/glob/ls) are confined to the target "
    "repository. If `execute` is available, it runs inside the configured "
    "Docker sandbox. Run target-controlled code, tests, or fuzzers only "
    "when that sandbox has network egress disabled, and only as short, "
    "targeted checks after reading the exact command and relevant test script. "
    "Use dummy inputs, isolated loopback only, and keep every write in sandbox "
    "scratch; do not run setup or install scripts. If "
    "egress is restricted, full, or unknown, use execute only for read-only "
    "inspection and static checks; do not run repository code. Put generated "
    "output only in sandbox scratch. Never modify source, deploy, install "
    "packages, download code, make network requests, contact external "
    "services, or run unbounded fuzzing. Respect command and resource limits. "
    "If execute is unavailable, continue with static analysis. A failed, "
    "blocked, or untested check is inconclusive, not evidence that a threat "
    "is absent."
)

# A SEED, not a checklist: one concrete token per row sets the specificity bar.
SURFACE_GREP_TABLE = (
    "Surface lookup seeds (extend with the target's own idioms):\n"
    "- Network: socket listen/accept/bind; HTTP route definitions "
    "(e.g. @app.route, app.get); RPC/gRPC/GraphQL service definitions\n"
    "- File / format parsing: file-open calls (e.g. open(); format "
    "magic-byte checks; 'parse'/'decode'/'load'/'unmarshal' function names\n"
    "- CLI / env: argv parsers (e.g. argparse); env reads (e.g. getenv)\n"
    "- Deserialization: language-native deserializers on external data "
    "(e.g. pickle, ObjectInputStream, yaml.load)\n"
    "- DB / query: raw query-string construction; ORM .raw()/.query() "
    "escapes\n"
    "- IPC / plugins: dynamic load (e.g. dlopen); subprocess spawn; "
    "eval/exec on config; dynamic import\n"
    "- Supply chain: dependency lockfiles; vendored libs; curl | sh in "
    "build scripts\n"
    "- Infra / IAM: terraform *_iam_* resources; k8s serviceAccountName / "
    "workload-identity annotations; dataset/table ACL blocks; secrets mounts"
)

RESEARCHER_SYSTEM = (
    "You are a threat-model research agent covering three briefs at once: "
    "surface mapper, asset finder, and infra reader. You enumerate where a "
    "lower-trust actor hands input to the code, what the system protects, "
    "and which controls already exist — every claim grounded in a file you "
    "actually read.\n" + READ_ONLY_NOTE + "\nFill the structured schema "
    "exactly."
)


def build_research_task(repo: str, draft_md: str, files: list[str]) -> str:
    return (
        f"Repository (read-only): {repo}\n\n"
        f"Indexed files ({len(files or [])}):\n"
        + "\n".join(f"- {f}" for f in (files or [])[:200])
        +         f"\n\nDeterministic draft for orientation (may be thin):\n{(draft_md or '').strip()[:6000]}\n\n"
        "BRIEF 0 — Docs reader. Read README*, SECURITY.md, CHANGELOG*, "
        "top-level docs/, and the build manifest (setup.py / Cargo.toml / "
        "package.json / CMakeLists.txt / pyproject.toml). Summarize what the "
        "project says it is, who uses it, and any security claims or "
        "self-documented fixes — then use that summary as the basis of "
        "context_prose. Treat a published SECURITY.md scope as a constraint, "
        "not a suggestion. Do not cite harness-generated artifacts "
        "(.harness/, graphify-out/, runs/) as project documentation: they "
        "are tool outputs, not owner evidence, and they appear and disappear "
        "between scans.\n\n"
        "BRIEF 1 — Surface mapper. " + SURFACE_GREP_TABLE + "\n"
        "Bound the scan: exclude vendor/, node_modules/, third_party/, and "
        "generated code; cap at ~5 representative hits per surface row. For "
        "each hit, name the surface, the file:function, and what crosses it. "
        "Supply-chain surfaces (lockfiles, vendored deps, curl | sh in build "
        "scripts, CI workflows, container/IaC definitions) are entry points "
        "too, even though no runtime input crosses them. Every entry point "
        "must get at least one threat row later — miss none.\n\n"
        "BRIEF 2 — Asset finder. Identify what the code protects or "
        "produces: sensitive data it reads/writes (secrets, keys, user "
        "records, databases), process integrity (always present for native "
        "code), service availability, and downstream embedder assets if it "
        "is a library. Assign sensitivity honestly — a fixture placeholder "
        "secret is not a live credential.\n\n"
        "BRIEF 3 — Infra reader. Read deploy-time config: terraform, k8s "
        "manifests, Dockerfile*, CI workflows, IAM/service-account/ACL "
        "files. For each, name (a) the identity the workload runs as and "
        "what that identity can reach, (b) any access grant NOT managed in "
        "this tree (ad-hoc IAM, hand-created service accounts, missing "
        "policy tags), (c) credentials or principals that survive a "
        "migration or teardown. Where an automated approval, merge, or "
        "write path exists, ask what bounds it to its intended scope "
        "(path allowlist, label, reviewer set).\n\n"
        "Also list controls you actually found in code/config (auth "
        "middleware, parameterized queries, size caps, sandboxing, security "
        "headers) — never assumed ones. Anything you could not determine "
        "goes to open_questions; do not guess."
    )


HISTORIAN_SYSTEM = (
    "You are a threat-model history miner. Given a repository's past "
    "security-fix commits, you classify each into a normalized "
    "past-vulnerability row that will later serve as EVIDENCE for threat "
    "rows. Classify only the commits you were given; never invent ids. Read "
    "the repository to ground a commit's component and reach vector when the "
    "subject alone is ambiguous.\n" + READ_ONLY_NOTE
)


def build_historian_task(repo: str, bug_shapes: str, draft_md: str,
                         vulns: list[dict] | None = None) -> str:
    task = (
        f"Repository (read-only): {repo}\n\n"
        f"Past fix-shaped commits (deterministically mined from security-fix "
        f"keywords in the subjects):\n{bug_shapes or '(none found)'}\n\n"
        f"Deterministic draft for orientation:\n{(draft_md or '').strip()[:3000]}\n\n"
        "For each commit: give its short sha as id, a title, the component "
        "it touched, the bug class (e.g. xss, sqli, overflow, authz, "
        "deser), and how an attacker would have reached it (the surface). "
        "Where a subject is ambiguous, say so in the title rather than "
        "inventing detail. If the list is empty, return an empty list — a "
        "repository with no fix history is a finding about the evidence "
        "base, not something to fill in."
    )
    rows = [v for v in (vulns or []) if isinstance(v, dict) and v.get("id")]
    if rows:
        lines = ["", "Past vulnerabilities supplied by the owner via --vulns:",
                 ""]
        for v in rows[:200]:
            parts = [f"- {v.get('id')}"]
            for key in ("title", "component", "description"):
                if str(v.get(key, "")).strip():
                    parts.append(f"{key}: {v[key]}")
            lines.append(" | ".join(parts))
        task += ("\n" + "\n".join(lines)
                 + "\n\nClassify these rows the same way (id stays the "
                   "supplied one — CVE/GHSA ids are the durable handle). "
                   "They are EVIDENCE that a threat class is live on a "
                   "surface, not threats themselves.")
    return task


SYNTH_SYSTEM = (
    "You are the threat-model synthesizer: you turn a deterministic draft "
    "plus two research returns into the JUDGMENT half of a threat model. "
    "Harness code owns the mechanical cells (ids, sort order, provenance, "
    "measured facts, the surface skeleton, enum validation) — you supply "
    "only decisions: ratings, clusters, parked threats, open questions, "
    "class-level mitigations. Fill the structured schema exactly."
)


# Row budget for the planner's `threats` (merge-side ROW_CAPS["threats"] is too loose: unbounded asks returned empty threats). NARROW is the retry brief.
THREAT_ROW_BUDGET = 8
THREAT_ROW_BUDGET_NARROW = 5


def _threat_row_budget(cap: int) -> str:
    return (
        f"ROW BUDGET — at most {cap} threat rows, one row per CLASS "
        f"cluster, never one row per finding, ranked by impact (worst "
        f"first). Fewer rows is better than padded rows: merge every past "
        f"vuln and every research surface into the class it belongs to and "
        f"park the remainder in deprioritized with a reason. NEVER return "
        f"an empty threats list to save space — a short sharp list is "
        f"always better than none."
    )


# STAGE 4 for the default brief; the narrow retry drops it wholesale (the STRIDE walk inflates the row count without adding judgment).
STRIDE_GAPFILL_STAGE = (
    "STAGE 4 — Gap-fill (the part past vulns can't give you). Past "
    "vulns are biased toward what was already found. For every entry "
    "point with no threat row yet, walk STRIDE and add the plausible "
    "ones with EMPTY evidence:\n"
    "- Spoofing: could an attacker pretend to be a trusted source?\n"
    "- Tampering: could they modify data in transit or at rest?\n"
    "- Repudiation: could they act without leaving attributable logs?\n"
    "- Info disclosure: could they read data they shouldn't?\n"
    "- DoS: could they exhaust a resource (CPU, memory, disk, connections)?\n"
    "- Elevation: could they end up with more privilege than they "
    "started with?\n"
    "For infra/IAM entry points STRIDE maps poorly — walk these "
    "instead: over-grant (identity reaches more than the app needs), "
    "lateral identity (co-located workload can assume it), drift "
    "(grant managed outside the tree), residual access (credentials "
    "surviving a migration), column exposure (broad read exposing PII), "
    "scope enforcement (what bounds an automated write path). Also walk "
    "the entry points that DO have rows: a parser with an RCE threat "
    "probably also has a DoS threat.\n\n"
)

# Replaces the gap-fill stage in the narrow retry brief (no walk, no sweep).
NARROW_GAPFILL_SKIP = (
    "STAGE 4 — Skipped in this retry: no coverage sweep and no "
    "per-entry-point walk. Work only from the clusters the past vulns and "
    "the research surfaces actually support, merge overlapping clusters, "
    "and put anything else in deprioritized with the reason it was "
    "parked.\n\n"
)


def build_synth_task(repo: str, draft_md: str, research_json: str,
                     history_json: str,
                     measured_facts: str = "",
                     *, narrow: bool = False) -> str:
    cap = THREAT_ROW_BUDGET_NARROW if narrow else THREAT_ROW_BUDGET
    gapfill = NARROW_GAPFILL_SKIP if narrow else STRIDE_GAPFILL_STAGE
    return (
        f"Repository (read-only): {repo}\n\n"
        f"MEASURED FACTS (code-owned canon — route counts, stack hint, "
        f"detector coverage; never contradict these):\n"
        f"{(measured_facts or '').strip()[:8000]}\n\n"
        f"Prior deterministic document (orientation; its §1-§6 prose is a "
        f"draft, not canon):\n{(draft_md or '').strip()[:8000]}\n\n"
        f"Research return — surface mapper + asset finder + infra reader:\n{research_json or '(unavailable)'}\n\n"
        f"Research return — history miner (past vulns; these are EVIDENCE "
        f"for threat rows, never the threats themselves):\n{history_json or '(unavailable)'}\n\n"
        "STAGE 2 — Synthesize. Produce the plan fields from the research "
        "returns:\n"
        "- context_prose: 1-3 paragraphs — what the system is, who uses it, "
        "where it runs. Facts, not marketing. The harness appends the "
        "measured-fact block itself, so do not repeat counts or stack hints.\n"
        "- entry_points: final section-3 rows, refined from research (name, "
        "what crosses it with file:refs, the trust_boundary crossing, "
        "reachable assets). Every research entry point must survive.\n"
        "- assets: research assets with sensitivity (low, medium, high, critical). Identify real application and business data assets (e.g., credentials, user records, database tables, sessions, API tokens, cryptographic secrets), process integrity for native code, and supply-chain assets. Never emit dummy or placeholder entries like 'test' or 'unknown'.\n\n"
        "STAGE 3 — Generalize: vulns -> threats. Cluster past vulns AND "
        "research surfaces by (entry point, bug class, asset reached). Each "
        "cluster becomes ONE threat row.\n"
        + _threat_row_budget(cap) + "\n"
        "Litmus test: if patching one line of code makes the entry "
        "disappear, it was a vulnerability, not a threat — zoom out until "
        "the statement survives patching every listed bug.\n"
        "Variant scan (for likelihood only): for each cluster, look for "
        "siblings — other call sites, other format parsers, other endpoints "
        "calling the same unsafe helper. More siblings raises likelihood; "
        "siblings NEVER enter the evidence cell (evidence is confirmed past "
        "vulns only).\n\n"
        + gapfill
        + "SCORING. impact: from the asset and the bug class (memory "
        "corruption on a network service -> critical; info leak of "
        "non-sensitive data -> low). likelihood: start from evidence — at "
        "least one confirmed past vuln on this exact surface -> at least "
        "'likely'; public exploit or active exploitation -> "
        "'almost_certain'; no evidence but siblings found and the technique "
        "is well known -> 'possible' — then adjust DOWN for controls you "
        "actually found, never up. Score the RESIDUAL likelihood after "
        "current controls. status: 'unmitigated' unless a control fully "
        "closes it. controls: real mitigations from the research return, "
        "or 'none'. 'surface' must name the entry point(s) the threat "
        "traverses.\n\n"
        "STAGE 5 — Emit the rest:\n"
        "- deprioritized: threats considered and explicitly parked, with "
        "the reason.\n"
        "- open_questions: what the code could not answer (deployment "
        "exposure, intended actors, unverifiable controls, owner risk "
        "appetite).\n"
        "- mitigations: one row per CLASS-LEVEL control that closes or "
        "materially shrinks a whole threat cluster regardless of which "
        "instance is found next (e.g. 'sandbox the decoder process', "
        "'parameterized queries everywhere') — prefer a control that "
        "survives the next bug over a patch for the last one.\n\n"
        "INVARIANTS (checked by code): every entry point must be named by "
        "at least one threat surface; at least one threat row must have an "
        "EMPTY evidence cell (the gap-fill ran). Order does not matter — "
        "the harness sorts threats and assigns ids."
    )


INTERVIEWER_SYSTEM = (
    "You are a security threat-model interviewer. You resolve doubts, "
    'not collect trivia. Return exactly one JSON object with a "questions" '
    "array of strings and no prose."
)


def build_interview_task(draft_md: str, history_text: str, max_questions: int) -> str:
    return (
        f"Draft threat model (FULL text):\n{(draft_md or '').strip()}\n\n"
        f"Interview so far:\n{history_text}\n\n"
        f"Ask up to {max_questions} sharp follow-up questions targeting the "
        "biggest open doubts: trust boundaries (what is TRUSTED and why), "
        "what is out of scope and why, entry points, crown-jewel assets, "
        "dependency policies. Skip anything the draft + history already "
        'answer. Return {"questions": []} when nothing material is left open.'
    )


FINALIZE_SYSTEM = (
    "You write THREAT_MODEL.md files. Keep the fixed ## sections, full "
    "detail, no truncation. Reply ONLY with markdown."
)


def build_finalize_task(draft_md: str, history_text: str) -> str:
    return (
        f"Draft threat model (FULL text):\n{(draft_md or '').strip()}\n\n"
        f"Owner interview:\n{history_text}\n\n"
        "Rewrite the draft incorporating the answers: sharpen entry points "
        "and trust boundaries (name what is TRUSTED and why), fill assets, "
        "add or promote threat rows in section 4 for what the owner raised, "
        "move answered doubts out of section 6, record parked threats in "
        "section 5 with reasons (a threat model prioritizes, it never "
        "excludes), and append an 'Owner notes (interview)' section quoting "
        f"the Q&A.\n\n{SCHEMA_CONTRACT}"
    )
