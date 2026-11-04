from pydantic import BaseModel, Field

from cerberus.prompts.contract import structured_output_contract
from cerberus.prompts.engine import block

# Output contract for both swarm stages and the synthesizer; mirrors the threat-model skill's schema contract.
SCHEMA_CONTRACT = block("threat/schema_contract")


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


SYNTHESIZER_CONTRACT = structured_output_contract(SwarmPlan)


class QuestionList(BaseModel):
    """Structured-output contract for the interview-question stage."""
    questions: list[str] = Field(
        default_factory=list,
        description="Follow-up threat-model questions; empty means nothing "
                    "material is left open.")


# A SEED, not a checklist: one concrete token per row sets the specificity bar.
SURFACE_GREP_TABLE = block("threat/surface_grep_table")

RESEARCHER_SYSTEM = block("threat/researcher_system")


def build_research_task(repo: str, draft_md: str, files: list[str]) -> str:
    return (
        f"Repository (read-only): {repo}\n\n"
        f"Indexed files ({len(files or [])}):\n"
        + "\n".join(f"- {f}" for f in (files or [])[:200])
        +         f"\n\nDeterministic draft for orientation (may be thin):\n{(draft_md or '').strip()[:6000]}\n\n"
        + block("threat/research_brief0_docs")
        + "BRIEF 1 — Surface mapper. " + SURFACE_GREP_TABLE + "\n"
        + block("threat/research_brief1_bound")
        + block("threat/research_brief2_assets")
        + block("threat/research_brief3_infra")
        + block("threat/research_controls_tail")
    )


HISTORIAN_SYSTEM = block("threat/historian_system")


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


SYNTH_SYSTEM = block("threat/synth_system")


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
STRIDE_GAPFILL_STAGE = block("threat/stride_gapfill_stage")

# Replaces the gap-fill stage in the narrow retry brief (no walk, no sweep).
NARROW_GAPFILL_SKIP = block("threat/narrow_gapfill_skip")


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
        "the harness sorts threats and assigns ids.\n\n"
        f"{SYNTHESIZER_CONTRACT}"
    )


INTERVIEWER_SYSTEM = block("threat/interviewer_system")


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


FINALIZE_SYSTEM = block("threat/finalize_system")


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
