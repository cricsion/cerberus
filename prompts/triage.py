"""Triage prompts: duplicate rules and severity rubric for the dedup pass."""
from pydantic import BaseModel, Field

DEDUP_RULES = (
    "Two findings are DUPLICATES if fixing one would automatically fix the other (e.g. the exact same code line reported twice, or identical vulnerability reported by two different scanners).\n"
    "Two findings are DISTINCT if they are in different functions, different methods, different routes, or different line numbers that each require an independent code change — even if they share the same file or CWE category (e.g. multiple distinct vulnerable functions in a trigger or utility module).\n"
    "Treat as DUPLICATE:\n"
    "- Same root cause on the same line described with different wording or by different scanners\n"
    "- The exact same vulnerable sink call site reported under two different rule IDs\n"
    "Treat as DISTINCT:\n"
    "- Different functions or methods in the same file (e.g. do_open vs do_tarfile, re.match vs re.search)\n"
    "- Different lines in the same file that each require their own separate code fix\n"
    "- Different vulnerability classes in the same file region"
)

SEVERITY_GUIDE = (
    "Rate severity based on concrete exploitability evidence, not the generic bug class:\n"
    "1. Reachability: Can an attacker reach this from an external entry point, or is it internal-only?\n"
    "2. Attacker control: Does untrusted input reach the sink intact, or is it constrained/sanitized?\n"
    "The finding's `control_type` (sanitizer, auth_check, none) is the validator's control signal; "
    "use it when judging whether the control actually stops the input.\n"
    "3. Preconditions: What must hold (non-default setting, feature flag, race window)?\n"
    "4. Authentication: Unauthenticated, standard logged-in user, or administrator?\n"
    "5. Read vs Write: Read-only data disclosure or state/filesystem modification / code execution?\n"
    "6. Blast radius: Single record, tenant data, or full platform compromise?\n"
    "Scoring rubric: Unauthenticated remote access with zero preconditions = critical/high. "
    "Authenticated access or 1-2 preconditions = medium. Local-only or 3+ narrow preconditions = low."
)

TRIAGE_SYSTEM = (
    "You triage security findings: deduplicate by root cause, "
    'then rank by exploitability evidence. Return exactly one JSON object '
    'with a "verdicts" array and no prose.'
)


def build_triage_batch_task(scope: str, slim_json: str) -> str:
    return (
        f"{scope}All triage findings of this scan (JSON):\n"
        f"{slim_json}\n"
        f"Deduplication rules: {DEDUP_RULES}\n"
        f"Severity rubric: {SEVERITY_GUIDE}\n"
        "Reply with a JSON object containing the array of verdicts: "
        '{"verdicts": [{"id": ..., "duplicate_of": "<primary id or null when distinct/primary>", '
        '"severity": "critical|high|medium|low (earned from the rubric above)", '
        '"triage": {"reachable": ..., "control": ..., "preconditions": [...], '
        '"auth": ..., "rw": ..., "blast": ..., "rationale": "..."}, '
        '"reason": "one line"}]}. '
        "No prose. The threat model may clarify actors and assets. It moves severity DOWN never up: "
        "an explicitly deprioritized threat in section 5 keeps its status and takes severity low, but "
        "never acquits anything on its own. Unnamed or in-scope threats must be scored strictly according to "
        "their earned exploitability evidence from the severity rubric above. "
        "If the threat model conflicts with that evidence, note the conflict in reason for human review."
    )


class TriageItem(BaseModel):
    """Exploitability evidence behind one triage verdict."""

    reachable: str = Field(default="", description="Can an attacker reach this from a real entry point")
    control: str = Field(default="", description="Control that should stop it, if any")
    preconditions: list[str] = Field(default_factory=list,
                                     description="What must hold for exploitation")
    auth: str = Field(default="", description="Required auth: unauthenticated, logged-in, admin")
    rw: str = Field(default="", description="Read-only or modification")
    blast: str = Field(default="", description="Blast radius: one user, all users, tenant, platform")
    rationale: str = Field(default="", description="One-line reason for the verdict")


class TriageVerdict(BaseModel):
    """One triage verdict. Lenient: unknown ids and bad severities are
    filtered downstream, never here."""

    id: str = Field(default="", description="Finding id this verdict covers")
    duplicate_of: str | None = Field(default=None,
                                     description="Primary id, or null when distinct")
    severity: str = Field(default="", description="Earned severity from the rubric")
    triage: TriageItem = Field(default_factory=TriageItem,
                               description="Exploitability evidence")
    reason: str = Field(default="", description="One-line reason")


class TriageBatch(BaseModel):
    """One batch of triage verdicts (object wrapper: backends choke on bare
    top-level arrays)."""

    verdicts: list[TriageVerdict] = Field(default_factory=list,
                                          description="One verdict per finding id")
