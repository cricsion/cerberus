"""Triage prompts: duplicate rules and severity rubric for the dedup pass."""
from pydantic import BaseModel, Field

from harness.prompts.engine import block

DEDUP_RULES = block("triage/dedup_rules")

SEVERITY_GUIDE = block("triage/severity_guide")

TRIAGE_SYSTEM = block("triage/triage_system")


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
