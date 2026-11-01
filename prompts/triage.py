"""Triage prompts: duplicate rules and severity rubric for the dedup pass."""
from pydantic import BaseModel, Field

from harness.prompts.contract import structured_output_contract
from harness.prompts.engine import block

DEDUP_RULES = block("triage/dedup_rules")

SEVERITY_GUIDE = block("triage/severity_guide")

TRIAGE_SYSTEM = block("triage/triage_system")


def build_triage_batch_task(scope: str, slim_json: str) -> str:
    # Static prefix first: dedup rules, severity rubric, and output instructions (~6k tokens)
    # Cached across all triage batches in the scan.
    scope_prefix = f"{scope}\n\n" if (scope or "").strip() else ""
    contract = structured_output_contract(
        TriageBatch,
        guidance=(
            "Score findings strictly according to their earned exploitability evidence from the severity rubric above.\n"
            "The threat model may clarify actors and assets. It moves severity DOWN never up: "
            "an explicitly deprioritized threat in section 5 keeps its status and takes severity low, but "
            "never acquits anything on its own. Unnamed or in-scope threats must be scored strictly according to "
            "their earned exploitability evidence from the severity rubric above. "
            "If the threat model conflicts with that evidence, note the conflict in reason for human review."
        ),
    )
    return (
        f"{scope_prefix}"
        f"Deduplication rules:\n{DEDUP_RULES}\n\n"
        f"Severity rubric:\n{SEVERITY_GUIDE}\n\n"
        f"{contract}\n\n"
        # Dynamic tail: candidate findings JSON
        f"All triage findings of this batch (JSON):\n"
        f"{slim_json}"
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
