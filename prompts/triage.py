"""Triage prompts: duplicate rules and severity rubric for the dedup pass."""
from pydantic import BaseModel, Field

from cerberus.prompts.contract import structured_output_contract
from cerberus.prompts.engine import block

TRIAGE_INSTRUCTIONS = block("triage/instructions")
TRIAGE_SYSTEM = TRIAGE_INSTRUCTIONS

def build_triage_batch_task(scope: str, slim_json: str) -> str:
    scope_prefix = f"{scope}\n\n" if (scope or "").strip() else ""
    contract = structured_output_contract(TriageBatch)
    return (
        f"{contract}\n\n"
        f"{scope_prefix}"
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
