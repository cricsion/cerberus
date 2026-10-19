"""Finding schema — single source of truth for structured output + reports."""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["confirmed", "needs-review", "fp"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

UNKNOWN_SEVERITY_RANK = 5

def sort_findings(findings) -> list[dict]:
    """The one findings ordering: severity rank asc, confidence desc.

    Every artifact writer and the CLI renderer sort through here so the
    artifacts can never disagree on which finding ranks first
    """
    def _key(f: dict):
        sev = str(f.get("severity", "medium")).lower()
        return (SEVERITY_ORDER.get(sev, UNKNOWN_SEVERITY_RANK),
                -safe_float(f.get("confidence", 0)))
    return sorted((f for f in (findings or []) if isinstance(f, dict)), key=_key)


def group_duplicates(rows: list[dict]) -> dict[str, list[dict]]:
    """duplicate_of id -> collapsed rows, in row order (MD report shape)."""
    dupes: dict[str, list[dict]] = {}
    for f in (rows or []):
        if (f or {}).get("duplicate_of"):
            dupes.setdefault(str(f["duplicate_of"]), []).append(f)
    return dupes


def safe_int(value: object, default: int = 0) -> int:
    """Lenient int for LLM-produced numbers ("12-15", "unknown", 12.7 all occur); never raises."""
    try:
        if isinstance(value, bool):
            return default
        if isinstance(value, str):
            text = value.strip()
            if text.isdigit():
                return int(text)
            return default
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def safe_float(value: object, default: float = 0.0) -> float:
    """Lenient float for LLM-produced confidences. Never raises."""
    try:
        if isinstance(value, bool):
            return default
        return float(value or 0)
    except (TypeError, ValueError):
        return default


class TaintPath(BaseModel):
    source: str = ""
    sink: str = ""
    path: list[str] = Field(default_factory=list)


class Reachability(BaseModel):
    reachable: bool = False
    sanitizer: str = ""
    auth_check: str = ""


class Finding(BaseModel):
    id: str
    title: str
    cwe: str = ""  # e.g. CWE-89
    owasp: str = ""
    severity: Severity = "medium"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    path: str
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""
    taint: TaintPath = Field(default_factory=TaintPath)
    reachability: Reachability = Field(default_factory=Reachability)
    rationale: str = ""  # why this is real (source->sink), first for reasoning order
    evidence: str = ""
    fix_suggestion: str = ""
    status: Status = "needs-review"
    cost_usd: float = 0.0
    duplicate_of: str = ""  # triage: primary finding id when collapsed as duplicate
    triage: dict = Field(default_factory=dict)  # rubric answers (M4)
