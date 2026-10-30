"""Canonical finding schema plus ordering and coercion helpers.

``Finding`` (wrapped by ``DiscoveryResult``) is the structured-output contract
hunters emit. After discovery, findings travel as plain dicts; the validator
and triage stages add ``status``, ``fix_suggestion``, ``control_type``,
``duplicate_of`` and ``triage`` in place.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

UNKNOWN_SEVERITY_RANK = 5


class Taint(BaseModel):
    """Source-to-sink chain. All optional: partial chains still carry signal."""

    source: str = Field(default="", description="Where untrusted input enters")
    sink: str = Field(default="", description="Dangerous operation it reaches")
    path: list[str] = Field(default_factory=list,
                            description="Intermediate steps, file:line each")


class EvidenceRef(BaseModel):
    """One structured file:line citation.

    The audit schema's evidence objects are ``[{file, line, note}]``
    and required: machine-checkable, never parsed out of prose. Hunters
    attach these alongside the free-text evidence so ``evidence_gate`` and
    the reporters can decide on typed data instead of heuristics.
    """

    file: str = Field(default="", description="Repo-relative file path")
    line: int = Field(default=0, ge=0,
                      description="Line number, 0 when unknown")
    note: str = Field(default="",
                      description="What this line shows for the claim")


class Finding(BaseModel):
    """One candidate finding. Lenient by design: missing fields fall back to
    fail-open defaults downstream, so a thin-but-real claim is never lost to
    schema strictness. Values that matter are constrained (Literal/bounds/
    pattern) so a wrong one is re-prompted in-loop instead of being silently
    clamped by the normalizer."""

    id: str = Field(default="", description="Stable finding id")
    title: str = Field(default="", description="Short vulnerability title")
    cwe: str = Field(default="", pattern=r"^(CWE-\d{1,7})?$",
                     description="CWE id, e.g. CWE-89, or empty")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        default="medium", description="Claimed severity; the validator re-rates it")
    confidence: float = Field(default=0.3, ge=0.0, le=1.0,
                              description="Confidence 0-1")
    path: str = Field(default="", description="Repo-relative file path")
    start_line: int = Field(default=0, ge=0, description="Exact 1-based start line of the sink statement")
    end_line: int = Field(default=0, ge=0, description="Exact 1-based end line of the sink statement")
    snippet: str = Field(default="", description="Exact 1-4 lines containing the sink statement (never paste entire functions)")
    taint: Taint = Field(default_factory=Taint,
                         description="Source-to-sink chain")
    refs: list[EvidenceRef] = Field(
        default_factory=list,
        description="Structured file:line citations backing the claim")
    rationale: str = Field(default="", description="Why this is real: who controls the input, how it reaches the sink, what breaks")
    evidence: str = Field(default="", description="Supporting detail with file:line")
    status: Literal["needs-review"] = Field(
        default="needs-review", description="Always needs-review from discovery")


class DiscoveryResult(BaseModel):
    """Candidate findings returned by a unit hunter or the system pass."""

    model_config = ConfigDict(extra="allow")

    findings: list[Finding] = Field(default_factory=list,
                                    description="Candidate findings from this pass")


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
