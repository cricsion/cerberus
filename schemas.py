"""Canonical finding schema plus ordering and coercion helpers.

``Finding`` (wrapped by ``DiscoveryResult``) is the structured-output contract
hunters emit. After discovery, findings travel as plain dicts; the validator
and triage stages add ``status``, ``patch_summary``, ``control_type``,
``duplicate_of`` and ``triage`` in place.
"""
from __future__ import annotations

from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

UNKNOWN_SEVERITY_RANK = 5


class TaintDict(TypedDict, total=False):
    source: str
    sink: str
    path: list[str]


class EvidenceRefDict(TypedDict, total=False):
    file: str
    line: int
    note: str


class PocReceiptDict(TypedDict, total=False):
    runs: int
    successes: int
    control_status: Literal["passed", "violated", "invalid", "skipped"]
    outputs: list[str]
    error: str | None
    stamped_by: str


class PocItemDict(TypedDict, total=False):
    approach: str
    command: str
    script: str
    filename: str
    language: str
    expected: str
    control: str
    runs: int
    successes: int
    flaky: bool
    status: Literal["proven", "attempted", "blocked", "planned"]
    receipt: PocReceiptDict


class FindingDict(TypedDict, total=False):
    """The canonical vulnerability finding dictionary representation."""
    id: str
    title: str
    cwe: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    path: str
    start_line: int
    end_line: int
    snippet: str
    taint: TaintDict
    refs: list[EvidenceRefDict]
    rationale: str
    evidence: str
    status: Literal["needs-review", "confirmed", "fp"]
    hunter_evidence: str
    hunter_snippet: str
    control_type: str
    patch_summary: str
    patch: str
    duplicate_of: str
    triage: dict
    cvss: float
    rank: int
    fallback_note: str
    poc: PocItemDict
    conditions: list[str]


class DiscoveryResultDict(TypedDict, total=False):
    findings: list[FindingDict]


class Taint(BaseModel):
    """Source-to-sink chain. All optional: partial chains still carry signal."""
    model_config = ConfigDict(extra="allow")

    source: str = Field(default="", description="Where untrusted input enters")
    sink: str = Field(default="", description="Dangerous operation it reaches")
    path: list[str] = Field(default_factory=list,
                            description="Intermediate steps, file:line each")


class EvidenceRef(BaseModel):
    """One structured file:line citation."""
    model_config = ConfigDict(extra="allow")

    file: str = Field(default="", description="Repo-relative file path")
    line: int = Field(default=0, ge=0,
                      description="Line number, 0 when unknown")
    note: str = Field(default="",
                      description="What this line shows for the claim")


class PocReceipt(BaseModel):
    model_config = ConfigDict(extra="allow")

    runs: int = 0
    successes: int = 0
    control_status: Literal["passed", "violated", "invalid", "skipped"] = "skipped"
    outputs: list[str] = Field(default_factory=list)
    error: str | None = None
    stamped_by: str = "harness"


class PocItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    approach: str = Field(default="", description="Why this test proves the claim")
    command: str = Field(default="", description="Replay command relative to repo root")
    script: str = Field(default="", description="Full repro script source (<= 8KB)")
    filename: str = Field(default="poc.py", description="Script filename, e.g. poc.py, poc.js, poc.go, poc.sh")
    language: str = Field(default="", description="Optional language identifier: python, javascript, go, bash, etc.")
    expected: str = Field(default="[POC_PROVEN]", description="Sentinel line that MUST appear on stdout")
    control: str = Field(default="--control", description="Control flag requiring [POC_CONTROL_PASSED]")
    runs: int = 3
    successes: int = 0
    flaky: bool = False
    status: Literal["proven", "attempted", "blocked", "planned"] = "planned"
    receipt: PocReceipt | None = None


class Finding(BaseModel):
    """One candidate finding with all lifecycle stages supported."""
    model_config = ConfigDict(extra="allow")

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
    status: Literal["needs-review", "confirmed", "fp"] = Field(
        default="needs-review", description="Status of finding: needs-review from discovery; confirmed or fp after validation")
    hunter_evidence: str = Field(default="", description="Original hunter evidence preserved before validation")
    hunter_snippet: str = Field(default="", description="Original hunter snippet preserved before validation")
    control_type: str = Field(default="", description="Validator identified control type")
    patch_summary: str = Field(default="", description="Technical summary of the patch and security invariant enforced")
    patch: str = Field(default="", description="Unified diff or concrete code patch fixing the vulnerability")
    duplicate_of: str = Field(default="", description="ID of primary finding if duplicate")
    triage: dict | None = Field(default=None, description="Triage rubric metadata")
    cvss: float | None = Field(default=None, description="CVSS base score")
    rank: int = Field(default=0, description="Rank ordered by severity and confidence")
    fallback_note: str = Field(default="", description="Note if fallback triggered")
    poc: PocItem | dict = Field(default_factory=dict, description="In-process reproduction test or exploit item")
    conditions: list[str] = Field(default_factory=list, description="Prerequisite conditions for exploitability")


class DiscoveryResult(BaseModel):
    """Candidate findings returned by a unit hunter or the system pass."""

    model_config = ConfigDict(extra="allow")

    findings: list[Finding] = Field(default_factory=list,
                                    description="Candidate findings from this pass")


def structured_items(parsed: object, field: str = "verdicts") -> list[dict]:
    """List of dicts from a parsed structured-output payload."""
    out: list[dict] = []
    try:
        raw = (parsed.get(field) if isinstance(parsed, dict)
               else getattr(parsed, field, None))
        items = raw or []
        for it in items:
            try:
                data = it.model_dump() if hasattr(it, "model_dump") else dict(it)
            except Exception:
                continue
            if isinstance(data, dict):
                out.append(data)
    except Exception:
        return []
    return out


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
