"""Validator prompts: adversarial system prompt, shared refutation method,
and falsify instructions.

Structured output lives here too, next to the text that describes it: the
Pydantic models ARE the verdict shape the instructions ask for.
"""
from pydantic import BaseModel, Field

VALIDATOR_SYSTEM = (
    "You are a security validator. You did not write these candidate findings and you "
    "cannot see how they were found. Your default assumption is that each one is WRONG; "
    "your job is to re-derive the claim from the source code and decide if it is truly exploitable. "
    "Work from the source, not from the finding's description: re-derive the path "
    "yourself, verify reachability from untrusted input, then check for neutralizing controls or exclusion rules. "
    "Cite file:line for every claim you make. A finding survives only on concrete source evidence."
)

# Shared adversarial procedure. Injected into every validator path (single,
# plain-text, and batched) so all three use the same method and vocabulary.
REFUTE_METHOD = (
    "For each finding, in order:\n"
    "1. Re-derive the path yourself from the code at the cited location. Do not trust "
    "the finding's description; scanners misread code, and starting from the summary "
    "inherits the misreading.\n"
    "2. Trace reachability backwards from the sink: establish whether attacker-controlled input "
    "can actually reach this line intact. Unreachable or dead code is a FALSE POSITIVE. "
    "Test-only code is excluded unless the benchmark/demo target intentionally evaluates it.\n"
    "3. Hunt for protections along that path: validation, escaping, parameterization, framework "
    "defaults, type constraints, allowlists, auth, config gating. Actively look for reasons the "
    "claim does NOT hold.\n"
    "4. Stress-test protections: is the control applied on every route this input can take, or "
    "are there alternate routes or bypasses? Do not audit unrelated entry points — settle this "
    "finding and report the verdict.\n"
    "You have NOT seen the hunter's reasoning and must not try to reconstruct it."
)

EXCLUSION_RULES = (
    "EXCLUSION RULES (mark status='fp' citing the rule number if any apply):\n"
    "1. Volumetric DoS or missing rate-limiting (infrastructure layer concern). ReDoS / algorithmic complexity ARE valid.\n"
    "2. Test-only scaffolding, fixtures, dead code, or crashes with no security impact. "
    "Do not exclude a build, CI, IaC, or release path when it crosses an in-scope "
    "security boundary. In benchmark repositories or intentionally vulnerable demo "
    "suites, the triggers and routes being evaluated are in scope.\n"
    "3. Intended application design or documentation examples. (Note: do NOT use rule 3 to dismiss purposely-vulnerable benchmark modules, demo apps, or test cases being evaluated).\n"
    "4. Memory-safety concerns in memory-safe languages outside unsafe/FFI blocks.\n"
    "5. SSRF where the attacker only controls URL path/query parameters, not host or protocol.\n"
    "6. User input into LLM prompt without code execution consequence (prompt injection is not a code bug).\n"
    "7. Path traversal in cloud storage (S3/GCS) where '../' does not escape trust boundary.\n"
    "8. Operator-controlled inputs (env vars, CLI flags) unless environment specifies untrusted. (Note: mock wrappers like @mock_connection used to prevent outbound test traffic are test scaffolding, not sanitizers; evaluate whether the underlying function sink is vulnerable).\n"
    "9. Client-side code flagged for server-side vulnerability classes.\n"
    "10. Outdated dependency versions (SCA concern, not source vulnerability).\n"
    "11. Weak randomness used for non-security purposes (UUIDv4, jitter, UI colors, math). In benchmark targets where PRNG weaknesses are under test, flag the weak primitive.\n"
    "12. Low-impact nuisance issues (log spoofing, open redirect without token leak, self-XSS, tabnabbing).\n"
    "13. Missing hardening or best-practice gap with no concrete exploit path (missing headers, no audit logs). In benchmark targets where weak hashing (MD5/SHA1) is under test, report the weak primitive.\n"
    "14. XSS in frameworks with context-aware auto-escaping (React/Angular/Vue/Jinja2 autoescape=on) without raw HTML escape hatches.\n"
    "15. Unguessable identifiers (UUIDv4, 128-bit cryptographic tokens) flagged as predictable.\n"
    "16. Purely theoretical race conditions / TOCTOU with no realistic race window."
)

FALSIFY_INSTRUCTIONS = (
    "Judge each finding by backwards reachability, neutralizing controls, and exclusion rules:\n"
    "- status='confirmed': The path is reachable from untrusted entry point to the dangerous sink, "
    "and controls along the path are absent, ineffective, or bypassable. Real-world exploitation is feasible.\n"
    "- status='fp': The sink is unreachable from untrusted input, the input is strictly sanitized/bound/cast "
    "before the sink, the scanner misread non-vulnerable code, or one of the EXCLUSION RULES applies. "
    "In evidence, cite the specific neutralizing control or exclusion rule with file:line.\n"
    "- status='needs-review': Static evidence cannot settle reachability or control effectiveness "
    "(e.g., depends on uninspected external configuration or complex runtime state). Name the specific unsettled fact.\n"
    "Return only the status, confidence, severity, and evidence you can support with file:line."
)

class VerdictUpdate(BaseModel):
    """Single-finding verdict. Lenient by design: all optional, merged and
    clamped by code, so a partial verdict still carries signal."""

    status: str = Field(default="needs-review",
                        description="Verdict: confirmed, fp, or needs-review")
    confidence: float | None = Field(default=None,
                                     description="Confidence 0-1")
    severity: str | None = Field(default=None,
                                 description="critical, high, medium, low, or info")
    evidence: str | None = Field(default=None,
                                 description="One-line reason with file:line")
    cwe: str | None = Field(default=None, description="Corrected CWE if any")
    fix_suggestion: str | None = Field(default=None,
                                       description="Minimal fix if confirmed")
    snippet: str | None = Field(default=None,
                                description="Corrected code snippet if any")


class VerdictItem(VerdictUpdate):
    """One batch verdict: the update plus which finding it belongs to."""

    id: str = Field(default="", description="Finding id this verdict covers")


class VerdictBatch(BaseModel):
    """One cell of batch verdicts (object wrapper: backends choke on bare
    top-level arrays)."""

    verdicts: list[VerdictItem] = Field(default_factory=list,
                                        description="One verdict per finding id")


def _validator_message(base: dict, instructions: str, threat_md: str = "") -> str:
    """Pure message builder: specialist instructions + finding JSON + threat-model
    context (prioritization only — scope never acquits)."""
    import json as _json

    parts = [
        f"{instructions}",
        REFUTE_METHOD,
        EXCLUSION_RULES,
        f"Finding JSON:\n{_json.dumps(base, default=str)[:6000]}",
    ]
    if (threat_md or "").strip():
        parts.append(
            "Threat-model context for this scan (FULL text, prioritization "
            "ONLY, not truncated):\n"
            + threat_md.strip()
            + "\nThreat-model rows NEVER justify fp — judge ONLY the data flow "
              "into the sink. Scope/deprioritization opinions belong in "
              "EVIDENCE text, never in STATUS.")
    parts.append(
        "Reply with status (confirmed|fp|needs-review), confidence 0-1, "
        "severity, and evidence (required: file:line + snippet + source->sink "
        "or the disproving sanitizer).")
    return "\n".join(parts)


def build_batch_task(group_name: str, threat_md: str, payload: list) -> str:
    """Assemble the partition batch prompt: adversarial framing plus one
    verdict object per finding id."""
    import json as _json

    return (
        f"You did not write these {len(payload)} findings and you cannot "
        f"see how they were found. Assume each is wrong until the source "
        f"proves otherwise. Partition '{group_name}'.\n"
        + (f"Threat-model context (FULL text, prioritization ONLY, not "
           f"truncated):\n{threat_md.strip()}\n"
           "Threat-model rows NEVER justify fp — judge ONLY the data flow "
           "into the sink. Scope/deprioritization opinions belong in "
           "EVIDENCE text, never in STATUS.\n" if threat_md else "")
        + REFUTE_METHOD + "\n"
        + EXCLUSION_RULES + "\n"
        + FALSIFY_INSTRUCTIONS + "\n"
        f"Findings JSON:\n{_json.dumps(payload, default=str)[:20000]}\n"
        "Reply with a JSON object containing the array of verdicts: "
        '{"verdicts": [{"id": ..., "status": "confirmed|fp|needs-review", '
        '"confidence": 0-1, "severity": ..., "evidence": "..."}]}. '
        "Cover EVERY listed id."
    )
