"""One best-effort parser for JSON arrays inside LLM replies.

Agent stages ask the model for a JSON array of per-finding verdicts; replies
come back fenced, prefixed with prose, or wrapped in a contract object
(``{"verdicts": [...]}``). Hand-rolled copies drift — one stage silently
stops parsing a format change the others absorb — so the extraction lives
here once. Stdlib only, and fail-open: any malformed reply is ``[]`` so the
caller keeps its deterministic stage rather than raising.
"""
from __future__ import annotations

import json


def extract_json_array(text: object) -> list | None:
    """First JSON array in an LLM reply, or None when none decodes.

    Scans each '[' offset and raw-decodes from there (bracket-matching
    fails on citations like "[1]" in prose). When several arrays decode,
    the one with the most dict elements wins (so a scalar citation "[1]"
    never shadows the real array of finding objects); ties break on the
    longer array, then the earlier offset.
    """
    if not text or not str(text).strip():
        return None
    s = str(text)
    dec = json.JSONDecoder()
    best: list | None = None
    best_key: tuple[int, int, int] | None = None
    for i, ch in enumerate(s):
        if ch != "[":
            continue
        try:
            parsed, _ = dec.raw_decode(s[i:])
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, list):
            continue
        key = (sum(1 for it in parsed if isinstance(it, dict)), len(parsed), -i)
        if best_key is None or key > best_key:
            best_key = key
            best = parsed
    return best


def parse_verdict_array(text: object, *, require_id: bool = False) -> list[dict]:
    """Best-effort parse of a JSON array of dicts from an LLM reply.

    Unwraps a ``{"verdicts": [...]}`` contract object and drops non-dict
    items. ``require_id`` additionally drops items with no truthy ``"id"``
    — used by the stages that merge verdicts back into findings by id, which
    would otherwise KeyError (or silently mis-merge) on an id-less item.
    Never raises.
    """
    if not text or not str(text).strip():
        return []
    arr = extract_json_array(text)
    if arr is None:
        return []
    return [it for it in arr
            if isinstance(it, dict) and (it.get("id") or not require_id)]


def structured_items(parsed: object, field: str = "verdicts") -> list[dict]:
    """List of dicts from a parsed structured-output payload (never raises)."""
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


def extract_structured_items(parsed: object, raw_text: object, *,
                             field: str = "verdicts",
                             require_id: bool = True) -> list[dict]:
    """Prefer parsed structured output, then parse raw text as fallback.

    This is the shared core for validator and triage: both accept a
    ``{field: [...]}`` structured result and fall back to the agent's final
    text. Keeping it here stops the two stages from drifting apart.
    """
    items = [it for it in structured_items(parsed, field)
             if isinstance(it, dict) and (it.get("id") or not require_id)]
    if items:
        return items
    return parse_verdict_array(raw_text, require_id=require_id)


def extract_string_array(text: object,
                         field: str = "questions") -> list[str] | None:
    """Best-effort array of strings from raw LLM text.

    Accepts ``["a", "b"]`` or a wrapper object such as
    ``{"questions": ["a"]}``. Returns None when no decodable array exists.
    Never raises.
    """
    if not text or not str(text).strip():
        return None
    s = str(text)
    decoder = json.JSONDecoder()
    best: list[str] | None = None
    best_key: tuple[int, int, int, int] | None = None
    for idx, char in enumerate(s):
        if char not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(s[idx:])
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            parsed = parsed.get(field)
        if not isinstance(parsed, list):
            continue
        values = [str(x) for x in parsed if str(x).strip()]
        # Prefer question-shaped payloads over citation arrays like `[1]`.
        any_question = int(any(v.strip().endswith("?") for v in values))
        key = (any_question, len(values), len(parsed), -idx)
        if best_key is None or key > best_key:
            best_key = key
            best = values
    return best
