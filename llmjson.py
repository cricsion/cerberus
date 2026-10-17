"""Best-effort parser for JSON arrays in LLM replies (fenced, prose-prefixed, or
wrapped in a contract object). Stdlib only; fail-open."""
from __future__ import annotations

import json


def extract_json_array(text: object) -> list | None:
    """First JSON array in an LLM reply, or None. Scans each '[' offset; the most
    dict-heavy array wins, so citation arrays cannot shadow findings."""
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
        except ValueError:
            continue
        if not isinstance(parsed, list):
            continue
        key = (sum(1 for it in parsed if isinstance(it, dict)), len(parsed), -i)
        if best_key is None or key > best_key:
            best_key = key
            best = parsed
    return best


def parse_verdict_array(text: object, *, require_id: bool = False) -> list[dict]:
    """Best-effort parse of a JSON array of dicts; unwraps a ``verdicts`` object,
    drops non-dict items and (with require_id) id-less items."""
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
    """Structured items first, else a raw-text fallback (shared validator and
    triage core)."""
    items = [it for it in structured_items(parsed, field)
             if isinstance(it, dict) and (it.get("id") or not require_id)]
    if items:
        return items
    return parse_verdict_array(raw_text, require_id=require_id)


def extract_string_array(text: object,
                         field: str = "questions") -> list[str] | None:
    """Best-effort string array from raw LLM text (bare or wrapper object); never
    raises, None when none decodes."""
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
        except ValueError:
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
