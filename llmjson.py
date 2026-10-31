"""Best-effort parser for JSON arrays in LLM replies (fenced, prose-prefixed, or
wrapped in a contract object). Stdlib only; fail-open."""
from __future__ import annotations

import json
import re

_FENCE_RE = re.compile(r"```(?:json)?\s*(.+?)\s*```", re.DOTALL)


def candidate_jsons(text: object) -> list[str]:
    """Best-effort JSON candidates from an LLM reply: the whole reply first,
    then every fenced block. Callers take the first candidate that parses, so
    prose replies are tried (and fail) before their fenced payloads are tried
    (and succeed)."""
    s = str(text or "").strip()
    if not s:
        return []
    return [s, *[m.group(1) for m in _FENCE_RE.finditer(s)]]


def extract_json_array(text: object) -> list | None:
    """First JSON array in an LLM reply, or None. Tries direct JSON decode,
    code fences, and then bracket offsets with preference for dict-heavy arrays."""
    if not text or not str(text).strip():
        return None
    s = str(text).strip()
    try:
        parsed = json.loads(s)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            for v in parsed.values():
                if isinstance(v, list) and any(isinstance(it, dict) for it in v):
                    return v
    except (ValueError, TypeError):
        pass

    for m in _FENCE_RE.finditer(s):
        try:
            parsed = json.loads(m.group(1).strip())
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                for v in parsed.values():
                    if isinstance(v, list) and any(isinstance(it, dict) for it in v):
                        return v
        except (ValueError, TypeError):
            continue

    dec = json.JSONDecoder()
    best: list | None = None
    best_key: tuple[int, int, int] | None = None
    for m in re.finditer(r"\[", s):
        i = m.start()
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
