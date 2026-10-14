"""Verification helpers: reachability gate."""
from __future__ import annotations

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(*dargs, **dkwargs):  # type: ignore
        def deco(fn):
            return fn
        if dargs and callable(dargs[0]):
            return dargs[0]
        return deco


@tool(parse_docstring=True)
def reachability_check(path: str, snippet: str, sanitizer_hint: str = "") -> str:
    """Heuristic static check: flags obvious sanitizers to aid the validator LLM.

    Looks for common sanitizer signals in the snippet + file context.
    The LLM makes the final call; this only surfaces evidence.

    Args:
        path: File path containing the candidate snippet.
        snippet: Suspicious code snippet.
        sanitizer_hint: Optional hint of a sanitizer present.
    """
    from harness.tools.code import _safe_path
    try:
        p = _safe_path(path)
    except ValueError as e:
        return f"ERROR: {e}"
    context = ""
    try:
        if p.is_file() and not p.is_symlink():
            context = p.read_text(errors="replace")[:20000]
    except OSError:
        pass
    blob = f"{snippet}\n{context}\n{sanitizer_hint}".lower()
    signals = []
    for sig in ["parameterized", "placeholder", "execute(", "sanitize_html", "escape",
                "int(", "allowlist", "realpath", "csrf", "auth_required",
                "login_required", "permission", "prepared", "bound parameter"]:
        if sig in blob:
            signals.append(sig)
    if signals:
        return f"possible-sanitizer signals: {', '.join(signals)}. Validator must confirm they actually neutralize the sink."
    return "no obvious sanitizer signal found. Treat as potentially reachable."
