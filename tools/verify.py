"""Verification helpers: reachability gate."""
from __future__ import annotations

from ._compat import tool


@tool(parse_docstring=True)
def reachability_check(path: str, snippet: str, sanitizer_hint: str = "",
                       from_symbol: str = "", to_symbol: str = "") -> str:
    """Heuristic static and call-graph reachability check.

    Flags sanitizers and optionally traces call paths between an entry symbol and a sink.
    Surfaces evidence only; the validator LLM makes the final call.

    Args:
        path: File path containing the candidate snippet.
        snippet: Suspicious code snippet.
        sanitizer_hint: Optional hint of a sanitizer present.
        from_symbol: Optional entry point or caller symbol (e.g. 'handle_request').
        to_symbol: Optional sink or callee symbol (e.g. 'execute_query').
    """
    lines = []
    if from_symbol and to_symbol:
        try:
            from harness.codegraph import native
            call_path = native.find_path(from_symbol, to_symbol)
            if isinstance(call_path, dict) and call_path.get("error"):
                lines.append(f"Call-graph reachability unavailable: {call_path['error']}")
            elif call_path:
                lines.append(f"Call-graph reachability: PROVEN path from {from_symbol} to {to_symbol} ({len(call_path)} steps):")
                for step in call_path[:5]:
                    node = step.get("node", {})
                    edge = step.get("edge")
                    node_desc = f"[{node.get('kind', 'symbol')}] {node.get('name')} ({node.get('filePath')}:{node.get('startLine')})"
                    if edge:
                        lines.append(f"  --({edge.get('kind', 'calls')})--> {node_desc}")
                    else:
                        lines.append(f"  -> {node_desc}")
            else:
                lines.append(f"Call-graph reachability: no path found between {from_symbol} and {to_symbol}.")
        except Exception as exc:
            lines.append(f"Call-graph reachability check failed: {exc}")

    from harness.tools.code import _safe_path
    try:
        p = _safe_path(path)
    except ValueError as e:
        err_msg = f"ERROR: {e}"
        return f"{err_msg}\n" + "\n".join(lines) if lines else err_msg

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
        lines.append(f"possible-sanitizer signals: {', '.join(signals)}. Validator must confirm they actually neutralize the sink.")
    else:
        lines.append("no obvious sanitizer signal found. Treat as potentially reachable.")
    return "\n".join(lines)
