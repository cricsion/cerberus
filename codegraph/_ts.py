"""Tree-sitter helpers over the CodeGraph index — local parsing, no subprocess.

What this gives that a raw ``tree_sitter`` session does not:

- **One entry point per question the SAST tools actually ask**: which parser
  owns this file, what is the text at this line, which function encloses this
  line, what does this function call, what are the parameters in this
  ``nodes.signature`` string, what does the source look like around this line.
  Each of those is otherwise twenty lines of node-walking copy-pasted per tool.
- **CodeGraph-compatible naming.** ``nodes.language`` says ``csharp``; the
  grammar module is ``tree_sitter_c_sharp``; ``.tsx`` needs a second language
  out of ``tree_sitter_typescript``. :func:`parser_for_language` and
  :data:`LANG_BY_EXT` absorb that mismatch, cached per process so a tool call
  costs a dict lookup, not a grammar load.
- **The same 1 MB per-file cap CodeGraph indexes with** — a file the indexer
  skipped has no symbols here either, and parsing it would only produce
  half-formed spans that disagree with the graph.
- **Signature parsing.** CodeGraph stores ``signature`` as text
  (``def f(a: int, b: str = 'x') -> bool``); nothing joins it back to the call's
  arity, so a taint check that needs parameter names/types would re-implement a
  parser per language. :func:`parse_signature_params` is that parser, best
  effort and never raising.

Everything degrades to ``None``/``[]`` rather than raising: an unsupported
extension, an unreadable file, a grammar that is not installed. ``parse`` only
ever receives ``bytes`` — passing a ``str`` is the one mistake the 0.24+ API
punishes, and this module is the only place that can make it.
"""
from __future__ import annotations

import re
from pathlib import Path

# Extension -> the CodeGraph language name (``nodes.language`` spelling).
LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "c_sharp",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
}

# Grammar module name per canonical language key. CodeGraph spells C# as
# ``csharp`` in nodes.language while LANG_BY_EXT spells it ``c_sharp``; both
# resolve through here.
_GRAMMAR_MODULE: dict[str, str] = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "tsx": "tree_sitter_typescript",
    "go": "tree_sitter_go",
    "java": "tree_sitter_java",
    "rust": "tree_sitter_rust",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "ruby": "tree_sitter_ruby",
    "php": "tree_sitter_php",
    "csharp": "tree_sitter_c_sharp",
    "kotlin": "tree_sitter_kotlin",
    "swift": "tree_sitter_swift",
    "scala": "tree_sitter_scala",
}

# Alternate spellings seen in the wild (CodeGraph language values, file
# extensions, agent shorthand) folded onto the canonical key above.
_LANGUAGE_ALIASES: dict[str, str] = {
    "c_sharp": "csharp", "c#": "csharp", "cs": "csharp",
    "py": "python",
    "ts": "typescript", "typescriptreact": "tsx",
    "js": "javascript", "jsx": "javascript",
    "golang": "go",
    "rs": "rust",
    "kt": "kotlin",
    "objc": "c", "objective-c": "c", "objectivec": "c",
    "cpp": "cpp", "c++": "cpp", "cxx": "cpp", "cc": "cpp",
    "rb": "ruby",
}

# Node types that mean "a callable". Python: function_definition covers both
# ``def`` and ``async def``. The rest are the JS/TS/Go/Java/Rust/C spellings.
CALL_NODE_TYPES = frozenset({
    "call", "call_expression", "method_invocation", "macro_invocation",
    "function_call", "invocation_expression", "constructor_invocation",
})

FUNCTION_NODE_TYPES = frozenset({
    "function_definition", "method_definition", "function_declaration",
    "method_declaration", "func", "function", "function_item",
    "constructor_declaration", "arrow_function", "function_expression",
    "method", "closure_expression", "fn_item",
})

CLASS_NODE_TYPES = frozenset({
    "class_definition", "class_declaration", "class_specifier",
    "class_body", "struct_specifier", "struct_item", "impl_item",
    "trait_item", "interface_declaration", "protocol_declaration",
    "object_declaration", "enum_declaration", "record_declaration",
})

# CodeGraph's own cap: a file above 1 MB yields no symbols at all, so parsing
# one here would invent spans the index does not have.
MAX_FILE_BYTES = 1_000_000

_language_cache: dict[str, object] = {}
_parser_cache: dict[str, object] = {}


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------

def _canonical_language(language: str | None) -> str:
    """Fold a spelling onto a grammar key ('' when unknown)."""
    if not language:
        return ""
    key = str(language).strip().lower().replace("-", "_")
    key = _LANGUAGE_ALIASES.get(key, key)
    return key if key in _GRAMMAR_MODULE else ""


def _load_language(key: str):
    """The tree-sitter Language for a canonical key, or None (not installed)."""
    if not key:
        return None
    if key in _language_cache:
        return _language_cache[key]
    from tree_sitter import Language  # imported lazily: grammar-free callers
    module_name = _GRAMMAR_MODULE[key]
    lang = None
    try:
        import importlib
        module = importlib.import_module(module_name)
    except ImportError:
        module = None
    if module is not None:
        factory = None
        if key == "typescript":
            factory = getattr(module, "language_typescript", None)
        elif key == "tsx":
            factory = getattr(module, "language_tsx", None)
        if factory is None:
            factory = getattr(module, "language", None)
        if factory is None:
            factory = getattr(module, f"language_{key}", None)
        if factory is not None:
            try:
                lang = Language(factory())
            except Exception:
                lang = None
    _language_cache[key] = lang
    return lang


def parser_for_language(language: str):
    """Cached parser for a CodeGraph ``nodes.language`` value; None if unknown.

    Accepts the index spellings (``csharp``, ``typescript``, ``tsx``, ``cpp``)
    and the LANG_BY_EXT spellings (``c_sharp``).
    """
    if not language:
        return None
    key = _canonical_language(language)
    if not key:
        return None
    if key in _parser_cache:
        return _parser_cache[key]
    from tree_sitter import Parser
    lang = _load_language(key)
    parser = None
    if lang is not None:
        try:
            parser = Parser(lang)
        except Exception:
            parser = None
    _parser_cache[key] = parser
    return parser


def parser_for_file(path):
    """Cached parser for a file's extension; None when unsupported."""
    try:
        suffix = Path(str(path)).suffix.lower()
    except Exception:
        return None
    return parser_for_language(LANG_BY_EXT.get(suffix, ""))


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def _read_capped(path, max_bytes: int = MAX_FILE_BYTES):
    """(source_bytes, stat_size) or (None, reason). Never raises."""
    try:
        p = Path(str(path))
        size = p.stat().st_size
        if size > max_bytes:
            return None, size
        with open(p, "rb") as fh:
            return fh.read(max_bytes + 1), size
    except OSError:
        return None, -1


def parse_file(path, max_bytes: int = MAX_FILE_BYTES):
    """(tree, source_bytes) for a source file, or None.

    None when the extension is unsupported, the grammar is missing, the file is
    unreadable, or the file is over ``max_bytes`` — the same 1 MB cap the
    indexer applies, so a skipped file produces no symbols on either side.
    ``max_bytes <= 0`` means "the default cap", not "unlimited": parsing a
    file the index refused to index would invent spans the graph disagrees
    with, and a runaway parse costs more than the symbols are worth.
    """
    if max_bytes is None:
        max_bytes = MAX_FILE_BYTES
    try:
        max_bytes = int(max_bytes)
    except (TypeError, ValueError):
        max_bytes = MAX_FILE_BYTES
    if max_bytes <= 0:
        max_bytes = MAX_FILE_BYTES
    parser = parser_for_file(path)
    if parser is None:
        return None
    src, _size = _read_capped(path, max_bytes)
    if src is None or len(src) > max_bytes:
        return None
    try:
        tree = parser.parse(src)
    except Exception:
        return None
    if tree is None or tree.root_node is None:
        return None
    return tree, src


def parse_source(text, language: str):
    """Parse an in-memory string. A tree, or None for an unsupported language.

    ``text`` is encoded to bytes first — ``Parser.parse`` in the 0.24+ API
    rejects a ``str`` outright, and this is the one helper every other module
    funnels through.
    """
    if text is None:
        return None
    parser = parser_for_language(language)
    if parser is None:
        return None
    if isinstance(text, str):
        src = text.encode("utf-8", errors="replace")
    else:
        src = bytes(text)
    try:
        return parser.parse(src)
    except Exception:
        return None


def node_text(node, src: bytes) -> str:
    """The exact source text of a node ('' when the span is unreadable)."""
    if node is None or not src:
        return ""
    try:
        raw = src[node.start_byte:node.end_byte]
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace")


def line_text(src_lines_or_bytes, line_no: int) -> str:
    """One 1-based source line. Accepts bytes, str, or a list of lines."""
    try:
        n = int(line_no)
    except (TypeError, ValueError):
        return ""
    if src_lines_or_bytes is None:
        return ""
    if isinstance(src_lines_or_bytes, (bytes, bytearray)):
        lines = bytes(src_lines_or_bytes).decode("utf-8", errors="replace").splitlines()
    elif isinstance(src_lines_or_bytes, str):
        lines = src_lines_or_bytes.splitlines()
    else:
        try:
            lines = list(src_lines_or_bytes)
        except TypeError:
            return ""
    if n < 1 or n > len(lines):
        return ""
    out = lines[n - 1]
    return out if isinstance(out, str) else out.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# span queries
# ---------------------------------------------------------------------------

def _contains(node, line: int) -> bool:
    """1-based line containment for a node's start/end points."""
    try:
        return (node.start_point[0] + 1) <= line <= (node.end_point[0] + 1)
    except Exception:
        return False


def _walk(node):
    """Depth-first, parent before children."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        children = list(current.children)
        stack.extend(reversed(children))


def _best_containing(tree, line: int, wanted):
    """Deepest node whose span contains ``line`` and whose type is in ``wanted``."""
    try:
        root = tree.root_node
    except Exception:
        return None
    best = None
    best_span = None
    for node in _walk(root):
        if not _contains(node, line):
            continue
        if wanted is not None and node.type not in wanted:
            continue
        span = (node.end_point[0] - node.start_point[0],
                node.end_byte - node.start_byte)
        if best is None or span <= best_span:
            best, best_span = node, span
    return best


def enclosing_node(tree, line: int):
    """The innermost function/method/class node whose span contains ``line``.

    Falls back to the deepest span-containing node of any type, so a call
    inside a lambda, a comprehension or a decorator still gets a location.
    ``tree`` is a ``Tree`` from :func:`parse_source` / :func:`parse_file`.
    """
    try:
        target = int(line)
    except (TypeError, ValueError):
        return None
    node = _best_containing(tree, target, FUNCTION_NODE_TYPES | CLASS_NODE_TYPES)
    if node is not None:
        return node
    return _best_containing(tree, target, None)


def enclosing_function(tree, line: int):
    """Same search, functions/methods only — the unit a finding belongs to."""
    try:
        target = int(line)
    except (TypeError, ValueError):
        return None
    return _best_containing(tree, target, FUNCTION_NODE_TYPES)


def calls_in_span(tree, start_line: int, end_line: int, src: bytes) -> list[dict]:
    """Every call in the 1-based inclusive line span.

    Each entry is ``{"line", "col", "text", "node"}`` where ``text`` is the
    callee as written (``db.query`` — the whole member chain, not just the last
    segment) so it can be fed straight into :func:`sinks.classify_call`.
    """
    out: list[dict] = []
    if tree is None:
        return out
    try:
        start, end = int(start_line), int(end_line)
    except (TypeError, ValueError):
        return out
    if end < start:
        start, end = end, start
    try:
        root = tree.root_node
    except Exception:
        return out
    for node in _walk(root):
        if node.type not in CALL_NODE_TYPES:
            continue
        try:
            node_start = node.start_point[0] + 1
        except Exception:
            continue
        if node_start < start or node_start > end:
            continue
        callee = node.child_by_field_name("function")
        if callee is None:
            callee = node.child_by_field_name("callee")
        if callee is None:
            named = [c for c in node.children if c.is_named]
            callee = named[0] if named else None
        text = node_text(callee, src) if callee is not None else ""
        if not text:
            text = node_text(node, src)
        out.append({
            "line": node_start,
            "col": node.start_point[1] + 1,
            "text": text,
            "node": node,
        })
    out.sort(key=lambda c: (c["line"], c["col"]))
    return out


# ---------------------------------------------------------------------------
# signature parsing
# ---------------------------------------------------------------------------

_PARAM_KEYWORDS = (
    "async def ", "def ", "async function ", "function ", "fn ", "func ",
    "sub ", "fun ", "pub fn ", "public ", "private ", "protected ", "static ",
    "final ", "override ", "export ", "default ", "virtual ", "abstract ",
    "suspend ", "inline ", "extern ", "async ",
)

# Parameter-property / receiver modifiers that sit before a JS/TS parameter name.
_PARAM_NAME_MODIFIERS = (
    "public", "private", "protected", "readonly", "static", "final",
    "override", "var", "let", "const", "in", "out", "ref", "params", "this",
)

# Languages whose parameter lists read ``Type name`` rather than ``name: Type``.
_TYPE_FIRST_LANGUAGES = frozenset({
    "java", "kotlin", "scala", "csharp", "c", "cpp", "objc", "php",
    "objectivec", "c_sharp",
})

# Languages that write ``name Type`` with no colon at all (Go: ``cmd string``).
_NAME_FIRST_LANGUAGES = frozenset({"go", "rust", "php", "swift"})


def _strip_param_modifiers(text: str) -> str:
    out = str(text or "").strip()
    if not out:
        return ""
    changed = True
    while changed:
        changed = False
        low = out.lower()
        for kw in _PARAM_KEYWORDS:
            if low.startswith(kw):
                out = out[len(kw):].lstrip()
                changed = True
                break
    # A leading return type on a Java-ish declaration: `void doThing(...)`.
    head = out.split("(", 1)[0].strip()
    if head and " " in head and re.fullmatch(r"[A-Za-z_$][\w$.<>,\[\]]*", head):
        parts = head.split()
        last = parts[-1]
        if re.fullmatch(r"[A-Za-z_$][\w$]*", last) and "<" not in parts[0]:
            out = out[len(parts[0]):].lstrip()
    return out


def _split_top_level(text: str, separators: str = ",") -> list[str]:
    """Split on separators that are not inside (), [], {}, <> or a string."""
    parts: list[str] = []
    depth = 0
    angle = 0
    quote = ""
    buf: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        if ch in separators and depth == 0 and angle == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _balanced_parens(text: str) -> str:
    """The text between the first '(' and its matching ')'."""
    start = text.find("(")
    if start < 0:
        return ""
    depth = 0
    quote = ""
    i = start
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return ""


def parse_signature_params(signature: str, language: str) -> list[dict]:
    """Best-effort parameter list from a ``nodes.signature`` string.

    Handles ``def f(a: int, b: str = 'x') -> bool``,
    ``async handle(req: Request, res: Response)`` and the ``Type name`` order of
    the C/JVM family. Never raises — an unparsable signature yields ``[]``
    rather than costing a tool call.
    """
    try:
        text = _strip_param_modifiers(signature)
        if not text:
            return []
        inner = _balanced_parens(text)
        if not inner.strip():
            return []
        lang = _canonical_language(language) or str(language or "").lower()
        type_first = lang in _TYPE_FIRST_LANGUAGES
        out: list[dict] = []
        for index, raw in enumerate(_split_top_level(inner)):
            piece = raw.strip()
            if not piece or piece in ("*", "**", "/", "...", "self", "cls"):
                continue
            name_part, default = piece, ""
            head_tail = _split_top_level(piece, "=")
            if len(head_tail) >= 2:
                name_part = head_tail[0].strip()
                default = "=".join(head_tail[1:]).strip()
            name, type_name = "", ""
            colon = _split_top_level(name_part, ":")
            if len(colon) >= 2:
                type_name = ":".join(colon[1:]).strip()
                name_tokens = [t for t in colon[0].split() if t]
                while name_tokens and name_tokens[0] in _PARAM_NAME_MODIFIERS:
                    name_tokens.pop(0)
                name = name_tokens[-1] if name_tokens else ""
            else:
                tokens = [t for t in name_part.replace(",", " ").split() if t]
                while tokens and tokens[0] in _PARAM_NAME_MODIFIERS:
                    tokens.pop(0)
                if len(tokens) >= 2 and type_first:
                    type_name, name = tokens[0], tokens[1]
                elif len(tokens) >= 2 and lang in _NAME_FIRST_LANGUAGES:
                    name, type_name = tokens[0], " ".join(tokens[1:])
                elif tokens:
                    # A JS/TS parameter property (`readonly x`) or a spread:
                    # the name is the last word that is not a modifier.
                    name = tokens[-1]
            name = re.sub(r"^[*.$\s]+", "", name).strip()
            type_name = type_name.strip().strip("`").strip()
            if not name and not type_name:
                continue
            out.append({"name": name, "type": type_name,
                        "default": default, "index": index})
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# context windows
# ---------------------------------------------------------------------------

def window(src, center_line: int, radius: int = 3) -> str:
    """``"139: ...\\n140: ..."`` — a numbered window around a 1-based line."""
    try:
        center = int(center_line)
        rad = int(radius)
    except (TypeError, ValueError):
        return ""
    if isinstance(src, (bytes, bytearray)):
        text = bytes(src).decode("utf-8", errors="replace")
    else:
        text = str(src or "")
    lines = text.splitlines()
    if not lines or center < 1 or center > len(lines):
        return ""
    lo = max(1, center - max(0, rad))
    hi = min(len(lines), center + max(0, rad))
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(lo, hi + 1))
