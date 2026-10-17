from __future__ import annotations

import re
from pathlib import Path

from ._compat import tool
from .code import _resolve_limit, grep_files


def _safe_root(root: str) -> Path:
    from harness.tools.code import _safe_path
    return _safe_path(root)


@tool(parse_docstring=True)
def manifest_parse(root: str = ".", limit: int | None = None) -> str:
    """Summarize dependency manifests + container/IaC files under root. Paginated via limit (0=unlimited).

    Args:
        root: Directory containing manifests/IaC files.
        limit: Max files to summarize. 0 = unlimited.
    """
    try:
        base = _safe_root(root)
    except ValueError as e:
        return f"ERROR: {e}"
    if not base.exists():
        return "(no manifests found)"
    lines: list[str] = []
    known = [
        "package.json", "package-lock.json", "requirements.txt",
        "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
        "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
        "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
        "Cargo.toml", "Cargo.lock", "packages.config",
        "CMakeLists.txt", "Makefile",
    ]
    for proj in sorted(base.glob("*.csproj")):
        try:
            if proj.is_file():
                lines.append(f"{proj.name} (.NET)")
        except OSError:
            continue
    for name in known:
        p = base / name
        if p.is_file():
            try:
                size = p.stat().st_size
            except OSError:
                size = -1
            try:
                preview = p.read_text(errors="replace")[:1500].strip().replace("\n", " ")[:500]
            except OSError:
                preview = "(unreadable)"
            lines.append(f"{name} ({size} bytes): {preview}")
    for f in sorted(base.glob("requirements*.txt")):
        if f.name == "requirements.txt":
            continue
        if len(lines) >= 20:
            break
        try:
            if f.is_file():
                lines.append(f"{f.name} ({f.stat().st_size} bytes)")
        except OSError:
            continue
    for f in sorted(base.rglob("*")):
        if len(lines) >= 30:
            break
        try:
            if not f.is_file():
                continue
            n = f.name.lower()
            if n == "dockerfile" or n.startswith("dockerfile.") or n == "docker-compose.yml" or n == "docker-compose.yaml":
                try:
                    rel = f.relative_to(base)
                except ValueError:
                    rel = f
                lines.append(f"{rel} (docker)")
            elif f.suffix.lower() == ".tf":
                try:
                    rel = f.relative_to(base)
                except ValueError:
                    rel = f
                lines.append(f"{rel} (terraform)")
        except OSError:
            continue
    if not lines:
        return "(no manifests found)"
    _lim = _resolve_limit(limit, "MANIFEST_LINES", 200)
    total = len(lines)
    page = lines if _lim <= 0 else lines[:_lim]
    body = "\n".join(page)[:20000]
    if total > len(page):
        body += f"\n… +{total - len(page)} more manifests (total {total})"
    return body


@tool(parse_docstring=True)
def framework_routes(root: str = ".", limit: int | None = None, offset: int = 0) -> str:
    """Grep for web-framework route declarations. Paginated via limit/offset (0=unlimited).

    Args:
        root: Directory to scan for route declarations.
        limit: Max routes per page. 0 = unlimited.
        offset: Route index to start from, for paging.
    """
    pattern = (
        r"(@(app|router|api)\.(get|post|put|delete|patch|route)\b"
        r"|@app\.route\b"
        r"|app\.(get|post|put|delete|route)\s*\("
        r"|router\.(get|post|put|delete|use)\s*\("
        r"|@(?:Get|Post|Put|Delete|Patch|Route|Controller|RestController|RequestMapping)\b"
        r"|express\s*\.\s*(get|post)"
        r"|\.get\s*\(\s*['\"]/"
        r"|Route\s*::"
        r"|^\s*(get|post|put|patch|delete)\s+['\"][^'\"]*['\"]\s*(=>|do|,)"
        r"|^\s*resources\s+:\w+"
        r"|\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\b"
        r"|Map(Get|Post|Put|Delete)\s*\("
        r"|http\.HandleFunc\s*\("
        r"|\b(gin|echo)\.(GET|POST|PUT|DELETE)\s*\("
        r"|^\s*(path|re_path|url)\s*\("
        r"|\(\s*r?['\"]/[^'\"]*['\"]\s*,\s*\w+Handler\b"
        r"|\badd_url_rule\s*\("
        r"|^\s{2}(/[a-zA-Z0-9_{}/-]+):"
        r")"
    )
    # Ask grep for a large window; we page locally for stable offsets.
    res = grep_files(regex=pattern, include="*", root=root, limit=5000)
    raw_lines = [l for l in res.splitlines() if l.strip() and not l.startswith("… ")] if res and "(no matches)" not in res else []
    valid_exts = (
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".java",
        ".cs", ".rs", ".kt", ".scala", ".yml", ".yaml", ".json"
    )
    skip_parts = (
        "/tests/", "/test/", "/spec/", "/specs/", "/fixtures/",
        "/codefixes/", "static/font-awesome/", "node_modules/"
    )
    all_lines = []
    for line in raw_lines:
        path_part = line.split(":", 1)[0].replace("\\", "/").lower()
        if not path_part.startswith("/"):
            path_part = "/" + path_part
        if any(path_part.endswith(ext) for ext in valid_exts):
            if not any(sp in path_part for sp in skip_parts):
                if path_part.endswith((".yml", ".yaml", ".json")):
                    if not any(k in path_part for k in ("openapi", "swagger", "api")):
                        continue
                all_lines.append(line)

    try:
        from pathlib import Path as _Path
        base = _Path(root)
        for pages_dir_name in ("pages", "src/pages"):
            p_dir = base / pages_dir_name
            if p_dir.is_dir():
                for f in sorted(p_dir.rglob("*")):
                    if f.is_file() and f.suffix in (".js", ".ts", ".jsx", ".tsx"):
                        name = f.name
                        if not name.startswith(("_app.", "_document.", "_error.")):
                            rel = f.relative_to(base)
                            all_lines.append(f"{rel}:1: [page route] {rel}")
    except OSError:
        pass

    if not all_lines:
        return "(no matches)"
    _lim = _resolve_limit(limit, "ROUTES_LIMIT", 500)
    _off = int(offset or 0)
    total = len(all_lines)
    page = all_lines[_off:] if _lim <= 0 else all_lines[_off: _off + _lim]
    body = "\n".join(page)[:20000]
    if total > len(page) or _off > 0:
        body += f"\n… showing {_off + 1}-{_off + len(page)} of {total} (use offset={_off + len(page)} to page)"
    return body


def _sanitize_func_name(func_name: str) -> str:
    name = str(func_name or "").strip()
    if not name or len(name) > 200:
        return ""
    if not re.match(r"^[\w.]+$", name):
        return ""
    return name


@tool(parse_docstring=True)
def callers(func_name: str, root: str = ".", limit: int | None = None) -> str:
    """Find call sites of func_name (grep def + calls). Paginated via limit (0=unlimited).

    Args:
        func_name: Function name whose call sites to find.
        root: Directory to search.
        limit: Max call sites. 0 = unlimited.
    """
    name = _sanitize_func_name(func_name)
    if not name:
        return "(no matches)"
    esc = re.escape(name)
    _lim = _resolve_limit(limit, "CALLERS_LIMIT", 100)
    out: list[str] = []
    def_res = grep_files(regex=rf"^\s*(def|function|func|fn)\s+{esc}\b", include="*", root=root, limit=5000)
    if (not def_res or "(no matches)" in def_res) and "." not in name:
        # C-family definitions: `<type> name(` — looser, may over-match.
        c_res = grep_files(regex=rf"^\s*[A-Za-z_][\w\s\*&:<>]*\b{esc}\s*\(", include="*", root=root)
        if c_res and "(no matches)" not in c_res:
            def_res = c_res if not def_res or "(no matches)" in def_res else def_res + "\n" + c_res
    call_res = grep_files(regex=rf"\b{esc}\s*\(", include="*", root=root, limit=5000)
    if def_res and "(no matches)" not in def_res:
        out.append("## def")
        def_lines = [l for l in def_res.splitlines() if l.strip() and not l.startswith("… ")]
        out.extend(def_lines if _lim <= 0 else def_lines[:_lim])
    if call_res and "(no matches)" not in call_res:
        out.append("## calls")
        call_lines = [l for l in call_res.splitlines() if l.strip() and not l.startswith("… ")]
        out.extend(call_lines if _lim <= 0 else call_lines[:_lim])
    return "\n".join(out)[:20000] or "(no matches)"


@tool(parse_docstring=True)
def callees(func_name: str, root: str = ".", limit: int | None = None) -> str:
    """Find what func_name calls: locate def, list invoked identifiers. Paginated via limit (0=unlimited).

    Args:
        func_name: Function name whose body to scan.
        root: Directory to search.
        limit: Max callees. 0 = unlimited.
    """
    name = _sanitize_func_name(func_name)
    if not name:
        return "(no matches)"
    try:
        base = _safe_root(root)
    except ValueError as e:
        return f"ERROR: {e}"
    if not base.exists():
        return "(no matches)"
    esc = re.escape(name)
    def_res = grep_files(regex=rf"^\s*def\s+{esc}\s*\(", include="*.py", root=root)
    if def_res and "(no matches)" in def_res:
        def_res = ""
    if not def_res:
        def_res = grep_files(regex=rf"^\s*(def|function|func)\s+{esc}\b", include="*", root=root)
        if def_res and "(no matches)" in def_res:
            return "(no matches)"
    if not def_res:
        return "(no matches)"
    call_pat = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    _lim2 = _resolve_limit(limit, "CALLERS_LIMIT", 100)
    seen: list[str] = []
    seen_set: set[str] = set()
    for line in def_res.splitlines()[:10]:
        try:
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            rel, num = parts[0], parts[1]
            lineno = int(num)
        except (ValueError, IndexError):
            continue
        try:
            fpath = (base / rel).resolve()
            # Re-check after resolving: rel may traverse a symlink dir.
            fpath.relative_to(base.resolve())
            if not fpath.is_file() or fpath.is_symlink():
                continue
            text = fpath.read_text(errors="replace").splitlines()
        except OSError:
            continue
        except ValueError:
            continue
        body = text[lineno - 1: lineno - 1 + 200]
        for bline in body[1:]:
            # Stop at next top-level def to avoid bleeding into sibling funcs.
            if re.match(r"^(def|class)\s+\w+", bline):
                break
            for m in call_pat.finditer(bline):
                callee = m.group(1)
                if callee == name.split(".")[-1]:
                    continue
                if callee not in seen_set:
                    seen_set.add(callee)
                    seen.append(f"{rel}:{callee}()")
                if _lim2 > 0 and len(seen) >= _lim2:
                    break
        if _lim2 > 0 and len(seen) >= _lim2:
            break
    if not seen:
        return "(no callees found)"
    page = seen if _lim2 <= 0 else seen[:_lim2]
    body_out = "\n".join(page)[:20000]
    if len(seen) > len(page):
        body_out += f"\n… +{len(seen) - len(page)} more"
    return body_out
