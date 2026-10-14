"""Lightweight static code-graph helpers. Read-only, capped, no network, no LLM.

All tools degrade gracefully when binaries/files are missing.
"""
from __future__ import annotations

import re
from pathlib import Path

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(*dargs, **dkwargs):  # type: ignore
        def deco(fn):
            return fn
        if dargs and callable(dargs[0]):
            return dargs[0]
        return deco


def _safe_root(root: str) -> Path:
    """Resolve a tool-supplied root against the repo boundary.

    Delegates to :func:`harness.tools.code._safe_path`, which confines to
    TARGET_REPO when set and raises ``ValueError`` on escape. Callers convert
    that to an agent-facing error string.
    """
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
    try:
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
            try:
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
            except Exception:
                continue
        # requirements*.txt variants
        try:
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
        except Exception:
            pass
        # Dockerfile variants
        try:
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
        except Exception:
            pass
    except Exception:
        return "(no manifests found)"
    if not lines:
        return "(no manifests found)"
    import os as _os
    try:
        _lim = int(limit) if limit is not None else int(_os.environ.get("MANIFEST_LINES", "200") or 200)
    except (TypeError, ValueError):
        _lim = 200
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
    try:
        from harness.tools.code import grep_files
    except Exception:
        return "(no matches)"
    pattern = (
        r"(@(app|router|api)\.(get|post|put|delete|patch|route)\b"
        r"|@app\.route\b"
        r"|app\.(get|post|put|delete|route)\s*\("
        r"|router\.(get|post|put|delete|use)\s*\("
        r"|@(?:Get|Post|Put|Delete|Patch|Route|Controller|RestController|RequestMapping)\b"
        r"|express\s*\.\s*(get|post)"
        r"|\.get\s*\(\s*['\"]/"
        r"|Route\s*::"
        # Rails / Django / ASP.NET / Go
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
    try:
        # Ask grep for a large window; we page locally for stable offsets.
        res = grep_files(regex=pattern, include="*", root=root, limit=5000)
    except Exception:
        return "(no matches)"
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
    except Exception:
        pass

    if not all_lines:
        return "(no matches)"
    import os as _os2
    try:
        _lim = int(limit) if limit is not None else int(_os2.environ.get("ROUTES_LIMIT", "500") or 500)
    except (TypeError, ValueError):
        _lim = 500
    try:
        _off = int(offset or 0)
    except (TypeError, ValueError):
        _off = 0
    total = len(all_lines)
    page = all_lines[_off:] if _lim <= 0 else all_lines[_off: _off + _lim]
    body = "\n".join(page)[:20000]
    if total > len(page) or _off > 0:
        body += f"\n… showing {_off + 1}-{_off + len(page)} of {total} (use offset={_off + len(page)} to page)"
    return body


def _sanitize_func_name(func_name: str) -> str:
    try:
        name = str(func_name or "").strip()
    except Exception:
        return ""
    # Allow qualified names like module.func; keep word chars, dots, underscores.
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
    try:
        from harness.tools.code import grep_files as fn
    except Exception:
        return "(no matches)"
    esc = re.escape(name)
    import os as _os3
    try:
        _lim = int(limit) if limit is not None else int(_os3.environ.get("CALLERS_LIMIT", "100") or 100)
    except (TypeError, ValueError):
        _lim = 100
    out: list[str] = []
    try:
        def_res = fn(regex=rf"^\s*(def|function|func|fn)\s+{esc}\b", include="*", root=root, limit=5000)
    except Exception:
        def_res = ""
    if (not def_res or "(no matches)" in def_res) and "." not in name:
        # C-family definitions: `<type> name(` — looser, may over-match.
        try:
            c_res = fn(regex=rf"^\s*[A-Za-z_][\w\s\*&:<>]*\b{esc}\s*\(", include="*", root=root)
        except Exception:
            c_res = ""
        if c_res and "(no matches)" not in c_res:
            def_res = c_res if not def_res or "(no matches)" in def_res else def_res + "\n" + c_res
    try:
        call_res = fn(regex=rf"\b{esc}\s*\(", include="*", root=root, limit=5000)
    except Exception:
        call_res = ""
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
    try:
        from harness.tools.code import grep_files as fn
    except Exception:
        return "(no matches)"
    esc = re.escape(name)
    try:
        def_res = fn(regex=rf"^\s*def\s+{esc}\s*\(", include="*.py", root=root)
    except Exception:
        def_res = ""
    if def_res and "(no matches)" in def_res:
        def_res = ""
    # Fall back to generic def search across all files.
    if not def_res:
        try:
            def_res = fn(regex=rf"^\s*(def|function|func)\s+{esc}\b", include="*", root=root)
        except Exception:
            def_res = ""
        if def_res and "(no matches)" in def_res:
            return "(no matches)"
    if not def_res:
        return "(no matches)"
    call_pat = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    import os as _os4
    try:
        _lim2 = int(limit) if limit is not None else int(_os4.environ.get("CALLERS_LIMIT", "100") or 100)
    except (TypeError, ValueError):
        _lim2 = 100
    seen: list[str] = []
    seen_set: set[str] = set()
    for line in def_res.splitlines()[:10]:
        # Format is relpath:lineno: content
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
        except Exception:
            continue
        body = text[lineno - 1: lineno - 1 + 200]
        for bline in body[1:]:
            # Stop at next top-level def to avoid bleeding into sibling funcs.
            if re.match(r"^(def|class)\s+\w+", bline):
                break
            try:
                for m in call_pat.finditer(bline):
                    callee = m.group(1)
                    if callee == name.split(".")[-1]:
                        continue
                    if callee not in seen_set:
                        seen_set.add(callee)
                        seen.append(f"{rel}:{callee}()")
                    if _lim2 > 0 and len(seen) >= _lim2:
                        break
            except Exception:
                continue
        if _lim2 > 0 and len(seen) >= _lim2:
            break
    if not seen:
        return "(no callees found)"
    page = seen if _lim2 <= 0 else seen[:_lim2]
    body_out = "\n".join(page)[:20000]
    if len(seen) > len(page):
        body_out += f"\n… +{len(seen) - len(page)} more"
    return body_out
