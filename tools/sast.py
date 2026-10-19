from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from ._compat import env_int, run_cli, tool


def _resolve_targets(target: str) -> list[str]:
    from harness.tools.code import _safe_path
    out: list[str] = []
    for t in re.split(r"[\s,]+", (target or "").strip()):
        if not t:
            continue
        out.append(str(_safe_path(t)))
    if not out:
        raise ValueError(f"no scannable targets in {target!r}")
    return out


def _paginate(s: str, max_chars: int | None, *, total: bool = False) -> str:
    lim = env_int("SAST_BYTES", 200000) if max_chars is None else int(max_chars or 0)
    if lim <= 0 or len(s) <= lim:
        return s
    suffix = f" (total {len(s)})" if total else ""
    return s[:lim] + f"\n… +{len(s) - lim} more chars{suffix}"


def _scan_json(build_cmd: Callable[[list[str]], list[str]], target: str,
               max_chars: int | None) -> str:
    try:
        resolved = _resolve_targets(target)
    except ValueError as e:
        return f"ERROR: {e}"
    return _paginate(json.dumps(_run(build_cmd(resolved))), max_chars)


_run = run_cli


@tool(parse_docstring=True)
def secrets_scan(target: str = ".", max_chars: int | None = None) -> str:
    """Run Gitleaks (if installed).

    Args:
        target: Path to scan.
        max_chars: Max output chars. 0 = unlimited.
    """
    return _scan_json(
        lambda resolved: ["gitleaks", "detect", "--source", resolved[0], "--no-git", "-v"],
        target, max_chars)


@tool(parse_docstring=True)
def sca_scan(target: str = ".", max_chars: int | None = None) -> str:
    """Run osv-scanner (if installed).

    Args:
        target: Path to scan.
        max_chars: Max output chars. 0 = unlimited.
    """
    return _scan_json(
        lambda resolved: ["osv-scanner", "--format", "json", resolved[0]],
        target, max_chars)


@tool(parse_docstring=True)
def iac_check(target: str = ".", max_chars: int | None = None) -> str:
    """Run Checkov IaC scan (if installed).

    Args:
        target: IaC target (dir/file) to scan.
        max_chars: Max output chars. 0 = unlimited.
    """
    return _scan_json(
        lambda resolved: ["checkov", "-d", resolved[0], "-o", "json", "--quiet"],
        target, max_chars)


@tool(parse_docstring=True)
def regex_prefilter(target: str = ".") -> str:
    """Stack-aware regex prefilter (always available, no binary).

    Args:
        target: Directory or file to scan.
    """
    from harness.tools.code import grep_files
    patterns: list[tuple[str, list[str], str]] = [
        ("hardcoded-secret", ["*"],
         r"(?i)(password|passwd|secret|api[_-]?key|aws_.{0,20}key|token)\s*[:=]\s*['\"][^'\"]+['\"]"),
        ("sqli-cursor", ["*.py"],
         r"(cursor\.execute|conn\.execute|\.execute\s*\(|executemany\s*\(|\.raw\s*\(|SELECT\s+.*FROM)"),
        ("shell-true", ["*.py"],
         r"(os\.system|os\.popen|subprocess\.(Popen|call|run|check_output)|shell\s*=\s*True|popen\s*\()"),
        ("eval-exec", ["*.py"],
         r"(\beval\s*\(|\bexec\s*\(|__import__\s*\(|\bcompile\s*\(|runpy|InteractiveConsole)"),
        ("jinja-render", ["*.py"],
         r"(render_template_string|render_template\s*\(|Markup\s*\(|jinja2|Template\s*\(.*render)"),
        ("pickle-loads", ["*.py"],
         r"(pickle\.(loads?|Unpickler)|cPickle|marshal\.(loads?|load)|shelve\.open|jsonpickle|dill\.(loads?|load)|torch\.load\s*\()"),
        ("yaml-load", ["*.py", "*.yml", "*.yaml"],
         r"(yaml\.(load|unsafe_load|full_load)\s*\(|yaml\.load\s*\(|Loader\s*=\s*yaml\.Loader)"),
        ("ssrf-requests", ["*.py"],
         r"(requests\.(get|post|put|delete|patch|request)\s*\(|urllib.*urlopen\s*\(|http\.client|urlopen\s*\(|httpx\.(get|post|request|Client)|aiohttp\.ClientSession|urllib3\.PoolManager)"),
        ("redos-regex", ["*.py"],
         r"(re\.(compile|search|match|finditer|sub|split)\s*\(|regex\.(compile|search|match)\s*\()"),
        ("xpath-xml", ["*.py"],
         r"(\.xpath\s*\(|\.evaluate\s*\(|selectNodes|xml\.etree|xml\.dom|xml\.sax|lxml\.etree|xmlrpc\.client)"),
        ("jwt-decode-verify-false", ["*.py"],
         r"(jwt\.decode\s*\(|verify\s*=\s*False|verify_signature\s*=\s*False|algorithms\s*=)"),
        ("md5-sha1", ["*.py"],
         r"(hashlib\.(md5|sha1)\s*\(|\bmd5\s*\(|\bsha1\s*\(|Crypto\.Cipher\.(DES|ARC4)|random\.random\s*\()"),
        ("path-open-join", ["*.py"],
         r"(\bopen\s*\(|os\.path\.join\s*\(|send_file\s*\(|send_from_directory\s*\(|\.\./)"),
        ("csrf-exempt", ["*.py"],
         r"(csrf_exempt|csrf\.disable|CSRF_TRUSTED|_csrf\b|@login_not_required|@allow_anonymous)"),
        ("cookie-flags", ["*.py"],
         r"(set_cookie\s*\(|response\.set_cookie)"),
        ("cors-wildcard", ["*.py"],
         r"(Access-Control-Allow-Origin.*\*|CORS.*\*)"),
        ("js-exec", ["*.js", "*.jsx", "*.ts", "*.tsx"],
         r"(\beval\s*\(|new\s+Function\s*\(|child_process|execSync|spawnSync|\.exec\s*\(|vm\.(runIn|compileFunction))"),
        ("js-xss", ["*.js", "*.jsx", "*.ts", "*.tsx"],
         r"(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)"),
        ("js-ssrf", ["*.js", "*.jsx", "*.ts", "*.tsx"],
         r"(fetch\s*\(\s*req|axios\.(get|post)\s*\(\s*req|http\.(get|request)\s*\()"),
        ("java-exec", ["*.java"],
         r"(Runtime\.getRuntime\s*\(\s*\)\.exec|ProcessBuilder\s*\(|ScriptEngine.*\.eval\s*\()"),
        ("java-sqli", ["*.java"],
         r"(\.executeQuery\s*\(.*\+|\.execute\s*\(.*\+|createStatement\s*\(\))"),
        ("java-deser", ["*.java"],
         r"(readObject\s*\(|XMLDecoder|new\s+ObjectInputStream)"),
        ("java-crypto", ["*.java"],
         r"(MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1)\"|Cipher\.getInstance\s*\(\s*\"DES)"),
        ("java-src", ["*.java"],
         r"(getParameter\s*\(|getHeader\s*\(|getCookies\s*\()"),
        ("go-exec", ["*.go"],
         r"(exec\.Command|syscall\.(Exec|ForkExec))"),
        ("go-template", ["*.go"],
         r"(text/template|template\.HTML)"),
        ("go-sqli", ["*.go"],
         r"(db\.(Query|Exec)\s*\(.*(fmt\.Sprintf|\+))"),
        ("rb-exec", ["*.rb"],
         r"(\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|%x\{|`[^`]*#\{)"),
        ("rb-rails-sqli", ["*.rb"],
         r"(\.where\s*\(\s*[\"'].*#\{|\.find_by_sql\s*\()"),
        ("rb-deser", ["*.rb"],
         r"(YAML\.load\s*\(|Marshal\.(load|restore)|\.constantize)"),
        ("php-exec", ["*.php"],
         r"(\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|passthru|shell_exec\s*\(|popen\s*\()"),
        ("php-sqli", ["*.php"],
         r"(mysql_query\s*\(|mysqli_query\s*\(.*\$_(GET|POST)|mysqli_query\s*\(.*\+)"),
        ("php-deser", ["*.php"],
         r"(unserialize\s*\(\s*\$|extract\s*\(\s*\$_(GET|POST|REQUEST))"),
        ("c-banned", ["*.c", "*.h", "*.cpp", "*.hpp", "*.cc"],
         r"(\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(|\bgets\s*\()"),
        ("c-exec", ["*.c", "*.h", "*.cpp", "*.hpp", "*.cc"],
         r"(\bsystem\s*\(|\bpopen\s*\(|\bexeclp?\s*\()"),
        ("rs-unsafe", ["*.rs"],
         r"(\bunsafe\s*\{|\btransmute\s*\(|from_raw|Command::new\s*\()"),
        ("cs-exec", ["*.cs"],
         r"(Process\.Start\s*\(|SqlCommand\s*\(.*\+|BinaryFormatter|LosFormatter|SoapFormatter)"),
        ("tpl-xss", ["*.html", "*.htm", "*.j2", "*.jinja", "*.jinja2", "*.ejs", "*.erb", "*.twig", "*.vue"],
         r"(\{\{.*\|\s*safe\s*\}\}|\{%\s*autoescape\s+off\s*%\}|mark_safe|<%=\s*raw|v-html\s*=|\{\{\{\s*)"),
        ("tf-open", ["*.tf"],
         r"(cidr_blocks\s*=\s*\[.*0\.0\.0\.0|privileged\s*=\s*true|skip_final_snapshot\s*=\s*true)"),
        ("debug-exposure", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.go"],
         r"(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True|traceback\.print_exc\s*\(|printStackTrace\s*\(|console\.error\s*\(.*err)"),
        ("log-inject", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.go", "*.rb", "*.php"],
         r"(logging\.(info|error|warning|exception)\s*\(.*(%|\+)|logger\.(info|error|warn)\s*\(.*(\+|%s)|console\.(log|error)\s*\(.*\+|log\.(info|error)\s*\(.*\+)"),
        ("open-redirect", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.php", "*.go", "*.rb"],
         r"(redirect\s*\(\s*req|HttpResponseRedirect\s*\(\s*req|res\.redirect\s*\(\s*req|header\s*\(\s*[\"']Location[\"']\s*,\s*\$)"),
        ("upload", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.php", "*.rb", "*.go"],
         r"(request\.FILES|multer\s*\(|move_uploaded_file\s*\(|DiskFileItemFactory|MultipartFile|req\.file\b|\.SaveAs\s*\()"),
        ("weak-random", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.go", "*.rb", "*.php", "*.c"],
         r"(random\.random\s*\(|Math\.random\s*\(|rand\s*\(\s*\)|new\s+Random\s*\(\s*\))"),
        ("plaintext-creds", ["*"],
         r"(?i)(session\s*\[.{0,30}password|localStorage\.setItem.{0,30}pass|password.{0,20}(plain|cleartext)|(plain|cleartext).{0,20}password)"),
        ("ldap-xpath", ["*.py", "*.java", "*.php", "*.js", "*.rb"],
         r"(ldap\.(search|search_s|search_st|search_ext)\s*\(|XPath|selectNodes|evaluate\s*\(.*[Xx]path)"),
        ("crlf", ["*.py", "*.java", "*.php", "*.js", "*.jsx", "*.ts", "*.go", "*.rb"],
         r"(setHeader\s*\(.*(req\.|params|input)|header\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\$_(GET|POST)|Location.*\+)"),
        ("chmod-perms", ["*.py", "*.js", "*.php", "*.rb", "*.sh"],
         r"(chmod\s+777|os\.chmod\s*\(.*0o?777|umask\s*\(\s*0\s*\)|fs\.chmod.*0o777)"),
        ("range-dos", ["*.py", "*.js", "*.jsx", "*.ts", "*.go", "*.java", "*.c", "*.cpp"],
         r"(range\s*\(\s*int\s*\(\s*req|new\s+byte\s*\[.*req|malloc\s*\(.*req|len\s*\(.*req.*\)\s*\*\s*)"),
        ("toctou-hint", ["*.py", "*.c", "*.cpp", "*.go", "*.rb"],
         r"(os\.path\.exists\s*\(|access\s*\([^)]*W_OK)"),
        ("docker-add", ["Dockerfile*"],
         r"(^ADD\s+|\bprivileged\b|ENV\s+\w*(PASS|SECRET|KEY)\w*\s*=\s*\S+)"),
    ]
    hits: list[str] = []
    base = Path(target)
    gf = grep_files
    for name, includes, rx in patterns:
        for include in includes:
            # grep_files converts its own path/regex errors to ERROR strings;
            # a residual raise goes to the tool boundary as ToolMessage.
            res = gf(regex=rx, include=include, root=str(base), limit=500) if gf else ""
            if res and "(no matches)" not in res and "(unavailable" not in res:
                # Grep page is already paginated; 20000 is only a size cap.
                hits.append(f"## {name}\n{res[:20000]}")
    for c in template_reflect_candidates(target):
        hits.append(f"## tpl-form-reflect\n{c['path']}: form + {{{{ }}}} "
                    "reflection surface (verify server-side)")
    return "\n".join(hits) or "(no prefilter hits)"


TPL_GLOBS = ("*.html", "*.htm", "*.j2", "*.jinja", "*.jinja2",
             "*.ejs", "*.erb", "*.twig", "*.vue")


def template_reflect_candidates(target: str = ".") -> list[dict]:
    import fnmatch as _fn
    import re as _re

    # Confinement contract (pinned): an escaping/empty target refuses as
    # empty candidates — no raise, so the surrounding scan continues.
    try:
        resolved = _resolve_targets(target)
    except ValueError:
        return []
    base = Path(resolved[0])
    out: list[dict] = []
    max_tpl = env_int("SAST_FINDINGS", 5000)
    if max_tpl <= 0:
        max_tpl = 10**9
    try:
        walker = [base] if base.is_file() else sorted(base.rglob("*"))
    except OSError:
        return out
    for f in walker:
        if len(out) >= max_tpl:
            break
        try:
            if not f.is_file() or f.is_symlink():
                continue
            # Walker may descend through symlink dirs; re-check each file.
            f.resolve().relative_to(base.resolve())
            if not any(_fn.fnmatch(f.name, g) for g in TPL_GLOBS):
                continue
            if f.stat().st_size > 1_000_000:
                continue
            text = f.read_text(errors="replace")
        except OSError:
            continue
        except ValueError:
            continue
        if _re.search(r"<form\b", text, _re.I) and _re.search(r"\{\{", text):
            rel = str(f.relative_to(base if base.is_dir() else f.parent))
            out.append({
                "id": f"tpl-form-reflect@{rel}",
                "title": "template reflection surface",
                "cwe": "CWE-79", "severity": "low", "confidence": 0.4,
                "path": rel,
                "start_line": 0, "end_line": 0,
                "snippet": "form + {{ }} in template (verify server-side reflection)",
                "taint": {"source": "form input", "sink": "template render", "path": []},
                "evidence": "heuristic: form + {{ }} co-occurrence",
                "status": "needs-review",
            })
    return out
