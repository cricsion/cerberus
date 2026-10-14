"""Deterministic SAST wrappers. Gracefully degrade if binaries missing."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
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


# Never inherited by SAST child processes. They parse untrusted source and
# have no legitimate need for the harness's credentials.
_SECRET_ENV = frozenset({
    "API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
})

# Suffixes that mark a credential by naming convention. Catches OPENCODE_API_KEY
# (which holds the same live value as API_KEY via .env indirection) and any
# custom api_key_env pointer following the convention, without needing config.
_SECRET_SUFFIXES = ("_API_KEY", "_APIKEY", "_SECRET_KEY", "_PRIVATE_KEY")


def _is_secret_key(name: str) -> bool:
    return name in _SECRET_ENV or name.endswith(_SECRET_SUFFIXES)


def scrubbed_env() -> dict[str, str]:
    """Process env minus credentials, for any subprocess parsing untrusted input."""
    return {k: v for k, v in os.environ.items() if not _is_secret_key(k)}


def _resolve_targets(target: str) -> list[str]:
    """Split an agent-supplied target and enforce repo containment on each part.

    Every path is resolved (symlinks followed) and checked against the repo
    boundary by :func:`harness.tools.code._safe_path`. Anything escaping the
    root raises ``ValueError`` instead of reaching a subprocess.
    """
    from harness.tools.code import _safe_path
    out: list[str] = []
    for t in re.split(r"[\s,]+", (target or "").strip()):
        if not t:
            continue
        out.append(str(_safe_path(t)))
    if not out:
        raise ValueError(f"no scannable targets in {target!r}")
    return out


def _check_ruleset(ruleset: str) -> str:
    """Validate an agent-supplied semgrep/opengrep ``--config`` value.

    ``--config`` accepts registry slugs, local paths, AND URLs. Only registry
    slugs and our own bundled rules directory are legitimate here; a URL would
    turn a host subprocess into an agent-triggered fetch, and any other local
    path is never intended.
    """
    r = (ruleset or "auto").strip()
    if not r:
        raise ValueError("ruleset not allowed: empty (use 'auto')")
    # Our bundled rules: always safe, always allowed.
    try:
        Path(r).resolve().relative_to(Path(_rules_dir()).resolve())
        return r
    except (ValueError, OSError):
        pass
    if "://" in r or r.startswith(("-", "/", ".")) or ".." in r:
        raise ValueError(
            f"ruleset not allowed: {ruleset!r} "
            "(use 'auto' or a registry slug like 'p/security-audit')")
    return r


def _cap_int(env_key: str, default: int) -> int:
    import os as _os
    try:
        v = _os.environ.get(env_key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _run(cmd: list[str], timeout: int = 300, max_bytes: int | None = None) -> dict:
    if max_bytes is None:
        max_bytes = _cap_int("SAST_BYTES", 200000)
    if shutil.which(cmd[0]) is None:
        return {"tool": cmd[0], "skipped": True, "reason": f"binary not found: {cmd[0]}"}
    # SAST binaries parse untrusted source; they must not inherit the
    # harness's credentials even if a tool or library is compromised.
    env = scrubbed_env()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        out = proc.stdout if max_bytes <= 0 else proc.stdout[:max_bytes]
        return {"tool": cmd[0], "returncode": proc.returncode,
                "stdout": out, "stderr": proc.stderr[:20000],
                "truncated": bool(max_bytes > 0 and len(proc.stdout) > max_bytes)}
    except subprocess.TimeoutExpired:
        return {"tool": cmd[0], "skipped": True, "reason": "timeout"}
    except OSError as e:
        return {"tool": cmd[0], "skipped": True, "reason": str(e)}


def _rules_dir() -> str:
    """Absolute path of the bundled custom rules (always applied)."""
    try:
        return str((Path(__file__).resolve().parent.parent / "rules").resolve())
    except Exception:
        return "harness/rules"


@tool(parse_docstring=True)
def semgrep_scan(target: str = ".", ruleset: str = "auto", max_chars: int | None = None) -> str:
    """Run Semgrep OSS (if installed). Registry config + bundled custom rules.

    Pass explicit file paths (space-separated), not a directory: directory
    scans silently return zero findings when the tree has no .git (semgrep
    limits directory scans to git-tracked files). Prefer the unit's assigned
    files. Returns JSON envelope (paginated via max_chars, 0=unlimited).
    Gracefully degrades when binary missing.

    Args:
        target: File paths to scan (space-separated), not a directory.
        ruleset: Semgrep config, e.g. "auto" or "p/security-audit".
        max_chars: Max output chars. 0 = unlimited.
    """
    try:
        ruleset = _check_ruleset(ruleset)
    except ValueError as e:
        return f"ERROR: {e}"
    cmds = ["semgrep", "scan", "--json", "--config", ruleset]
    rules = _rules_dir()
    try:
        if Path(rules).is_dir():
            cmds += ["--config", rules]
    except Exception:
        pass
    target_args: list[str] = []
    try:
        resolved = _resolve_targets(target)
    except ValueError as e:
        return f"ERROR: {e}"
    for rp in resolved:
        p = Path(rp)
        if p.is_dir() and "tests/" in str(p):
            # Semgrep ignores directories under tests/ by default; expand files directly
            resolved_p = p.resolve()
            files = []
            for f in p.rglob("*"):
                if not f.is_file() or f.is_symlink() or f.name.startswith("."):
                    continue
                try:
                    f.resolve().relative_to(resolved_p)
                except ValueError:
                    continue
                files.append(str(f))
            target_args.extend(files if files else [str(p)])
        else:
            target_args.append(str(p))
    if not target_args:
        target_args = [target]
    out = _run(cmds + target_args)
    lim = _cap_int("SAST_BYTES", 200000) if max_chars is None else int(max_chars or 0)
    s = json.dumps(out)
    if lim > 0 and len(s) > lim:
        return s[:lim] + f"\n… +{len(s) - lim} more chars (total {len(s)})"
    return s


@tool(parse_docstring=True)
def secrets_scan(target: str = ".", max_chars: int | None = None) -> str:
    """Run Gitleaks (if installed). Paginated via max_chars (0=unlimited).

    Args:
        target: Path to scan.
        max_chars: Max output chars. 0 = unlimited.
    """
    try:
        resolved = _resolve_targets(target)
    except ValueError as e:
        return f"ERROR: {e}"
    out = _run(["gitleaks", "detect", "--source", resolved[0], "--no-git", "-v"])
    lim = _cap_int("SAST_BYTES", 200000) if max_chars is None else int(max_chars or 0)
    s = json.dumps(out)
    return s if lim <= 0 or len(s) <= lim else s[:lim] + f"\n… +{len(s) - lim} more chars"


@tool(parse_docstring=True)
def sca_scan(target: str = ".", max_chars: int | None = None) -> str:
    """Run osv-scanner (if installed). Paginated via max_chars (0=unlimited).

    Args:
        target: Path to scan.
        max_chars: Max output chars. 0 = unlimited.
    """
    try:
        resolved = _resolve_targets(target)
    except ValueError as e:
        return f"ERROR: {e}"
    out = _run(["osv-scanner", "--format", "json", resolved[0]])
    lim = _cap_int("SAST_BYTES", 200000) if max_chars is None else int(max_chars or 0)
    s = json.dumps(out)
    return s if lim <= 0 or len(s) <= lim else s[:lim] + f"\n… +{len(s) - lim} more chars"


@tool(parse_docstring=True)
def opengrep_scan(target: str = ".", ruleset: str = "auto", max_chars: int | None = None) -> str:
    """Run OpenGrep OSS (if installed). Paginated via max_chars (0=unlimited).

    Pass explicit file paths (space-separated), not a directory: directory
    scans silently return zero findings when the tree has no .git. Prefer the
    unit's assigned files.

    Args:
        target: File paths to scan (space-separated), not a directory.
        ruleset: OpenGrep config, e.g. "auto" or "p/security-audit".
        max_chars: Max output chars. 0 = unlimited.
    """
    try:
        ruleset = _check_ruleset(ruleset)
        resolved = _resolve_targets(target)
    except ValueError as e:
        return f"ERROR: {e}"
    out = _run(["opengrep", "scan", "--json", "--config", ruleset] + resolved)
    lim = _cap_int("SAST_BYTES", 200000) if max_chars is None else int(max_chars or 0)
    s = json.dumps(out)
    return s if lim <= 0 or len(s) <= lim else s[:lim] + f"\n… +{len(s) - lim} more chars"


@tool(parse_docstring=True)
def iac_check(target: str = ".", max_chars: int | None = None) -> str:
    """Run Checkov IaC scan (if installed). Paginated via max_chars (0=unlimited).

    Args:
        target: IaC target (dir/file) to scan.
        max_chars: Max output chars. 0 = unlimited.
    """
    try:
        resolved = _resolve_targets(target)
    except ValueError as e:
        return f"ERROR: {e}"
    out = _run(["checkov", "-d", resolved[0], "-o", "json", "--quiet"])
    lim = _cap_int("SAST_BYTES", 200000) if max_chars is None else int(max_chars or 0)
    s = json.dumps(out)
    return s if lim <= 0 or len(s) <= lim else s[:lim] + f"\n… +{len(s) - lim} more chars"


@tool(parse_docstring=True)
def regex_prefilter(target: str = ".") -> str:
    """Cheap stack-aware regex prefilter (always available, no binary).

    Sections are (name, filename globs, regex) so each language gets its own
    sink list. One grep walk per (section, glob); SKIP_DIRS/binary/size caps
    from grep apply. Not a substitute for Semgrep rules — breadth for recall.

    Args:
        target: Directory or file to scan.
    """
    from harness.tools.code import grep_files  # internal engine, no tool overhead
    # Global (any file).
    patterns: list[tuple[str, list[str], str]] = [
        ("hardcoded-secret", ["*"],
         r"(?i)(password|passwd|secret|api[_-]?key|aws_.{0,20}key|token)\s*[:=]\s*['\"][^'\"]+['\"]"),
        # --- Python ---
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
        # --- JavaScript / TypeScript ---
        ("js-exec", ["*.js", "*.jsx", "*.ts", "*.tsx"],
         r"(\beval\s*\(|new\s+Function\s*\(|child_process|execSync|spawnSync|\.exec\s*\(|vm\.(runIn|compileFunction))"),
        ("js-xss", ["*.js", "*.jsx", "*.ts", "*.tsx"],
         r"(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)"),
        ("js-ssrf", ["*.js", "*.jsx", "*.ts", "*.tsx"],
         r"(fetch\s*\(\s*req|axios\.(get|post)\s*\(\s*req|http\.(get|request)\s*\()"),
        # --- Java ---
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
        # --- Go ---
        ("go-exec", ["*.go"],
         r"(exec\.Command|syscall\.(Exec|ForkExec))"),
        ("go-template", ["*.go"],
         r"(text/template|template\.HTML)"),
        ("go-sqli", ["*.go"],
         r"(db\.(Query|Exec)\s*\(.*(fmt\.Sprintf|\+))"),
        # --- Ruby ---
        ("rb-exec", ["*.rb"],
         r"(\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|%x\{|`[^`]*#\{)"),
        ("rb-rails-sqli", ["*.rb"],
         r"(\.where\s*\(\s*[\"'].*#\{|\.find_by_sql\s*\()"),
        ("rb-deser", ["*.rb"],
         r"(YAML\.load\s*\(|Marshal\.(load|restore)|\.constantize)"),
        # --- PHP ---
        ("php-exec", ["*.php"],
         r"(\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|passthru|shell_exec\s*\(|popen\s*\()"),
        ("php-sqli", ["*.php"],
         r"(mysql_query\s*\(|mysqli_query\s*\(.*\$_(GET|POST)|mysqli_query\s*\(.*\+)"),
        ("php-deser", ["*.php"],
         r"(unserialize\s*\(\s*\$|extract\s*\(\s*\$_(GET|POST|REQUEST))"),
        # --- C / C++ ---
        ("c-banned", ["*.c", "*.h", "*.cpp", "*.hpp", "*.cc"],
         r"(\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(|\bgets\s*\()"),
        ("c-exec", ["*.c", "*.h", "*.cpp", "*.hpp", "*.cc"],
         r"(\bsystem\s*\(|\bpopen\s*\(|\bexeclp?\s*\()"),
        # --- Rust ---
        ("rs-unsafe", ["*.rs"],
         r"(\bunsafe\s*\{|\btransmute\s*\(|from_raw|Command::new\s*\()"),
        # --- C# ---
        ("cs-exec", ["*.cs"],
         r"(Process\.Start\s*\(|SqlCommand\s*\(.*\+|BinaryFormatter|LosFormatter|SoapFormatter)"),
        # --- Templates (XSS sinks live here in Django/Jinja/ERB/EJS) ---
        ("tpl-xss", ["*.html", "*.htm", "*.j2", "*.jinja", "*.jinja2", "*.ejs", "*.erb", "*.twig", "*.vue"],
         r"(\{\{.*\|\s*safe\s*\}\}|\{%\s*autoescape\s+off\s*%\}|mark_safe|<%=\s*raw|v-html\s*=|\{\{\{\s*)"),
        # --- Terraform ---
        ("tf-open", ["*.tf"],
         r"(cidr_blocks\s*=\s*\[.*0\.0\.0\.0|privileged\s*=\s*true|skip_final_snapshot\s*=\s*true)"),
        # --- Info exposure / logging ---
        ("debug-exposure", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.go"],
         r"(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True|traceback\.print_exc\s*\(|printStackTrace\s*\(|console\.error\s*\(.*err)"),
        ("log-inject", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.go", "*.rb", "*.php"],
         r"(logging\.(info|error|warning|exception)\s*\(.*(%|\+)|logger\.(info|error|warn)\s*\(.*(\+|%s)|console\.(log|error)\s*\(.*\+|log\.(info|error)\s*\(.*\+)"),
        # --- Redirect / upload ---
        ("open-redirect", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.php", "*.go", "*.rb"],
         r"(redirect\s*\(\s*req|HttpResponseRedirect\s*\(\s*req|res\.redirect\s*\(\s*req|header\s*\(\s*[\"']Location[\"']\s*,\s*\$)"),
        ("upload", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.php", "*.rb", "*.go"],
         r"(request\.FILES|multer\s*\(|move_uploaded_file\s*\(|DiskFileItemFactory|MultipartFile|req\.file\b|\.SaveAs\s*\()"),
        # --- Weak randomness / plaintext creds ---
        ("weak-random", ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java", "*.go", "*.rb", "*.php", "*.c"],
         r"(random\.random\s*\(|Math\.random\s*\(|rand\s*\(\s*\)|new\s+Random\s*\(\s*\))"),
        ("plaintext-creds", ["*"],
         r"(?i)(session\s*\[.{0,30}password|localStorage\.setItem.{0,30}pass|password.{0,20}(plain|cleartext)|(plain|cleartext).{0,20}password)"),
        # --- LDAP / XPath / CRLF ---
        ("ldap-xpath", ["*.py", "*.java", "*.php", "*.js", "*.rb"],
         r"(ldap\.(search|search_s|search_st|search_ext)\s*\(|XPath|selectNodes|evaluate\s*\(.*[Xx]path)"),
        ("crlf", ["*.py", "*.java", "*.php", "*.js", "*.jsx", "*.ts", "*.go", "*.rb"],
         r"(setHeader\s*\(.*(req\.|params|input)|header\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\$_(GET|POST)|Location.*\+)"),
        # --- Perms / DoS / races ---
        ("chmod-perms", ["*.py", "*.js", "*.php", "*.rb", "*.sh"],
         r"(chmod\s+777|os\.chmod\s*\(.*0o?777|umask\s*\(\s*0\s*\)|fs\.chmod.*0o777)"),
        ("range-dos", ["*.py", "*.js", "*.jsx", "*.ts", "*.go", "*.java", "*.c", "*.cpp"],
         r"(range\s*\(\s*int\s*\(\s*req|new\s+byte\s*\[.*req|malloc\s*\(.*req|len\s*\(.*req.*\)\s*\*\s*)"),
        ("toctou-hint", ["*.py", "*.c", "*.cpp", "*.go", "*.rb"],
         r"(os\.path\.exists\s*\(|access\s*\([^)]*W_OK)"),
        # --- Docker ---
        ("docker-add", ["Dockerfile*"],
         r"(^ADD\s+|\bprivileged\b|ENV\s+\w*(PASS|SECRET|KEY)\w*\s*=\s*\S+)"),
    ]
    hits: list[str] = []
    base = Path(target)
    gf = grep_files
    for name, includes, rx in patterns:
        for include in includes:
            try:
                res = gf(regex=rx, include=include, root=str(base), limit=500) if gf else ""
            except Exception:
                res = ""
            if res and "(no matches)" not in res and "(unavailable" not in res:
                # Keep full grep page (already paginated with totals); don't re-truncate.
                hits.append(f"## {name}\n{res[:20000]}")
    # Template reflection surfaces (text form for hunter context; structured
    # candidates come from template_reflect_candidates below).
    for c in template_reflect_candidates(target):
        hits.append(f"## tpl-form-reflect\n{c['path']}: form + {{{{ }}}} "
                    "reflection surface (verify server-side)")
    return "\n".join(hits) or "(no prefilter hits)"


TPL_GLOBS = ("*.html", "*.htm", "*.j2", "*.jinja", "*.jinja2",
             "*.ejs", "*.erb", "*.twig", "*.vue")


def template_reflect_candidates(target: str = ".") -> list[dict]:
    """One heuristic candidate per template containing <form> + {{ }}.

    Reflected-XSS benchmarks label the TEMPLATE file while the sink lives in
    the view; static analysis cannot prove server-side reflection, so these
    ship as low-confidence needs-review claims for hunters/validators to
    corroborate, never as confirmed.
    """
    import fnmatch as _fn
    import re as _re

    try:
        resolved = _resolve_targets(target)
    except ValueError:
        return []
    base = Path(resolved[0])
    out: list[dict] = []
    max_tpl = _cap_int("SAST_FINDINGS", 5000)
    if max_tpl <= 0:
        max_tpl = 10**9
    try:
        walker = [base] if base.is_file() else sorted(base.rglob("*"))
    except Exception:
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
        except Exception:
            continue
        if _re.search(r"<form\b", text, _re.I) and _re.search(r"\{\{", text):
            try:
                rel = str(f.relative_to(base if base.is_dir() else f.parent))
            except ValueError:
                rel = f.name
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


def normalize_to_candidates(sast_json: str) -> list[dict]:
    """Best-effort normalize of Semgrep JSON; returns [] on skip/error (fail-open upstream).

    Accepts either raw Semgrep JSON ({"results": [...]}) or the _run wrapper
    JSON produced by semgrep_scan ({"tool": ..., "stdout": "<semgrep json>"}).
    Maps check_id -> CWE via regex, severity -> lower (default medium),
    confidence defaults to 0.0.
    """
    try:
        data = json.loads(sast_json)
        if isinstance(data, dict) and data.get("skipped"):
            return []
    except Exception:
        return []
    # Unwrap _run/semgrep_scan envelope: {"tool":..., "stdout": "..."}.
    try:
        if isinstance(data, dict) and "results" not in data and "findings" not in data:
            stdout = data.get("stdout")
            if stdout is None:
                return []
            if isinstance(stdout, str):
                if not stdout.strip():
                    return []
                try:
                    data = json.loads(stdout)
                except Exception:
                    return []
                if isinstance(data, dict) and data.get("skipped"):
                    return []
            else:
                return []
    except Exception:
        return []
    try:
        if isinstance(data, dict):
            results = data.get("results", data.get("findings", []))
        elif isinstance(data, list):
            results = data
        else:
            return []
        if not isinstance(results, list):
            return []
        out: list[dict] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            try:
                check_id = str(r.get("check_id") or r.get("rule_id") or r.get("id") or "semgrep-finding")
                extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
                message = str(extra.get("message") or r.get("message") or r.get("title") or check_id)
                raw_sev = str(extra.get("severity") or r.get("severity") or "medium")
                sev_lower = raw_sev.strip().lower()
                if sev_lower in ("critical", "high", "medium", "low", "info"):
                    severity = sev_lower
                elif sev_lower == "error":
                    severity = "high"
                elif sev_lower == "warning":
                    severity = "medium"
                else:
                    severity = "medium"
                cwe = ""
                m = re.search(r"CWE-\d+", check_id)
                if m:
                    cwe = m.group(0)
                else:
                    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
                    cands = [
                        str(meta.get("cwe", "")),
                        str(meta.get("cwes", "")),
                        message,
                        str(r.get("cwe", "")),
                    ]
                    for cand in cands:
                        mm = re.search(r"CWE-\d+", cand)
                        if mm:
                            cwe = mm.group(0)
                            break
                path = str(r.get("path") or r.get("filename") or "")
                start = r.get("start") if isinstance(r.get("start"), dict) else {}
                end = r.get("end") if isinstance(r.get("end"), dict) else {}
                try:
                    start_line = int(start.get("line", r.get("start_line", 0)) or 0)
                except (ValueError, TypeError):
                    start_line = 0
                try:
                    end_line = int(end.get("line", r.get("end_line", start_line)) or start_line)
                except (ValueError, TypeError):
                    end_line = start_line
                snippet = str(extra.get("lines") or r.get("snippet") or r.get("code") or "")[:2000]
                evidence = f"{check_id}: {message}"[:4000]
                fid = f"{check_id}@{path}:{start_line}"
                out.append({
                    "id": fid,
                    "title": message[:500] or check_id,
                    "cwe": cwe,
                    "severity": severity,
                    "confidence": 0.0,
                    "path": path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "snippet": snippet,
                    "evidence": evidence,
                    "status": "needs-review",
                })
            except Exception:
                continue
        return out
    except Exception:
        return []
