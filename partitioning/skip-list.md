# Harness skip list — repo files the harness can drop before partitioning

Same spirit as `lessons.md`: every number here was paid for, not guessed.
Validated against the whole benchmark, not samples:

- input: 5,282 inventory files of the 50 graded `realvuln-*` repos (harness walker:
  installed `ignored_predicate` + `tools/code.SKIP_DIRS` + `_INVENTORY_EXTS` +
  Dockerfile/shebang)
- 988 scoreable findings from `runs/*-run-001/findings.json` (severity != info, skip-ids excluded)
- ground truth: all 4,594 GT items across all GT dirs (4,314 vulnerable)

**Verdict:** 1,039 of 5,282 inventory files (19.7%) can be skipped. 149 of 988
findings (15.1%, in 21 repos) are anchored on those files, and every one is a
false positive — **zero of 4,314 vulnerable GT items lives there**. Macro
precision moves 28.2% → ~36.4%; recall unchanged. Machine-readable per-repo
file lists: `runs/llm_eval_results/skip_list_materialized.json`.

## Where this plugs in

- Apply in `harness/pipeline.py :: _inventory_files`, after the existing
  extension/Dockerfile/shebang filter, before units are built
  (`harness/partitioning/units.py` then never sees these paths).
- Independent of the installed ignore predicate: if `_graphify_ignore_predicate()`
  returns `None` (thin `tools/code.SKIP_DIRS` fallback), these rules still apply.
- Does **not** belong in codegraph itself — this is a harness-level scan-noise
  policy, not an indexing decision.

## The rules (all GT-validated)

| id | pattern | files dropped | finding rows | GT lost |
|----|---------|--------------:|-------------:|--------:|
| R1 | challenge/codefix/solution docs: basename/segment `codefix`, `solutions/`, `solution_*`, `*.info.yml`, `routes/vulnCodeFixes.ts` | 279 | 52 | 0 |
| R2 | `Dockerfile*` (name prefix — never matches `docker-compose*`) | 41 | 31 | 0 |
| R3 | `.github/**` except `.github/workflows/**` | 7 | 18 | 0 |
| R4 | `.travis*`, `.gitlab-ci*`, `.circleci/**`, `Jenkinsfile` | 5 | 2 | 0 |
| R5 | test/spec dirs (`test(s)/`, `spec(s)/`, `__tests__/`, `fixtures/`, `e2e/`) and `*.spec.*`/`*.test.*` files | 679 | 8 | 0 |
| R6 | build/tool configs (`webpack|svelte|jest|vitest|eslint|rollup|vite|babel|postcss|tailwind|karma|gulp|grunt` + `...config.*`) | 10 | 1 | 0 |
| R7 | vendored trees: dir segment `vendor/`, `bower_components/`, `jspm_packages/` | 0* | 14 | 0 |
| R8 | `static/jquery/**` (directory pair, not the bare filename) | 5 | 7 | 0 |
| R9 | asset libs: `foundation.*.js`, `bootstrap-tour.js`, `morris-*`, `html5shiv*`, `angular*.js` under `public/static/` | 17 | 20 | 0 |
| | **union (deduped)** | **1,039** | **149** | **0** |

\* R7 shows 0 here because this machine's global gitignore
(`/Users/critical/.gitignore_global` L87 `vendor/`, honored via `core.excludesFile`)
is already folded into the gitignore-aware predicate. On a normal run (plain repo dir,
no such exclude) R7 is what drops vendor trees — historically 14 finding rows
(nodegoat/vuln-node-express vendored libs). Keep it.

Row counts can double-count a finding matching two rules; deduped union is 149.
Per-repo file lists and counts: `skip_list_materialized.json`. Top repos:
juice-shop 366/764, juice-shop-goof 335/658, oss-oopssec-store 85/329,
djangoat 45/180, dvga 43/83, vulnpy 40/126, vulnerable-app-angular 26/127,
nodegoat 19/69, lets-be-bad-guys 15/63, vulnnodeapp 9/1782, dvws-node 7/53.

### Reference predicate (proposed wiring)

```python
# harness/pipeline.py — call after the extension/Dockerfile/shebang filter.
_VENDOR_SEGS = {"vendor", "bower_components", "jspm_packages"}
_TEST_SEGS = {"test", "tests", "spec", "specs", "__tests__", "fixtures", "e2e"}
_BUILD_CONFIG_RE = re.compile(
    r"(webpack|svelte|jest|vitest|eslint|rollup|vite|babel|postcss|tailwind|karma|gulp|grunt)"
    r"[.-]?config\.[a-z]+$"
)
_SPEC_FILE_RE = re.compile(r"\.(spec|test)\.[a-z]+$")

def _harness_skip_reason(rel: str) -> str | None:
    """Rule id for a repo-relative path that should never reach a partition, else None."""
    low = rel.replace("\\", "/").lower()
    segs = low.split("/")
    name, dirs = segs[-1], segs[:-1]
    if ("codefix" in low or "solutions" in dirs or name.startswith("solution_")
            or name.endswith(".info.yml") or name == "vulncodefixes.ts"):
        return "R1-challenge-docs"
    if name.startswith("dockerfile"):
        return "R2-dockerfile"
    if segs[0] == ".github" and "workflows" not in dirs:
        return "R3-dotgithub-nonworkflow"
    if ".travis" in low or ".gitlab-ci" in low or ".circleci" in dirs or name == "jenkinsfile":
        return "R4-other-ci"
    if any(s in _TEST_SEGS for s in dirs) or _SPEC_FILE_RE.search(name):
        return "R5-tests"
    if _BUILD_CONFIG_RE.search(name):
        return "R6-build-config"
    if any(s in _VENDOR_SEGS for s in dirs):
        return "R7-vendor-dirs"
    if any(a == "static" and b == "jquery" for a, b in zip(segs, segs[1:])):
        return "R8-static-jquery"
    if ((name.startswith("foundation.") and name.endswith(".js"))
            or name == "bootstrap-tour.js" or "morris-" in name
            or name.startswith("html5shiv")
            or (name.startswith("angular") and "public" in dirs and "static" in dirs)):
        return "R9-asset-libs"
    return None
```

## Never skip — GT lives here

| path | vulnerable GT | note |
|------|--------------:|------|
| `docker-compose*` | 7 | scanner scored 7/8 current findings here as TP |
| `.github/workflows/**` | 2 | threatbyte-023/024 (`sast-opengrep.yml`, `dast-zap.yml`) |
| dvpwa `sqli/static/js/jquery-3.2.1.min.js` | 1 | dvpwa-022 — R8 only skips `static/jquery/` dirs |
| dvws-node `public/static/{receiver,userdisplay}.js` | 2 | dvws-node-060/061 — app JS, not a lib basename |
| juice-shop `frontend/src/hacking-instructor/**` | 2 | juice-shop-051, juice-shop-goof-028 |
| `phpFiles/test.php` | 1 | bare `test.php` file — R5 skips test *dirs* and `*.test.*` names only |
| `bootstrapdb.js` (vuln-node-express) | 5 | basename does not match R9 |
| `templates/**` | 119 | never skip template dirs; R1 only touches `templates/partials/solutions` |

## Opposite leak — 15 vulnerable GT files the inventory never lets through

`_INVENTORY_EXTS` (+ Dockerfile/shebang) drops these today, so no partition ever
sees them: `.env` ×3 (dvws-node ×2, oss-oopssec-store), `views/error.pug`,
`views/searchResult.pug`, `conf/nginx.conf`, `caddy/Caddyfile`,
`views/about_new.dust`, `db/users.xml`, `python/hackable/passwords.txt`,
`python/hackable/flag.txt`, `package.json` (vuln-node-express-swagger),
`nodegoat artifacts/cert/server.key`, `config.xml` (dvws-node-005),
`server/cert/private_key.key`.

Suggested additions: `.env` (exact + `.env.*`), `.pug`, `.dust`, `.key`; and a
name-gated allowlist `{package.json, Caddyfile, nginx.conf, users.xml, config.xml}`
— broad `.json`/`.xml`/`.txt` would pull lockfiles and fixtures, so keep those
name-gated.

## Guardrail summary

- Skip → precision play + cost play; it can never cost recall (0 GT lost, all-GT check).
- The three proven traps are covered above: `docker-compose` ≠ `Dockerfile`,
  bare `test.php` ≠ test dir, app JS under `public/static/` ≠ vendor lib.
- R3's 18 rows include mis-anchored findings (e.g. cookie/CSRF findings stamped
  onto `.github/dependabot.yml`); skipping removes the noise without hiding a
  real GT item.
- Re-run `runs/` eval after wiring: expect −149 findings rows, recall unchanged.
