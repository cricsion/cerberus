"""Host-side guard for the custom semgrep rules pack.

The pack is otherwise validated only inside docker image builds (build.sh
self-test), so a malformed rule or a missing metadata.cwe can ship silently.
"""
import re
from pathlib import Path

import yaml

_RULES = (Path(__file__).resolve().parents[1] / "rules" / "custom-taint.yaml")


def test_rules_pack_parses_unique_ids_and_cwe_metadata():
    data = yaml.safe_load(_RULES.read_text(encoding="utf-8"))
    rules = data["rules"]
    assert rules, "rules pack must not be empty"
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"
    for r in rules:
        cwe = (r.get("metadata") or {}).get("cwe")
        assert re.fullmatch(r"CWE-\d+", str(cwe)), f"{r['id']}: bad cwe {cwe!r}"


# The regex prefilter (cerberus/tools/sast.py regex_prefilter) is the
# always-available detector; this yaml pack only loads inside the sandbox.
# The grid below is the reconciliation map (rule id -> prefilter family):
# a new rule id must be reconciled here explicitly, and stale rows surface
# when a rule is retired.
_RULE_TO_PREFILTER = {
    "custom-py-sqli-taint": "sqli-cursor",
    "custom-py-cmd-taint": "shell-true",
    "custom-py-xss-taint": "jinja-render",
    "custom-py-path-taint": "path-open-join",
    "custom-py-ssrf-taint": "ssrf-requests",
    "custom-py-deser-taint": "pickle-loads",
    "custom-py-code-exec-taint": "eval-exec",
    "custom-py-xxe-taint": "xpath-xml",
    "custom-py-xpath-taint": "xpath-xml",
    "custom-js-eval-taint": "js-exec",
    "custom-js-xss-taint": "js-xss",
    "custom-java-sqli-taint": "java-sqli",
    "custom-java-cmd-taint": "java-exec",
    "custom-go-cmd-taint": "go-exec",
    "custom-go-sqli-taint": "go-sqli",
    "custom-rb-inject-taint": "rb-rails-sqli",
    "custom-php-inject-taint": "php-sqli",
    "custom-php-deser-taint": "php-deser",
    "custom-redirect-taint-py": "open-redirect",
    "custom-redirect-taint-js": "open-redirect",
    "custom-redirect-taint-java": "open-redirect",
    "custom-redirect-taint-go": "open-redirect",
    "custom-redirect-taint-php": "open-redirect",
    "custom-redirect-taint-rb": "open-redirect",
    "custom-upload-taint-pyjs": "upload",
    "custom-upload-taint-php": "upload",
    "custom-ldap-taint-py": "ldap-xpath",
    "custom-ldap-taint-java": "ldap-xpath",
    "custom-debug-info": "debug-exposure",
    "custom-perms-open": "chmod-perms",
    "custom-weakhash-pass-taint-py": "md5-sha1",
    "custom-weakhash-pass-taint-java": "java-crypto",
    # No prefilter analog today: no js family greps crypto.createHash/md5(
    "custom-weakhash-pass-taint-js": None,
}


def test_rules_pack_reconciles_against_the_prefilter_grid():
    data = yaml.safe_load(_RULES.read_text(encoding="utf-8"))
    ids = [r["id"] for r in data["rules"]]
    unknown = [i for i in ids if i not in _RULE_TO_PREFILTER]
    assert not unknown, f"rules not reconciled against the prefilter grid: {unknown}"
    stale = [r for r in _RULE_TO_PREFILTER if r not in ids]
    assert not stale, f"mapping rows with no rule anymore: {stale}"
