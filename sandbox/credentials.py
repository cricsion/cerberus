"""Credential files inside the target repo: detect, expose, and block.

An agent runs with the repo in reach (read-only, but reachable) and, since
egress is allowed, anything it can read it can send out. The dangerous files
are the ones an operator leaves in a working tree without thinking of them as
secrets: ``.env`` with a live API key, ``.netrc``, ``.pypirc``, ``id_rsa``,
``.npmrc`` with an auth token, ``*.pem``/``*.key``.

This module answers three questions, so the harness never has to guess:

* :func:`find_credential_files` -- which repo-relative paths match (a scan
  start walk, recorded in scan metadata).
* :func:`credential_warning` -- the operator-facing sentence, and the louder
  one for when the target IS the harness checkout (its own ``.env`` holds the
  live model API key).
* :func:`blocked_paths` -- the glob set the repo-local file tools refuse, so
  the cheap in-process read path is closed even in modes that cannot mask the
  file (sbx attaches the whole workspace; only Docker can mask paths, and the
  docker backend does that with a read-only ``/dev/null`` bind per target).

This does NOT make the model channel safe: an agent that reads a credential can
always write it into its own answer, and no sandbox stops that. It removes the
easy read path, records what was exposed, and says so out loud.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path

# Conservative on purpose: a false positive hides a file from a scan (fixable,
# visible in scan metadata), a false negative hands a live key to an agent.
CREDENTIAL_GLOBS: tuple[str, ...] = (
    ".env", ".env.*", "*.env",                  # dotenv files
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",   # SSH keys
    ".netrc", "_netrc", ".pgpass", ".my.cnf",           # legacy plaintext creds
    ".pypirc", ".npmrc", ".yarnrc", ".curlrc",          # package manager auth
    "credentials", "credentials.*", "*.credentials",
    ".htpasswd", "shadow", "master.key",               # misc service secrets
    "*.kdbx", "*.asc", "*.gpg",                         # keyrings/exports
)

# Where the harness's own credentials live, so a self-scan can be called out.
_HARNESS_MARKERS = ("harness", "config", "Dockerfile")


def is_credential_path(rel_path: str, globs: tuple[str, ...] = CREDENTIAL_GLOBS) -> bool:
    """True when a repo-relative path matches one of the credential globs."""
    name = str(rel_path or "").replace("\\", "/").rsplit("/", 1)[-1]
    rel = str(rel_path or "").replace("\\", "/").lstrip("/")
    return any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat)
               for pat in globs)


def find_credential_files(repo: str | Path,
                          globs: tuple[str, ...] = CREDENTIAL_GLOBS) -> list[str]:
    """Repo-relative credential paths present in the tree, including aliases.

    A credential-named symlink is included when it points to a file. Callers
    that mask files should resolve that path and mask its in-repo target too;
    file-tool callers should refuse both the alias and the resolved target.
    Symlink directories are not traversed.
    """
    base = Path(repo)
    found: list[str] = []
    try:
        for path in sorted(base.rglob("*")):
            try:
                rel = path.relative_to(base)
            except ValueError:
                continue
            if not is_credential_path(str(rel), globs):
                continue
            if path.is_file():
                found.append(str(rel))
    except OSError:
        return []
    return found


def blocked_paths() -> tuple[str, ...]:
    """Globs the repo-local file tools must refuse to read."""
    return CREDENTIAL_GLOBS


def looks_like_harness_checkout(repo: str | Path) -> bool:
    """Best-effort "the target is the harness itself" detection.

    Used only to make the warning louder: the harness checkout is the one repo
    whose credential file holds the operator's live model API key.
    """
    base = Path(repo)
    hits = sum(1 for marker in _HARNESS_MARKERS
               if (base / marker).is_dir() or (base / marker).is_file())
    return hits >= 2 and (base / ".env").is_file()


def credential_warning(repo: str | Path, files: list[str]) -> list[str]:
    """Operator-facing warning lines; empty when nothing was found."""
    if not files:
        return []
    lines = [f"[sandbox] {len(files)} credential file(s) are readable inside the "
             f"scan target (egress is allowed): {', '.join(files[:6])}"
             + (" …" if len(files) > 6 else "")]
    if looks_like_harness_checkout(repo):
        lines.append("[sandbox] WARNING: the target is the harness checkout "
                     "itself; its .env holds the live model API key and agents "
                     "can read it. Consider scanning a copy without .env.")
    return lines
