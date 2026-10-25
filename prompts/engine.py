"""Prompt template loader
File contract
-------------
- Byte 0 opens the frontmatter fence: ``---``, metadata lines, ``---``.
- Frontmatter keys: ``role`` (must equal the file's parent directory name; one
  of hunter | validator | triage | threat | partition) and ``module``
  (provenance pointer to the consuming prompts module; test-checked).
- Body: plain Markdown, byte-preserved. Writers end the file with a single
  newline that is NOT part of the payload (standard POSIX editor behavior);
  every other byte — including trailing newlines inside the payload — is
  verbatim.
- Placeholders: ``{{ name }}`` resolved from caller-supplied variables.
  No ``str.format()`` — prompt bodies are full of literal JSON braces.
  Unknown placeholder or variable names raise: template and caller move
  together.
- Missing or empty body raises (a developer error in shipped prompt copy,
  not degradable operator input like config.py's paths).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_FRONTMATTER = re.compile(r"\A---\n(.+?)\n---\n", re.DOTALL)
_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_]\w*)\s*\}\}")

_CACHE: dict[tuple[str, str], tuple[dict[str, Any], str]] = {}


def _read(name: str, base: Path) -> tuple[dict[str, Any], str]:
    path = base / f"{name}.md"
    key = (str(base), name)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    if not path.is_file():
        raise FileNotFoundError(f"prompt template not found: {path}")
    text = path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(text)
    if match is None:
        raise ValueError(
            f"prompt template must start with '---' frontmatter: {path}")
    front = yaml.safe_load(match.group(1))
    if not isinstance(front, dict):
        raise ValueError(f"prompt template frontmatter is not a mapping: {path}")
    body = text[match.end():]
    if body.endswith("\n"):
        body = body[:-1]
    if not body:
        raise ValueError(f"prompt template body is empty: {path}")
    if front.get("role") != path.parent.name:
        raise ValueError(
            f"prompt template role {front.get('role')!r} does not match "
            f"directory {path.parent.name!r}: {path}")
    result = (front, body)
    _CACHE[key] = result
    return result


def meta(name: str, *, base: Path | None = None) -> dict[str, Any]:
    """The frontmatter mapping for one template."""
    front, _body = _read(name, (base or TEMPLATES_DIR).resolve())
    return dict(front)


def block(name: str, *, base: Path | None = None, **variables: Any) -> str:
    """The prompt copy for one template, placeholders substituted.

    Variables must exactly cover the template's placeholders: unresolved or
    unused names raise, so a template edit and its caller move together.
    """
    _front, body = _read(name, (base or TEMPLATES_DIR).resolve())
    found = set(_PLACEHOLDER.findall(body))
    if not variables:
        if found:
            raise ValueError(
                f"unresolved placeholders {sorted(found)} in prompt template: {name}")
        return body
    missing = sorted(found - set(variables))
    if missing:
        raise ValueError(
            f"unresolved placeholders {missing} in prompt template: {name}")
    extra = sorted(set(variables) - found)
    if extra:
        raise ValueError(f"unused variables {extra} for prompt template {name}")

    def _sub(match: re.Match[str]) -> str:
        return str(variables[match.group(1)])

    return _PLACEHOLDER.sub(_sub, body)
