"""Untrusted-data block helpers for composing agent prompts.

Blocks are nonce-delimited (per-prompt random, both tags): the text predates the
nonce, so it cannot contain a matching close tag.
"""
from __future__ import annotations

import re
import secrets

_CLOSING_TAG = re.compile(r"</\s*untrusted_data", re.IGNORECASE)


def make_nonce(seed: str | None = None) -> str:
    """Per-block delimiter id for <untrusted_data> blocks.
    When seed is provided, generates a deterministic 32-hex character nonce from sha256(seed)
    so prompts hit prefix caches across identical calls. Otherwise generates a random hex."""
    if seed is not None:
        import hashlib
        return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:32]
    return secrets.token_hex(16)


def sanitize_untrusted(text: str) -> str:
    """Neutralize anything that could close an <untrusted_data> block early."""
    return _CLOSING_TAG.sub("<untrusted_data", str(text))


def untrusted_block(text: str, nonce: str) -> str:
    """Wrap untrusted text in nonce-delimited isolation tags."""
    return (
        f'<untrusted_data id="{nonce}">\n'
        f"{sanitize_untrusted(text)}\n"
        f'</untrusted_data id="{nonce}">'
    )


__all__ = ["make_nonce", "sanitize_untrusted", "untrusted_block"]
