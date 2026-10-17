"""A deny-only command prefilter shared by every sandbox backend.

CHEAP PRE-FILTER, not the security boundary (the sandbox is; egress is the
backend's network posture, never this check). Defeatable by shell syntax,
unknown commands pass through. Do not claim more for it in docs or prompts.
"""
from __future__ import annotations

import os
import re
import shlex

DENIED = frozenset({
    "docker", "podman", "kubectl", "crun", "runc", "nsenter", "unshare",
    "mount", "iptables", "nft", "pfctl", "route", "ifconfig", "ip", "arp",
    "ssh-agent", "gpg-agent",
})

# Shell wrappers need one extra look so `bash -c 'docker ps'` gets the same
# obvious-command check as a direct call. Still a pre-filter, not a parser.
_SHELLS = frozenset({"bash", "sh", "zsh", "dash"})
_SHELL_COMMAND_FLAGS = frozenset({"-c", "-lc"})

_SEGMENT_SPLIT = re.compile(r"(?:\|\||&&|[;|\n()]|\$\(|\$\{|`)")


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError:  # malformed shell text: retain a cheap best effort
        return segment.split()


def _segments(source: str) -> list[str]:
    return [part for part in _SEGMENT_SPLIT.split(source) if part.strip()]


def _commands_in_segment(segment: str) -> list[str]:
    """The segment's executable and any simple shell-wrapper command.

    Arguments are ignored so `ip` in `grep -rn ip .` is not read as an
    executable; only the common sh -c / eval / exec forms are unwrapped.
    """
    words = _tokens(segment)
    while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        words.pop(0)
    if not words:
        return []

    executable = words[0]
    base = os.path.basename(executable).lower()
    commands = [executable]
    if base in _SHELLS:
        for i, word in enumerate(words[1:], start=1):
            if word in _SHELL_COMMAND_FLAGS and i + 1 < len(words):
                commands.extend(_commands_in_source(words[i + 1]))
                break
            if not word.startswith("-"):
                break
    elif base in {"eval", "exec"} and len(words) > 1:
        commands.extend(_commands_in_source(" ".join(words[1:])))
    return commands


def _commands_in_source(source: str) -> list[str]:
    return [word for segment in _segments(source)
            for word in _commands_in_segment(segment)]


def policy_error(command: str) -> str | None:
    """Fail fast on obvious host/runtime commands; all others pass through
    (egress is the sandbox's business, not this function's)."""
    segments = _segments(command)
    for segment in segments:
        for base in (os.path.basename(w).lower()
                     for w in _commands_in_segment(segment)):
            if base in DENIED:
                return (f"refused by sandbox policy: {base!r} is a "
                        "container-runtime/host-namespace tool")
    return None
