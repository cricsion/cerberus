"""Setting validation shared by the backends: every function raises
``ValueError`` at construction time, before a container or microVM exists."""
from __future__ import annotations

import re

# A Docker image reference: registry/repo components plus one optional tag or
# digest. A leading "-" is refused: docker would parse it as a FLAG.
IMAGE_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]*)?"
    r"(?:@sha256:[a-f0-9]{64})?$"
)


def validate_image(image: str) -> str:
    if not IMAGE_RE.match(image):
        raise ValueError(
            f"invalid docker image reference {image!r}: expected "
            "'repo/name[:tag][@sha256:digest]' with no leading dash "
            "(a leading dash would be parsed as a docker flag)")
    return image


# The only two network modes the docker container runs: `host` is deliberately
# not one -- it would put the agent in the host netns, beside our own services.
NETWORK_MODES = ("none", "bridge")


def validate_network(network: str) -> str:
    mode = str(network or "bridge").strip().lower()
    if mode not in NETWORK_MODES:
        raise ValueError(
            f"invalid sandbox network {network!r}: expected one of "
            f"{', '.join(NETWORK_MODES)} (bridge = full egress; "
            "none = no egress; host would join the host network namespace "
            "and is refused)")
    return mode


def validate_cpus(cpus: object) -> str:
    """sbx cpu share: a bare count, 0 meaning "the runtime default"."""
    try:
        n = int(str(cpus or 0).strip() or 0)
    except (TypeError, ValueError) as exc:
        # Same contract as validate_memory/validate_image: garbage config
        # fails the resolve (callers degrade to the local backend), it is
        # never silently coerced to the runtime default.
        raise ValueError(f"invalid sandbox.sbx.cpus {cpus!r}: expected a "
                         "bare count (0 = runtime default)") from exc
    if n < 0:
        n = 0
    return str(n)


def validate_memory(memory: str) -> str:
    """sbx takes binary units: 512m, 2g, 8g, or a bare MiB count."""
    m = str(memory or "").strip().lower()
    if not m:
        return "2g"
    if not ((m[-1] in "gmk" and m[:-1].isdigit()) or m.isdigit()):
        raise ValueError(
            f"invalid sandbox.sbx.memory {memory!r}: expected binary units "
            "such as 512m, 2g or 8g")
    return m


def validate_skills(mode: str) -> str:
    m = str(mode or "off").strip().lower()
    if m not in ("off", "readonly", "readwrite"):
        raise ValueError(
            f"invalid sandbox.sbx.skills {mode!r}: expected off|readonly|readwrite")
    return m


def validate_pull(policy: str) -> str:
    p = str(policy or "never").strip().lower()
    if p not in ("always", "missing", "never"):
        raise ValueError(
            f"invalid sandbox.sbx.pull {policy!r}: expected always|missing|never")
    return p
