"""Setting validation shared by the backends: every function raises
``ValueError`` at construction time, before a container exists."""
from __future__ import annotations

from .settings_defaults import NETWORK


def validate_image(image: str) -> str:
    # Construction-time hazard: a leading dash is parsed by docker as a FLAG;
    # anything else malformed is docker's own validation, with clearer errors.
    i = str(image or "").strip()
    if not i or i.startswith("-"):
        raise ValueError(f"invalid docker image reference {image!r}: "
                         "must not start with '-' (parsed as a docker flag)")
    return i


# The only two network modes the docker container runs: `host` is deliberately
# not one -- it would put the agent in the host netns, beside our own services.
NETWORK_MODES = ("none", "bridge")

DEFAULT_NETWORK = NETWORK


def validate_network(network: str) -> str:
    mode = str(network or DEFAULT_NETWORK).strip().lower()
    if mode not in NETWORK_MODES:
        raise ValueError(
            f"invalid sandbox network {network!r}: expected one of "
            f"{', '.join(NETWORK_MODES)} (bridge = full egress; "
            "none = no egress; host would join the host network namespace "
            "and is refused)")
    return mode
