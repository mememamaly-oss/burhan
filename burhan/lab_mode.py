"""r19-2.4 (owner followup item 2): the EXPLICIT laboratory mode.

Doctrine: scanning loopback/private hosts (fixtures, lab apps, training
targets) is a DIFFERENT activity from scanning production targets, and
it must never happen by accident — an operator who points the tool at
127.0.0.1 out of habit, or a CI job that inherits an env var, must not
get a silent private-range scan.

The mode is explicit on BOTH channels the owner named:
  - a CLI flag:      --lab
  - an env variable: BURHAN_LAB_MODE=1 (CI + the demo UI + containers)

Activation = flag OR env (each surface has its own natural channel),
and EVERY scan report RECORDS the mode and which channel carried it
(stats["lab_mode"] = {"active": bool, "via": "flag"|"env"|None}).

Refusal: the authorization gate's self-hosted proof path (loopback/
private targets) REQUIRES the mode — without it, a private target is
refused loudly with the two sanctioned activation channels named.
"""
from __future__ import annotations

import os

ENV_VAR = "BURHAN_LAB_MODE"


def is_lab_mode(flag: bool = False) -> tuple[bool, str | None]:
    """(active, via) — the flag wins for the report's 'via', env second.

    `flag` is what the CLI/API layer passed explicitly; the env var
    covers CI, the demo UI, and containers where no argv exists.
    """
    if flag:
        return True, "flag"
    if os.environ.get(ENV_VAR, "").strip().lower() in ("1", "true", "yes", "on"):
        return True, "env"
    return False, None


def refusal_reason(target_host: str) -> str:
    """The loud refusal text when a private target has no lab mode."""
    return (
        "loopback/private target %r requires the EXPLICIT laboratory "
        "mode: pass --lab on the CLI (or set %s=1 for CI / the demo UI "
        "/ containers). Without it, private-range scans are refused — "
        "zero requests were sent." % (target_host, ENV_VAR))
