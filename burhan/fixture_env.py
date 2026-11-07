"""R17-8: the fixture spawn environment — extend-inherited, scoped-isolated.

Why this module exists: ci_fixture_run.py and repro_attest.py used to
spawn fixtures/vulnapp.py with a wholesale-replaced environment
(env={"PORT": ..., "PATH": "/usr/bin:/bin"}). Two live failures from
that (Windows audit, Round 17):

  - on Windows the replacement broke networking outright — WinError
    10106: Winsock needs SYSTEMROOT (and friends) which the minimal
    dict dropped;
  - on every platform it dropped host-required variables (CI proxies,
    TEMP, ...) for no benefit.

But the replacement was NOT accidental — it had a deliberate isolation
purpose: vulnapp.py reads BEHAVIORAL environment variables used by the
chaos/demo batteries (DELAY_MS, AUTH_TTL, CONFUSION, BFLA, SHADOW,
RACE_MODE, SIGNOFF). An inherited BFLA=1 or RACE_MODE=broken from the
operator's shell would silently mutate the fixture and break the
deterministic record (TP=38/FP=0/FN=0) the benchmark and
reproducibility gates assert.

The contract (single source of truth, shared by both scripts and the
tests — no drift possible):
  - EXTEND the inherited environment (Windows Winsock, CI vars work);
  - NEUTRALIZE every vulnapp behavioral var (present-but-empty string
    == the vulnapp default for each), preserving the isolation;
  - FORCE PORT to the intended port.
"""
from __future__ import annotations

import os

# every behavioral env var fixtures/vulnapp.py reads (grep-verified).
# ABSENT, not empty: vulnapp parses some as float/int
# (float(os.environ.get("DELAY_MS", "0"))), where "" is a ValueError —
# absence alone equals each reader's default, keeping determinism safe
# from outside mutation.
FIXTURE_NEUTRALIZED_ENV = (
    "DELAY_MS", "AUTH_TTL", "CONFUSION", "BFLA", "SHADOW",
    "RACE_MODE", "SIGNOFF",
)


def fixture_env(port: int) -> dict:
    """The environment for spawning the deterministic fixture."""
    env = {k: v for k, v in os.environ.items()
           if k not in FIXTURE_NEUTRALIZED_ENV}
    env["PORT"] = str(port)
    return env
