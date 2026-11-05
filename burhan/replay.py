"""Part 2 — Interactive "replay this finding".

Reuses the EXISTING re-execution verification engine (evidence.replay_finding)
— no second, parallel exploitation mechanism. The replay gate is the SAME
authorized-targets registry the live-scan workflow uses (authorized_targets.
require_authorized), checked LIVE before every replay (never cached), and
each replay is rate-limited per finding.

Verdicts (honest lifecycle events, linked to the original finding identity):
  REPRODUCTION_VERIFIED — the vuln still reproduces; a NEW signed replay
                          event is recorded, linked to the finding identity
  REPRODUCTION_FAILED   — the replay ran and did NOT reproduce (the target
                          fixed it) — NOT an error, a distinct lifecycle event
  REFUSED               — target not in authorized-targets.json: zero live
                          requests sent, refusal logged loudly (exit 2)
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlsplit

from .authorized_targets import authorize, DEFAULT_REGISTRY

# ---------------------------------------------------------------------------
# 2.3 rate limit — stated plainly with the reason:
# REPLAY_MIN_INTERVAL_SECONDS = 60: one replay per finding per minute. WHY
# this number: a replay re-fires the finding's own verified exploitation
# request (1-3 requests typical, 10 for race classes). Without a limit, a
# script or an over-eager analyst could loop replays into a de-facto DoS
# against a real authorized target. 60s bounds any single identity to <=3
# requests/minute (race: <=10/min) — far below any realistic degradation
# threshold, while still allowing an analyst to re-check after a fix within
# a minute. Per-finding (identity) granularity, in-process + persisted.
# ---------------------------------------------------------------------------
REPLAY_MIN_INTERVAL_SECONDS = 60.0
_RATE_FILE = Path("results/replay-rate-limit.json")


class ReplayRefused(Exception):
    """The target is not currently authorized — no live request was sent."""


class ReplayRateLimited(Exception):
    """This finding was replayed within the rate-limit window."""


def _load_rate_state() -> dict:
    try:
        return json.loads(_RATE_FILE.read_text())
    except Exception:
        return {}


def _save_rate_state(state: dict) -> None:
    _RATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _RATE_FILE.write_text(json.dumps(state))


def _origin_of(proof: dict) -> str:
    req = (proof.get("requests") or [{}])[0]
    url = req.get("url", "")
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme else ""


def _identity_of(proof: dict) -> str:
    """The finding-identity model from the risk-prioritization layer:
    prefer the recorded identity, else the deterministic
    detector+endpoint+parameter hash (prioritize.finding_identity)."""
    if proof.get("identity"):
        return proof["identity"]
    from .prioritize import finding_identity
    req = (proof.get("requests") or [{}])[0]
    return finding_identity(proof.get("detector") or proof.get("type", ""),
                            req.get("url", ""), req.get("parameter", ""))


def check_rate_limit(identity: str, now: float | None = None) -> float:
    """Seconds remaining in this identity's rate-limit window (0 = free)."""
    now = time.time() if now is None else now
    state = _load_rate_state()
    last = float(state.get(identity, 0))
    remaining = REPLAY_MIN_INTERVAL_SECONDS - (now - last)
    return max(0.0, remaining)


def replay_finding_gated(proof: dict, registry_path: str | None = None,
                         fetch=None, respect_rate_limit: bool = True) -> dict:
    """Replay ONE stored finding through the gate.

    2.2 the gate: authorize() is called LIVE against the registry BEFORE
    any re-execution — a target that is absent/unverified/pending-pin is
    REFUSED loudly (zero live requests, refusal recorded in the result).

    2.1 the replay: delegates to evidence.replay_finding (the existing
    re-execution engine) and wraps its verdict as a lifecycle event linked
    to the finding identity.
    """
    origin = _origin_of(proof)
    identity = _identity_of(proof)
    base = {"finding_id": proof.get("finding_id", ""),
            "identity": identity, "target": origin,
            "replayed_at": time.time()}

    if not origin:
        return {**base, "replay": "REFUSED",
                "reason": "no request URL recorded in the proof"}
    ok, reason, entry_id = authorize(origin, registry_path or DEFAULT_REGISTRY,
                                     fetch)
    if not ok:
        # zero live requests sent; the refusal itself is the record
        return {**base, "replay": "REFUSED",
                "reason": f"authorization gate: {reason}",
                "registry_entry": entry_id, "live_requests_sent": 0}

    if respect_rate_limit:
        remaining = check_rate_limit(identity)
        if remaining > 0:
            raise ReplayRateLimited(
                f"finding {identity} was replayed {remaining:.0f}s ago — "
                f"per-finding rate limit is {REPLAY_MIN_INTERVAL_SECONDS:.0f}s "
                f"(anti-DoS: see REPLAY_MIN_INTERVAL_SECONDS)")

    from .core import ScopeRule, EventBus
    from .evidence import replay_finding
    req = (proof.get("requests") or [{}])[0]
    scope = ScopeRule(allowed_domains=[urlsplit(req.get("url", "")).hostname],
                      allow_private=True)
    replay_oast = None
    _host = (urlsplit(req.get("url", "")).hostname or "").lower()
    if _host in ("127.0.0.1", "localhost", "::1"):
        from .oast import OastServer
        replay_oast = OastServer()
    try:
        result = replay_finding(proof, scope, EventBus("replay-gated"),
                                oast=replay_oast)
    finally:
        if replay_oast is not None:
            replay_oast.stop()

    # record the lifecycle event + rate-limit stamp
    state = _load_rate_state()
    state[identity] = time.time()
    _save_rate_state(state)

    verdict = result.get("replay", "NOT_REPLAYABLE")
    lifecycle_event = ("REPRODUCTION_VERIFIED"
                       if verdict == "REPRODUCTION_VERIFIED"
                       else "REPRODUCTION_NOT_REPRODUCED"
                       if verdict == "REPRODUCTION_FAILED"
                       else verdict)     # NOT_REPLAYABLE passes through as-is
    return {**base, **result,
            "replay": verdict,
            "lifecycle_event": lifecycle_event,
            "linked_identity": identity,
            "registry_entry": entry_id,
            "live_requests_sent": 1 if verdict != "NOT_REPLAYABLE" else 0}
