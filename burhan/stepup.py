"""Master-password step-up authentication — round 9, part 2 (2026-11-04).

A SECOND-FACTOR authorization gate, separate from the owner's normal
login, required specifically to trigger the two sensitive actions the
round-9 order names:
  - closure_reexploit — re-exploitation of a finding for closure-proof
    purposes;
  - patch_generation  — generation of a remediation patch.
Both entry points live in burhan/remediation.py and call require() here
BEFORE doing anything — the gate is wired in code, not documentation.

Credential design (per the order):
  - a DISTINCT high-entropy secret (32 bytes = 256 bits of os.urandom),
    never the owner's normal password — generate_master_secret() prints
    it once for storage in the operator's vault; the repo stores only a
    VERIFIER (scrypt digest) + per-store salt, never the secret;
  - rate-limited attempts: a sliding window over the FAILED attempts
    recorded in the store's own event chain (5 failures / 300 s default);
    exceeding the window refuses with StepUpRateLimited until it slides;
  - EVERY use — success or failure — is appended to a tamper-evident hash
    chain (head_i = sha256(head_{i-1} || canonical(event_i))): the chain
    head covers every event, and verify_chain() recomputes it end-to-end,
    so editing, deleting or reordering history is detectable. The
    canonicalization discipline is the one burhan/audit.py established
    (sorted keys, compact separators, UTF-8).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time

GENESIS = hashlib.sha256(b"burhan-stepup-genesis-v1").hexdigest()
PURPOSES = ("closure_reexploit", "patch_generation")
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1


class StepUpRequired(RuntimeError):
    """The action demands the step-up credential and it was not supplied
    (or wrong). Loud refusal; the attempt is already in the chain."""


class StepUpRateLimited(RuntimeError):
    """Too many failed attempts inside the sliding window. The gate stays
    closed until the window slides — no secret is even compared."""


class StepUpChainTampered(RuntimeError):
    """The event chain no longer matches its recorded head — the audit
    trail was edited, deleted or reordered. The gate refuses to operate
    on a tampered trail."""


def canonical_event(event: dict) -> str:
    """audit.py's canonicalization discipline: sorted keys, compact
    separators, UTF-8, no volatile fields to strip here (every field of a
    step-up event is part of the record by design)."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _chain_hash(prev_head: str, event: dict) -> str:
    return hashlib.sha256(
        (prev_head + canonical_event(event)).encode("utf-8")).hexdigest()


def _scrypt_digest(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt,
                          n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                          dklen=32)


def generate_master_secret() -> str:
    """A fresh 256-bit step-up secret, base64. Printed ONCE by the
    operator's setup command and stored in their vault; only the scrypt
    verifier ever reaches a store file. Distinct from every login
    password by construction (it is not chosen by a human)."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


class StepUpGate:
    """The step-up credential store + rate limiter + audit chain.

    store file shape (JSON):
      {salt_b64, verifier_b64, chain_head, events: [{ts, purpose, ok,
      detail?}]}
    """

    def __init__(self, store_path: str, *, window_s: float = 300.0,
                 max_failures: int = 5):
        self.path = str(store_path)
        self.window_s = window_s
        self.max_failures = max_failures

    # ---- setup ---------------------------------------------------------
    @classmethod
    def setup(cls, store_path: str, secret: str, **kw) -> "StepUpGate":
        """Create the store from a fresh secret. REFUSES to overwrite an
        existing store (no silent reset of the audit trail)."""
        if os.path.exists(store_path):
            raise FileExistsError(
                f"step-up store already exists at {store_path} — refusing "
                f"to overwrite its audit trail; rotate by explicit deletion")
        salt = secrets.token_bytes(16)
        data = {
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "verifier_b64": base64.b64encode(
                _scrypt_digest(secret, salt)).decode("ascii"),
            "chain_head": GENESIS,
            "events": [],
        }
        os.makedirs(os.path.dirname(os.path.abspath(store_path)) or ".",
                    exist_ok=True)
        with open(store_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        return cls(store_path, **kw)

    def _load(self) -> dict:
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def _save(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, self.path)

    # ---- the audit chain ------------------------------------------------
    def append_event(self, event: dict) -> dict:
        """Append one event and extend the chain. Every field of the event
        enters the hash — ts, purpose, ok, detail."""
        data = self._load()
        event = dict(event, ts=round(time.time(), 3))
        head = _chain_hash(data["chain_head"], event)
        data["events"].append(event)
        data["chain_head"] = head
        self._save(data)
        return event

    def verify_chain(self) -> int:
        """Recompute the whole chain; return the event count. Any edit,
        deletion or reordering breaks the head and raises
        StepUpChainTampered."""
        data = self._load()
        head = GENESIS
        for ev in data["events"]:
            if "ts" not in ev:
                raise StepUpChainTampered("event missing its timestamp")
            head = _chain_hash(head, ev)
        if head != data["chain_head"]:
            raise StepUpChainTampered(
                "chain head mismatch — the step-up audit trail was modified")
        return len(data["events"])

    # ---- the gate --------------------------------------------------------
    def _recent_failures(self, data: dict) -> int:
        """Credential failures inside the sliding window. Rate-limited
        refusals do NOT count (they are the lock's own output, not
        attempts) — otherwise a sustained attacker would keep the window
        alive forever and the legitimate owner could never unlock."""
        now = time.time()
        return sum(1 for ev in data["events"]
                   if ev.get("ok") is False
                   and not str(ev.get("detail", "")).startswith("rate-limited")
                   and now - float(ev.get("ts", 0)) <= self.window_s)

    def require(self, purpose: str, secret: str | None) -> dict:
        """THE gate. Returns the success event on pass; raises
        StepUpRequired / StepUpRateLimited on refusal. Every attempt —
        pass or fail — lands in the chain. A tampered trail refuses
        everything (verify_chain first, fail-closed)."""
        if purpose not in PURPOSES:
            raise ValueError(f"unknown step-up purpose {purpose!r} "
                             f"(known: {PURPOSES})")
        n = self.verify_chain()          # fail-closed on a tampered trail
        data = self._load()
        if self._recent_failures(data) >= self.max_failures:
            ev = self.append_event({"purpose": purpose, "ok": False,
                                    "detail": "rate-limited (window "
                                              f"{self.window_s}s/" 
                                              f"{self.max_failures})"})
            raise StepUpRateLimited(
                f"step-up gate closed: {self.max_failures} failed attempts "
                f"in the last {self.window_s}s (attempt recorded in the "
                f"chain, event #{n + 1})")
        if not secret:
            ev = self.append_event({"purpose": purpose, "ok": False,
                                    "detail": "credential not supplied"})
            raise StepUpRequired(
                f"the action {purpose!r} requires the master-password "
                f"step-up credential (refusal recorded in the chain, "
                f"event #{n + 1})")
        salt = base64.b64decode(data["salt_b64"])
        want = base64.b64decode(data["verifier_b64"])
        got = _scrypt_digest(secret, salt)
        if not secrets.compare_digest(want, got):
            ev = self.append_event({"purpose": purpose, "ok": False,
                                    "detail": "credential mismatch"})
            raise StepUpRequired(
                f"wrong step-up credential for {purpose!r} (refusal "
                f"recorded in the chain, event #{n + 1})")
        return self.append_event({"purpose": purpose, "ok": True,
                                  "detail": "step-up granted"})
