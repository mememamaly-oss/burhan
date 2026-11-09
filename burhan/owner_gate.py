"""Owner-password scan gate — round 19, part 2 (2026-11-09).

The owner's order (R19): scan execution is controlled by the
installation owner's own password.
  - Each installation's owner sets their password at FIRST SETUP.
  - They can CHANGE it (current password required).
  - They can TRANSFER ownership (a sale): the buyer sets their own
    password with no dependency on the seller's secret or cooperation.
  - No default/backdoor value exists anywhere.

Credential design (the stepup.py discipline, r9p2):
  - the store keeps ONLY a scrypt VERIFIER + per-store salt — never the
    password, never any recoverable form;
  - setup is ATOMIC + EXCLUSIVE (O_CREAT|O_EXCL): two racing setups
    cannot both win, and an existing store is never silently reset;
  - every attempt (pass/fail) lands in a tamper-evident hash chain —
    the chain head covers the whole history and is recomputed on every
    gate use (fail-closed on tamper);
  - rate limiting: sliding window over FAILED attempts (5/300s default);
  - zero network: the gate is purely local file + scrypt.

Change/transfer semantics:
  - change_password(old, new): requires the CURRENT password; recorded
    in the chain as owner_change (the old verifier is dead, the audit
    trail survives);
  - transfer_arm()  — the SELLING owner, authenticated by their
    current password, arms a ONE-TIME handover ticket (256-bit,
    15-minute TTL default). The ticket lets the buyer take ownership
    exactly once;
  - transfer_take(ticket, new_password) — the BUYER completes the sale:
    consumes the ticket and installs THEIR OWN password. From that
    moment the seller's password is dead (verifier replaced) — the
    buyer depends on nobody. Ticket replay after consumption fails;
    an expired ticket fails.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time

GENESIS = hashlib.sha256(b"burhan-owner-gate-genesis-v1").hexdigest()
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1
TRANSFER_TTL_S = 15 * 60


class OwnerGateError(RuntimeError):
    """Base: loud refusal (the attempt is already in the chain)."""


class OwnerGateRequired(OwnerGateError):
    """No/unusable credential supplied for an action that demands it."""


class OwnerGateRateLimited(OwnerGateError):
    """Too many failures inside the sliding window — the gate stays
    closed until the window slides; no comparison happens."""


class OwnerGateChainTampered(OwnerGateError):
    """The audit chain no longer matches its head — the trail was
    edited, deleted or reordered; the gate refuses to operate."""


class OwnerGateTransferError(OwnerGateError):
    """Handover ticket invalid, expired, or already consumed."""


def canonical_event(event: dict) -> str:
    """audit.py's canonicalization: sorted keys, compact separators,
    UTF-8."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _chain_hash(prev_head: str, event: dict) -> str:
    return hashlib.sha256(
        (prev_head + canonical_event(event)).encode("utf-8")).hexdigest()


def _scrypt_digest(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt,
                          n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                          dklen=32)


class OwnerGate:
    """The owner credential store + rate limiter + audit chain.

    store file shape (JSON, 0600):
      {salt_b64, verifier_b64, chain_head, events: [...],
       transfer?: {ticket_b64, expires_ts, consumed: bool}}
    """

    def __init__(self, store_path: str, *, window_s: float = 300.0,
                 max_failures: int = 5):
        self.path = str(store_path)
        self.window_s = window_s
        self.max_failures = max_failures

    # ---- setup ---------------------------------------------------------
    @classmethod
    def setup(cls, store_path: str, password: str, **kw) -> "OwnerGate":
        """FIRST-SETUP: create the store from the owner's chosen
        password. Refuses to overwrite an existing store (no silent
        reset of the audit trail); atomic + exclusive create."""
        if not password or len(password) < 8:
            raise OwnerGateError(
                "owner password must be at least 8 characters "
                "(first-setup refused — nothing was written)")
        salt = secrets.token_bytes(16)
        data = {
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "verifier_b64": base64.b64encode(
                _scrypt_digest(password, salt)).decode("ascii"),
            "chain_head": GENESIS,
            "events": [],
        }
        os.makedirs(os.path.dirname(os.path.abspath(store_path)) or ".",
                    exist_ok=True)
        try:
            fd = os.open(store_path, os.O_CREAT | os.O_EXCL |
                         os.O_WRONLY, 0o600)
        except FileExistsError:
            raise FileExistsError(
                f"owner-gate store already exists at {store_path} — "
                f"refusing to overwrite its audit trail; ownership "
                f"changes go through change_password/transfer, never "
                f"re-setup") from None
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        gate = cls(store_path, **kw)
        gate.append_event({"action": "first_setup", "ok": True,
                           "detail": "owner password installed"})
        return gate

    def exists(self) -> bool:
        return os.path.exists(self.path)

    # ---- store io -------------------------------------------------------
    def _load(self) -> dict:
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def _save(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, self.path)

    # ---- the audit chain --------------------------------------------------
    def append_event(self, event: dict) -> dict:
        data = self._load()
        event = dict(event, ts=round(time.time(), 3))
        head = _chain_hash(data["chain_head"], event)
        data["events"].append(event)
        data["chain_head"] = head
        self._save(data)
        return event

    def verify_chain(self) -> int:
        data = self._load()
        head = GENESIS
        for ev in data["events"]:
            if "ts" not in ev:
                raise OwnerGateChainTampered("event missing timestamp")
            head = _chain_hash(head, ev)
        if head != data["chain_head"]:
            raise OwnerGateChainTampered(
                "chain head mismatch — the owner-gate audit trail was "
                "modified")
        return len(data["events"])

    # ---- the gate ---------------------------------------------------------
    def _recent_failures(self, data: dict) -> int:
        now = time.time()
        return sum(1 for ev in data["events"]
                   if ev.get("ok") is False
                   and not str(ev.get("detail", "")).startswith("rate-limited")
                   and now - float(ev.get("ts", 0)) <= self.window_s)

    def _rate_guard(self, action: str) -> int:
        n = self.verify_chain()          # fail-closed on tamper
        if self._recent_failures(self._load()) >= self.max_failures:
            self.append_event({"action": action, "ok": False,
                               "detail": "rate-limited (window "
                                         f"{self.window_s}s/"
                                         f"{self.max_failures})"})
            raise OwnerGateRateLimited(
                f"owner gate closed: {self.max_failures} failed attempts "
                f"in the last {self.window_s}s")
        return n

    def _check_password(self, data: dict, password: str | None) -> bool:
        if not password:
            return False
        salt = base64.b64decode(data["salt_b64"])
        want = base64.b64decode(data["verifier_b64"])
        return secrets.compare_digest(want, _scrypt_digest(password, salt))

    def unlock_scan(self, password: str | None) -> dict:
        """THE gate every scan must pass. Returns the success event;
        raises OwnerGateRequired / OwnerGateRateLimited on refusal. If
        the store does not exist yet, the gate is CLOSED: scans refuse
        with the setup instruction (there is no default password)."""
        if not self.exists():
            raise OwnerGateRequired(
                "no owner password is set on this installation — run "
                "`burhan owner init` to set yours first; scans stay "
                "refused until then (no default value exists)")
        n = self._rate_guard("scan")
        data = self._load()
        if not self._check_password(data, password):
            self.append_event({"action": "scan", "ok": False,
                               "detail": "credential not supplied"
                                         if not password
                                         else "credential mismatch"})
            raise OwnerGateRequired(
                "wrong or missing owner password (refusal recorded in "
                f"the chain, event #{n + 1})")
        return self.append_event({"action": "scan", "ok": True,
                                  "detail": "scan authorized"})

    # ---- change / transfer ---------------------------------------------
    def change_password(self, old: str | None, new: str) -> dict:
        """Owner changes their own password. The CURRENT password is
        required; the audit chain survives (the old verifier dies)."""
        n = self._rate_guard("owner_change")
        data = self._load()
        if not self._check_password(data, old):
            self.append_event({"action": "owner_change", "ok": False,
                               "detail": "current credential wrong"})
            raise OwnerGateRequired(
                f"password change refused — the current password did not "
                f"verify (event #{n + 1})")
        if not new or len(new) < 8:
            raise OwnerGateError("new owner password must be at least 8 "
                                 "characters (nothing was changed)")
        salt = secrets.token_bytes(16)
        data["salt_b64"] = base64.b64encode(salt).decode("ascii")
        data["verifier_b64"] = base64.b64encode(
            _scrypt_digest(new, salt)).decode("ascii")
        self._save(data)
        return self.append_event({"action": "owner_change", "ok": True,
                                  "detail": "owner password changed"})

    def transfer_arm(self, current: str | None) -> str:
        """The SELLING owner arms a one-time handover ticket. Their
        current password authenticates the arm; the ticket is valid
        once for TRANSFER_TTL_S seconds."""
        self._rate_guard("transfer_arm")
        data = self._load()
        if not self._check_password(data, current):
            self.append_event({"action": "transfer_arm", "ok": False,
                               "detail": "seller credential wrong"})
            raise OwnerGateRequired(
                "transfer arming refused — the current owner password "
                "did not verify")
        # A leading "-" would make argparse treat the ticket as an
        # option, not a value (`--ticket -abc` fails to parse), and the
        # buyer could never complete the takeover. Re-roll instead; the
        # ticket stays 256 bits of CSPRNG output either way.
        ticket = base64.urlsafe_b64encode(
            secrets.token_bytes(32)).decode("ascii").rstrip("=")
        while ticket.startswith("-"):
            ticket = base64.urlsafe_b64encode(
                secrets.token_bytes(32)).decode("ascii").rstrip("=")
        data["transfer"] = {"ticket_b64": ticket,
                            "expires_ts": time.time() + TRANSFER_TTL_S,
                            "consumed": False}
        self._save(data)
        self.append_event({"action": "transfer_arm", "ok": True,
                           "detail": "handover ticket issued "
                                     f"(ttl {TRANSFER_TTL_S}s)"})
        return ticket

    def transfer_take(self, ticket: str | None,
                      new_password: str) -> dict:
        """The BUYER completes the sale: consume the one-time ticket
        and install THEIR OWN password. From this point the seller's
        password is dead — the buyer depends on nobody. Replays and
        expired tickets fail loudly."""
        self._rate_guard("transfer_take")
        data = self._load()
        tr = data.get("transfer")
        if not tr:
            self.append_event({"action": "transfer_take", "ok": False,
                               "detail": "no armed transfer"})
            raise OwnerGateTransferError(
                "no handover ticket is armed — the current owner must "
                "run `burhan owner transfer-arm` first")
        if tr.get("consumed"):
            self.append_event({"action": "transfer_take", "ok": False,
                               "detail": "ticket already consumed"})
            raise OwnerGateTransferError(
                "this handover ticket was already used — ownership moved; "
                "a new transfer must be armed by the CURRENT owner")
        if time.time() > float(tr.get("expires_ts", 0)):
            self.append_event({"action": "transfer_take", "ok": False,
                               "detail": "ticket expired"})
            raise OwnerGateTransferError(
                "the handover ticket expired — the owner must arm a "
                "fresh one")
        if not ticket or not secrets.compare_digest(
                str(tr.get("ticket_b64", "")), str(ticket or "")):
            self.append_event({"action": "transfer_take", "ok": False,
                               "detail": "ticket mismatch"})
            raise OwnerGateTransferError(
                "wrong handover ticket")
        if not new_password or len(new_password) < 8:
            raise OwnerGateError("buyer password must be at least 8 "
                                 "characters (transfer not completed)")
        salt = secrets.token_bytes(16)
        data["salt_b64"] = base64.b64encode(salt).decode("ascii")
        data["verifier_b64"] = base64.b64encode(
            _scrypt_digest(new_password, salt)).decode("ascii")
        data["transfer"]["consumed"] = True
        self._save(data)
        return self.append_event({"action": "transfer_take", "ok": True,
                                  "detail": "ownership transferred — "
                                            "buyer password installed, "
                                            "seller credential dead"})
