"""Burhan v2.9.0 — Credential Vault (Phase 57).

Encrypted at-rest retention for credentials the Credential Exposure Engine
proves are exposed, with the access model of an authorized security-test
deliverable:

  * 🔐  ENCRYPTED STORAGE — pure-stdlib authenticated encryption:
         stream cipher  : ChaCha20 (RFC 8439 §2.3), pure Python
         authentication: HMAC-SHA256, encrypt-then-MAC over (AAD ‖ nonce ‖ ct)
         key separation: enc_key / mac_key / wrap_key derived via HMAC-SHA256
                          from the 256-bit blob key (domain-separated labels)
    The vault file never contains a plaintext secret — verified by byte-level
    gates in the test suite (data.count(raw) == 0).

  * 👤  AUTHORIZED KEYS — access is granted to KEY FILES, not passwords in
         code or Git. A key file is 32 random bytes (os.urandom) in a
         0600 JSON file with a deterministic key_id (first 8 hex of SHA-256).
         The vault holds one WRAP of the blob key per authorized key file;
         `authorize` / `revoke` add and remove wraps (revoke re-randomizes the
         blob key — a removed key cannot decrypt ANY copy of the file).

  * 📝  AUDIT TRAIL — every meaningful operation (INIT, AUTHORIZE, REVOKE,
         STORE, LIST, EXPORT, REPORT, PURGE) appends {ts, actor=key_id,
         action, target} inside the ENCRYPTED blob: the audit log itself is
         confidential and tamper-evident (covered by the blob MAC).

  * 📄  MASKED EVERYWHERE — records carry a non-reversible preview (4-char
         prefix + length, the same mask the scanner uses). list() and every
         public artifact show the preview only; the raw value exists solely
         inside the encrypted blob. scrub() additionally walks arbitrary
         report structures replacing any known raw value with '********'
         (defense in depth for accidental leakage paths).

  * 🔓  AUTHENTICATED REVEAL — export(record_id) / report() are the only
         paths that produce plaintext, and both write an audit entry first.

  * 🗑️  PURGE — removing a record rewrites the blob WITHOUT the value (fresh
         nonce, new ciphertext); the audit entry survives by design so the
         destruction itself is provable.

  * 🏢  ORG SEPARATION — one vault file per organization; the org id is bound
         into the AAD, so a blob transplanted between vaults fails its MAC.

Threat model (honest limits):
  - Local-file vault: an attacker with write access to the vault file can
    roll it back to an older revision (re-introducing purged records) or
    delete it. Rollback is visible via the monotonic `revision` field and
    the audit log, but not preventable without external state — same class
    of limit as any local encrypted store.
  - Python cannot truly zeroize immutable strings; best-effort deletion of
    references is performed. RAM forensics is out of scope.
  - Key files must be stored outside any VCS; the shipped .gitignore-vault
    template covers vault + key patterns.

Key file format (JSON, 0600):
    {"format": "burhan-vault-key/1", "key_id": "a1b2c3d4",
     "created": "<iso>", "data": "<base64 of 32 bytes>"}

Vault file format (JSON, 0600):
    {"format": "burhan-vault/1", "org": "...", "created": "<iso>",
     "revision": 7,
     "kdf": {"salt": "<b64>"},
     "keys": [{"key_id": "...", "label": "designer", "added": "<iso>",
               "actor": "<key_id|init>"}],
     "wraps": [{"key_id": "...", "nonce": "<b64>", "ct": "<b64>",
                "tag": "<b64>"}],
     "blob": {"nonce": "<b64>", "ct": "<b64>", "tag": "<b64>"}}
where each wrap = ChaCha20-Poly1305 AEAD under wrap_key(keyfile, salt) over
the 32-byte blob key K, and blob = ChaCha20-Poly1305 AEAD under enc_key(K)
over the JSON payload {records: [...], audit: [...]} (library AEAD since
2026-10-30; tags are 16-byte Poly1305 — files written by the previous
hand-rolled ChaCha20+HMAC scheme no longer decrypt).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
import time
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VAULT_FORMAT = "burhan-vault/1"
KEY_FORMAT = "burhan-vault-key/1"
MASK_STARS = "********"


class VaultError(Exception):
    """Refused operation — wrong key, tampered file, unauthorized access."""


# ============================================================ authenticated AEAD
# 2026-10-30: the hand-rolled ChaCha20 stream cipher + separate
# HMAC-SHA256 MAC (encrypt-then-MAC) were replaced by the ChaCha20Poly1305
# AEAD primitive from the cryptography library (pyca) — one audited call
# instead of hand-assembled parts. The storage envelope keeps the
# {nonce, ct, tag} shape, but the tag is now the 16-byte Poly1305 tag
# (was a 32-byte HMAC tag), so vault files written by the previous
# implementation fail authentication explicitly and can no longer be
# decrypted. The RFC 8439 §2.8.2 known-answer vector for this AEAD is
# pinned in crypto_selftest() (called by the doctor) and in
# tests/test_vault_aead_rfc8439.py. The domain-separated subkey
# derivation (_derive, stdlib hmac) is unchanged — it is not a
# hand-rolled primitive.


def _derive(master: bytes, label: str) -> bytes:
    """Domain-separated subkey derivation from the 256-bit blob key."""
    return hmac.new(master, f"burhan-vault/1/{label}".encode(),
                    hashlib.sha256).digest()


def aead_encrypt(master: bytes, aad: str, plaintext: bytes) -> dict:
    """AEAD under the enc subkey of `master`. Returns {nonce, ct, tag}."""
    nonce = os.urandom(12)
    ct_tag = ChaCha20Poly1305(_derive(master, "enc")).encrypt(
        nonce, plaintext, aad.encode())
    return {"nonce": nonce, "ct": ct_tag[:-16], "tag": ct_tag[-16:]}


def aead_decrypt(master: bytes, aad: str, envelope: dict) -> bytes:
    """Verify-then-decrypt. ANY tamper (ct, tag, aad, truncation) -> VaultError."""
    try:
        nonce, ct, tag = envelope["nonce"], envelope["ct"], envelope["tag"]
    except (KeyError, TypeError):
        raise VaultError("malformed envelope")
    if not (isinstance(nonce, bytes) and isinstance(ct, bytes)
            and isinstance(tag, bytes)):
        raise VaultError("malformed envelope")
    try:
        return ChaCha20Poly1305(_derive(master, "enc")).decrypt(
            nonce, ct + tag, aad.encode())
    except InvalidTag:
        raise VaultError("authentication failed: wrong key or tampered data")


# RFC 8439 §2.8.2 — the official AEAD known-answer vector, verbatim.
_KAT_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f")
_KAT_NONCE = bytes.fromhex("070000004041424344454647")
_KAT_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
_KAT_PT = (b"Ladies and Gentlemen of the class of '99: If I could offer "
           b"you only one tip for the future, sunscreen would be it.")
_KAT_EXPECTED = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "61161ae10b594f09e26a7e902ecbd0600691")


def crypto_selftest() -> None:
    """Known-answer test: RFC 8439 §2.8.2 through the very AEAD primitive
    used for storage — any drift raises VaultError (the doctor calls this)."""
    aead = ChaCha20Poly1305(_KAT_KEY)
    got = aead.encrypt(_KAT_NONCE, _KAT_PT, _KAT_AAD)
    if got != _KAT_EXPECTED:
        raise VaultError("RFC 8439 2.8.2 AEAD known-answer mismatch")
    if aead.decrypt(_KAT_NONCE, got, _KAT_AAD) != _KAT_PT:
        raise VaultError("RFC 8439 2.8.2 AEAD roundtrip failed")


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    """Decode envelope base64. TAMPER HARDENING (2026-10-31, order 2.5): a
    corrupted/tampered vault file previously escaped as a raw binascii.Error
    (ugly traceback, unclassified) — every malformed-envelope path now fails
    closed as VaultError("malformed envelope"), the documented refusal."""
    import binascii
    try:
        return base64.b64decode(s)
    except (binascii.Error, ValueError) as e:
        raise VaultError(f"malformed envelope: {type(e).__name__}") from e

# ============================================================ key files

def keygen(path: str, label: str = "") -> dict:
    """Create a new authorized key file (32 random bytes, 0600). The key never
    lives in code or Git — only in this file, for the operator to hand to an
    authorized party (tool designer / organization owner)."""
    data = os.urandom(32)
    key_id = hashlib.sha256(data).hexdigest()[:8]
    payload = {"format": KEY_FORMAT, "key_id": key_id, "label": label,
               "created": _now(), "data": _b64e(data)}
    _write_private_json(path, payload)
    return payload


def load_key(path: str) -> tuple[str, bytes]:
    """Load + validate a key file. Returns (key_id, 32-byte key material).

    KEY-FILE PERMISSION GATE (2026-10-31, order 2.5): the vault file was
    already refused when group/world-readable, but the KEY file — which
    holds the actual master material — was not. Same doctrine now: a key
    file with group/world bits is refused (expected 0600, as keygen writes).

    TOCTOU HARDENING (2026-10-31, order item 1.5): the path is resolved
    ONCE and the permission check runs on the OPEN descriptor
    (_open_private_json) — the stat-then-reopen window that a
    same-directory writer could race is gone.
    """
    kf = _open_private_json(path, "key file")
    if kf.get("format") != KEY_FORMAT:
        raise VaultError(f"not a burhan vault key file: {path}")
    data = _b64d(kf.get("data", ""))
    if len(data) != 32:
        raise VaultError("key file corrupted: key must be 32 bytes")
    key_id = hashlib.sha256(data).hexdigest()[:8]
    if key_id != kf.get("key_id"):
        raise VaultError("key file corrupted: key_id does not match key data")
    return key_id, data


def _wrap_key_for(key_data: bytes, salt: bytes) -> bytes:
    """Per-vault wrap key: binds the key file's material to THIS vault's salt,
    so a wrap cannot be transplanted into another vault file."""
    return hmac.new(key_data, salt + b"|wrap", hashlib.sha256).digest()


# ============================================================ helpers

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_private_json(path: str, obj: dict) -> None:
    """Atomic, 0600 write (temp file in the same dir + os.replace)."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".vault-tmp-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(obj, fh, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _open_private_json(path: str, what: str) -> dict:
    """TOCTOU-hardened open + permissions gate (owner order 2026-10-31, item 1.5).

    The path is resolved ONCE; permissions are checked with fstat() on the
    OPEN descriptor and the JSON is read from THAT descriptor — what was
    checked is exactly what is read. The previous gate stat'ed the path and
    then opened the path AGAIN by name: a same-directory writer could race
    the window (stat sees the legit 0600 file, open reads the attacker's
    0644 file) — proven live by scripts/attack_vault_toctou.py (1 bypass in
    a 20-second real two-process race, pre-fix).

    O_NOFOLLOW (where the platform provides it) additionally refuses
    symlinked vault/key files.

    R17-3 (Windows, fail-closed): Windows has no POSIX permission model
    — every file reports mode 0o666 regardless of its real NTFS ACL, so
    the mode-bit check below would reject EVERY key/vault file with a
    misleading "permissions 0o666" message (verified live on Windows 11:
    os.chmod(p, 0o600) leaves the reported mode at 0o666). The gate is
    NOT silently skipped — that would downgrade a real security
    guarantee — and NOT left lying. It fails closed with the true
    situation: vault unsupported on Windows pending a genuine
    ACL-based check (issue #61).
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise VaultError(f"{what} unreadable: {e}")
    try:
        st = os.fstat(fd)
        if os.name == "nt":
            raise VaultError(
                f"refusing {path}: the vault's permission gate is POSIX "
                f"mode-bit based and Windows does not model that (every "
                f"file reports 0o666 regardless of its NTFS ACL). The "
                f"vault is UNSUPPORTED on Windows pending a real "
                f"ACL-based permission check — see issue #61")
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise VaultError(
                f"refusing {path}: permissions {oct(mode)} are group/world "
                f"accessible (expected 0600) — chmod it first")
        if not stat.S_ISREG(st.st_mode):
            raise VaultError(f"refusing {path}: not a regular file")
        with os.fdopen(fd, "r") as fh:
            fd = -1  # ownership transferred to the file object
            return json.load(fh)
    except ValueError as e:
        raise VaultError(f"{what} unreadable: invalid JSON: {e}")
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


# ============================================================ the vault

class Vault:
    """An opened credential vault. All mutations rewrite the file atomically
    with a fresh nonce and an incremented revision."""

    def __init__(self, path: str, key_id: str, key_data: bytes,
                 envelope: dict, blob_key: bytes, payload: dict):
        self.path = path
        self.key_id = key_id                     # acting identity (audit actor)
        self.key_data = key_data
        self._envelope = envelope
        self._blob_key = blob_key                # 32 bytes, in-memory only
        self._payload = payload or {"records": [], "audit": []}

    # ------------------------------------------------------------ properties
    @property
    def org(self) -> str:
        return self._envelope.get("org", "")

    @property
    def revision(self) -> int:
        return int(self._envelope.get("revision", 0))

    def status(self) -> dict:
        return {"org": self.org, "format": VAULT_FORMAT,
                "revision": self.revision,
                "created": self._envelope.get("created"),
                "records": len(self._payload["records"]),
                "authorized_keys": [{"key_id": k["key_id"], "label": k.get("label", "")}
                                    for k in self._envelope.get("keys", [])],
                "audit_entries": len(self._payload["audit"])}

    # ------------------------------------------------------------ open/init
    @classmethod
    def init(cls, path: str, key_file: str, org: str, label: str = "designer") -> "Vault":
        """Create a new vault for `org`, authorized to `key_file`."""
        if os.path.exists(path):
            raise VaultError(f"vault already exists: {path}")
        key_id, key_data = load_key(key_file)
        salt = os.urandom(16)
        blob_key = os.urandom(32)
        envelope = {"format": VAULT_FORMAT, "org": org, "created": _now(),
                    "revision": 0, "kdf": {"salt": _b64e(salt)},
                    "keys": [{"key_id": key_id, "label": label,
                              "added": _now(), "actor": "init"}],
                    "wraps": [], "blob": None}
        v = cls(path, key_id, key_data, envelope, blob_key,
                {"records": [], "audit": []})
        v._audit("INIT", "-", f"vault created for org={org}")
        v._save(initial=True)
        return v

    @classmethod
    def open(cls, path: str, key_file: str) -> "Vault":
        """Open + unlock a vault with an authorized key file.

        TOCTOU HARDENING (item 1.5): the vault file is opened and
        permission-checked through ONE descriptor (_open_private_json),
        same as the key file.
        """
        envelope = _open_private_json(path, "vault")
        if envelope.get("format") != VAULT_FORMAT:
            raise VaultError(f"not a burhan vault file: {path}")
        key_id, key_data = load_key(key_file)
        wrap = next((w for w in envelope.get("wraps", [])
                     if w.get("key_id") == key_id), None)
        if wrap is None:
            raise VaultError(
                f"key {key_id} is not authorized for this vault "
                f"(authorized: {[k['key_id'] for k in envelope.get('keys', [])]})")
        salt = _b64d(envelope["kdf"]["salt"])
        wk = _wrap_key_for(key_data, salt)
        aad = f"{VAULT_FORMAT}|wrap|key={key_id}"
        try:
            blob_key = aead_decrypt(wk, aad, cls._env_of(wrap))
        except VaultError:
            raise VaultError(f"unlock failed for key {key_id}: "
                             f"wrong key file or tampered wrap")
        v = cls(path, key_id, key_data, envelope, blob_key, None)
        v._payload = v._decrypt_blob()
        return v

    @staticmethod
    def _env_of(w: dict) -> dict:
        return {"nonce": _b64d(w["nonce"]), "ct": _b64d(w["ct"]),
                "tag": _b64d(w["tag"])}

    # ------------------------------------------------------------ crypto I/O
    def _blob_aad(self) -> str:
        return f"{VAULT_FORMAT}|org={self.org}|revision={self.revision}"

    def _decrypt_blob(self) -> dict:
        blob = self._envelope.get("blob")
        if not blob:
            raise VaultError("vault has no encrypted blob")
        raw = aead_decrypt(self._blob_key, self._blob_aad(), self._env_of(blob))
        try:
            payload = json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            raise VaultError("vault blob corrupted after authentication")
        if payload.get("org") != self.org:
            raise VaultError(
                f"org mismatch: file says org={self.org!r}, blob says "
                f"{payload.get('org')!r} — transplanted vault rejected")
        return payload

    def _save(self, initial: bool = False,
              extra_wraps: dict | None = None) -> None:
        """Rewrite the vault atomically: fresh nonce, revision+1, re-wrapped
        blob key for every authorized key."""
        self._envelope["revision"] = self.revision + (0 if initial else 1)
        payload = dict(self._payload)
        payload["org"] = self.org            # org binding INSIDE the ciphertext
        plaintext = json.dumps(payload, separators=(",", ":")).encode()
        self._envelope["blob"] = {
            k: _b64e(v) for k, v in aead_encrypt(self._blob_key,
                                                 self._blob_aad(), plaintext).items()}
        salt = _b64d(self._envelope["kdf"]["salt"])
        self._envelope["wraps"] = self._rewrap(salt, extra_wraps or {})
        _write_private_json(self.path, self._envelope)

    def _rewrap(self, salt: bytes, extra_wraps: dict) -> list[dict]:
        """Build the wrap list for every authorized key. Our own key gets a
        FRESH wrap (we hold its material); keys just authorized via
        `extra_wraps` use the wrap created with THEIR material at authorize
        time; all other existing wraps are copied verbatim — the blob key they
        wrap is unchanged, so they remain valid."""
        wraps: list[dict] = []
        old = {w["key_id"]: w for w in self._envelope.get("wraps", []) or []}
        for k in self._envelope.get("keys", []):
            kid = k["key_id"]
            if kid == self.key_id:
                aad = f"{VAULT_FORMAT}|wrap|key={kid}"
                env = aead_encrypt(_wrap_key_for(self.key_data, salt),
                                   aad, self._blob_key)
                wraps.append({"key_id": kid,
                              **{kk: _b64e(vv) for kk, vv in env.items()}})
            elif kid in extra_wraps:
                wraps.append(extra_wraps[kid])
            elif kid in old:
                wraps.append(old[kid])          # untouched wrap, still valid
            else:
                raise VaultError(
                    f"cannot wrap for key {kid}: its key file was not provided "
                    f"and no prior wrap exists (authorize it explicitly)")
        return wraps

    # ------------------------------------------------------------ audit
    def _audit(self, action: str, target: str, detail: str = "") -> None:
        self._payload["audit"].append({"ts": _now(), "actor": self.key_id,
                                       "action": action, "target": target,
                                       "detail": detail[:200]})

    # ------------------------------------------------------------ records
    def store(self, cls: str, raw: str, source: dict, severity: str = "high",
              verification: str = "") -> str:
        """Capture a credential: encrypt raw into the blob, return record id.
        Idempotent per (cls, masked, url): repeat observations increment hits."""
        from .secrets import mask
        masked = mask(raw)
        url = (source or {}).get("url", "")
        for rec in self._payload["records"]:
            if (rec["cls"], rec["masked"], rec["source"].get("url", "")) == \
                    (cls, masked, url):
                rec["hits"] = int(rec.get("hits", 1)) + 1
                rec["last_seen"] = _now()
                self._audit("STORE", rec["id"],
                            f"re-observed {cls} {masked} (hits={rec['hits']})")
                self._save()
                return rec["id"]
        rid = "rec-" + os.urandom(4).hex()
        rec = {"id": rid, "cls": cls, "masked": masked, "raw": raw,
               "severity": severity, "source": source or {},
               "first_seen": _now(), "last_seen": _now(), "hits": 1,
               "verification": verification}
        self._payload["records"].append(rec)
        self._audit("STORE", rid, f"{cls} {masked} from {url}")
        self._save()
        return rid

    def capture_callback(self, run_id: str, url: str
                         ) -> Callable[..., str | None]:
        """The hook handed to SecretsScanner:
        (cls, raw, location, request_id, severity) -> record id. Raw values
        flow STRAIGHT into the vault — never into findings, events, logs or
        stats."""
        def _capture(cls: str, raw: str, location: str, request_id: str,
                     severity: str = "high") -> str:
            return self.store(cls, raw,
                              {"run_id": run_id, "url": url,
                               "location": location, "request_id": request_id},
                              severity=severity,
                              verification="re-test:fresh-fetch-reexposure")
        return _capture

    def list(self) -> list[dict]:
        """Masked listing — the public view. Raw values NEVER leave here."""
        self._audit("LIST", "-", f"{len(self._payload['records'])} records")
        self._save()
        return [{k: rec[k] for k in
                 ("id", "cls", "masked", "severity", "source", "first_seen",
                  "last_seen", "hits", "verification")}
                for rec in self._payload["records"]]

    def export(self, record_id: str) -> dict:
        """Authenticated reveal of ONE record (audited first)."""
        rec = self._find(record_id)
        self._audit("EXPORT", record_id, f"revealed {rec['cls']} {rec['masked']}")
        self._save()
        return rec

    def report(self) -> dict:
        """Owner-only Credential Exposure report: full reveal of every record.
        Audited. Marked CONFIDENTIAL — hand only to the organization owner."""
        recs = [dict(r) for r in self._payload["records"]]
        self._audit("REPORT", "-", f"owner reveal report, {len(recs)} records")
        self._save()
        return {"format": "burhan-credential-report/1",
                "classification": "CONFIDENTIAL — organization owner only",
                "org": self.org, "generated": _now(),
                "records": recs}

    def audit(self) -> list[dict]:
        """Read the audit trail (read-only, not itself audited)."""
        return list(self._payload["audit"])

    def purge(self, record_id: str | None = None, all_records: bool = False
              ) -> int:
        """🗑️ Shred records: the blob is rewritten WITHOUT the values (fresh
        nonce + new ciphertext). The audit entry proves the destruction."""
        if all_records:
            n = len(self._payload["records"])
            self._payload["records"] = []
            self._audit("PURGE", "-", f"shredded ALL {n} records")
            self._save()
            return n
        rec = self._find(record_id)
        self._payload["records"].remove(rec)
        self._audit("PURGE", record_id, f"shredded {rec['cls']} {rec['masked']}")
        self._save()
        return 1

    def _find(self, record_id: str) -> dict:
        rec = next((r for r in self._payload["records"]
                    if r["id"] == record_id), None)
        if rec is None:
            raise VaultError(f"no such record: {record_id}")
        return rec

    # ------------------------------------------------------------ key mgmt
    def authorize(self, new_key_file: str, label: str = "") -> str:
        """Add a second authorized key (e.g. the organization owner's). The
        wrap for the new key is created with ITS key material; the audit entry
        records who authorized whom."""
        key_id, new_key_data = load_key(new_key_file)
        if any(k["key_id"] == key_id for k in self._envelope["keys"]):
            raise VaultError(f"key {key_id} is already authorized")
        self._envelope["keys"].append({"key_id": key_id, "label": label,
                                       "added": _now(), "actor": self.key_id})
        salt = _b64d(self._envelope["kdf"]["salt"])
        aad = f"{VAULT_FORMAT}|wrap|key={key_id}"
        env = aead_encrypt(_wrap_key_for(new_key_data, salt),
                           aad, self._blob_key)
        pending = {"key_id": key_id,
                   **{kk: _b64e(vv) for kk, vv in env.items()}}
        self._audit("AUTHORIZE", key_id, f"authorized new key label={label!r}")
        self._save(extra_wraps={key_id: pending})
        return key_id

    def revoke(self, key_id: str) -> None:
        """Remove an authorized key AND rotate the blob key (re-encrypt every
        remaining wrap with a FRESH blob key) — a revoked key must not open
        any copy of the vault file. All validation happens BEFORE any state
        mutation: a refused revoke leaves the session exactly as it was."""
        keys = list(self._envelope["keys"])
        if not any(k["key_id"] == key_id for k in keys):
            raise VaultError(f"no such authorized key: {key_id}")
        if key_id == self.key_id:
            raise VaultError("cannot revoke the key currently in use")
        remaining = [k["key_id"] for k in keys if k["key_id"] != key_id]
        others = [k for k in remaining if k != self.key_id]
        if others:
            raise VaultError(
                "revocation with other authorized keys present requires their "
                "key files to re-wrap (pass each remaining --key-file); "
                "refusing to weaken the vault")
        self._envelope["keys"] = [k for k in keys if k["key_id"] != key_id]
        # rotate: fresh blob key, then re-wrap for the only remaining key (us)
        self._blob_key = os.urandom(32)
        self._audit("REVOKE", key_id, "revoked; blob key rotated")
        self._save()

    # ------------------------------------------------------------ scrubbing
    def known_raws(self) -> list[str]:
        return [r["raw"] for r in self._payload["records"] if r.get("raw")]

    def scrub(self, obj: Any) -> Any:
        """Defense in depth: replace any known raw value inside an arbitrary
        report structure (dict/list/str) with '********'."""
        raws = self.known_raws()
        if not raws:
            return obj

        def _s(x):
            if isinstance(x, str):
                for r in raws:
                    if r and r in x:
                        x = x.replace(r, MASK_STARS)
                return x
            if isinstance(x, dict):
                return {k: _s(v) for k, v in x.items()}
            if isinstance(x, list):
                return [_s(v) for v in x]
            return x
        return _s(obj)
