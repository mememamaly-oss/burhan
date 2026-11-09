"""R19-2 — owner-password scan gate: acceptance tests.

The owner's order: scan execution controlled by the installation
owner's password; first-setup sets it; change requires the current
one; a sale transfers to the buyer's OWN password with no dependency
on the seller. Acceptance (measured, per the R19 rule — no claim
without evidence, no closed item without a measurable criterion):

  1. no scan without a passing gate (negative test)
  2. first setup enforces setting (no default/backdoor — negative test)
  3. change requires the current password (negative test)
  4. transfer: buyer installs their own password; the seller's is DEAD
     after the handover (negative test on the old credential)
  5. storage: scrypt verifier + salt, never plaintext, no embedded key
  6. no network use (code-level: module imports no network facility)
"""
from __future__ import annotations

import base64
import json
import sys

import pytest

from burhan.owner_gate import (
    GENESIS, OwnerGate, OwnerGateChainTampered, OwnerGateError,
    OwnerGateRateLimited, OwnerGateRequired, OwnerGateTransferError)


@pytest.fixture()
def store(tmp_path):
    return str(tmp_path / "owner-gate.json")


class TestFirstSetup:
    def test_setup_then_scan_passes(self, store):
        OwnerGate.setup(store, "owner-pass-1")
        ev = OwnerGate(store).unlock_scan("owner-pass-1")
        assert ev["ok"] is True and ev["action"] == "scan"

    def test_no_store_means_closed_no_default(self, store):
        # acceptance 2: nothing set -> refuse WITH the setup instruction
        with pytest.raises(OwnerGateRequired, match="owner init"):
            OwnerGate(store).unlock_scan("anything")
        with pytest.raises(OwnerGateRequired, match="owner init"):
            OwnerGate(store).unlock_scan("")          # no magic empty
        with pytest.raises(OwnerGateRequired, match="owner init"):
            OwnerGate(store).unlock_scan("admin")      # no magic default

    def test_weak_password_refused_nothing_written(self, store):
        with pytest.raises(OwnerGateError, match="8 characters"):
            OwnerGate.setup(store, "short")
        import os
        assert not os.path.exists(store)

    def test_setup_refuses_overwrite(self, store):
        OwnerGate.setup(store, "owner-pass-1")
        with pytest.raises(FileExistsError):
            OwnerGate.setup(store, "attacker-pass")   # no silent reset
        # and the original still works
        assert OwnerGate(store).unlock_scan("owner-pass-1")["ok"] is True


class TestScanGate:
    def test_wrong_password_refused(self, store):
        OwnerGate.setup(store, "owner-pass-1")
        with pytest.raises(OwnerGateRequired):
            OwnerGate(store).unlock_scan("wrong")
        # the refusal is IN the chain
        data = json.load(open(store))
        assert any(e.get("ok") is False for e in data["events"])

    def test_rate_limit_sliding_window(self, store):
        OwnerGate.setup(store, "owner-pass-1")
        g = OwnerGate(store, window_s=300, max_failures=3)
        for _ in range(3):
            with pytest.raises(OwnerGateRequired):
                g.unlock_scan("wrong")
        # acceptance: gate closed, no comparison even with the RIGHT pw
        with pytest.raises(OwnerGateRateLimited):
            g.unlock_scan("owner-pass-1")

    def test_tampered_trail_fail_closed(self, store):
        OwnerGate.setup(store, "owner-pass-1")
        data = json.load(open(store))
        data["events"][0]["detail"] = "edited by attacker"
        json.dump(data, open(store, "w"))
        with pytest.raises(OwnerGateChainTampered):
            OwnerGate(store).unlock_scan("owner-pass-1")


class TestChangePassword:
    def test_change_requires_current(self, store):
        # acceptance 3
        OwnerGate.setup(store, "owner-pass-1")
        with pytest.raises(OwnerGateRequired, match="current password"):
            OwnerGate(store).change_password("wrong", "new-pass-2")
        # failed change did not swap the verifier
        assert OwnerGate(store).unlock_scan("owner-pass-1")["ok"] is True

    def test_change_then_old_dead_new_works(self, store):
        OwnerGate.setup(store, "owner-pass-1")
        OwnerGate(store).change_password("owner-pass-1", "new-pass-2")
        with pytest.raises(OwnerGateRequired):
            OwnerGate(store).unlock_scan("owner-pass-1")
        assert OwnerGate(store).unlock_scan("new-pass-2")["ok"] is True


class TestOwnershipTransfer:
    def test_full_sale_buyer_independent(self, store):
        # acceptance 4: the buyer depends on neither the seller's
        # password nor their cooperation after the arm
        OwnerGate.setup(store, "seller-pass-1")
        g = OwnerGate(store)
        ticket = g.transfer_arm("seller-pass-1")
        g.transfer_take(ticket, "buyer-pass-1")
        # buyer scans with THEIR password
        assert OwnerGate(store).unlock_scan("buyer-pass-1")["ok"] is True
        # seller's password is DEAD
        with pytest.raises(OwnerGateRequired):
            OwnerGate(store).unlock_scan("seller-pass-1")

    def test_arm_requires_seller_password(self, store):
        OwnerGate.setup(store, "seller-pass-1")
        with pytest.raises(OwnerGateRequired, match="did not verify"):
            OwnerGate(store).transfer_arm("wrong")

    def test_ticket_single_use(self, store):
        OwnerGate.setup(store, "seller-pass-1")
        g = OwnerGate(store)
        ticket = g.transfer_arm("seller-pass-1")
        g.transfer_take(ticket, "buyer-pass-1")
        with pytest.raises(OwnerGateTransferError, match="already used"):
            g.transfer_take(ticket, "second-buyer")   # replay fails

    def test_ticket_expiry(self, store):
        OwnerGate.setup(store, "seller-pass-1")
        g = OwnerGate(store)
        ticket = g.transfer_arm("seller-pass-1")
        # force-expire the ticket in the store
        data = json.load(open(store))
        data["transfer"]["expires_ts"] = 0
        json.dump(data, open(store, "w"))
        with pytest.raises(OwnerGateTransferError, match="expired"):
            g.transfer_take(ticket, "buyer-pass-1")

    def test_wrong_ticket_fails(self, store):
        OwnerGate.setup(store, "seller-pass-1")
        g = OwnerGate(store)
        g.transfer_arm("seller-pass-1")
        with pytest.raises(OwnerGateTransferError, match="wrong handover"):
            g.transfer_take("forged-ticket", "buyer-pass-1")


class TestStorageAndNetwork:
    def test_verifier_only_no_plaintext(self, store):
        # acceptance 5: scrypt verifier + salt, never the password
        OwnerGate.setup(store, "owner-pass-1")
        raw = open(store, encoding="utf-8").read()
        assert "owner-pass-1" not in raw
        data = json.loads(raw)
        assert set(data) >= {"salt_b64", "verifier_b64", "chain_head"}
        salt = base64.b64decode(data["salt_b64"])
        import hashlib
        want = base64.b64decode(data["verifier_b64"])
        got = hashlib.scrypt(b"owner-pass-1", salt=salt,
                             n=2 ** 14, r=8, p=1, dklen=32)
        assert want == got          # it IS an scrypt digest of the pw

    def test_no_network_surface(self, store):
        # acceptance 6: the module imports no network facility
        import burhan.owner_gate as og
        src = open(og.__file__, encoding="utf-8").read()
        for banned in ("socket", "urllib", "http.client", "requests"):
            assert banned not in src, f"network facility in gate: {banned}"
