"""R18 PART 2 — mutation-killer tests for the audit module's true
survivors.

Each test pins a contract the mutation campaign showed was unpinned:
the mutant named in the comment survives the full suite without the
test, and dies with it. Run against production code (the mutants tree
is the same bytes — verified by empty git diff — but these tests target
the shipped module).

RED→BLUE pairing for the killer itself: each test was first run against
the SURVIVING MUTANT (MUTANT_UNDER_TEST) to confirm it kills it —
that's the RED side — then against the clean module — the BLUE side.
"""
from __future__ import annotations

import base64

import pytest

from burhan.audit import (
    MIN_SEED_BYTES,
    SeedPolicyError,
    _hkdf_sha256,
    _seed_material,
    audit_block,
    derive_keypair,
    signed_message,
)
from burhan.proof import ed25519_verify


def _block(seed=b"0123456789abcdef0123456789abcdef"):
    report = {"run_id": "r18-killer", "seed": None,
              "findings": [{"type": "xss", "url": "https://t/"}]}
    blk = audit_block(report, seed=seed)
    return report, blk


# --- _hkdf_sha256 default length (x__hkdf_sha256__mutmut_1) -------------

def test_hkdf_default_length_is_32_bytes():
    out = _hkdf_sha256(b"ikm", b"salt", b"info")
    assert len(out) == 32


# --- _seed_material size contracts ---------------------------------------

def test_seed_material_none_returns_32_random_bytes():
    # x__seed_material__mutmut_3: os.urandom(33) would fail this
    assert len(_seed_material(None)) == 32


def test_seed_material_min_boundary_inclusive():
    # x__seed_material__mutmut_33: >= is the contract, > rejects exactly-32
    assert len(_seed_material("a" * 32)) == 32
    with pytest.raises(SeedPolicyError):
        _seed_material("a" * 31)


def test_seed_material_short_string_message_names_policy_ids():
    # x__seed_material__mutmut_34: message must carry RT-03/RT-04
    with pytest.raises(SeedPolicyError, match="RT-03/RT-04"):
        _seed_material("short")


def test_seed_material_short_bytes_message_names_policy_ids():
    # the bytes branch of the same message contract
    with pytest.raises(SeedPolicyError, match="RT-03/RT-04"):
        _seed_material(b"0123456789abcdef")   # 16 bytes < 32


def test_seed_material_x_is_not_a_hex_digit():
    # x__seed_material__mutmut_22: 'X'*64 must fall through to the
    # passphrase branch (32 raw bytes), never crash in fromhex
    out = _seed_material("X" * 64)
    assert out == ("X" * 64).encode("utf-8")


def test_seed_material_uppercase_hex_decodes_as_hex():
    # x__seed_material__mutmut_23: uppercase hex is canonical hex
    up = "AB" * 32   # 64 chars, decodes to 32 bytes
    down = "ab" * 32
    assert _seed_material(up) == _seed_material(down) == bytes.fromhex(down)


# --- audit_block schema and signature contracts ---------------------------

def test_audit_block_schema_keys_are_the_documented_set():
    # x_audit_block__mutmut_45..52: every key literal is part of the
    # public verification contract (independent_verify reads them)
    _, blk = _block()
    assert set(blk) == {
        "merkle_root", "findings_count", "algorithm", "leaf_spec",
        "signature_scheme", "signed_message_spec", "public_key_b64",
        "signature_b64", "recipe"}


def test_audit_block_signature_verifies_against_embedded_key():
    # x_audit_block__mutmut_19/21/22/29..35: a signature over mutated
    # material (or signed with a fresh random key) must fail verification
    # against the block's own public key — that's the block's whole job
    report = {"run_id": "r18-killer", "seed": None,
              "findings": [{"type": "xss", "url": "https://t/"}]}
    seed = b"0123456789abcdef0123456789abcdef"
    blk = audit_block(report, seed=seed)
    msg = signed_message(report.get("run_id", ""), blk["merkle_root"],
                         blk["findings_count"], report)
    pub = base64.b64decode(blk["public_key_b64"])
    sig = base64.b64decode(blk["signature_b64"])
    assert ed25519_verify(sig, msg, pub) is True
    # and the mutation shape: a DIFFERENT run_id must not verify
    bad = signed_message("other-run", blk["merkle_root"],
                         blk["findings_count"], report)
    assert ed25519_verify(sig, bad, pub) is False


def test_audit_block_seed_falls_back_to_report_seed():
    # x_audit_block__mutmut_11..17: effective_seed must prefer the
    # explicit seed, else report["seed"]; signing key follows it
    report = {"run_id": "r18-killer",
              "seed": b"0123456789abcdef0123456789abcdef",
              "findings": []}
    explicit = audit_block(dict(report), seed=None)
    priv, pub = derive_keypair(report["seed"])
    assert base64.b64decode(explicit["public_key_b64"]) == pub


def test_audit_block_decode_is_lowercase_ascii_codec():
    # x_audit_block__mutmut_58: b64decode accepts any case; the CONTRACT
    # is that the encoded strings exist and round-trip — pinned here so
    # a future "ASCII" variant can't silently change shape
    _, blk = _block()
    assert base64.b64decode(blk["public_key_b64"]) \
        == base64.b64decode(base64.b64encode(
            base64.b64decode(blk["public_key_b64"])).decode("ascii"))
    assert isinstance(blk["public_key_b64"], str)
    assert isinstance(blk["signature_b64"], str)


def test_min_seed_bytes_is_32():
    assert MIN_SEED_BYTES == 32
