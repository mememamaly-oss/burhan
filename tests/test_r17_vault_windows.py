"""R17-3: the vault's permission gate on Windows — fail closed, loudly.

RED (the pre-fix behavior this test pins): on Windows every file reports
POSIX mode 0o666 (there is no Unix permission model — stat mode bits do
not reflect NTFS ACLs), so `_open_private_json` rejected EVERY key/vault
file with a misleading `permissions 0o666` message. The vault was fully
unusable on Windows AND the message lied about why.

The Round-17 decision (fail-closed, issue #61): on Windows the gate does
NOT silently weaken (skipping the check would downgrade a real security
guarantee) and does NOT keep lying. It raises a VaultError that states
the true situation: the POSIX mode check is meaningless on Windows, the
vault is unsupported there pending a real NTFS-ACL check (issue #61).

The simulation is platform-portable so Linux CI proves the CONTRACT too:
`_SIM_NT` patches os.name to "nt" and st_mode to a group/world-readable
0o666 — exactly what Windows stat reports — and the test asserts the
explicit unsupported-message (not the old misleading permission refusal,
not a silent pass). The POSIX branch keeps its own pins: 0644 rejected,
0600 accepted, with the real filesystem.
"""
import os
import stat
import sys
import json
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from burhan.vault import VaultError, _open_private_json  # noqa: E402


def _write_private(path, payload=None):
    payload = payload or {"k": "v"}
    Path(path).write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


class _SimWindowsStat:
    """os.stat result wrapper presenting the Windows reality: mode 0o666
    regardless of the file's actual restrictions."""

    def __init__(self, real_st):
        self._real = real_st

    def __getattr__(self, name):
        return getattr(self._real, name)

    @property
    def st_mode(self):
        return 0o100666  # regular file + 0o666 — what Windows stat reports


def test_windows_mode_rejection_is_explicit_not_misleading(tmp_path, monkeypatch):
    """THE contract: on a simulated Windows stat (0o666 for everything),
    the gate must say 'unsupported pending ACL' — not the old
    'permissions 0o666' refusal that blamed the operator."""
    p = _write_private(tmp_path / "k.json")
    monkeypatch.setattr(os, "name", "nt")
    real_fstat = os.fstat

    def win_fstat(fd):
        return _SimWindowsStat(real_fstat(fd))

    monkeypatch.setattr(os, "fstat", win_fstat)
    with pytest.raises(VaultError) as ei:
        _open_private_json(str(p), "key file")
    msg = str(ei.value)
    assert "Windows" in msg and "ACL" in msg, (
        f"the Windows rejection must state the real situation (unsupported "
        f"pending an ACL check, issue #61), got: {msg!r}")
    assert "issue #61" in msg
    # the OLD lie must be gone: no 'chmod it first' advice on Windows —
    # chmod CANNOT fix a mode the filesystem does not model
    assert "chmod" not in msg


def test_posix_branch_still_enforces_mode_bits(tmp_path):
    """The fix must not weaken the POSIX guarantee: a group/world-readable
    file (0o644) is still rejected on the POSIX path, a 0600 file still
    passes. Real filesystem, no simulation."""
    p = _write_private(tmp_path / "k.json")
    # 0600 passes on POSIX (on real Windows this branch is unreachable —
    # the nt branch raises first; that split is itself asserted above)
    if os.name != "nt":
        assert _open_private_json(str(p), "key file") == {"k": "v"}
    os.chmod(p, 0o644)
    if os.name != "nt":
        with pytest.raises(VaultError) as ei:
            _open_private_json(str(p), "key file")
        assert "0o644" in str(ei.value)
        assert "chmod" in str(ei.value)


def test_posix_gate_unchanged_for_world_readable(tmp_path):
    """Anchor: 0o666 on a REAL POSIX filesystem is still refused with the
    actionable message (kills the mutant where the Windows fix accidentally
    accepts group/world-readable files everywhere)."""
    if os.name == "nt":
        pytest.skip("POSIX mode-bit semantics do not exist on Windows — "
                    "the nt branch raises before this assertion could "
                    "mean anything here")
    p = _write_private(tmp_path / "k.json")
    os.chmod(p, 0o666)
    with pytest.raises(VaultError) as ei:
        _open_private_json(str(p), "key file")
    assert "0o666" in str(ei.value)
    assert "chmod" in str(ei.value)
    os.chmod(p, 0o600)
