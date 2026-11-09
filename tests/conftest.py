"""Shared pytest configuration — put the repo root on sys.path so the
`burhan` package imports cleanly."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# R19-2b: the engine's scan path gates on the owner password BEFORE its
# first request. Many suites drive `python -m burhan.cli scan` as a REAL
# subprocess (honest-exit codes, SIGINT/SIGTERM mid-scan, SSRF refusals,
# the browser-phase interrupt) and assert engine behavior PAST the gate —
# without a gate store they all die at exit 2 before doing anything.
# Session-wide throwaway store + password, exported so every spawned CLI
# inherits it. The gate's own refusal contract is tested ISOLATED in
# tests/test_r19_owner_cli.py, whose runner strips these two variables
# from the child env before each invocation (run_cli) — the session
# defaults never leak into the gate's negative tests.
if "BURHAN_OWNER_GATE" not in os.environ:
    import secrets as _secrets
    import tempfile
    _gate_dir = tempfile.mkdtemp(prefix="burhan-test-owner-gate-")
    _gate_path = os.path.join(_gate_dir, "gate.json")
    _gate_pw = _secrets.token_urlsafe(24)
    try:
        from burhan.owner_gate import OwnerGate
        OwnerGate.setup(_gate_path, _gate_pw)
        os.environ["BURHAN_OWNER_GATE"] = _gate_path
        os.environ["BURHAN_OWNER_PASSWORD"] = _gate_pw
    except Exception:  # noqa: BLE001 — never break collection
        os.environ.pop("BURHAN_OWNER_GATE", None)
        os.environ.pop("BURHAN_OWNER_PASSWORD", None)
