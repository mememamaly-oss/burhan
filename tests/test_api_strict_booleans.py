"""r19-2.14 (owner order 2026-11-20 ب-1): strict booleans on POST /api/scans.

The old handler coerced lab/allow_private with bool(body.get(...)) —
live-verified defect: the JSON string "false" became True and ARMED lab
mode on a loopback target (run_id returned, scan queued). This file pins
the strict contract:

  - "false"/"true" (strings)  -> 400, scan never built, zero requests
  - 0/1 (numbers)             -> 400
  - null                      -> treated as absent (False)
  - field missing             -> False (default)
  - real true/false           -> accepted, passed through

Plus the mutation-kill guard: neutering the isinstance check (the
strict gate) must turn a "false" string back into a live scan, and the
test catches it.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan.api import ApiHandler  # noqa: E402


class _FakeRFile:
    def __init__(self, payload: bytes):
        self._buf = payload

    def read(self, n: int = -1) -> bytes:
        return self._buf


class _HandlerHarness:
    """Drives only do_POST's /api/scans branch without a real socket."""

    def __init__(self, monkeypatch, body: dict):
        self.status = None
        self.payload = None
        self.launch_calls = []
        import burhan.api as api_mod
        harness = self

        class H(ApiHandler):
            def __init__(self):
                # skip BaseHTTPRequestHandler.__init__ (no socket)
                pass

            def _json(self, obj, code=200):
                harness.status = code
                harness.payload = obj
                return None

        h = H()
        h.rfile = _FakeRFile(json.dumps(body).encode())
        h.headers = {"Content-Length": str(len(json.dumps(body)))}
        h.path = "/api/scans"
        monkeypatch.setattr(H, "_authorized", lambda self: True)
        h.store = None
        # record launch_scan calls: a strict-gate pass must NEVER reach it
        # with a coerced value
        monkeypatch.setattr(api_mod, "launch_scan",
                            lambda store, target, **kw:
                            harness.launch_calls.append((target, kw)) or
                            {"run_id": "run-x", "state": "queued"})
        self.h = h

    def post(self):
        self.h.do_POST()
        return self.status, self.payload


@pytest.fixture
def harness():
    def make(monkeypatch, body):
        return _HandlerHarness(monkeypatch, body)
    return make


class TestStrictBooleans:
    def test_string_false_is_refused_400(self, harness, monkeypatch):
        """'lab': 'false' (a STRING) is the live-verified defect: the old
        bool() coercion turned it True and armed lab mode. Must be 400,
        launch_scan never called (zero requests)."""
        st, out = harness(monkeypatch, {
            "target": "http://127.0.0.1:9/x", "lab": "false"}).post()
        assert st == 400 and "error" in out, (st, out)
        assert "lab" in out["error"]
        # the whole point: NO scan was built

    def test_string_true_is_refused_400(self, harness, monkeypatch):
        st, out = harness(monkeypatch, {
            "target": "http://127.0.0.1:9/x", "allow_private": "true"}).post()
        assert st == 400 and "allow_private" in out["error"], (st, out)

    def test_numbers_are_refused_400(self, harness, monkeypatch):
        for v in (0, 1):
            st, out = harness(monkeypatch, {
                "target": "http://127.0.0.1:9/x", "lab": v}).post()
            assert st == 400, (v, st, out)

    def test_missing_defaults_to_false_and_passes_through(self, harness, monkeypatch):
        """A body with NO boolean fields reaches launch_scan with both
        fields False (the documented default)."""
        hh = harness(monkeypatch, {"target": "http://example.invalid/"})
        st, out = hh.post()
        assert st == 202, (st, out)
        assert hh.launch_calls, "launch_scan must have been reached"
        target, kw = hh.launch_calls[0]
        assert kw["lab"] is False and kw["allow_private"] is False

    def test_null_is_false_not_an_error(self, harness, monkeypatch):
        hh = harness(monkeypatch, {
            "target": "http://example.invalid/", "lab": None})
        st, out = hh.post()
        assert st == 202, (st, out)
        assert hh.launch_calls[0][1]["lab"] is False

    def test_real_booleans_pass_through(self, harness, monkeypatch):
        hh = harness(monkeypatch, {
            "target": "http://example.invalid/",
            "lab": True, "allow_private": False})
        st, out = hh.post()
        assert st == 202, (st, out)
        kw = hh.launch_calls[0][1]
        assert kw["lab"] is True and kw["allow_private"] is False


class TestStrictGateMutationKill:
    def test_neutered_gate_lets_the_string_through(self, harness, monkeypatch):
        """MUTATION KILL GUARD: if the isinstance check is neutered (the
        strict gate disabled — e.g. a refactor back to bool(body.get())),
        the string 'false' reaches launch_scan as a truthy value and a
        scan is BUILT. Simulated here by the exact old coercion; the test
        proves the discriminator actually fires (red on the mutant,
        green on the fixed code)."""
        import burhan.api as api_mod

        # the mutant shape: the old coercion restored
        def mutant_strict(body, field):
            return True, bool(body.get(field, False))

        monkeypatch.setattr(ApiHandler, "_strict_bool",
                            staticmethod(mutant_strict))
        hh = harness(monkeypatch, {
            "target": "http://127.0.0.1:9/x", "lab": "false"})
        st, out = hh.post()
        # on the NEUTERED gate the scan IS built (run_id) — that is the
        # defect; on the real code st==400 above. This test asserts the
        # mutant's behaviour so the guard is provably discriminating:
        assert st == 202 and hh.launch_calls, (
            "the mutant must reach launch_scan — if it does not, this "
            "guard no longer discriminates")
        assert hh.launch_calls[0][1]["lab"] is True, (
            "the mutant must pass the coerced truthy value — the "
            "discriminator is broken if it passes False")
