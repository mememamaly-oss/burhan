"""Round-8 pins — anti-pattern sweep + authorized-target registry gate.

R8-AP-01: jrand.uniquifier_relation_solve no longer swallows numpy RUNTIME
failures into a silent [] — the pre-fix code returned [] on a broken numpy
module (indistinguishable from "no relation"); the fixed code propagates the
error to the phase-level failure ledger. numpy ABSENCE stays a loud
WeakRandRelationUnavailable via the FM-21d gate.
"""
import importlib
import sys
import types

import pytest

from burhan import jrand
from burhan.core import Endpoint, Parameter, ParamLocation, ParamKind


def _ep(url, method="GET", params=None):
    ep = Endpoint(url=url, method=method)
    if params:
        ep.parameters = params
    return ep


def test_r8ap01_solver_runtime_failure_is_loud(monkeypatch):
    """Behavior contract pin (regression guard): numpy that breaks at
    ATTRIBUTE USE (import succeeds, np.uint64 explodes) must PROPAGATE —
    this pins the never-swallow contract against anyone re-wrapping the
    solver body in a blanket try/except."""
    broken = types.ModuleType("numpy")

    def _boom(name):
        raise RuntimeError("numpy broken at runtime (install corrupted)")

    broken.__getattr__ = _boom
    monkeypatch.setitem(sys.modules, "numpy", broken)

    # numpy_available() honestly reports True: import of the cached module
    # object succeeds — the breakage is at USE time, past the probe's reach
    assert jrand.numpy_available() is True

    with pytest.raises(RuntimeError, match="numpy broken at runtime"):
        jrand.uniquifier_relation_solve(0x123456789ABC, 0xDEF012345678,
                                       1000, 2000, window=64)


def test_r8ap01_solver_import_failure_is_loud(monkeypatch):
    """RED->BLUE discriminator: numpy that fails AT IMPORT (corrupted
    install, ABI mismatch — import itself raises). The PRE-FIX solver
    caught the ImportError and returned [] — a direct API caller read a
    broken solver as a clean 'no relation' negative. The fixed solver
    PROPAGATES the ImportError; absence handling stays with the loud
    numpy_available() gate upstream (FM-21d)."""
    monkeypatch.setitem(sys.modules, "numpy", None)
    assert jrand.numpy_available() is False

    with pytest.raises(ImportError):
        jrand.uniquifier_relation_solve(0x123456789ABC, 0xDEF012345678,
                                       1000, 2000, window=64)


def test_r8ap01_solver_still_solves_when_numpy_is_healthy():
    """The healthy path is unchanged: the searched fixture pair from the
    FM-21b pin still yields the true solution among the returned list."""
    sols = jrand.uniquifier_relation_solve(0x79B9D458B121, 0xE6FD1BBFA6ED,
                                           2870136116, 2870140212,
                                           window=1 << 23)
    assert sols, "healthy numpy must keep solving the relation"
    # the forward-confirmable solution (u1 whose two-step advance decodes
    # the third sample) is in the returned set — not merely 'a' solution
    true_u1 = 133837600675897
    assert any(u1 == true_u1 for u1, _t1, _t2 in sols), sols[:3]
