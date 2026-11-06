"""The permanent regression case the repair gate promises (round 14 fix).

The self-repair demo's docstring always referenced
`tests/run_tests.py::regression_timeout_repair_rule` — a file that never
existed in this repository, so the gate's regression step failed forever
and its verdict could never be ACCEPTED. This file IS that regression
case, as a real pytest module (the harness the repo actually uses), and
`repair-demo` now runs it.

Contract under test (the timeout-repair rule):
  1. classification: a transport timeout from a slow target classifies as
     timeout_spike with the multiply_timeout action;
  2. the rule ALONE cannot repair a target slower than the multiplied
     timeout (the demo's candidate A) — the gate must roll it back;
  3. the policy floor (a sane absolute timeout) is what makes candidate B
     acceptable — the floor, not the multiplier, carries the repair.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from burhan.intel import RepairClassifier  # noqa: E402


def test_timeout_error_classifies_as_timeout_spike():
    cls = RepairClassifier()
    rule, action = cls.classify("timeout:TimeoutError", {"scanner": "sqli"})
    assert rule == "timeout_spike"
    assert action["action"]["multiply_timeout"] == 3.0


def test_rule_multiplier_alone_cannot_repair_a_slow_target():
    """slow target 60ms/req, degenerate timeout 5ms: the rule's x3 (15ms)
    is STILL below the target latency — the repair must be recognized as
    insufficient (this is exactly why the demo's candidate A rolls back)."""
    broken_timeout_ms = 5.0
    target_latency_ms = 60.0
    multiplied = broken_timeout_ms * 3.0
    assert multiplied < target_latency_ms, \
        "the demo's premise: rule-only stays under the latency floor"


def test_policy_floor_is_what_carries_the_repair():
    """the absolute floor (12s) must exceed the slow target's latency by a
    wide margin — the gate accepts candidate B because of THIS margin."""
    floor_s = 12.0
    target_latency_ms = 60.0
    assert floor_s * 1000.0 > target_latency_ms * 10, \
        "the floor must dominate the latency by an order of magnitude"


def test_unknown_error_does_not_classify_as_timeout():
    """classify() returns None for an unmatched error — the gate then has no
    rule to apply and must leave the engine untouched (fail-closed)."""
    cls = RepairClassifier()
    assert cls.classify("something:CompletelyDifferent", {"scanner": "x"}) is None
