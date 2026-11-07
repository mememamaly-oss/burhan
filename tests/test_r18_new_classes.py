"""R18 PART 1: the seven new permanent scanner classes.

Each test re-introduces the EXACT bug shape into a temp module and
asserts the consolidated scanner catches it (RED-side proof: the
walker exists and fires on the defect), plus the paired BLUE-side
proof: the real tree passes the gate with these classes live (that is
the CI gate itself, run in the engine job).

The calibration truth each class was wired with (honesty, not victory
claims): MUTABLE_DEFAULT_ARG and NAIVE_DATETIME found ZERO live
instances — they land as tripwires for new code, exactly like
ENTRYPOINT_UNREACHABLE did in round 12 for shapes already fixed. The
classes with live hits (UNENCODED_READ x5, BARE_EXCEPT_REBIND x1 real,
FLOAT_EQUALITY x2, UNBOUNDED_GROWTH x1, WINDOWS_RESERVED_NAME x4)
were hand-reviewed: real ones fixed in this commit, benign ones
ledgered with specific reasons (see scripts/quantum_sweep_ledger.json,
ids r18-*).
"""
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.audit_quantum_sweep as aqs  # noqa: E402


def _scan_module(tmp_path, body, name="sample.py"):
    # engine-scoped walkers (UNENCODED_READ/WRITE, like r17-7) only fire
    # for burhan/** and src/** paths — write the temp module under a
    # burhan/ dir so the scan path matches the real scope contract
    d = tmp_path / "burhan"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text(textwrap.dedent(body), encoding="utf-8")
    # absolute path: read as-is, and the 'burhan/' leading segment keeps
    # the engine-scope walkers active exactly as in a real scan
    return [h for h in aqs.scan_py(str(f))]


def test_mutable_default_arg_caught(tmp_path):
    hits = _scan_module(tmp_path, """
        def collect(items=[]):
            items.append(1)
            return items
        """)
    assert any(h.cls == "MUTABLE_DEFAULT_ARG" for h in hits), \
        [h.cls for h in hits]


def test_float_equality_caught(tmp_path):
    hits = _scan_module(tmp_path, """
        def done(score):
            return score == 0.5
        """)
    assert any(h.cls == "FLOAT_EQUALITY" for h in hits), \
        [h.cls for h in hits]


def test_float_equality_literal_pair_not_flagged(tmp_path):
    """literal == literal is a constant-fold, not a computed compare."""
    hits = _scan_module(tmp_path, """
        def cfg(x):
            return x if x == 3 else 2
        """)
    assert not any(h.cls == "FLOAT_EQUALITY" for h in hits)


def test_bare_except_rebind_caught(tmp_path):
    hits = _scan_module(tmp_path, """
        def load(p):
            try:
                return parse(p)
            except ValueError:
                raise LoadError("bad input")
        """)
    assert any(h.cls == "BARE_EXCEPT_REBIND" for h in hits), \
        [h.cls for h in hits]


def test_rebind_with_cause_embedded_not_flagged(tmp_path):
    """raise New(f"...{e}") keeps the cause in-band — not lossy."""
    hits = _scan_module(tmp_path, """
        def load(p):
            try:
                return parse(p)
            except ValueError as e:
                raise LoadError(f"bad input: {e}")
        """)
    assert not any(h.cls == "BARE_EXCEPT_REBIND" for h in hits)


def test_rebind_with_from_not_flagged(tmp_path):
    """raise New(...) from e keeps the chain — not lossy."""
    hits = _scan_module(tmp_path, """
        def load(p):
            try:
                return parse(p)
            except ValueError as e:
                raise LoadError("bad input") from e
        """)
    assert not any(h.cls == "BARE_EXCEPT_REBIND" for h in hits)


def test_unbounded_growth_caught(tmp_path):
    hits = _scan_module(tmp_path, """
        _LOG = []

        def record(ev):
            _LOG.append(ev)
        """)
    assert any(h.cls == "UNBOUNDED_GROWTH" for h in hits), \
        [h.cls for h in hits]


def test_local_growth_not_flagged(tmp_path):
    """a local list dies with the frame — no unbounded lifetime."""
    hits = _scan_module(tmp_path, """
        def build(n):
            out = []
            for i in range(n):
                out.append(i)
            return out
        """)
    assert not any(h.cls == "UNBOUNDED_GROWTH" for h in hits)


def test_windows_reserved_name_caught(tmp_path):
    hits = _scan_module(tmp_path, """
        def dump(d, rid):
            open(f"{d}/run-{rid}.json", "w", encoding="utf-8").write("{}")
        """)
    assert any(h.cls == "WINDOWS_RESERVED_NAME" for h in hits), \
        [h.cls for h in hits]


def test_naive_datetime_caught(tmp_path):
    hits = _scan_module(tmp_path, """
        import datetime

        def stamp(rec):
            rec["t"] = datetime.now()
        """)
    assert any(h.cls == "NAIVE_DATETIME" for h in hits), \
        [h.cls for h in hits]


def test_aware_datetime_not_flagged(tmp_path):
    hits = _scan_module(tmp_path, """
        import datetime

        def stamp(rec):
            rec["t"] = datetime.now(datetime.timezone.utc)
        """)
    assert not any(h.cls == "NAIVE_DATETIME" for h in hits)


def test_unencoded_read_caught(tmp_path):
    hits = _scan_module(tmp_path, """
        def load(p):
            return open(p).read()
        """)
    assert any(h.cls == "UNENCODED_READ" for h in hits), \
        [h.cls for h in hits]


def test_encoded_read_not_flagged(tmp_path):
    hits = _scan_module(tmp_path, """
        def load(p):
            return open(p, encoding="utf-8").read()
        """)
    assert not any(h.cls == "UNENCODED_READ" for h in hits)


def test_binary_read_not_flagged(tmp_path):
    hits = _scan_module(tmp_path, """
        def load(p):
            return open(p, "rb").read()
        """)
    assert not any(h.cls == "UNENCODED_READ" for h in hits)
