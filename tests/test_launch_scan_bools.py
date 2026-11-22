"""r19-2.20 (supervisor 2026-11-20 item 1أ): launch_scan enforces the
boolean contract ITSELF, not only do_POST.
RED (recorded live earlier): launch_scan(lab="false") STARTED a scan —
bool("false") is True armed lab mode. GREEN: non-boolean lab/allow_private
return the error payload BEFORE the gate or scanner construction."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import warnings
warnings.filterwarnings("ignore")


def test_launch_scan_refuses_string_lab():
    from burhan.api import launch_scan
    from burhan.store import Store
    import tempfile
    st = Store(str(Path(tempfile.mkdtemp()) / "s.db"))
    r = launch_scan(st, "http://127.0.0.1:59999", lab="false")
    assert "error" in r and "lab" in r["error"] and "str" in r["error"], r
    assert "run_id" not in r, "the scan must never start"


def test_launch_scan_refuses_string_allow_private():
    from burhan.api import launch_scan
    from burhan.store import Store
    import tempfile
    st = Store(str(Path(tempfile.mkdtemp()) / "s.db"))
    r = launch_scan(st, "http://127.0.0.1:59999", allow_private="true")
    assert "error" in r and "allow_private" in r["error"], r
    assert "run_id" not in r


def test_launch_scan_refuses_int_and_none():
    from burhan.api import launch_scan
    from burhan.store import Store
    import tempfile
    st = Store(str(Path(tempfile.mkdtemp()) / "s.db"))
    for bad in (1, 0, None):
        r = launch_scan(st, "http://127.0.0.1:59999", lab=bad)
        assert "error" in r, (bad, r)
        assert "run_id" not in r


def test_launch_scan_real_booleans_pass_the_contract():
    """True/False themselves are accepted (they reach the gate, whose
    refusal shape differs from the argument-error shape)."""
    from burhan.api import launch_scan
    from burhan.store import Store
    import tempfile
    st = Store(str(Path(tempfile.mkdtemp()) / "s.db"))
    r = launch_scan(st, "http://127.0.0.1:59999", lab=True)
    assert "invalid argument" not in str(r.get("error", "")), r
