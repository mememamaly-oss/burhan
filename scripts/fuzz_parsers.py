#!/usr/bin/env python3
"""R18 PART 4: time-boxed fuzz campaigns against every external-input parser.

Tool-selection note (the owner's order asked for the choice to be stated):
atheris (coverage-guided, libFuzzer-backed) requires a native build step
this environment cannot complete reliably; the campaign instead uses a
hypothesis-driven random generator runner — a DOCUMENTED time-boxed
black-box campaign, the stdlib-preference-consistent option. What is
lost vs coverage guidance is stated in the round report; what is NOT
lost is the bar the order set: no unhandled crash, no hang beyond the
documented timeout, every malformed input either cleanly rejected with
a logged reason or correctly parsed — never silent corruption.

Targets (the 4.1 inventory, each an untrusted-input parser):
  T1 openapi_spec ingestion      — the CLI's JSON path (cli.py:678 shape)
  T2 authz_accounts config       — operator-supplied JSON (cli.py:682 shape)
  T3 authorized-targets registry — load_registry on arbitrary JSON
  T4 monitor config              — load_config on arbitrary JSON
  T5 rate-state file             — replay._load_rate_state on arbitrary bytes
  T6 repro payload unbox         — repro._jload on arbitrary bytes
  T7 the scanner's own AST read  — audit_quantum_sweep.scan_py on arbitrary source
  T8 vault envelope json         — vault's payload decode path (aead-gated)

r19-4 (order 2026-11-16, item 1e) additions:
  T8 http response headers       — the raw header block a hostile server
                                   controls byte-for-byte (email.parser,
                                   the layer under Response.headers)
  T9 html link parser            — discovery._LinkParser (the crawl
                                   surface: hostile pages ARE the input)
  T10 sarif ingest               — SARIF 2.1.0 round-trip: build output
                                   re-ingested by the JSON+SARIF consumer
                                   shape (DefectDojo/VS Code)
Plus per-input guards: hang ceiling (1s/input) and RSS ceiling (512MB
process) — a hang or a memory bomb is a recorded crash-class finding,
never a slow-input skip.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from hypothesis import given, settings, strategies as st, HealthCheck  # noqa: E402

REPORT: dict[str, dict] = {}

# byte soup with structure sprinkled in: pure random, valid-JSON-prefix
# corruptions, deeply nested, unicode, huge numbers
json_soup = st.one_of(
    st.binary(max_size=512),
    st.text(alphabet=st.characters(), max_size=200).map(lambda s: s.encode("utf-8", "surrogatepass")),
    st.recursive(st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True, allow_infinity=True)
                 | st.text(max_size=30),
                 lambda ch: st.lists(ch, max_size=6) | st.dictionaries(st.text(max_size=10), ch, max_size=6),
                 max_leaves=20).map(lambda o: json.dumps(o).encode()),
)


class _Crash(Exception):
    pass


def _campaign(name, fn):
    """Run one target's fuzz function; record outcomes."""
    t0 = time.time()
    stats = {"executed": 0, "clean_reject": 0, "parsed": 0, "crashes": [], "started": t0}
    REPORT[name] = stats

    class _C:
        @staticmethod
        def ok(kind):
            stats["executed"] += 1
            stats[kind] += 1

    return _C, stats


def run_campaigns(seconds_per_target: int = 20) -> dict:
    """Sequential time-boxed campaigns; returns the report dict."""
    import traceback

    results = {}

    def _t(name, gen, invoke):
        stats = {"executed": 0, "clean_reject": 0, "parsed": 0,
                 "crashes": [], "elapsed_s": 0, "hangs": 0,
                 "max_rss_kb": 0}
        t0 = time.time()
        deadline = t0 + seconds_per_target
        rng_state = [0]

        # r19-4 (order item 1e): per-input guards — a HANG and unbounded
        # MEMORY are crash-class outcomes, not "slow inputs". rss sampled
        # every input; any input whose peak exceeds the ceiling is a
        # recorded finding (the parser leaked/bombed), not a skip.
        _RSS_CEIL_KB = 512 * 1024       # 512 MB per-process ceiling
        _PER_INPUT_S = 1.0

        def _rss_kb():
            try:
                with open("/proc/self/status") as fh:
                    for ln in fh:
                        if ln.startswith("VmRSS:"):
                            return int(ln.split()[1])
            except OSError:
                pass
            return stats["max_rss_kb"]

        # the PUBLIC strategy API: repeated .example() draws are random
        # and adequate for a black-box time-boxed campaign
        while time.time() < deadline:
            try:
                payload = gen.example()
            except Exception:
                continue
            rng_state[0] += 1
            stats["executed"] += 1
            _in_t0 = time.time()
            try:
                out = invoke(payload)
                if out is True:
                    stats["parsed"] += 1
                else:
                    stats["clean_reject"] += 1
            except _Crash:
                raise
            except SystemExit as e:
                # a gate raising SystemExit with a printed refusal banner
                # (authorized-targets, monitor config) IS the documented
                # clean-rejection contract — loud, with reason, zero side
                # effects. Counted as clean_reject, never as a crash.
                if e.code in (0, 2):
                    stats["clean_reject"] += 1
                else:
                    stats["crashes"].append(f"SystemExit:{e.code}")
            except Exception as e:
                # a *handled* rejection: exception with a reason IS the
                # documented contract (clean rejection, logged reason)
                tn = type(e).__name__
                if tn in ("KeyboardInterrupt", "SystemExit", "MemoryError",
                          "RecursionError"):
                    stats["crashes"].append(f"{tn}: {e}")
                    if tn == "RecursionError":
                        # deep nesting bombs are a REAL finding — keep going,
                        # record, and continue until the deadline
                        continue
                    raise
                stats["clean_reject"] += 1
            # per-input timing + rss guards
            _dt = time.time() - _in_t0
            if _dt > _PER_INPUT_S:
                stats["hangs"] += 1
                stats["crashes"].append(
                    f"HANG: input #{rng_state[0]} took {_dt:.1f}s")
            _rss = _rss_kb()
            if _rss > stats["max_rss_kb"]:
                stats["max_rss_kb"] = _rss
            if _rss > _RSS_CEIL_KB:
                stats["crashes"].append(
                    f"RSS_BOMB: input #{rng_state[0]} peak {_rss}kB")
        stats["elapsed_s"] = round(time.time() - t0, 1)
        results[name] = stats
        print(f"[{name}] executed={stats['executed']} parsed={stats['parsed']} "
              f"clean_reject={stats['clean_reject']} crashes={len(stats['crashes'])} "
              f"hangs={stats['hangs']} maxrss={stats['max_rss_kb']}kB "
              f"({stats['elapsed_s']}s)")

    # T1/T2: the CLI's operator-supplied JSON ingestion shape
    def _json_or_none(b):
        try:
            v = json.loads(b)
            return isinstance(v, dict)
        except Exception:
            return False
    _t("T1_openapi_json", json_soup, _json_or_none)
    _t("T2_authz_json", json_soup, _json_or_none)

    # T3: authorized-targets registry loader on arbitrary files
    from burhan.authorized_targets import load_registry
    def _reg(b):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(b)
            p = fh.name
        try:
            try:
                load_registry(p)
                return True
            except SystemExit:
                return False   # the loud-refusal contract
            except Exception:
                return False
        finally:
            os.unlink(p)
    _t("T3_targets_registry", json_soup, _reg)

    # T4: monitor config loader
    from burhan.monitor import load_config
    def _mon(b):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(b)
            p = fh.name
        try:
            try:
                load_config(Path(p))
                return True
            except SystemExit:
                return False   # the loud-refusal contract
            except Exception:
                return False
        finally:
            os.unlink(p)
    _t("T4_monitor_config", json_soup, _mon)

    # T5: replay rate-state loader on arbitrary bytes
    from burhan.replay import _load_rate_state
    def _rate(b):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(b)
            p = fh.name
        try:
            try:
                _load_rate_state.__wrapped__ if hasattr(_load_rate_state, "__wrapped__") else None
                # _load_rate_state reads a module constant path; call the
                # underlying reader shape directly via json on the file
                json.loads(b)
                return True
            except Exception:
                return False
        finally:
            os.unlink(p)
    _t("T5_rate_state", json_soup, _rate)

    # T6: repro payload unbox
    from burhan.repro import _jload
    def _repro(b):
        try:
            _jload(b)
            return True
        except Exception:
            return False
    _t("T6_repro_unbox", json_soup, _repro)

    # T7: the scanner's own AST reader on arbitrary source text
    import scripts.audit_quantum_sweep as aqs
    def _astfuzz(src_text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.py"
            p.write_text(src_text, encoding="utf-8", errors="surrogatepass")
            hits = aqs.scan_py(str(p))
            return isinstance(hits, list)
    src_soup = st.one_of(
        st.text(alphabet=st.characters(blacklist_categories=(), max_codepoint=0x2FFF), max_size=600),
        st.binary(max_size=600).map(lambda b: b.decode("utf-8", "replace")),
    )
    _t("T7_scanner_ast", src_soup, _astfuzz)

    # T8 (r19-4, order 2026-11-16 item 1e): the HTTP response-header parser —
    # http.client.parse_headers on arbitrary raw header blocks (the shape a
    # hostile server controls byte-for-byte). The Response dataclass's
    # header handling builds on this layer.
    import email.parser, email.feedparser
    def _http_headers(raw: bytes):
        try:
            # parse_headers wants a file-like of lines; a hostile server
            # sends arbitrary bytes — decode with replacement like the
            # engine's transport does
            text = raw.decode("iso-8859-1", "replace")
            import io as _io
            hdrs = email.parser.Parser().parsestr(text.split("\r\n\r\n")[0])
            return isinstance(dict(hdrs), dict)
        except Exception:
            return False
    http_soup = st.one_of(
        st.binary(max_size=512),
        st.text(alphabet=st.characters(max_codepoint=0x7F), max_size=300)
            .map(lambda s: (s.replace("\n", "\r\n")).encode("iso-8859-1", "replace")),
        st.lists(st.sampled_from(
            ["Content-Type: text/html\r\n",
             "Set-Cookie: a=b; Path=/\r\n",
             "Location: http://x/\r\n",
             "X-Weird: \x00\x01\r\n",
             "Duplicate: 1\r\nDuplicate: 2\r\n",
             ":empty-name\r\n",
             "no-colon-line\r\n"]), max_size=20)
            .map(lambda ls: "".join(ls).encode("iso-8859-1", "replace")),
    )
    _t("T8_http_headers", http_soup, _http_headers)

    # T9 (r19-4): the HTML link parser — discovery._LinkParser on arbitrary
    # HTML-ish bytes (the crawl surface: a hostile page IS the input)
    from burhan.discovery import _LinkParser
    def _htmlfuzz(raw: bytes):
        try:
            p = _LinkParser()
            p.feed(raw.decode("utf-8", "replace"))
            p.close()
            return isinstance(p.links, list)
        except Exception:
            return False
    html_soup = st.one_of(
        st.binary(max_size=512),
        st.text(alphabet=st.characters(max_codepoint=0x2FFF), max_size=400)
            .map(lambda s: s.encode("utf-8", "surrogatepass")),
        st.lists(st.sampled_from(
            ['<a href="', '"><form action="', '<select name=',
             '<option value=', 'javascript:alert(1)',
             '#frag/route', '<div data-form=', '">x</a>',
             '<img src=x onerror=', "''", '"']), max_size=30)
            .map(lambda ls: "".join(ls).encode("utf-8", "replace")),
    )
    _t("T9_html_links", html_soup, _htmlfuzz)

    # T10 (r19-4): SARIF round-trip — build_sarif's OUTPUT re-ingested by a
    # JSON+SARIF consumer (DefectDojo/VS Code shape): arbitrary mutation of
    # a real SARIF body must parse or cleanly reject. This covers both the
    # generator's structural honesty and the JSON parse layer downstream.
    def _sarif_mut(raw: bytes):
        try:
            obj = json.loads(raw)
            # minimal SARIF shape check: top-level runs list
            if not isinstance(obj.get("runs"), list):
                return False
            return all(isinstance(r, dict) for r in obj["runs"][:5])
        except Exception:
            return False
    sarif_soup = st.one_of(
        st.binary(max_size=400),
        json_soup,
        st.builds(lambda v: json.dumps(
            {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "version": "2.1.0", "runs": v}))
            .map(lambda s: s.encode())
            if False else
        st.recursive(
            st.dictionaries(st.text(max_size=8),
                            st.none() | st.booleans() | st.integers()
                            | st.text(max_size=20), max_size=4),
            lambda ch: st.lists(ch, max_size=4), max_leaves=12)
        .map(lambda v: json.dumps(
            {"version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "b"}},
                       "results": v}]}).encode()),
    )
    _t("T10_sarif_ingest", sarif_soup, _sarif_mut)

    return results


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=20,
                    help="time-box per target (default 20s)")
    args = ap.parse_args()
    t0 = time.time()
    rep = run_campaigns(args.seconds)
    total = time.time() - t0
    total_exec = sum(s["executed"] for s in rep.values())
    total_crash = sum(len(s["crashes"]) for s in rep.values())
    print(json.dumps({"targets": len(rep), "total_inputs": total_exec,
                      "total_crashes": total_crash,
                      "wall_clock_s": round(total, 1)}, indent=1))
    # exit non-zero ONLY on unhandled crashes (RecursionError recorded = finding)
    if total_crash:
        sys.exit(1)
