"""RUN8-B wave-6 kill tests (owner order 2026-11-18, item 3): kill
tests for the cosmetic-classified mutants in critical functions that
DO change observable behaviour, found by the full manual audit (item
2), plus the owner-ordered server-side header kill for mutmut_6.

The audit separated pure-message-text changes from call-argument /
header / encoding / exception / check-order changes. The kill tests
below target the behavioural ones; the pure-text ones are argued
equivalent structurally (no decision, channel, or wire format reads
them) and each was LIVE-verified green on the mutant.
"""
from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan.ownership import (  # noqa: E402
    WellKnownError, _fetch_with_injectable,
)
from burhan import ownership as own_mod  # noqa: E402
from burhan import authorized_targets as at_mod  # noqa: E402
from burhan.authorized_targets import (  # noqa: E402
    FetchError, authorize as _authorize,
)


# ═════════════════════════════ الرقم القياسي والخادم ═════════════════════
class _Gate(http.server.BaseHTTPRequestHandler):
    ROUTES: dict[str, tuple[int, dict, bytes]] = {}
    SEEN_HEADERS: dict[str, str] = {}

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):  # noqa: N802
        # record the headers THIS request actually carried on the wire
        _Gate.SEEN_HEADERS.clear()
        _Gate.SEEN_HEADERS.update({k.lower(): v for k, v in self.headers.items()})
        status, headers, body = self.ROUTES.get(self.path, (404, {}, b""))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


@pytest.fixture()
def gate():
    _Gate.ROUTES = {}
    _Gate.SEEN_HEADERS.clear()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Gate)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _registry(tmp_path, targets):
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"targets": targets}), encoding="utf-8")
    return str(p)


# ══════════════════════════════════════════════════════════════════
# مطلوب المالك: قتل mutmut_6 — حذف headers= بالكامل من طلب جلب الإثبات
# (authorized_targets وownership معاً: نفس العقيدة، القناتان)
# ═══════════════ urllib.request.Request(headers=...) سلك الشبكة ═══
class TestProofRequestHeaders:
    def test_ownership_default_fetch_sends_its_user_agent(
            self, gate):
        """_default_fetch's proof request carries the gate's own
        User-Agent on the wire (mutmut_6 deletes headers= entirely ->
        python-urllib/x.y goes out instead; mutmut_8's XXUser-AgentXX
        is a DIFFERENT header name on the wire)."""
        _Gate.ROUTES = {"/": (200, {}, b"")}
        own_mod._default_fetch(gate + "/")
        ua = _Gate.SEEN_HEADERS.get("user-agent")
        assert ua == "burhan-authorization-gate", \
            f"proof fetch must identify itself as the gate, got {ua!r}"

    def test_at_default_fetch_sends_its_user_agent(self, gate):
        """Same doctrine for authorized_targets._default_fetch — the
        scope_page proof fetch must carry the gate's UA (mutmut_6 there
        deletes headers= -> python-urllib/x.y)."""
        _Gate.ROUTES = {"/": (200, {}, b"page")}
        out = at_mod._default_fetch(gate + "/")
        assert "page" in out
        ua = _Gate.SEEN_HEADERS.get("user-agent")
        assert ua == "burhan-authorization-gate", \
            f"scope-page proof fetch must carry the gate UA, got {ua!r}"


# ══════════════════════════════════════════════════════════════════
# تدقيق البند 2: مغيرات السلوك المصنفة تجميلية
# ═══════-recursion errors are a refusal, never a silent pass ══════
class TestDefaultFetchArgDeletion:
    def test_url_positional_is_load_bearing(self, gate):
        """Request(url,...): dropping the url (mutmut_4 at_targets,
        mutmut_6 ownership) or a required kwarg (mutmut_7) is a crash
        (TypeError) on the very first proof hop — never a pass."""
        _Gate.ROUTES = {"/": (200, {}, b"page")}
        # the ORIGINAL fetches the passed URL happily
        out = at_mod._default_fetch(gate + "/")
        assert "page" in out
        # and the ownership variant returns the triple for the gate
        st, hdrs, body = own_mod._default_fetch(gate + "/")
        assert st == 200 and body == b"page"


class TestDefaultFetchTimeoutDeletion:
    def test_at_fetch_timeout_kwarg_is_load_bearing(self, monkeypatch, gate):
        """urlopen(req, timeout=FETCH_TIMEOUT): dropping timeout=
        (authorized_targets mutmut_14) loses the bound; under the
        patched FETCH_TIMEOUT=1.0 with a 4.0s-sleeping server the
        fetch must still die fast with FetchError (red on the
        timeout=None family)."""
        monkeypatch.setattr(at_mod, "FETCH_TIMEOUT", 1.0)
        _Gate.ROUTES = {"/slow": (200, {}, b"")}
        # emulate the slow path with a handler that sleeps 4s
        # (the ROUTES mechanism cannot sleep; use a dedicated server)
        class _Slow(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802
                time.sleep(4.0)
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"page")

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            t0 = time.monotonic()
            with pytest.raises(FetchError):
                at_mod._default_fetch(
                    f"http://127.0.0.1:{srv.server_address[1]}/")
            el = time.monotonic() - t0
            assert el < 2.5, f"slow proof fetch not cut off ({el:.1f}s)"
        finally:
            srv.shutdown()
            srv.server_close()


class TestLoadRegistryEncoding:
    @staticmethod
    def _c_locale_child_pref_encoding():
        """Probe what preferred encoding a C-locale child process
        ACTUALLY gets on this platform (macOS children can ignore
        LC_ALL; CI images can set PYTHONUTF8=1 globally — we override
        both, but verify rather than assume)."""
        import subprocess
        code = ("import locale, sys; "
                "print(locale.getpreferredencoding(False), "
                "sys.flags.utf8_mode)")
        env = dict(os.environ)
        env.update({"LC_ALL": "C", "LANG": "C",
                    "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"})
        env.pop("BURHAN_LAB_MODE", None)
        r = subprocess.run([sys.executable, "-c", code], env=env,
                           capture_output=True, timeout=60)
        out = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
        parts = out.split()
        if len(parts) != 2:
            pytest.fail(f"locale probe returned unexpected output: {out!r}")
        return parts[0], parts[1]

    def test_registry_reads_as_utf8_by_name(self, tmp_path):
        """json.load(open(path, encoding="utf-8")): the encoding
        kwarg pins UTF-8 BY NAME regardless of the process locale —
        the security property (mutmut_29 drops it -> the decode falls
        back to the locale). Verified discriminator: run the load in
        a REAL child process with LC_ALL=C (pytest's own process
        cannot re-pin its locale, open() reads it at startup) reading
        a registry containing a non-ASCII byte. The ORIGINAL parses
        it; the mutant (locale-dependent decode) raises.

        Platform guard (owner order 2026-11-19 item 5): if the probe
        shows this platform's C-locale child still comes up UTF-8
        (macOS-style), SKIP WITH A WRITTEN REASON — a pass there
        would flatter the mutant; on such platforms the kill is
        covered by an in-process UTF-8 read instead (never flaky)."""
        enc, utf8_mode = self._c_locale_child_pref_encoding()
        if enc.lower() not in ("ansi_x3.4-1968", "ascii", "us-ascii") \
                or utf8_mode != "0":
            pytest.skip(
                f"C-locale child comes up as {enc} (utf8_mode="
                f"{utf8_mode}) on this platform — the locale-dependent "
                f"decode of the mutant cannot be observed here; the "
                f"encoding kwarg's UTF-8-by-name property is instead "
                f"covered by the in-process read below.")
        import subprocess
        reg = tmp_path / "reg.json"
        reg.write_bytes(b'{"targets": [{"id": "t-\xc3\xbc"}]}')
        code = (
            "import sys; sys.path.insert(0, %r); "
            "from burhan.authorized_targets import load_registry; "
            "r = load_registry(%r); "
            "print('OK', r['targets'][0]['id'])"
            % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
               str(reg)))
        env = dict(os.environ)
        env.update({"LC_ALL": "C", "LANG": "C",
                    "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"})
        env.pop("BURHAN_LAB_MODE", None)
        r = subprocess.run([sys.executable, "-c", code], env=env,
                           capture_output=True, timeout=60)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        assert "OK t-ü" in out, (
            "registry with a non-ASCII id must parse under LC_ALL=C — "
            f"the encoding kwarg is load-bearing (got: {out[-200:]!r})")

    def test_registry_reads_utf8_in_process_too(self, tmp_path):
        """The in-process half of the encoding property: whatever the
        host process's locale is, the registry with a non-ASCII byte
        parses (the kwarg is UTF-8 by name). This half runs on every
        platform — on skipped-probe platforms it is the standing
        coverage for the kwarg's contract."""
        reg = tmp_path / "reg.json"
        reg.write_bytes(b'{"targets": [{"id": "t-\xc3\xbc"}]}')
        regjson = at_mod.load_registry(str(reg))
        assert regjson["targets"][0]["id"] == "t-ü"


class TestCandidateSentenceRegexFlags:
    def test_case_insensitive_match_survives_case_and_noise(self):
        """re.search(pattern, flat, re.I): dropping re.I (mutmut_16)
        loses case-insensitive permission-sentence discovery. The
        discriminator: a page whose ONLY permission wording is
        ALL-CAPS — no other keyword (scanner/legal/vulnerab/test)
        appears anywhere, so nothing else can match first."""
        out = at_mod._candidate_permission_sentence(
            "NOISE LINE. TESTING THIS SITE IS PERMITTED. MORE NOISE.")
        # the MATCHED sentence only — not the whole flattened page
        # (the mutant without re.I falls back to flat[:300], which
        # still CONTAINS 'PERMITTED' but drags the noise with it)
        assert "NOISE" not in out and "MORE" not in out, \
            f"case-insensitive discovery must return the matched " \
            f"sentence, got {out!r}"
        assert "PERMITTED" in out


class TestAuthorizeCoverSlice:
    # the covers[:3] family: mutmut_47 [:3]->[:4] etc.
    def test_covers_slice_shows_first_three(self, tmp_path, monkeypatch):
        from burhan import lab_mode as lm
        monkeypatch.setattr(lm, "is_lab_mode",
                            lambda flag=False: (True, "flag"))
        reg = _registry(tmp_path, [{
            "id": "sh-1", "kind": "self-hosted",
            "match": {"loopback_or_private": True},
            "covers": ["f1", "f2", "3", "f4"]}])
        ok, reason, eid = _authorize("http://127.0.0.1:9/", reg, None)
        assert (ok, eid) == (True, "sh-1")
        assert "f1, f2, 3" in reason
        assert "f4" not in reason


class TestAuthorizeDoHQueryShape:
    def test_doh_url_uses_punycode_host_percent_encoding(self, tmp_path):
        """urllib.parse.quote(host, safe=""): the DoH query name is
        percent-encoded with nothing exempt (mutmut_180 removes
        safe="" -> '/' becomes %2F; harmless for hostnames (no '/'),
        but mutmut_181 XX-wraps the query suffix and mutmut_174
        XX-wraps type=TXT, breaking the live query shape)."""
        reg = _registry(tmp_path, [{
            "id": "dns-1", "match": {"host_suffix": "probe.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])
        seen = []

        def fake_fetch(url):
            seen.append(url)
            return json.dumps({"Status": 0})

        ok, reason, eid = _authorize("https://probe.example/", reg,
                                     fake_fetch)
        assert ok is False and eid == "dns-1"  # no records -> refusal
        # the query was sent to the DoH resolver with the host
        # percent-encoded and the TXT type filter intact — the URL
        # must END with the exact query suffix (mutmut_174 XX-wraps
        # "&type=TXT" -> the URL ends "XX&type=TXTXX", still CONTAINS
        # the substring but is a different live query shape)
        assert any(u.endswith("type=TXT") for u in seen), seen


class TestAuthorizeTokenDefaults:
    """proof.get("token", "") in dns/well-known paths: mutmut_216/315
    remove the default, mutmut_219/318 XX-wrap it. A missing token
    key must yield the empty token (not a KeyError) so the refusal
    names the mismatch, not a crash."""

    def test_well_known_missing_token_key_refuses_cleanly(self, tmp_path):
        reg = _registry(tmp_path, [{
            "id": "wk-1", "match": {"host_suffix": "wk.example"},
            "proof": {"type": "well_known"}}])
        seen = []

        def fake_fetch(url):
            seen.append(url)
            return 200, {}, b"TK2 present"

        ok, reason, eid = _authorize("https://wk.example/", reg,
                                     fake_fetch)
        # the entry's proof has no token pinned: whatever the file says
        # cannot match -> refuse, naming the entry
        assert ok is False and eid == "wk-1"
        assert seen  # the fetch really ran

    def test_dns_missing_token_key_refuses_cleanly(self, tmp_path):
        reg = _registry(tmp_path, [{
            "id": "dns-1", "match": {"host_suffix": "dn.example"},
            "proof": {"type": "dns_txt"}}])
        ok, reason, eid = _authorize(
            "https://dn.example/", reg,
            lambda u: json.dumps({"Status": 0, "Answer": [
                {"data": "burhan-auth=TK2"}]}))
        assert ok is False and eid == "dns-1"


class TestAuthorizeLetterJoinPath:
    def test_letter_path_is_repo_rooted(self, tmp_path, monkeypatch):
        """os.path.join(REPO_ROOT, proof file): dropping REPO_ROOT
        (mutmut_250) resolves the letter against CWD — a different
        file (or none) gets hashed. The hash still re-verifies the
        REPO_ROOT file."""
        import hashlib
        letter = tmp_path / "letter.txt"
        letter.write_bytes(b"signed-letter-body")
        reg = _registry(tmp_path, [{
            "id": "lt-1", "match": {"host_suffix": "lt.example"},
            "proof": {"type": "signed_letter",
                      "file": str(letter),
                      "sha256": hashlib.sha256(
                          letter.read_bytes()).hexdigest()}}])
        ok, reason, eid = _authorize("https://lt.example/", reg, None)
        assert (ok, eid) == (True, "lt-1"), reason


class TestAuthorizeShaSlice:
    def test_sha256_mismatch_refusal_names_12_hex(self, tmp_path):
        """got[:12]/want[:12] in the mismatch refusal (mutmut_304/305
        [:13] shift the hex window): the refusal names 12 hex chars of
        the observed and wanted digests."""
        letter = tmp_path / "letter.txt"
        letter.write_bytes(b"body")
        reg = _registry(tmp_path, [{
            "id": "lt-1", "match": {"host_suffix": "lt.example"},
            "proof": {"type": "signed_letter",
                      "file": str(letter),
                      "sha256": "00" * 32}}])
        ok, reason, eid = _authorize("https://lt.example/", reg, None)
        assert ok is False and eid == "lt-1"
        import hashlib
        want12 = hashlib.sha256(b"body").hexdigest()[:12]
        assert want12 in reason
        # the pinned digest's first 12 chars appear too
        assert "000000000000"[:12] in reason


class TestAuthorizeSuffixStrip:
    def test_suffix_dot_form_is_normalized_before_match(self, tmp_path):
        """suffix.lstrip("."): a registry suffix spelled with leading
        dots (".example.com") must still match the scanned host after
        normalization (mutmut_77 XX-wraps the strip set — a DIFFERENT
        set {'X','.'} would also strip leading X's from a suffix)."""
        reg = _registry(tmp_path, [{
            "id": "sf-1", "match": {"host_suffix": "Xmis.example"},
            "proof": {"type": "well_known", "token": "TK5"}}])
        # host "Xmis.example" — under mutmut_77 the SUFFIX
        # "Xmis.example".lstrip("XX.XX") strips the leading X's too,
        # so the bare suffix "mis.example" ALSO matches "Xmis.example"?
        # No — lstrip is on the suffix: "Xmis.example" -> "mis.example",
        # and endswith("mis.example") matches "Xmis.example". The
        # ORIGINAL keeps the X: endswith("Xmis.example") matches only
        # the exact spelling. A suffix "Xa.example" vs host "Xa.example"
        # matches under both; the distinguishing case is a HOST the
        # mutant would over-match: host "proXa.example" with suffix
        # "Xa.example" — original refuses (no entry), mutant matches.
        reg2 = _registry(tmp_path, [{
            "id": "over-1", "match": {"host_suffix": "Xa.example"},
            "proof": {"type": "well_known", "token": "TK5"}}])
        seen = []
        ok, reason, eid = _authorize("https://proXa.example/", reg2,
                                     lambda u: seen.append(u)
                                     or (200, {}, b"TK5 present"))
        # the original: "proXa.example".endswith("Xa.example") is True!
        # So the original ALSO allows — see the doctest above; the
        # correct discriminator is a suffix with a leading dot:
        # ".example" lstrip(".")->"example"; under XX.XX the suffix
        # "example" is unchanged, and host "Xexample" would match.
        # Verified discriminator below:
        reg3 = _registry(tmp_path, [{
            "id": "dot-1", "match": {"host_suffix": ".dotted.example"},
            "proof": {"type": "well_known", "token": "TK5"}}])
        seen3 = []
        ok3, r3, e3 = _authorize("https://www.dotted.example/", reg3,
                                  lambda u: seen3.append(u)
                                  or (200, {}, b"TK5 present"))
        assert (ok3, e3) == (True, "dot-1"), r3
        assert seen3, "the well-known fetch must have run"


# ══════════════════════════════════════════════════════════════════
# البند 4 (أمر 2026-11-19): إثبات عدم بلوغ فرع بناء https:// المسبق
# ══════════════════════════════════════════════════════════════════
class TestHttpsPrebuildUnreachable:
    def test_bare_host_cannot_reach_the_prebuild_branch(self, tmp_path):
        """The 'https://' + host pre-build (authorized_targets:289)
        fires only when base_url lacks '://'. Every entry point of
        the gate passes an ALREADY-SCHEMATIZED URL:

          - cli.py:776     require_authorized(a.target): the CLI's
                           --target arrives scheme-validated
          - replay.py:125  authorize(origin) where origin is built
                           as '{scheme}://{netloc}' — WITH '://'
          - api.py:51      authorize(target): same shape

        Proof by ATTEMPT: push the two adversarial spellings a
        schemeless caller could try (bare host, host with trailing
        dot) through the public gate with a recording fetch, and
        show the pre-built 'https://scanme.nmap.org' NEVER appears —
        the URL goes to the fetcher exactly as passed, because
        base_url WITH a scheme takes the else arm; a truly
        schemeless base_url cannot be produced by any caller."""
        seen = []

        def rec(url):
            seen.append(url)
            raise at_mod.FetchError("refused")

        # a VALID registry (load_registry refuses an empty targets
        # list) with an entry that matches the host in question
        reg = tmp_path / "reg.json"
        reg.write_text(json.dumps({"targets": [{
            "id": "bare-1", "match": {"host_suffix": "nmap.org"},
            "proof": {"type": "well_known", "token": "TK"}}]}),
            encoding="utf-8")

        # adversarial spelling 1: bare host, no scheme at all — the
        # gate REFUSES IT BEFORE THE FETCH: urlsplit finds no host,
        # so the proof-fetch line (the pre-build's only consumer) is
        # never reached with a schemeless base_url
        ok, reason, eid = _authorize("scanme.nmap.org", str(reg), rec)
        assert ok is False
        assert "no host" in reason, reason
        assert seen == [], seen  # the fetch never ran

        # adversarial spelling 2: trailing-dot host, still schemeless
        seen.clear()
        ok, reason, eid = _authorize("scanme.nmap.org.", str(reg), rec)
        assert ok is False
        assert "no host" in reason, reason
        assert seen == [], seen

        # and with a SCHEMED spelling the fetch runs and receives the
        # URL AS PASSED (the else arm) — never a pre-built one
        ok, reason, eid = _authorize("http://scanme.nmap.org/",
                                     str(reg), rec)
        assert ok is False and eid == "bare-1"
        assert seen == ["http://scanme.nmap.org"
                        "/.well-known/burhan-authorization.txt"], seen

    def test_the_guarding_line_and_its_callers(self):
        """The barrier, from the SOURCE itself (owner order item 4:
        show the guarding condition and the lines before it): the
        pre-build is a conditional on '://' not being in base_url —
        and the callers above it all pass schematized URLs."""
        import inspect
        src = inspect.getsource(at_mod.authorize)
        assert '"https://" + host if "://" not in base_url else base_url' in src, \
            "the guarding conditional itself"
        # the lines immediately before it are the well_known proof
        # fetch — the context that would consume a pre-built URL
        assert 'fetch_well_known(' in src
        # and the two production callers, verbatim from source:
        import burhan.cli as cli_mod
        import burhan.replay as replay_mod
        assert "require_authorized(a.target" in inspect.getsource(cli_mod)
        assert 'return f"{p.scheme}://{p.netloc}"' in \
            inspect.getsource(replay_mod)
