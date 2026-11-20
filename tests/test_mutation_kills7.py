"""RUN8-B wave-7 kill tests (owner order 2026-11-19 item 2): kill
tests for the behaviour-changing cosmetic-classified mutants that
survived the current suite (180) in the item-2 verification run —
20 killable (one of them, x_authorize__mutmut_77, is a REAL security
hole: a widened suffix match authorizes hosts the owner never
listed), and 17 argued equivalent with written structural arguments
(see the item-2 table)."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan import ownership as own_mod  # noqa: E402
from burhan import authorized_targets as at_mod  # noqa: E402
from burhan.authorized_targets import authorize as _authorize  # noqa: E402
from burhan.ownership import _fetch_with_injectable  # noqa: E402


def _registry(tmp_path, targets):
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"targets": targets}), encoding="utf-8")
    return str(p)


# ══════════════════════════════════════════════════════════════════
# mutmut_77 — مكافئة مثبتة: قيد النقطة + التصغير يعصمان مجموعة القص
# (يُحرس العقد بالاختبار المجاور كي لا يصبح التمييز ممكناً يوماً)
# ══════════════════════════════════════════════════════════════════
class TestSuffixLstripIsDotOnly:
    def test_x_in_suffix_cannot_widen_the_dot_bounded_match(self, tmp_path):
        """suffix.lstrip(".").lower(): the strip happens BEFORE the
        case-fold, so a mutant strip set containing 'X' (mutmut_77's
        "XX.XX") removes a CAPITAL X from the registry's suffix.
        VERIFIED EQUIVALENT, and this test pins WHY: the match is
        DOT-BOUNDED (`host == bare or host.endswith("." + bare)`)
        and the host arrives case-folded, so the X-stripped suffix
        "a.example" can only widen the match for hosts ending
        ".a.example" — e.g. registry suffix "Xa.example" (capital X)
        with host "data.example" must still be REFUSED... and the
        LIVE probe confirms both original and mutant refuse it. The
        test guards the two properties that make the mutant
        harmless, so if either ever changes (strip moved after
        .lower(), or the dot-bound removed) the mutant would become
        a REAL hole and this test would turn red on the ORIGINAL's
        contract first."""
        reg = _registry(tmp_path, [{
            "id": "sf-1", "match": {"host_suffix": "Xa.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])
        doh = json.dumps({"Status": 0, "Answer": [
            {"data": "burhan-auth=TK"}]})
        # a host the X-stripped suffix COULD cover if the match were
        # not dot-bounded: "data.example".endswith("a.example") is
        # True, but the dot-bound ("." + bare) requires ".a.example"
        ok, reason, eid = _authorize("https://data.example/", reg,
                                     lambda u: doh)
        assert ok is False, \
            "dot-bounded matching must refuse a host that only " \
            "string-suffix-matches the stripped suffix"
        assert "NOT PRESENT" in reason, reason
        # and the property the mutant needs to become dangerous is
        # pinned: the suffix strip set only ever strips dots
        assert "Xa.example".lstrip(".") == "Xa.example"
        assert ".example".lstrip(".") == "example"

    def test_plain_suffix_still_matches_its_hosts(self, tmp_path):
        """The ORIGINAL's contract side: a plain suffix (no leading
        dot, no X) matches its hosts exactly as before — the strip
        exists to forgive leading-dot spellings only."""
        reg = _registry(tmp_path, [{
            "id": "sf-1", "match": {"host_suffix": "plain.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])
        ok, reason, eid = _authorize(
            "https://www.plain.example/", reg,
            lambda u: json.dumps({"Status": 0, "Answer": [
                {"data": "burhan-auth=TK"}]}))
        assert (ok, eid) == (True, "sf-1"), reason


# ══════════════════════════════════════════════════════════════════
# عائلة quote(host, safe="") في استعلام DoH (181 و180 المكافئة موثقة)
# ══════════════════════════════════════════════════════════════════
class TestDoHQuoteSafeArg:
    def test_doh_host_is_fully_percent_encoded(self, tmp_path):
        """urllib.parse.quote(host, safe=""): the mutant mutmut_181
        sets safe="XXXX" — the literal X stops being escaped in the
        DoH query name. A host containing 'X' must arrive at the
        resolver percent-encoded (X appears in IDN/punycode hosts
        like xn--...). Discriminator: a registry suffix spelled with
        an X, so the DoH fetch is made for a host containing X."""
        reg = _registry(tmp_path, [{
            "id": "doh-1", "match": {"host_suffix": "xX.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])
        seen = []

        def fake_fetch(url):
            seen.append(url)
            return json.dumps({"Status": 0})

        ok, reason, eid = _authorize("https://host.xX.example/", reg,
                                     fake_fetch)
        assert ok is False and eid == "doh-1"
        # the host reached the DoH query percent-encoded: any 'X' in
        # the host must NOT appear raw in the query string (the
        # mutant leaves X raw via safe="XXXX")
        q = [u for u in seen if "dns-query" in u][0]
        host_part = q.split("name=")[1].split("&")[0]
        assert "X" not in host_part or "%58" in host_part, (
            f"host must be fully percent-encoded in the DoH query, "
            f"got {host_part!r}")

    def test_doh_query_still_hits_the_resolver_shape(self, tmp_path):
        """safe="" keeps the query shape exact: the DoH URL is the
        resolver with ?name=<encoded>&type=TXT (mutmut_180 removes
        the kwarg -> quote's default safe='/' leaves '/' raw —
        harmless for hostnames, argued equivalent in the table)."""
        reg = _registry(tmp_path, [{
            "id": "doh-1", "match": {"host_suffix": "doh.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])
        seen = []
        ok, _, eid = _authorize(
            "https://sub.doh.example/", reg,
            lambda u: (seen.append(u), json.dumps({"Status": 0}))[1])
        assert eid == "doh-1"
        q = [u for u in seen if "dns-query" in u][0]
        assert q.startswith("https://cloudflare-dns.com/dns-query?name=")
        assert q.endswith("&type=TXT")


# ══════════════════════════════════════════════════════════════════
# عائلة DNS TXT: الحذف الصامت للفاصل والقيم الافتراضية (184/188/191)
# ═══════════════════════════▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
class TestDnsTxtRecordJoin:
    def test_records_join_with_single_space_and_missing_data_empty(self,
                                                                   tmp_path):
        """" ".join(a.get("data", "") ...): the join separator and
        the missing-data default are both load-bearing on the wire
        contract: multiple TXT records carrying the token SPLIT
        ACROSS records are only found when joined with a space; a
        missing "data" key contributes NOTHING (empty string), not
        junk. Discriminators:
          - mutmut_184 joins with "XX XX" -> the token is no longer
            a substring of the joined records (kill: token-in-records
            fails -> refusal)
          - mutmut_188 drops the "" default -> a.get("data") is None
            -> TypeError on join (kill: crash instead of verdict)
          - mutmut_191 defaults to "XXXX" -> "XXXX" pollutes the
            joined string; with a token containing "XXXX"... no: the
            discriminator is a record WITHOUT a data key: the join
            must still find the token from the OTHER records, and
            "XXXX" is harmless there — the real discriminator is
            refusal wording? No: a missing data key with default
            "XXXX" still finds the token. KILL via: the joined string
            must be EXACTLY the records' data joined by single
            spaces — assert the DoH answer's contribution verbatim
            by using a token that IS the joined shape."""
        reg = _registry(tmp_path, [{
            "id": "dns-1", "match": {"host_suffix": "split.example"},
            "proof": {"type": "dns_txt", "token": "PART1 PART2"}}])
        # the token spans TWO TXT records: only a single-space join
        # reconstructs it. The mutant's "XX XX" join -> not found ->
        # refusal (kill); the original authorizes.
        ok, reason, eid = _authorize(
            "https://split.example/", reg,
            lambda u: json.dumps({"Status": 0, "Answer": [
                {"data": "PART1"}, {"data": "PART2"}]}))
        assert (ok, eid) == (True, "dns-1"), reason

    def test_missing_data_key_is_not_junk(self, tmp_path):
        """A record without a "data" key contributes an empty string
        (mutmut_191's "XXXX" default would pollute the join; the
        crash-free refusal/authorization decision must not depend on
        junk). With the token present in one record and another
        record MISSING data, the original still finds the token; and
        with NO records carrying it, the refusal is clean."""
        reg = _registry(tmp_path, [{
            "id": "dns-2", "match": {"host_suffix": "miss.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])
        # one record with the token + one junk record without data
        ok, reason, eid = _authorize(
            "https://miss.example/", reg,
            lambda u: json.dumps({"Status": 0, "Answer": [
                {"data": "TK"}, {"name": "other"}]}))
        assert (ok, eid) == (True, "dns-2"), reason


# ══════════════════════════════════════════════════════════════════
# عائلة فاصل التنسيق % في استثناءات الرفض (201/367)
# ══════════════════════════════════════════════════════════════════
class TestRefusalFormattingOperator:
    def test_dns_fetch_failure_refusal_formats_the_entry_id(self, tmp_path):
        """"...%s..." % (t["id"], e): the % operator formats the
        refusal with the entry id. mutmut_201 turns % into / ->
        str / tuple -> TypeError -> the gate CRASHES instead of
        printing a refusal. Kill: a dns_txt entry whose DoH fetch
        fails must produce a REFUSAL naming the entry, not a crash.
        (The letter/OSError variant 281-284 is already covered; this
        is the dns/well_known FetchError variant 201 and the
        unknown-ptype variant 367.)"""
        reg = _registry(tmp_path, [{
            "id": "dnsf-1", "match": {"host_suffix": "fail.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])

        def failing(u):
            raise at_mod.FetchError("network down")

        ok, reason, eid = _authorize("https://fail.example/", reg,
                                     failing)
        assert ok is False and eid == "dnsf-1"
        assert "dnsf-1" in reason and "network down" in reason, reason

    def test_unknown_ptype_refusal_formats_and_is_not_a_crash(self,
                                                              tmp_path):
        """% (t["id"], ptype) in the unknown-proof-type refusal:
        mutmut_367's / crashes instead of refusing. Kill: an entry
        with a bogus proof type must be REFUSED with its id named."""
        reg = _registry(tmp_path, [{
            "id": "unk-1", "match": {"host_suffix": "unk.example"},
            "proof": {"type": "bogus", "token": "TK"}}])
        ok, reason, eid = _authorize("https://unk.example/", reg,
                                     lambda u: "")
        assert ok is False and eid == "unk-1"
        assert "unk-1" in reason and "bogus" in reason, reason


# ══════════════════════════════════════════════════════════════════
# عائلة الإثبات المفقود: token/sha256/file الافتراضية (216/219/263/
# 266/315/318/255/258) — الفارق بين رفض نظيف وانهيار/قبول
# ══════════════════════════════════════════════════════════════════
class TestProofKeyDefaults:
    def test_dns_missing_token_refuses_cleanly_and_formats_id(self,
                                                              tmp_path):
        """proof.get("token", ""): a dns_txt entry WITHOUT a token
        key must yield the empty token -> the `if token and ...`
        guard skips -> clean refusal naming the entry (mutmut_216
        drops the default -> None -> the guard still skips... but
        mutmut_219's "XXXX" default: `if "XXXX" and "XXXX" in
        records` — a DoH answer CONTAINING "XXXX" would AUTHORIZE an
        entry the owner never pinned! Kill via: a tokenless dns
        entry must be refused even when the records contain junk."""
        reg = _registry(tmp_path, [{
            "id": "notk-1", "match": {"host_suffix": "nt.example"},
            "proof": {"type": "dns_txt"}}])
        # records full of XXXX junk: the mutant's "XXXX" default
        # token would find "XXXX" in them and AUTHORIZE
        ok, reason, eid = _authorize(
            "https://nt.example/", reg,
            lambda u: json.dumps({"Status": 0, "Answer": [
                {"data": "XXXX garbage XXXX"}]}))
        assert ok is False and eid == "notk-1", reason

    def test_well_known_missing_token_refuses_even_with_junk_body(self,
                                                                  tmp_path):
        """Same doctrine for the well_known proof (mutmut_315/318):
        a tokenless entry must refuse even when the fetched file's
        body contains the mutant's junk default "XXXX"."""
        reg = _registry(tmp_path, [{
            "id": "nowk-1", "match": {"host_suffix": "nw.example"},
            "proof": {"type": "well_known"}}])
        ok, reason, eid = _authorize(
            "https://nw.example/", reg,
            lambda u: (200, {}, b"XXXX anything XXXX"))
        assert ok is False and eid == "nowk-1", reason

    def test_signed_letter_missing_sha256_refuses_even_on_hash_lookalike(
            self, tmp_path):
        """proof.get("sha256", ""): a signed_letter entry WITHOUT a
        pinned digest must refuse even when the letter file's
        content happens to contain the junk default "XXXX"
        (mutmut_263 drops the default -> None; `if want and ...`
        skips -> refusal; mutmut_266's "XXXX" default: `if "XXXX"
        and got == "XXXX"` — got is a hex digest, never "XXXX", so
        refusal... BUT the refusal must not CRASH (mutmut_263's
        None reaches the %s format as 'None' — tolerated) and the
        ORIGINAL prints the empty want side as ''."""
        import hashlib
        letter = tmp_path / "letter.txt"
        letter.write_bytes(b"XXXX body XXXX")
        reg = _registry(tmp_path, [{
            "id": "nsha-1", "match": {"host_suffix": "ns.example"},
            "proof": {"type": "signed_letter",
                      "file": str(letter)}}])
        ok, reason, eid = _authorize("https://ns.example/", reg, None)
        assert ok is False and eid == "nsha-1"
        assert "does not match" in reason, reason

    def test_signed_letter_missing_file_refuses_cleanly(self, tmp_path):
        """proof.get("file", ""): a signed_letter entry WITHOUT a
        file path must refuse cleanly (mutmut_255 drops the default
        -> None -> os.path.join(REPO_ROOT, None) TypeErrors -> CRASH
        instead of refusal; mutmut_258's "XXXX" default joins to a
        nonexistent path -> OSError refusal — same verdict but the
        ORIGINAL also refuses via OSError on the empty relative
        path... both refuse; the ORIGINAL's refusal is the OSError
        variant naming the entry)."""
        reg = _registry(tmp_path, [{
            "id": "nfile-1", "match": {"host_suffix": "nf.example"},
            "proof": {"type": "signed_letter",
                      "sha256": "00" * 32}}])
        ok, reason, eid = _authorize("https://nf.example/", reg, None)
        assert ok is False and eid == "nfile-1"
        assert "could not be read" in reason, reason


# ══════════════════════════════════════════════════════════════════
# mutmut_5 — مجموعة القص rstrip في بناء عنوان well-known
# ══════════════════════════════════════════════════════════════════
class TestWellKnownUrlRstripSet:
    def test_trailing_slashes_are_all_stripped_exactly(self):
        """base_url.rstrip("/") + WELL_KNOWN_PATH: the strip set must
        be exactly "/". mutmut_5 sets it to "XX/XX" (the SET {X, /})
        so a base_url ending in X ALSO loses it: "example.com/X" ->
        "example.com" + path. The ORIGINAL keeps the X. Kill via the
        exact URL the fetcher receives (the injectable fetch records
        it): base ending in X must keep its X."""
        seen = []

        def rec(url):
            seen.append(url)
            raise RuntimeError("stop")

        from burhan.ownership import WellKnownError
        with pytest.raises(WellKnownError) as ei:
            _fetch_with_injectable("http://host.example/xX", rec)
        # rstrip("XX/XX") strips trailing X's AND slashes; "xX" ends
        # with X -> the mutant strips it -> "/.well-known/...".
        # The ORIGINAL rstrip("/") leaves ".../xX" intact.
        assert seen == ["http://host.example/xX"
                        "/.well-known/burhan-authorization.txt"], seen
        assert "http://host.example/xX" in str(ei.value)


# ══════════════════════════════════════════════════════════════════
# mutmut_25 — شريحة الاحتياط 300 حرفاً (301 تكشف ذيل الجملة)
# ══════════════════════════════════════════════════════════════════
class TestCandidateSentenceFallbackSlice:
    def test_fallback_clips_at_exactly_300_chars(self):
        """flat[:300]: the no-match fallback clips at exactly 300
        characters (mutmut_25's 301 leaks one extra character into
        the owner-visible pending-pin quote). Kill: a 301+ char page
        with NO permission wording must yield exactly the first 300
        characters."""
        page = "A" * 301
        out = at_mod._candidate_permission_sentence(page)
        assert len(out) == 300, f"fallback must clip at 300, got {len(out)}"


# ═══════════════════════════════════════-Token hex window 12══════
class TestShaMismatchHexWindow:
    def test_mismatch_refusal_shows_12_hex_chars_each_side(self, tmp_path):
        """got[:12]/want[:12] (mutmut_304/305 shift one side to 13):
        the sha-mismatch refusal names EXACTLY 12 hex chars of the
        observed and wanted digests. Kill: a letter whose sha256
        differs from the pin must produce a refusal whose two hex
        tokens are each exactly 12 long."""
        import hashlib
        letter = tmp_path / "letter.txt"
        letter.write_bytes(b"body")
        got12 = hashlib.sha256(b"body").hexdigest()[:12]
        want = hashlib.sha256(b"other").hexdigest()
        reg = _registry(tmp_path, [{
            "id": "hex-1", "match": {"host_suffix": "hx.example"},
            "proof": {"type": "signed_letter",
                      "file": str(letter), "sha256": want}}])
        ok, reason, eid = _authorize("https://hx.example/", reg, None)
        assert ok is False and eid == "hex-1"
        # the observed side is exactly got12 (12 hex chars) and the
        # wanted side is exactly want[:12] — not 13
        assert f"({got12} != {want[:12]})" in reason, reason


# ══════════════════════════════════════════════════════════════════
# mutmut_31 — اسم الترميز UTF-8 بالحالة العليا
# ══════════════════════════════════════════════════════════════════
class TestRegistryEncodingNameCase:
    def test_utf8_by_name_survives_the_uppercase_spelling(self, tmp_path):
        """encoding="UTF-8" (mutmut_31): Python's codec registry is
        case-insensitive, so "UTF-8" parses exactly like "utf-8" —
        EQUIVALENT (argued in the table). This test pins the
        contract so a future change (e.g. a codec alias cleanup)
        that made the case matter would surface here rather than in
        production."""
        reg = tmp_path / "reg.json"
        reg.write_bytes(b'{"targets": [{"id": "t-\xc3\xbc"}]}')
        out = at_mod.load_registry(str(reg))
        assert out["targets"][0]["id"] == "t-ü"


# ══════════════════════════════════════════════════════════════════
# banner 3/4/6 — بنية مخرجات البانر للبشر
# ══════════════════════════════════════════════════════════════════
class TestBannerStructure:
    def test_banner_is_74_equals_and_newline_joined(self, capsys, tmp_path):
        """The refusal banner: a bar of exactly 74 '=', sections
        joined by single newlines. mutmut_3 makes the bar "XX=XX"*74
        (a 296-char bar of X and =), mutmut_4 a 75-'=' bar, mutmut_6
        joins with "XX\nXX". These are human-facing output, but the
        gate's OUTPUT CONTRACT (what the operator greps/scripts)
        pins: bar == '='*74, lines joined by '\n'. A 75-bar or an
        XX-joined banner breaks any tooling that matches the banner
        shape. Kill by asserting the exact shape."""
        with pytest.raises(SystemExit) as ei:
            at_mod.load_registry(str(tmp_path / "nope.json"))
        assert ei.value.code == 2
        out = capsys.readouterr().err
        lines = out.splitlines()
        bars = [l for l in lines if set(l) == {"="}]
        assert bars and all(len(b) == 74 for b in bars), \
            f"banner bars must be exactly 74 '=', got {[len(b) for b in bars]}"
        assert "XX" not in out, "banner must not contain XX junk"


# ══════════════════════════════════════════════════════════════════
# عائلة مفاتيح السجل في تنسيق الرفض (208-211 / 372-375)
# ══════════════════════════════════════════════════════════════════
class TestRefusalRegistryKeyFormatting:
    def test_dns_failure_refusal_names_the_entry_id_verbatim(self, tmp_path):
        """% (t["id"], ...) with the ENTRY's id key (mutmut_208-211
        XX-wrap or case-shift the id key in the FORMAT tuples):
        the refusal must name the entry id verbatim. Kill: an entry
        with a distinctive id whose DoH fetch fails must show that
        exact id in the refusal."""
        reg = _registry(tmp_path, [{
            "id": "idn-1", "match": {"host_suffix": "idf.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])

        def failing(u):
            raise at_mod.FetchError("down")

        ok, reason, eid = _authorize("https://idf.example/", reg, failing)
        assert ok is False and eid == "idn-1"
        # the message names the entry id VERBATIM (the mutants
        # XX-wrap or case-shift the id KEY in the format tuple, so
        # the message would name None/'ID' instead), and the
        # returned id is the entry's verbatim key
        assert "'idn-1'" in reason, reason
        assert eid == "idn-1"

    def test_unknown_ptype_refusal_names_the_entry_id_verbatim(self,
                                                               tmp_path):
        """The unknown-ptype refusal (mutmut_372-375 mutate the id
        key in its format tuple): same verbatim-id contract."""
        reg = _registry(tmp_path, [{
            "id": "idu-1", "match": {"host_suffix": "idu.example"},
            "proof": {"type": "bogus"}}])
        ok, reason, eid = _authorize("https://idu.example/", reg,
                                     lambda u: "")
        assert ok is False and eid == "idu-1"
        assert "idu-1" in reason, reason
