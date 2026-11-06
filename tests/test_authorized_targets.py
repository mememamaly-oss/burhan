"""Round-8 part 2 pins — the authorized-target registry gate.

The order's hard requirement: "Write a test proving this refusal actually
fires for an unlisted target." That is test_unlisted_public_target_is_
refused_loudly (plus the SystemExit(2) end-to-end shape the live scripts
hit). The remaining pins prove the gate's allow paths carry real, verified
proof — no allowance by assumption.
"""
import json
import os

import pytest

from burhan import authorized_targets as at


def test_unlisted_public_target_is_refused_loudly(capsys):
    """THE refusal pin: a target absent from the registry is refused with
    the banner naming the registry, and require_authorized exits 2."""
    ok, reason, eid = at.authorize("https://unlisted-target.example.com")
    assert ok is False and eid is None
    assert "NOT PRESENT in authorized-targets.json" in reason
    assert "unlisted-target.example.com" in reason

    with pytest.raises(SystemExit) as ex:
        at.require_authorized("https://unlisted-target.example.com")
    assert ex.value.code == 2
    out = capsys.readouterr()
    assert "REFUSED — LIVE SCAN AUTHORIZATION GATE" in out.out
    assert "authorized-targets.json" in out.out
    assert "ZERO scan requests" in out.out


def test_loopback_fixture_authorized_via_self_hosted_entry():
    ok, reason, eid = at.authorize("http://127.0.0.1:8888")
    assert ok is True and eid == "self-hosted-fixtures"
    assert "operator's own host" in reason


def test_private_docker_network_authorized():
    ok, _reason, eid = at.authorize("http://172.17.0.2:3000")
    assert ok is True and eid == "self-hosted-fixtures"


def test_ginandjuice_scope_page_quote_verified_live():
    page = ("<html><body>Welcome to the shop. This is a deliberately "
            "vulnerable web application designed for testing web "
            "vulnerability scanners. Open 24/7.</body></html>")
    ok, reason, eid = at.authorize("https://ginandjuice.shop",
                                   fetch=lambda url: page)
    assert ok is True and eid == "ginandjuice.shop"
    assert "pinned permission quote verified verbatim" in reason


def test_scope_page_quote_gone_means_refused():
    """The pinned quote NO LONGER on the live page -> the target's policy
    may have changed -> refused, even though the entry exists."""
    page = ("The shop has moved on and no longer permits "
            "automated testing of any kind.")
    ok, reason, eid = at.authorize("https://ginandjuice.shop",
                                   fetch=lambda url: page)
    assert ok is False and eid == "ginandjuice.shop"
    assert "NO LONGER on the live page" in reason


def test_scope_page_fetch_failure_is_refused():
    def _down(url):
        raise at.FetchError("connection timed out")

    ok, reason, eid = at.authorize("https://ginandjuice.shop", fetch=_down)
    assert ok is False and eid == "ginandjuice.shop"
    assert "could not be fetched live" in reason


def test_vulnweb_pending_pin_refused_with_observed_quote():
    """The vulnweb.com entry ships pending-quote-pin (the verbatim quote
    was NOT fetchable from the 2026-11-03 sandbox and must not be invented):
    even with a live page in hand, the gate refuses until the owner pins."""
    page = "Acunetix legal hacking site — you may test your scanner here."
    ok, reason, eid = at.authorize("https://testphp.vulnweb.com",
                                   fetch=lambda url: page)
    assert ok is False and eid == "vulnweb.com"
    assert "pending-quote-pin" in reason
    assert "OBSERVED on the live page" in reason
    assert "legal hacking site" in reason      # the observed evidence, printed


def test_dns_txt_token_verified_and_mismatch(tmp_path):
    reg = json.load(open(at.DEFAULT_REGISTRY, encoding="utf-8"))
    reg["targets"].append({
        "id": "dns-verified-example", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "dnstest.example"},
        "proof": {"type": "dns_txt", "token": "burhan-authorized-2026"}})
    p = tmp_path / "reg.json"
    p.write_text(json.dumps(reg), encoding="utf-8")

    doh_ok = json.dumps({"Answer": [{"data": "\"burhan-authorized-2026\""}]})
    doh_bad = json.dumps({"Answer": [{"data": "\"nothing-here\""}]})
    ok, _, eid = at.authorize("https://dnstest.example", str(p),
                              fetch=lambda url: doh_ok)
    assert ok is True and eid == "dns-verified-example"
    ok, reason, _ = at.authorize("https://dnstest.example", str(p),
                                 fetch=lambda url: doh_bad)
    assert ok is False and "do NOT carry the authorization token" in reason


def test_signed_letter_sha_mismatch_is_refused(tmp_path):
    letter = tmp_path / "letter.txt"
    letter.write_bytes(b"authorization letter body")
    import hashlib
    good = hashlib.sha256(letter.read_bytes()).hexdigest()
    reg = json.load(open(at.DEFAULT_REGISTRY, encoding="utf-8"))
    reg["targets"].append({
        "id": "letter-example", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "letter.example"},
        "proof": {"type": "signed_letter", "file": str(letter),
                  "sha256": good}})
    p = tmp_path / "reg.json"
    p.write_text(json.dumps(reg), encoding="utf-8")
    ok, reason, eid = at.authorize("https://letter.example", str(p))
    assert ok is True and "sha256 re-verified" in reason
    # tamper with the letter -> hash no longer matches -> refused
    letter.write_bytes(b"tampered")
    ok, reason, _ = at.authorize("https://letter.example", str(p))
    assert ok is False and "does not match the registry" in reason


def test_registry_corruption_is_a_loud_gate(tmp_path):
    bad = tmp_path / "reg.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        at.load_registry(str(bad))
    assert ex.value.code == 2


def test_missing_registry_is_a_loud_gate(tmp_path):
    with pytest.raises(SystemExit) as ex:
        at.load_registry(str(tmp_path / "absent.json"))
    assert ex.value.code == 2


def test_live_validate_script_refuses_unlisted_target_e2e():
    """END-TO-END: the actual live-validation SCRIPT (not the function)
    refuses an unlisted target: exit code 2, the refusal banner on stdout,
    and no verdict file written — zero scan requests ran."""
    import subprocess
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = "/tmp/render/e2e-refusal-out"
    os.makedirs(out, exist_ok=True)
    r = subprocess.run(
        [sys.executable, "scripts/live_validate_modern2.py",
         "--crapi", "https://unlisted-evil.example.com",
         "--out-dir", out],
        capture_output=True, text=True, timeout=60,
        cwd=root)
    assert r.returncode == 2, (r.returncode, r.stdout[:300])
    assert "REFUSED — LIVE SCAN AUTHORIZATION GATE" in r.stdout
    assert "unlisted-evil.example.com" in r.stdout
    assert "ZERO scan requests" in r.stdout
    assert os.listdir(out) == [], "no verdict may be written on refusal"



# ---- round 13: dot-bounded host-suffix matching (the CodeQL high) --------
# RED-proven on main@85b1c8a: host.endswith(suffix) with no dot boundary let
# the attacker-registered lookalike evilginandjuice.shop ENTER the
# ginandjuice.shop entry's proof path (authorization bypass); symmetrically,
# the dot-leading ".vulnweb.com" suffix never matched the apex host. Both
# fixed: a suffix authorizes exactly the apex and dot-bounded subdomains.


def test_lookalike_domain_never_enters_the_proof_path():
    """evil+suffix must be refused as NOT PRESENT (no entry match at all),
    not merely fail the proof — the proof belongs to the ORIGINAL owner."""
    import json
    import burhan.authorized_targets as at
    reg = json.load(open(at.DEFAULT_REGISTRY))
    quote = next((t["proof"].get("required_quote") for t in reg["targets"]
                  if t["id"] == "ginandjuice.shop"
                  and (t.get("proof") or {}).get("type") == "scope_page"), None)
    assert quote, "the ginandjuice.shop entry must stay a pinned scope_page"

    def fetch(url):
        return "preamble. " + quote + " postamble."

    for lookalike in ("evilginandjuice.shop", "not-really-ginandjuice.shop",
                      "evilvulnweb.com", "ginandjuice.shop.evil.example"):
        ok, reason, eid = at.authorize("https://%s/" % lookalike, fetch=fetch)
        assert not ok and eid is None, (lookalike, eid, reason[:80])
        assert "NOT PRESENT" in reason, (lookalike, reason[:120])


def test_apex_and_true_subdomains_match_the_suffix():
    """the apex host and real subdomains of a pinned entry stay authorized."""
    import json
    import burhan.authorized_targets as at
    reg = json.load(open(at.DEFAULT_REGISTRY))
    quote = next((t["proof"].get("required_quote") for t in reg["targets"]
                  if t["id"] == "ginandjuice.shop"
                  and (t.get("proof") or {}).get("type") == "scope_page"), None)

    def fetch(url):
        return "preamble. " + quote + " postamble."

    for host, want in (("ginandjuice.shop", "ginandjuice.shop"),
                       ("www.ginandjuice.shop", "ginandjuice.shop"),
                       ("deep.sub.ginandjuice.shop", "ginandjuice.shop")):
        ok, reason, eid = at.authorize("https://%s/" % host, fetch=fetch)
        assert ok and eid == want, (host, eid, reason[:80])


def test_dot_leading_suffix_matches_its_apex_shape():
    """.vulnweb.com is pending-quote-pin so its PROOF refuses — but the
    entry MATCH must now cover the apex (host == bare), where the old code
    matched neither apex nor bounded subdomain correctly."""
    import json
    import burhan.authorized_targets as at
    reg = json.load(open(at.DEFAULT_REGISTRY))
    entry = next(t for t in reg["targets"] if t["id"] == "vulnweb.com")
    assert entry["match"]["host_suffix"].startswith(".")
    assert entry["proof"].get("required_quote") is None  # still pending

    # entry-matching now correct: apex and subdomain REACH the proof (and are
    # refused BY the pending proof, not by absent matching); lookalikes never
    # reach any entry.
    ok, reason, eid = at.authorize("https://vulnweb.com/", fetch=lambda u: "x")
    assert not ok and eid == "vulnweb.com", (eid, reason[:100])
    assert "pending-quote-pin" in reason
    ok, reason, eid = at.authorize("https://www.vulnweb.com/",
                                   fetch=lambda u: "x")
    assert not ok and eid == "vulnweb.com", (eid, reason[:100])
