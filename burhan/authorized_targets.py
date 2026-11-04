"""Authorized-target registry gate — round 8, part 2 (2026-11-03).

The ONLY source of truth for what may be scanned live is
authorized-targets.json (repo root). Every live-scan entry point calls
require_authorized(base_url) BEFORE its first request; a target that is
absent, unverified, or whose proof no longer holds is refused LOUDLY:
a multi-line banner on stdout+stderr, zero scan requests, exit code 2.

Proof classes, verified AT SCAN TIME (never cached, never "verified once"):
  ownership      loopback/private fixtures this repo's own workflows build
                 and tear down — authorization is ownership of the host;
  scope_page      the target's own published permission page, fetched live
                 and matched against the pinned verbatim quote. A pinned
                 quote that disappears from the page = REFUSED (the
                 target's policy may have changed). An entry whose quote is
                 not yet pinned (pending-quote-pin) is refused with the
                 observed candidate sentence printed for the owner to pin;
  dns_txt        a DNS TXT record the owner controls, looked up live via
                 DNS-over-HTTPS, required to carry the entry's token;
  signed_letter  an authorization file in this repo, re-hashed at scan
                 time against the sha256 recorded in the registry.

No invented facts: nothing here decides authorization by assumption; every
allow path names the registry entry and the proof that carried it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REGISTRY = os.path.join(REPO_ROOT, "authorized-targets.json")
FETCH_TIMEOUT = 15.0


class FetchError(Exception):
    """The live proof fetch itself failed — a refusal reason, not a pass."""


def load_registry(path: str = DEFAULT_REGISTRY) -> dict:
    if not os.path.exists(path):
        print(_banner(path, "registry file missing",
                      "authorized-targets.json not found — "
                      "no target may be scanned."), file=sys.stderr, flush=True)
        raise SystemExit(2)
    try:
        reg = json.load(open(path, encoding="utf-8"))
        targets = reg["targets"]
        assert isinstance(targets, list) and targets
        return reg
    except Exception as e:  # noqa: BLE001 — the gate must fail LOUD, not crash quietly
        print(_banner(path, "registry corrupt",
                      "authorized-targets.json failed to load/parse: "
                      "%s: %s" % (type(e).__name__, e)), file=sys.stderr, flush=True)
        raise SystemExit(2) from e


def _banner(registry_path: str, title: str, detail: str) -> str:
    bar = "=" * 74
    return "\n".join([
        bar,
        "REFUSED — LIVE SCAN AUTHORIZATION GATE: " + title,
        bar,
        "registry : %s" % registry_path,
        "detail   : %s" % detail,
        "policy   : a target may be scanned live ONLY with a current, valid",
        "           proof in the registry (see the file's own policy field).",
        "action   : ZERO scan requests were sent. Add the target with real",
        "           proof, or fix the proof — do not bypass this gate.",
        bar,
    ])


def _default_fetch(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "burhan-authorization-gate"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            return r.read(200_000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        raise FetchError("fetch of %s failed (%s: %s)"
                         % (url, type(e).__name__, e))


def _host_of(base_url: str) -> str:
    return (urllib.parse.urlsplit(base_url).hostname or "").lower()


def _is_loopback_or_private(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        addr = host
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return False
        addrs = [i[4][0] for i in infos]
        return bool(addrs) and all(
            ipaddress.ip_address(a).is_private or ipaddress.ip_address(a).is_loopback
            for a in addrs)
    ip = ipaddress.ip_address(addr)
    return ip.is_private or ip.is_loopback


def _candidate_permission_sentence(page_text: str) -> str:
    """For pending-quote-pin entries: print what the live page actually
    says around permission-ish vocabulary — observed evidence for the
    owner to pin, never a guess."""
    flat = re.sub(r"\s+", " ", page_text)
    m = re.search(r"[^.!?]{0,180}(permission|legal|scanner|vulnerab|"
                  r"test(ing)? (this|our) (site|web))[^.!?]{0,180}[.!?]",
                 flat, re.I)
    return (m.group(0).strip() if m else flat[:300])


def authorize(base_url: str, registry_path: str = DEFAULT_REGISTRY,
              fetch=None) -> tuple[bool, str, str | None]:
    """Verdict for ONE target. Returns (ok, reason, entry_id).

    `fetch` is injectable for tests: fetch(url) -> page text.
    """
    reg = load_registry(registry_path)
    host = _host_of(base_url)
    if not host:
        return False, "no host in the given URL", None

    fetch = fetch or _default_fetch

    # ---- self-hosted fixtures: the operator's own loopback/private host
    if _is_loopback_or_private(host):
        for t in reg["targets"]:
            if t.get("kind") == "self-hosted" and \
                    (t.get("match") or {}).get("loopback_or_private"):
                return True, ("loopback/private target — the operator's own "
                              "host (self-hosted fixtures: %s)"
                              % ", ".join((t.get("covers") or [])[:3])), t["id"]
        return False, ("loopback/private target but NO self-hosted entry in "
                       "the registry"), None

    # ---- public targets: an entry with a scan-time-verified proof
    for t in reg["targets"]:
        suffix = (t.get("match") or {}).get("host_suffix")
        if not suffix:
            continue
        if host == suffix or host.endswith(suffix):
            proof = t.get("proof") or {}
            ptype = proof.get("type")
            if ptype == "scope_page":
                required = proof.get("required_quote")
                try:
                    page = fetch(proof["page_url"])
                except FetchError as e:
                    return False, ("registry entry '%s' proof page could not "
                                   "be fetched live: %s — proof NOT verified, "
                                   "refusing" % (t["id"], e)), t["id"]
                if not required:
                    return False, ("registry entry '%s' has status "
                                   "pending-quote-pin: the live page was "
                                   "fetched but no verbatim quote is pinned. "
                                   "OBSERVED on the live page (for the owner "
                                   "to pin): %r — refusing until pinned"
                                   % (t["id"],
                                      _candidate_permission_sentence(page))), \
                        t["id"]
                if required in page:
                    return True, ("scope page fetched live, pinned permission "
                                  "quote verified verbatim"), t["id"]
                return False, ("registry entry '%s': the pinned permission "
                               "quote is NO LONGER on the live page — the "
                               "target's published policy may have changed; "
                               "refusing" % t["id"]), t["id"]
            if ptype == "dns_txt":
                try:
                    doh = fetch("https://cloudflare-dns.com/dns-query?name=%s"
                                "&type=TXT" % urllib.parse.quote(host, safe=""))
                    records = " ".join(a.get("data", "")
                                      for a in json.loads(doh).get("Answer", [])
                                      if isinstance(a, dict))
                except (FetchError, ValueError) as e:
                    return False, ("registry entry '%s': live DNS TXT lookup "
                                   "failed (%s) — proof NOT verified, refusing"
                                   % (t["id"], e)), t["id"]
                token = proof.get("token", "")
                if token and token in records:
                    return True, ("live DNS TXT lookup carries the owner's "
                                  "authorization token"), t["id"]
                return False, ("registry entry '%s': the live DNS TXT "
                               "records do NOT carry the authorization token "
                               "— refusing" % t["id"]), t["id"]
            if ptype == "signed_letter":
                letter = os.path.join(REPO_ROOT, proof.get("file", ""))
                want = proof.get("sha256", "")
                try:
                    got = hashlib.sha256(open(letter, "rb").read()).hexdigest()
                except OSError as e:
                    return False, ("registry entry '%s': the authorization "
                                   "letter could not be read (%s) — refusing"
                                   % (t["id"], e)), t["id"]
                if want and got == want:
                    return True, ("signed authorization letter present, "
                                 "sha256 re-verified at scan time"), t["id"]
                return False, ("registry entry '%s': the letter's sha256 "
                               "does not match the registry (%s != %s) — "
                               "refusing" % (t["id"], got[:12], want[:12])), \
                    t["id"]
            return False, ("registry entry '%s' carries an unknown proof type "
                           "%r — refusing" % (t["id"], ptype)), t["id"]

    return False, ("host %r is NOT PRESENT in authorized-targets.json — "
                   "no authorization exists for this target" % host), None


def require_authorized(base_url: str, registry_path: str = DEFAULT_REGISTRY,
                       fetch=None) -> str:
    """The loud gate every live-scan entry point calls BEFORE any request.

    Returns the entry id on success; prints the refusal banner and raises
    SystemExit(2) on any refusal — the scan process must die here.
    """
    ok, reason, entry_id = authorize(base_url, registry_path, fetch)
    if not ok:
        banner = _banner(registry_path, "target refused", reason)
        print(banner, file=sys.stdout, flush=True)
        print(banner, file=sys.stderr, flush=True)
        raise SystemExit(2)
    print("[authorized-targets] %s -> registry entry '%s': %s"
          % (base_url, entry_id, reason), flush=True)
    return entry_id
