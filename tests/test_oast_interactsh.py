"""Part 4 — OAST interact.sh live integration + self-hosted listener tests.

4.5 REAL test with interact.sh LIVE (not simulated):
  RED  — a vulnerable fixture performs a genuine blind out-of-band HTTP
         fetch to an interact.sh-issued address; the interaction must be
         received, decrypted, and correlated to the right interaction id.
  BLUE — a hardened twin fixture issues NO out-of-band action; zero
         interaction received within the window, and the finding does NOT
         fire (pinned TESTED_NEGATIVE in the evidence, not here).

4.6 Self-hosted listener (DNS+HTTP) logic via LOCAL LOOPBACK simulation
  only — reported as logic-proven-but-infrastructure-pending, never as a
  live-network result.

Live tests are marked `live_interactsh`; the CI-safe subset (loopback
self-hosted listener + provider protocol shape) runs everywhere.
"""
from __future__ import annotations

import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from burhan.oast import (InteractshProvider, SelfHostedListener,
                         make_oast, OastServer)


# ---------------------------------------------------- provider protocol ----

def test_interactsh_provider_protocol_shape():
    """The provider exposes the same 3-call protocol as the other channels
    (url / poll / stop + channel + hits) — swappable by construction."""
    for attr in ("url", "poll", "stop", "hits", "channel"):
        assert hasattr(InteractshProvider, attr)
    assert InteractshProvider.channel == "interactsh"


def test_make_oast_modes():
    """local for loopback-capable targets; the public modes construct the
    interact.sh provider (network registration exercised in the live test)."""
    o = make_oast("127.0.0.1", mode="auto")
    assert isinstance(o, OastServer)
    o.stop()


# ---------------------------------------------- 4.5 LIVE interact.sh -------

@pytest.mark.live_interactsh
def test_live_interactsh_red_blind_oob_roundtrip():
    """RED: a genuine blind out-of-band action to an interact.sh-issued
    address is received, decrypted (RSA-OAEP + AES-CTR exactly like the
    official client), and correlated to the issuing interaction id."""
    with InteractshProvider() as p:
        iid = "oob-red000001"                     # deterministic test id
        url = p.url(iid)
        assert ".oast.fun" in url and "/i/" + iid in url
        # the "vulnerable fixture" side: a genuine outbound HTTP fetch of
        # the issued address (what an SSRF/XXE victim would do)
        urllib.request.urlopen(url, timeout=15).read()
        hits = p.poll(iid, timeout=25.0)
    assert hits, "no interaction received from interact.sh"
    h = hits[0]
    assert h["protocol"] in ("http", "dns")
    assert h["ip"], "source attribution missing"


@pytest.mark.live_interactsh
def test_live_interactsh_blue_no_interaction():
    """BLUE: a hardened twin issues NO out-of-band action — zero interaction
    for its id within the window (the negative that keeps the channel
    honest; the finding-level TESTED_NEGATIVE pin lives in the evidence
    pack, evidence/layers/oast/)."""
    with InteractshProvider() as p:
        iid = "oob-blue00001"
        p.url(iid)                                # address issued, never fetched
        hits = p.poll(iid, timeout=8.0)           # > server's own poll cadence
    assert hits is None, f"spurious interaction: {hits}"


@pytest.mark.live_interactsh
def test_live_interactsh_correlation_isolation():
    """Two different interaction ids on ONE registration: a fetch of id A's
    URL must NEVER surface under id B (correlation, not broadcast)."""
    with InteractshProvider() as p:
        ia, ib = "oob-isoA00001", "oob-isoB00001"
        p.url(ia), p.url(ib)
        urllib.request.urlopen(p.url(ia), timeout=15).read()
        ha = p.poll(ia, timeout=25.0)
        hb = p.poll(ib, timeout=1.0)              # short window: nothing there
    assert ha, "id A missed its own interaction"
    assert hb is None, "id B received id A's interaction — correlation broken"


# --------------------------------------- 4.6 self-hosted (loopback only) ----

def test_selfhosted_http_loopback_red_blue():
    """LOOPBACK SIMULATION (4.6): the self-hosted listener records an HTTP
    callback under the issuing id (RED) and stays silent for an id whose
    address was never fetched (BLUE). Infrastructure-pending: real DNS
    needs an NS delegation; this proves the correlation logic only."""
    with SelfHostedListener() as p:
        red, blue = "oob-shred001", "oob-shblue01"
        urllib.request.urlopen(p.url(red) + "?x=1", timeout=5).read()
        assert p.poll(red, timeout=3.0), "HTTP callback not recorded"
        assert p.poll(blue, timeout=0.3) is None, "phantom interaction"


def test_selfhosted_dns_loopback_red():
    """LOOPBACK SIMULATION (4.6): the DNS responder answers a query for
    <iid>.<domain> with A 127.0.0.1 and records the interaction id from the
    FIRST LABEL — the same prefix-correlation semantics interact.sh uses."""
    import socket as _s
    with SelfHostedListener() as p:
        iid = "oob-shdns001"
        qname = p.dns_url(iid)
        # hand-build a DNS query (header + QNAME + A? IN)
        q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for label in qname.split("."):
            q += bytes([len(label)]) + label.encode()
        q += b"\x00\x00\x01\x00\x01"
        s = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(q, ("127.0.0.1", p.dns_port))
        data, _ = s.recvfrom(4096)
        s.close()
        # response: QR=1, 1 answer, A record 127.0.0.1
        assert data[2] & 0x80, "not a response"
        assert data[7] == 1, "no answer record"
        assert data[-4:] == bytes([127, 0, 0, 1]), "wrong A record"
        hits = p.poll(iid, timeout=3.0)
    assert hits, "DNS interaction not recorded under its id"


def test_selfhosted_provider_protocol_swap():
    """Swappability proof: the self-hosted listener satisfies the SAME
    provider protocol — make_oast-level swapping is a config change."""
    for attr in ("url", "poll", "stop", "hits", "channel"):
        assert hasattr(SelfHostedListener, attr)
    assert SelfHostedListener.channel == "self-hosted"
