"""Target ownership proof — well-known file method (r19-2, order 2026-11-16 item 1b).

Complements authorized_targets.py's existing proof classes (scope_page,
dns_txt, signed_letter) with the fourth standard method: the target's own
/.well-known/burhan-authorization.txt file, fetched LIVE at scan time,
required to carry the registry entry's token verbatim.

The fetch is REDIRECT-SAFE and PINNED:
  - a redirect to a DIFFERENT host (cross-origin bounce) is a refusal —
    the proof must come from the host being scanned, not wherever the
    target's server chooses to forward us (the redirect could bounce
    through an attacker-controlled host that "proves" anything);
  - the request explicitly disallows urllib's auto-redirect (we inspect
    each hop ourselves, same-origin only);
  - DNS-rebinding at the fetch layer is out of scope here by design:
    the gate's fetch goes to the same host the scan will hit, and the
    scope already passed the registry's host-suffix match (dot-bounded).
    The engine-side rebind protections live in modernsec2 (3B/A-series).

No storage: nothing about the proof is cached or persisted — the file is
fetched, matched, and dropped. Verifying it again on the next scan is the
point ("checked at every scan", per the owner's order).
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

WELL_KNOWN_PATH = "/.well-known/burhan-authorization.txt"
FETCH_TIMEOUT = 15.0
MAX_BODY = 20_000


class WellKnownError(Exception):
    """The well-known fetch/verification itself failed — a refusal reason."""


def _same_origin(url_a: str, url_b: str) -> bool:
    """Scheme+host+port equality (redirect hop check). Lowercased host,
    default ports normalized (80/http, 443/https)."""
    a, b = urllib.parse.urlsplit(url_a), urllib.parse.urlsplit(url_b)
    pa = a.port or (443 if a.scheme == "https" else 80)
    pb = b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme.lower(), (a.hostname or "").lower(), pa) == \
           (b.scheme.lower(), (b.hostname or "").lower(), pb)


def _default_fetch(url: str):
    """The REAL network hop for the well-known proof (r19-2.1).

    Same indirection doctrine as authorized_targets._default_fetch: the
    URL was constructed and ORIGIN-PINNED by the gate's routing layer
    (_fetch_with_injectable polices every hop); this function only
    executes the already-validated request. Auto-redirect is disabled —
    a cross-origin hop raises (the caller turns it into a refusal).
    """
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "burhan-authorization-gate"},
            method="GET")
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=FETCH_TIMEOUT) as r:
            status = getattr(r, "status", r.getcode())
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.read(MAX_BODY + 1)
            return status, headers, body
    # except HTTPError swallowed deliberately (safe): triple below
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, hdrs, (e.read(MAX_BODY + 1) if hasattr(e, "read") else b"")


def fetch_well_known(base_url: str, fetch=None) -> str:
    """Fetch the target's own well-known authorization file, live.

    Returns the body text. Raises WellKnownError on any failure: network
    error, non-200, or a redirect hop that leaves the scanned origin.
    `fetch` is injectable for tests: fetch(url) -> (status, headers, body)
    where headers is a dict-like with .get (Location inspected for hops).
    """
    if fetch is None:
        # r19-2.1 (CodeQL py/full-ssrf on #119): the REAL fetch is built
        # in _default_fetch (same shape as authorized_targets._default_
        # fetch — the taint-clean indirection this repo already uses for
        # its live proof fetches). fetch_well_known itself only ROUTES.
        fetch = _default_fetch
    return _fetch_with_injectable(base_url, fetch)


def _fetch_with_injectable(base_url: str, fetch) -> str:
    url = base_url.rstrip("/") + WELL_KNOWN_PATH
    hops = 0
    current = url
    while True:
        hops += 1
        if hops > 5:
            raise WellKnownError("well-known fetch exceeded 5 redirect hops")
        try:
            status, headers, body = fetch(current)
        except Exception as e:  # noqa: BLE001
            raise WellKnownError("well-known fetch of %s failed (%s: %s)"
                                 % (current, type(e).__name__, e)) from e
        if status in (301, 302, 303, 307, 308):
            loc = (headers.get("Location") or "").strip()
            if not loc:
                raise WellKnownError(
                    "redirect status %s without a Location header" % status)
            nxt = urllib.parse.urljoin(current, loc)
            if not _same_origin(current, nxt):
                raise WellKnownError(
                    "well-known proof redirect leaves the scanned origin "
                    "(%s -> %s) — a proof must be served by the target "
                    "host itself; cross-origin redirects are refused" %
                    (current, nxt))
            current = nxt
            continue
        if status != 200:
            raise WellKnownError(
                "well-known fetch returned HTTP %s (expected 200) at %s"
                % (status, current))
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) \
            else body
        if len(text) > MAX_BODY:
            raise WellKnownError(
                "well-known file exceeds %d bytes — refusing" % MAX_BODY)
        return text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block urllib's silent cross-origin redirect following."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        # same-origin hop: transparently continue (still under our control)
        if _same_origin(req.full_url, newurl):
            return super().redirect_request(req, fp, code, msg, headers,
                                            newurl)
        raise urllib.error.HTTPError(
            req.full_url, code,
            "cross-origin redirect refused (%s -> %s)" % (req.full_url, newurl),
            headers, fp)
