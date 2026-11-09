"""R19-1 — SPA hash-fragment discovery: regression tests.

The gap (live-caught on WebGoat 2026.4, official GitHub release JAR):
the app routes its entire 40-lesson curriculum through hash-fragment
SPA routes — every menu link is start.mvc#lesson/X.lesson, and the
navigation tree itself is served as JSON (service/lessonmenu.mvc) with
each node carrying a '#lesson/X.lesson' link value. The crawler's
_normalize drops fragments (correct for URLs — the server never sees
them), and the crawl loop admitted only text/html / text/plain, so the
JSON menu taught nothing and all 40 routes collapsed onto the single
start.mvc page. The authenticated scan surfaced 14 endpoints instead
of the lesson surface (5 forms per lesson page — the real attack
surface).

The fix, all verified live against the official JAR before these
tests were written:
  1. _LinkParser records href fragments as hash_routes.
  2. JSON bodies are mined (_json_route_values) for route/URL-shaped
     values through the same plausible_js_url precision gate (DISC-01).
  3. _hash_route_target maps '#lesson/X.lesson' -> GET /X.lesson
     (the Backbone router's lesson/:name fetches the LEAF; the route
     prefix is the router's namespace, not a path component —
     /WebGoat/lesson/X.lesson is 404, /WebGoat/X.lesson is the page).
  4. Mapped resource pages are queued as normal pages (budgets apply);
     the fragment itself is NEVER fetched as a URL.

Fixtures are verbatim bytes from the live official target
(tests/fixtures/webgoat-spa/), saved 2026-11-09.
"""
from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from pathlib import Path

import pytest

from burhan.core import EventBus, ScopeRule
from burhan.discovery import DiscoveryEngine, _LinkParser, _json_route_values
from burhan.http_engine import RequestEngine

FIX = Path(__file__).parent / "fixtures" / "webgoat-spa"


# ---------------------------------------------------------------- unit level

class TestHashRouteTarget:
    """The route->resource mapping: WebGoat's shape exactly, and the
    no-guessing contract for every other shape."""

    def _t(self, page, frag):
        eng = object.__new__(DiscoveryEngine)   # pure method, no engine
        return DiscoveryEngine._hash_route_target(eng, page, frag)

    def test_webgoat_lesson_shape_maps_to_leaf_resource(self):
        # verified live: GET /WebGoat/HttpBasics.lesson = the lesson HTML
        assert self._t("http://127.0.0.1:8080/WebGoat/start.mvc",
                       "lesson/HttpBasics.lesson") == \
            "http://127.0.0.1:8080/WebGoat/HttpBasics.lesson"

    def test_route_prefix_is_namespace_not_path(self):
        # /WebGoat/lesson/HttpBasics.lesson is 404 on the live target —
        # the router prefix must NOT become a path component
        out = self._t("http://127.0.0.1:8080/WebGoat/start.mvc",
                      "lesson/HttpBasics.lesson")
        assert "/start.mvc/" not in out
        assert "/lesson/" not in out

    def test_bare_fragment_with_extension(self):
        assert self._t("http://h/app/page.mvc", "doc.pdf") == "http://h/app/doc.pdf"

    def test_anchor_only_fragment_rejected(self):
        # '#', '#top', '#main-content' — anchors, not routes
        assert self._t("http://h/app/page.mvc", "") == ""
        assert self._t("http://h/app/page.mvc", "top") == ""       # no extension
        assert self._t("http://h/app/page.mvc", "main-content") == ""

    def test_extensionless_spa_route_rejected(self):
        # Angular/React path routes ('/users/42') are NOT resources —
        # never guessed
        assert self._t("http://h/app/", "users/42") == ""
        assert self._t("http://h/app/", "profile/settings") == ""

    def test_page_filename_not_treated_as_directory(self):
        # the classic urljoin trap: page.mvc/lesson would nest under the
        # FILE. The mapping resolves against the page's DIRECTORY.
        out = self._t("http://h/app/start.mvc", "lesson/X.lesson")
        assert out == "http://h/app/X.lesson"


class TestLinkParserHashRoutes:
    def test_fragment_link_recorded(self):
        hp = _LinkParser()
        hp.feed('<a href="start.mvc?lang=en#lesson/HttpBasics.lesson">en</a>')
        assert hp.hash_routes == ["lesson/HttpBasics.lesson"]

    def test_bare_hash_link_recorded(self):
        hp = _LinkParser()
        hp.feed('<a href="#lesson/CIA.lesson">CIA</a>')
        assert hp.hash_routes == ["lesson/CIA.lesson"]

    def test_bare_anchor_hash_ignored(self):
        hp = _LinkParser()
        hp.feed('<a href="#">submit</a><a href="#top">top</a>')
        # 'top' IS recorded as a raw fragment (the parser does not
        # judge), but it maps to nothing — the mapping test pins that
        eng = object.__new__(DiscoveryEngine)
        assert DiscoveryEngine._hash_route_target(eng, "http://h/app/", "top") == ""
        assert DiscoveryEngine._hash_route_target(eng, "http://h/app/", "") == ""

    def test_real_startmvc_fixture(self):
        # verbatim start.mvc from the official JAR: the lang switcher
        # carries '#lesson/WebGoatIntroduction.lesson' fragments
        hp = _LinkParser()
        hp.feed((FIX / "start.mvc.html").read_text(encoding="utf-8"))
        assert "lesson/WebGoatIntroduction.lesson" in hp.hash_routes


class TestJsonRouteValues:
    def test_real_lessonmenu_fixture_yields_all_40(self):
        # the live menu (8701 bytes) carries the 40-lesson tree with
        # '#lesson/X.lesson' link values
        vals = _json_route_values((FIX / "lessonmenu.json").read_text(encoding="utf-8"))
        routes = [v for v in vals if v.startswith("#lesson/")]
        assert len(routes) == 40

    def test_nested_walk(self):
        body = json.dumps({"a": [{"link": "#lesson/A.lesson"},
                                 {"children": [{"link": "#lesson/B.lesson"}]}],
                           "name": "title"})
        assert sorted(_json_route_values(body)) == ["#lesson/A.lesson", "#lesson/B.lesson"]

    def test_non_json_yields_nothing(self):
        assert _json_route_values("<html>not json</html>") == []

    def test_precision_gate_applies(self):
        # code-fragment values (the DISC-01 class) stay out
        body = json.dumps({"x": "createElement(", "y": "#lesson/OK.lesson"})
        assert _json_route_values(body) == ["#lesson/OK.lesson"]

    def test_bare_identifiers_stay_out(self):
        # i18n label keys ('webgoat.title') have no route shape... but
        # note: 'webgoat.title' IS extension-shaped. It maps to a
        # resource URL that 404s on the live app — harmless (one dead
        # endpoint), and the alternative (whitelisting extensions)
        # would break the general case. Documented trade-off.
        vals = _json_route_values(json.dumps({"name": "webgoat.title"}))
        assert vals == ["webgoat.title"]   # extracted, then filtered by mapping


# ---------------------------------------------------------- integration level

class _SpaTarget(http.server.HTTPServer):
    """A minimal live mirror of the WebGoat SPA shape: a JSON menu, a
    start page, and per-lesson HTML pages with forms. Same wire shapes
    as the official JAR (content-types included)."""

    def __init__(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                p = urllib.parse.urlsplit(self.path).path
                if p == "/app/service/lessonmenu.mvc":
                    menu = [
                        {"link": "#lesson/Alpha.lesson", "name": "alpha",
                         "children": [{"link": "#lesson/Beta.lesson"}]},
                        {"link": "#lesson/Gamma.lesson", "name": "gamma",
                         "children": []},
                    ]
                    body = json.dumps(menu).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                elif p == "/app/start.mvc":
                    body = (b'<html><body><a href="/app/start.mvc?lang=en'
                            b'#lesson/Alpha.lesson">en</a>'
                            b'<script src="js/main"></script></body></html>')
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                elif p.endswith(".lesson"):
                    leaf = p.rsplit("/", 1)[-1]
                    body = (f'<html><body><form action="/app/service/attack"'
                            f'method="POST"><input name="field_{leaf}"/>'
                            f'</form></body></html>').encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html;charset=UTF-8")
                else:
                    body = b"{}"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        super().__init__(("127.0.0.1", 0), H)


class TestCrawlDiscoversSpaRoutes:
    """The end-to-end no-regression, mirroring the REAL WebGoat flow:
    the static crawl sees the HTML fragment routes (the lang switcher);
    the lesson MENU travels as JSON over an XHR the SPA fires at runtime
    (require.js loads goatApp via data-main — the JS chain is never in a
    <script src> tag), so the menu is reachable only through the browser
    pass. Both halves are tested with the exact composition the
    orchestrator uses (render_merge -> spa/xhr-tagged seeds -> crawl)."""

    @pytest.fixture()
    def server(self):
        srv = _SpaTarget()
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        yield srv
        srv.shutdown()

    def _engine(self, port):
        return RequestEngine(ScopeRule(allow_private=True,
                                       allowed_hosts=["127.0.0.1"]),
                             EventBus("r19-spa"), timeout=5.0)

    def test_static_fragment_route_becomes_probeable_endpoint(self, server):
        """The half the STATIC crawler owns: an href fragment maps to the
        resource, the resource is page-fetched, its form joins the map.
        Before r19-1 the fragment was dropped and Alpha.lesson never
        existed as an endpoint."""
        port = server.server_address[1]
        eng = self._engine(port)
        disc = DiscoveryEngine(eng, max_pages=10)
        endpoints, _js, _stats = disc.crawl(f"http://127.0.0.1:{port}/app/start.mvc")
        urls = {e.url for e in endpoints}
        assert f"http://127.0.0.1:{port}/app/Alpha.lesson" in urls, \
            "SPA fragment route collapsed onto the host page (r19-1 regression)"
        # the lesson page was FETCHED and its form parsed — the form's
        # action only exists inside the lesson body
        assert any("service/attack" in u for u in urls), \
            "lesson form target missing — lesson page never page-fetched"
        form_ep = next((e for e in endpoints
                        if e.url.endswith("/app/service/attack")), None)
        assert form_ep is not None and form_ep.source.value == "crawl:form"
        assert any("field_Alpha.lesson" in (p.name or "")
                   for p in form_ep.parameters)

    def test_fragment_itself_never_fetched(self, server):
        """The fragment is client-only; fetching it as a URL would return
        the start page and burn budget. The wire must never carry a '#'."""
        port = server.server_address[1]
        eng = self._engine(port)
        seen_urls = []
        orig = eng.send
        def spy(req):
            seen_urls.append(req.endpoint.url if req.endpoint else str(req))
            return orig(req)
        eng.send = spy
        disc = DiscoveryEngine(eng, max_pages=10)
        disc.crawl(f"http://127.0.0.1:{port}/app/start.mvc")
        assert all("#" not in u for u in seen_urls), \
            "a fragment-bearing URL was fetched — the server never sees fragments"

    def test_full_spa_flow_browser_carriers_to_lesson_surface(self, server):
        """The WebGoat shape end-to-end (no playwright needed — render()
        is canned with the exact structures the live JAR produces):
        rendered menu links carry '#lesson/X.lesson' fragments, and the
        menu JSON is an OBSERVED XHR. render_merge must surface BOTH the
        mapped lesson endpoints and the menu channel; feeding the
        tagged seeds back through crawl (the orchestrator's SPA
        expansion) mines the menu JSON and page-fetches every lesson —
        the 40-lesson collapse is gone."""
        from burhan.browser import BrowserEngine
        port = server.server_address[1]
        base = f"http://127.0.0.1:{port}/app"

        # canned render results mirroring the live start.mvc render:
        # Backbone built the menu (fragment links) and fetched the menu
        # JSON over XHR in front of the browser
        canned = {
            f"{base}/start.mvc": {
                "url": f"{base}/start.mvc",
                "html": "<html></html>",
                "forms": [],
                "links": [f"{base}/start.mvc#lesson/Alpha.lesson",
                          f"{base}/start.mvc#lesson/Gamma.lesson"],
                "xhrs": [{"method": "GET",
                          "url": f"{base}/service/lessonmenu.mvc",
                          "post_data": "", "content_type": "application/json"}],
            },
        }

        class _CannedBrowser(BrowserEngine):
            def __init__(self):
                self.pages_rendered = 0
            def render(self, url, settle_ms=500):
                return canned.get(url)

        be = _CannedBrowser()

        eng = self._engine(port)
        existing: dict = {}
        # seed_host is the FULL netloc (host:port) — the orchestrator's
        # r19-1b contract; a hostname-only value silently drops every
        # link on non-standard ports (the WebGoat :8080 case)
        netloc = urllib.parse.urlsplit(base).netloc
        new_eps = be.render_merge([f"{base}/start.mvc"], netloc, existing)
        by_url = {e.url: e for e in new_eps}
        # the mapped lesson resources (fragments survived _mk_dom_endpoint's
        # strip because they were mapped) + the observed menu channel
        assert f"{base}/Alpha.lesson" in by_url and f"{base}/Gamma.lesson" in by_url
        assert by_url[f"{base}/Alpha.lesson"].source.value == "dom:browser"
        assert any("spa_route:" in t for t in by_url[f"{base}/Alpha.lesson"].tags)
        assert f"{base}/service/lessonmenu.mvc" in by_url
        assert any(t == "xhr:observed" for t in by_url[f"{base}/service/lessonmenu.mvc"].tags)

        # the orchestrator's SPA expansion composition: tagged URLs become
        # extra seeds; the crawl fetches the menu (JSON mined: Beta was
        # ONLY in the JSON, never in any HTML) and every lesson page
        spa_seeds = [e.url for e in new_eps
                     if any(t.startswith(("spa_route:", "xhr:observed"))
                            for t in (e.tags or []))]
        disc = DiscoveryEngine(eng, max_pages=10)
        endpoints, _js, _stats = disc.crawl(f"{base}/start.mvc",
                                            extra_seeds=spa_seeds)
        urls = {e.url for e in endpoints}
        for leaf in ("Alpha.lesson", "Beta.lesson", "Gamma.lesson"):
            assert f"{base}/{leaf}" in urls, \
                f"lesson {leaf} missing — SPA expansion did not reach it"
        # every lesson's FORM was parsed (page-fetched, not just listed)
        for leaf in ("Alpha.lesson", "Beta.lesson", "Gamma.lesson"):
            form_ep = next((e for e in endpoints
                            if e.url.endswith("/app/service/attack")
                            and any(f"field_{leaf}" in (p.name or "")
                                    for p in e.parameters)), None)
            assert form_ep is not None, f"form of {leaf} never parsed"
