"""SPA interpolated query discovery.

Juice Shop's search is compiled as a template whose value is interpolated
(`/rest/products/search?q=${criteria}` or a trailing concatenation). The
backtick extractor plus plausible_js_url rejects `${`, so the parameter
never reached the battery. These tests pin the extractor and that a
default crawl records the parameter without fetching it.
"""
from __future__ import annotations

import http.server
import threading
import urllib.parse

from burhan.core import EventBus, ScopeRule
from burhan.discovery import DiscoveryEngine, js_interpolated_query_urls
from burhan.http_engine import RequestEngine


JS = """
http.get(host + `/rest/products/search?q=${criteria}`);
http.get('/api/Users');
legacy('/rest/user/login?email=' + email);
void `/static/main.js?v=${build}`;
void `/rest/x?q=${a}&y=${b}`;
void `/${notAPath}?q=${z}`;
"""


def test_extractor_keeps_only_static_single_params():
    urls = js_interpolated_query_urls(JS)
    assert urls == [
        "/rest/products/search?q=",
        "/rest/user/login?email=",
    ]


def test_extractor_rejects_empty_and_code():
    assert js_interpolated_query_urls("") == []
    assert js_interpolated_query_urls("url:" + "s.default.createElement(") == []
    assert js_interpolated_query_urls("`/rest/a?q=${a.b()}`") == []


class _App(http.server.HTTPServer):
    def __init__(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                if path == "/":
                    body = b'<html><script src="/app.js"></script></html>'
                    ctype = "text/html"
                elif path == "/app.js":
                    body = b"http.get(h+`/rest/products/search?q=${criteria}`);"
                    ctype = "application/javascript"
                else:
                    body = b"no"
                    ctype = "text/plain"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        super().__init__(("127.0.0.1", 0), H)


def test_crawl_records_param_and_does_not_fetch_it():
    srv = _App()
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        port = srv.server_address[1]
        eng = RequestEngine(ScopeRule(allow_private=True, allowed_hosts=["127.0.0.1"]),
                            EventBus("spa-interp"), timeout=5.0)
        fetched = []
        orig = eng.send

        def spy(req):
            fetched.append(getattr(req, "url", None) or req.endpoint.url)
            return orig(req)

        eng.send = spy
        disc = DiscoveryEngine(eng, max_pages=8)
        endpoints, _js, _stats = disc.crawl(f"http://127.0.0.1:{port}/")
        hit = [e for e in endpoints if e.url.endswith("/rest/products/search")]
        assert hit, "interpolated search endpoint was not recorded"
        assert any(p.name == "q" for p in hit[0].parameters)
        assert "spa:interp-query" in hit[0].tags
        assert all("/rest/products/search" not in u for u in fetched), \
            "the recovered URL was fetched during crawl; it must stay off the budget"
    finally:
        srv.shutdown()
