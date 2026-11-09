"""Phase 4: Discovery Engine — HTML crawler, forms, robots.txt, JS static extraction.
Phase 5: Endpoint/Parameter Intelligence (parameters classified on ingest).
"""
from __future__ import annotations
import json
import re, urllib.parse
from html.parser import HTMLParser
from .websocket import harvest_ws_bindings, harvest_ws_shapes, observe_ws_urls  # V411-WS + V4.3.2
from .core import DiscoverySource, Endpoint, Parameter, ParamLocation
from .http_engine import RequestEngine
# MAX-10a: the same logout vocabulary the authz engine refuses to probe —
# the crawler must never page-fetch it either (self-preservation of the
# scan's own session; live-caught on WebGoat 8.2.2).
LOGOUT_PATH_RE = re.compile(r"(log-?out|log-?off|sign-?out|sign-?off)", re.I)

# OWSP-21 (OWASP campaign, live-caught on Mutillidae II 2.12.7): the app
# routes its commands through the QUERY STRING (index.php?do=toggle-security,
# index.php?do=logout) — the path is a constant "/index.php" for the whole
# app. Every safety vocabulary in the engine was path-scoped, so a
# query-routed state change was INVISIBLE to all of them: the crawler
# followed the do=toggle-security header-menu link at journal index 11, and
# the scan session's security level oscillated 0->1->5->0 across 95 hits —
# 4661/4672 requests ran under an uncontrolled app posture while the scan
# looked perfectly healthy. Application-configuration toggles are a
# self-preservation class: fetching one changes the conditions every later
# request is tested under (the subtler sibling of the DVGA /start_over
# database re-seed).
STATE_CHANGE_GET_RE = re.compile(
    r"(toggle|switch|enable|disable|turn[_-]?(?:on|off))", re.I)


def gate_scope(url: str) -> str:
    """Path + query string of a URL — the surface the safety vocabularies
    (destructive-get / logout / state-change-toggle) must match against.
    Query-routed apps (index.php?do=toggle-security, ?do=logout) carry their
    commands in the query string; a path-only check never sees them. The '?'
    separator keeps words from straddling the boundary."""
    p = urllib.parse.urlsplit(url or "")
    return (p.path or "/") + ("?" + p.query if p.query else "")


def endpoint_gate_scope(ep) -> str:
    """OWSP-21b: gate scope of a CANONICAL Endpoint. _mk_endpoint strips the
    query into typed Parameters — ep.url carries no query, so a command value
    (index.php?do=logout) lives in a Parameter, invisible to gate_scope(ep.url).
    The active-battery gates must see the param name=value pairs too (live:
    batteries fired 16 do=logout BASE requests through the authenticated jar;
    the session survived only because the level-0 app re-authenticates from
    the uid cookie — target luck, not engine correctness)."""
    base = gate_scope(getattr(ep, "url", "") or "")
    pairs = []
    for p in (getattr(ep, "parameters", None) or []):
        try:
            pairs.append(f"{p.name}={getattr(p, 'value', '') or ''}")
        except Exception:
            continue
    if not pairs:
        return base
    sep = "&" if "?" in base else "?"
    return base + sep + "&".join(pairs)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms = [], []   # forms: (action, method, [params])
        self.hash_routes = []             # R19-1: SPA hash-fragment routes (#lesson/X.lesson)
        self.divforms = []                # DISC-10: div-based pseudo-forms
        self._cur_form = None
        self._cur_divform = None
        self._div_depth = 0
        # ENG-17 (live-caught on ginandjuice.shop add-to-cart): the parser had
        # NO <select> handling — quantity selects were dropped from the form's
        # parameter list entirely, so the CSRF baseline POST /catalog/cart
        # shipped without a required field, 400'd, and the cross-origin proof
        # (hostile.ok) could never pass. A browser ALWAYS submits a select:
        # the SELECTED option, else the FIRST option (text content when the
        # value attr is absent).
        self._cur_select = None           # name of the <select> currently open
        self._sel_default = ""            # resolved default for that select
        self._sel_val = None              # current <option> value attr (None -> text)
        self._sel_text: list = []         # current <option> text buffer
        self._sel_selected = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
            # R19-1: an href carrying a hash-fragment is a SPA route to a
            # distinct resource (WebGoat's #lesson/X.lesson -> GET /X.lesson).
            # Record the fragment; the crawl loop maps it to the route
            # target. A bare "#" (form submit-to-self) and anchor-only
            # fragments stay out — the route regex demands a
            # resource-shaped leaf.
            h = a["href"]
            if "#" in h and not h.startswith("#"):
                frag = h.split("#", 1)[1]
                if frag:
                    self.hash_routes.append(frag)
            elif h.startswith("#") and len(h) > 1:
                self.hash_routes.append(h[1:])
        elif tag in ("link", "script") and a.get("href") or (tag == "script" and a.get("src")):
            self.links.append(a.get("href") or a.get("src"))
        elif tag == "form":
            self._cur_form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "params": [], "submitctl": None, "files": set()}
        elif tag == "input" and self._cur_form is not None:
            if a.get("type") in ("submit", "button", "reset"):
                # OWSP-01 (OWASP campaign, live-caught on WrongSecrets 1.8.1):
                # a submit INPUT's name=value pair is PART of the submission
                # (routes gated on it: Spring params="action=submit" filters,
                # WebGoat lesson forms). Flow-control pairs were silently
                # dropped, every probe answered 405 and the whole POST
                # surface went dead while the gates stayed green.
                if (a.get("type") == "submit" and a.get("name") and a.get("value")
                        and not self._cur_form.get("submitctl")):
                    self._cur_form["params"].append((a["name"], a["value"]))
                    self._cur_form["submitctl"] = a["name"]
            elif a.get("type") == "file" and a.get("name"):
                # OWSP-18 (OWASP campaign, live-caught on DVWA 3.x): file inputs
                # are marked — a text-battery probe on a multipart file field is a
                # ghost request (the app reads $_FILES, never $_POST), and the
                # upload detector needs the real multipart surface.
                self._cur_form["params"].append((a["name"], ""))
                self._cur_form["files"].add(a["name"])
            elif a.get("name"):
                self._cur_form["params"].append((a["name"], a.get("value", "")))
        elif tag == "button" and self._cur_form is not None:
            # OWSP-01 (live-caught on WrongSecrets 1.8.1): <button type=submit
            # name= value=> contributes its name=value pair to the submission —
            # POST /challenge/{name} sits behind params="action=submit" whose
            # pair comes from the BUTTON; the form-only-inputs parser made the
            # entire challenge surface unreachable (candidates=0, all probes
            # 405, no coverage note). Capture name+value-bearing submit-type
            # buttons (spec: a button without type IS type=submit); only the
            # FIRST per form — one activated control per real submission, and
            # duplicate keys would corrupt param ordering. Valueless buttons
            # are inert for flow control and stay out (noise only).
            _btype = (a.get("type") or "submit").lower()
            if (_btype == "submit" and a.get("name") and a.get("value")
                    and not self._cur_form.get("submitctl")):
                self._cur_form["params"].append((a["name"], a["value"]))
                self._cur_form["submitctl"] = a["name"]
        elif tag == "textarea" and self._cur_form is not None and a.get("name"):
            self._cur_form["params"].append((a["name"], ""))
        elif tag == "select" and a.get("name") and (self._cur_form is not None
                                                     or self._cur_divform is not None):
            self._cur_select, self._sel_default = a["name"], ""
        elif tag == "option" and self._cur_select is not None:
            self._sel_val = a.get("value")          # None -> fall back to text
            self._sel_text = []
            # bare boolean attrs (selected) parse as None — test key presence
            self._sel_selected = "selected" in a
        # ---- DISC-10 (live-caught on ginandjuice.shop #subscribe): JS-driven
        # "forms" are <div data-action=... data-method=post> blocks, NOT <form>
        # elements — a form-only parser is structurally blind to the whole
        # subscribe surface. Track inputs inside such divs (nested divs counted).
        if tag == "div":
            if self._cur_divform is not None:
                self._div_depth += 1
            elif a.get("data-action") or (a.get("data-method") and "form" in (a.get("class") or "")):
                self._cur_divform = {"action": a.get("data-action", ""),
                                     "method": (a.get("data-method") or "POST").upper(), "params": []}
                self._div_depth = 1
        elif self._cur_divform is not None and tag == "input":
            if a.get("type") not in ("submit", "button", "reset") and a.get("name"):
                self._cur_divform["params"].append((a["name"], a.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "option" and self._cur_select is not None:
            value = self._sel_val if self._sel_val is not None else "".join(self._sel_text).strip()
            if value and (self._sel_selected or self._sel_default == ""):
                self._sel_default = value
            self._sel_val, self._sel_text, self._sel_selected = None, [], False
        elif tag == "select" and self._cur_select is not None:
            self._flush_select()
        elif tag == "form" and self._cur_form:
            self._flush_select()                     # malformed HTML: unterminated select
            self.forms.append(self._cur_form); self._cur_form = None
        elif tag == "div" and self._cur_divform is not None:
            self._div_depth -= 1
            if self._div_depth <= 0:
                self._flush_select()
                if self._cur_divform["params"]:
                    self.divforms.append(self._cur_divform)
                self._cur_divform = None

    def _flush_select(self):
        """ENG-17: commit the open <select> as a form param with its
        browser-faithful default (selected > first option; '' when the app
        really offers an empty placeholder)."""
        if self._cur_select is None:
            return
        target = self._cur_form if self._cur_form is not None else self._cur_divform
        if target is not None and not any(n == self._cur_select for n, _ in target["params"]):
            target["params"].append((self._cur_select, self._sel_default))
        self._cur_select = None

    def handle_data(self, data):
        # ENG-17: <option> without a value attr submits its TEXT — buffer it.
        if self._cur_select is not None and self._sel_val is None:
            self._sel_text.append(data)


# JS endpoint heuristics (static pass; AST-lite for fetch/axios/XHR/WebSocket)
JS_PATTERNS = [
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|\$\.(?:ajax|get|post))\(\s*['"`]([^'"`]{3,200})['"`]""", re.I),
    re.compile(r"""(?:url|endpoint|apiUrl|API_BASE)\s*[:=]\s*['"`]([^'"`]{3,200})['"`]""", re.I),
    re.compile(r"""new\s+WebSocket\(\s*['"`]([^'"`]+)['"`]""", re.I),
    # MAX-06 (maximum internal test, live-caught on Juice Shop 20.2.0): bundled
    # SPA frameworks (Angular HttpClient and friends) concatenate the API base
    # with BACKTICK template literals — http.get(host+`/rest/user/whoami`) —
    # which none of the fetch/axios/url patterns match. On the Juice Shop
    # bundle the old patterns extracted 2 endpoints; the template-literal
    # pattern extracts 95 (the whole /api/* + /rest/* surface). Interpolated
    # templates (`${...}`) are rejected by the plausible_js_url gate (braces),
    # keeping the DISC-01 minified-code-fragment precision lesson intact.
    re.compile(r"`(/[^`\\]{2,200})`"),
]
QUERY_RE = re.compile(r"[?&]([A-Za-z_][\w]*)=([^&#\s]*)")

# DISC-06 (live-caught on ginandjuice.shop): the XXE surface on /catalog/product/stock
# only exists for XML bodies that JavaScript builds at runtime (xmlStockCheckPayload.js
# overrides Content-Type to application/xml and wraps form fields in <stockCheck> XML).
# A DOM-less crawler can still learn this STATICALLY: while fetching .js assets, record
# (a) XML content-type overrides and (b) XML root templates from xml-building code.
# XxeDetector replays the JS transformation deterministically — no browser needed.
JS_XML_HINTS: set = set()          # XML root element names learned from JS assets
_JS_XML_ROOT = re.compile(r"""xml\s*\+=\s*['"]<(\w+)>['"]""")           # xml += '<stockCheck>';
_JS_XML_CT   = re.compile(r"""['"]application/xml['"]""")               # contentType override

# DISC-05 (live-caught on ginandjuice.shop): params that exist ONLY inside inline
# <script> bodies (e.g. const categories = {"Gin":"/catalog?category=Gin"};) are
# invisible to <a href>/form parsers. PortSwigger's scanme hides its entire /catalog
# attack surface (SQLi + XSS + header injection, all on ?category=) this way.
# Extract quoted URL-shaped strings from inline script blocks; the DISC-01
# plausible_js_url gate + same-host check keep precision.
_INLINE_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)
_INLINE_JS_URL_RE = re.compile(r"""["'](/[^"'\s]{2,200}\?[^"'\s]{1,200})["']""")

# DISC-08 (live-caught on ginandjuice.shop): styling/media assets were fetched as CRAWL
# PAGES, burning the page budget on resources that can never reveal endpoints — the
# XML-hint JS (xmlStockCheckPayload.js) queued behind 4 CSS files never got fetched,
# hiding the XXE surface. Static assets stay discoverable as ENDPOINTS (links still
# recorded); they are just not wasted page-fetches.
_SKIP_AS_PAGE = (".css", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
                 ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".webp")

# DISC-01 (live-caught on demo.testfire.net swagger-ui-bundle.js): minified webpack code
# satisfies JS_PATTERNS with code fragments like  url:",s.default.createElement("  or
# url:"responseURL"  -> these became phantom endpoints and polluted findings/requests.
# Deterministic plausibility gate for JS-extracted strings (HTML href/src stay exempt).
_JS_URL_FORBIDDEN = set('(){}<>"\'`\\ \t\n\r;')
_JS_URL_PATHISH = re.compile(r"\.[A-Za-z0-9]{2,5}$")


def plausible_js_url(s: str) -> bool:
    """A JS-extracted string is a plausible endpoint URL iff it is code-free and path-like.
    Rejects: function-call fragments, comma/plus-glued minified code, bare identifiers
    (e.g. 'responseURL', 'string'), anything with whitespace/quotes/braces."""
    s = s.strip()
    if not s or len(s) > 500:
        return False
    if any(c in _JS_URL_FORBIDDEN for c in s):
        return False
    if s.startswith(("/", "http://", "https://", "ws://", "wss://")):
        return True
    # relative candidate: must carry real path structure (a '/', a '?', or a file
    # extension) — bare JS identifiers carry none.
    return ("/" in s) or ("?" in s) or (_JS_URL_PATHISH.search(s) is not None)


def _json_route_values(body: str) -> list[str]:
    """R19-1 (live-caught on WebGoat 2026.4): the SPA's navigation tree
    arrives as JSON (service/lessonmenu.mvc) with every route in a
    "link" value — '#lesson/HttpBasics.lesson'. Walk ALL string values
    of the parsed document (nested arrays/objects) and return those
    shaped like a route or URL, each passing the plausible_js_url
    precision gate (the DISC-01 lesson applied to a new carrier). A
    body that fails json.loads yields nothing — no regex fishing in
    arbitrary text."""
    try:
        doc = json.loads(body)
    except Exception:
        return []
    out: list[str] = []
    def _walk(node):
        if isinstance(node, str):
            v = node.strip()
            if v.startswith("#") and len(v) > 1:
                out.append(v)
            elif plausible_js_url(v):
                out.append(v)
        elif isinstance(node, dict):
            for vv in node.values():
                _walk(vv)
        elif isinstance(node, list):
            for vv in node:
                _walk(vv)
    _walk(doc)
    return out


# DISC-10: a div-form's JS usually serializes inputs as JSON (live-proven on
# ginandjuice.shop subscribeNow.js: JSON.stringify(value) + Content-Type
# application/json;charset=UTF-8). Statically learnable from fetched JS assets;
# div-form params are upgraded to ParamLocation.JSON when the hint is present.
_JS_JSON_CT = re.compile(r"['\"]application/json", re.I)
_JS_JSONIFY = re.compile(r"JSON\.stringify")


# V411-DISC-SAFE (live-caught on DVGA): a state-changing GET is a real
# anti-pattern — DVGA's /start_over re-seeds the ENTIRE DATABASE on a plain
# GET, and the passive crawler's page-fetch of it destroyed the campaign's
# test identities mid-scan (burhan41a + its BOLA victim paste vanished).
# Such paths are NEVER page-fetched; they remain discovered endpoints and
# stay reachable through the planner-gated battery, which classifies the
# same vocabulary DESTRUCTIVE and blocks it.
DESTRUCTIVE_GET_RE = re.compile(
    r"(start[_-]?over|factory|restore[_-]?(default|all|db|data)|"
    r"reset[_-]?(all|db|data|default|world)|reseed|reinit|"
    r"initiali[sz]e|setup|install|migrate|seed[_-]?(all|db|data)|"
    r"flush[_-]?(all|db|cache[_-]?all)|clear[_-]?(all|db|data)|purge|wipe|"
    r"truncate|drop[_-]?(all|db|table|data))", re.I)


# R19-1: hash-fragment SPA route -> fetchable resource mapping.
# WebGoat 2026.4 (live-verified): '#lesson/HttpBasics.lesson' is fetched
# by the Backbone router as GET /WebGoat/HttpBasics.lesson (the lesson's
# form-bearing HTML); /WebGoat/lesson/HttpBasics.lesson is 404 — the
# route prefix is the router's namespace, NOT a path component.
_HASH_ROUTE_LEAF_RE = re.compile(r"^/?([A-Za-z0-9_][\w./-]*\.[A-Za-z]{2,8})$")


def hash_route_target(page_url: str, fragment: str) -> str:
    """Map a hash-fragment SPA route to the resource URL the client
    actually fetches. Only resource-shaped leaves (carrying a file
    extension) map; extensionless SPA paths ('/users/42') and plain
    anchors return '' — never guessed. Resolution is against the PAGE'S
    DIRECTORY (urljoin would treat 'start.mvc/' as a directory)."""
    m = _HASH_ROUTE_LEAF_RE.match(fragment or "")
    if not m:
        return ""
    leaf = m.group(1).rsplit("/", 1)[-1]
    dir_url = (page_url or "").rsplit("/", 1)[0] + "/"
    return urllib.parse.urljoin(dir_url, leaf)


class DiscoveryEngine:
    SAME_PATH_PAGE_CAP = 4    # DISC-09: max fetched pages per template key (see below)

    def _page_cap_key(self, norm: str) -> str:
        """OWSP-23 (OWASP campaign, live-caught on Mutillidae II 2.12.7):
        DISC-09's per-path fetch cap keyed on the BARE PATH — a query-routed
        app (every page is /index.php?page=X) had its ENTIRE menu strangled
        at 4 fetches: 20 of the 26 core vuln pages (user-info SQLi,
        dns-lookup OS-cmdi, privilege-escalation, jwt, source-viewer,
        pen-test-tool-lookup, ...) were never fetched, their forms never
        discovered, their batteries never scheduled — while the crawl looked
        busy on path-diverse decoration (documentation mirrors). The key now
        separates TEMPLATE duplicates (same path + same param names,
        differing DATA values — the cap's original target) from ROUTER pages
        (a param value shaped like a script filename selects a different
        actual page and gets its own budget)."""
        p = urllib.parse.urlsplit(norm)
        base = (p.path or "/").lower()
        q = urllib.parse.parse_qsl(p.query or "", keep_blank_values=True)
        names = "&".join(sorted(n for n, _v in q))
        router_vals = "&".join(
            f"{n}={v}" for n, v in sorted(q)
            if str(v).lower().endswith((".php", ".html", ".htm", ".asp",
                                        ".aspx", ".jsp", ".js")))
        return base + "?" + names + ("|" + router_vals if router_vals else "")

    def __init__(self, engine: RequestEngine, max_pages: int = 25):
        self.engine, self.max_pages = engine, max_pages
        self._path_queued: dict = {}   # path -> FETCHED page count (DISC-09 template cap)
        self.dom_sinks: list = []      # DISC-11: static DOM source->sink candidates
        self._js_bodies: list[tuple[str, str]] = []   # (url, body) of fetched JS assets
        self.script_pages: list[str] = []  # Phase 50: HTML pages carrying <script> — render candidates
        self.ws_observed: list[str] = []   # V411-WS-DISC-2: observed ws:// channels (var wsUri + new WebSocket(wsUri))

    def _normalize(self, base: str, href: str) -> str:
        href = href.strip()
        if href.startswith(("#", "javascript:", "mailto:", "data:")): return ""
        full = urllib.parse.urljoin(base, href)
        p = urllib.parse.urlsplit(full)
        if p.scheme not in ("http", "https"): return ""
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))

    # R19-1 (live-caught on WebGoat 2026.4): the app routes its 40-lesson
    # curriculum through HASH-FRAGMENT SPA routes — every menu link is
    # start.mvc#lesson/HttpBasics.lesson. The crawler's _normalize strips
    # the fragment (correctly: the SERVER never sees it), so all 40 routes
    # collapsed onto the single start.mvc page and the authenticated scan
    # surfaced 14 endpoints instead of the lesson surface. A fragment IS a
    # distinct client-side route to a distinct RESOURCE though: WebGoat's
    # Backbone router maps #lesson/<name> to a GET of /<name>.lesson (the
    # lesson's HTML with its forms — the real attack surface). The route
    # is preserved as a virtual path so it becomes a PROBEABLE endpoint;
    # it is never page-fetched as a URL (the fragment is not sent to the
    # server — fetching would just return start.mvc again).
    _HASH_ROUTE_RE = re.compile(r"^/?([A-Za-z0-9_][\w./-]*\.[A-Za-z]{2,8})$")

    def _hash_route_target(self, page_url: str, fragment: str) -> str:
        """Instance wrapper — see the module-level hash_route_target."""
        return hash_route_target(page_url, fragment)

    def _route_from_value(self, page_url: str, value: str) -> str:
        """R19-1: a route-shaped string found in HTML fragments or JSON
        values -> the resource URL the client fetches. Accepts both the
        '#lesson/X.lesson' fragment form and a path-like '/X.lesson'
        form; anything else maps to '' (no guessing)."""
        v = (value or "").strip()
        if v.startswith("#"):
            v = v[1:]
        if not v or v.startswith(("javascript:", "mailto:", "data:")):
            return ""
        if v.startswith(("http://", "https://")):
            return self._normalize(page_url, v)
        return hash_route_target(page_url, v)


    def _mk_endpoint(self, url: str, source: DiscoverySource, params=None, method="GET",
                     flow_control=(), file_names=()) -> Endpoint:
        p = urllib.parse.urlsplit(url)
        qs = [(k, v[0]) for k, v in urllib.parse.parse_qs(p.query, keep_blank_values=True).items()]
        plist = [Parameter(n, ParamLocation.QUERY, v).classify() for n, v in qs]
        # DISC-02 (live-caught on demo.testfire.net frmSearch): form params were ALWAYS
        # assigned BODY regardless of the form method. GET-method forms (Altoro search)
        # got a GET endpoint with body params — ENG-02 honored that wrong metadata and
        # the payload was silently dropped (GET sends no body). Location must follow
        # the endpoint's actual method.
        form_loc = ParamLocation.BODY if (method or "GET").upper() == "POST" else ParamLocation.QUERY
        for n, v in (params or []):
            pobj = Parameter(n, form_loc, v).classify()
            # OWSP-03: submit-button pairs ride along verbatim — never probed
            if n in flow_control:
                pobj.flow_control = True
            # OWSP-18: file inputs are the upload surface, not text fields
            if n in file_names:
                pobj.is_file = True
            plist.append(pobj)
        clean = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))
        return Endpoint(url=clean, method=method, parameters=plist, source=source)

    def crawl(self, seed_url: str, extra_seeds: list | None = None, exclude_urls: list | None = None):
        """BFS crawl same-host; returns (endpoints, js_findings, crawl_stats).
        Phase 51: extra_seeds (e.g. the authenticated landing page) join the BFS
        queue at position 0 — same normalization, same budget gates, so the
        authenticated surface is discovered by the exact same deterministic rules
        as the anonymous one (no separate privileged code path).
        Phase 51b: exclude_urls are never PAGE-FETCHED once authenticated —
        re-fetching the login page makes the server issue a fresh ANONYMOUS
        session cookie that clobbers the authenticated one in the jar (live-caught:
        the benchmark self-healed via AUTH-03 but burned a login per fetch). The
        page's endpoints remain reachable through the form-parse discovery."""
        seen_pages, endpoints, js_hits = set(), {}, []
        seed_host = urllib.parse.urlsplit(seed_url).netloc
        # R19-1c: the crawl's seed-root — the second anchor for
        # JSON-mined route candidates (menu directory vs app root)
        self._seed_url = seed_url
        queue = list(extra_seeds or []) + [seed_url]
        # V411-EXC: full URLs exclude EXACTLY (normalized); bare substrings
        # (operator pinning, e.g. "/difficulty/") exclude every URL that
        # contains them — the page-fetch itself must not flip target state
        excl_exact = {self._normalize(seed_url, u) for u in (exclude_urls or []) if u}
        excl_sub = [u for u in (exclude_urls or []) if u and "://" not in u]

        def _is_excluded(norm: str) -> bool:
            return (norm in excl_exact
                    or any(s in norm for s in excl_sub))
        pages = 0
        while queue and pages < self.max_pages:
            url = queue.pop(0)
            norm = self._normalize(seed_url, url)
            if not norm or norm in seen_pages: continue
            if _is_excluded(norm): continue
            seen_pages.add(norm)
            ok, _ = self.engine._scope_ok(norm)
            if not ok: continue
            # DISC-09 fix (live-caught via traced crawl): the per-path cap used to
            # count QUEUE INSERTIONS — the same menubar link appearing on every page
            # queued 4 duplicate copies, burned the whole path budget, and STARVED the
            # form-target URL (?search=...) that DISC-12 queued later: the DOM surface
            # was unreachable even though every gate individually passed. Counting
            # actual FETCHES keeps the template-page cap honest while duplicates
            # dedupe for free at pop-time via seen_pages.
            fpath = urllib.parse.urlsplit(norm).path or "/"
            # OWSP-23: the template cap keys on path + param names +
            # file-shaped (router) param VALUES — a bare path strangled
            # query-routed apps at 4 fetches total (live: 20 of 26 core
            # Mutillidae vuln pages never fetched).
            capkey = self._page_cap_key(norm)
            if self._path_queued.get(capkey, 0) >= self.SAME_PATH_PAGE_CAP:
                continue
            # OWSP-21: the vocabulary gates match PATH + QUERY — the command
            # of a query-routed app (index.php?do=toggle-security) lives in
            # the query string, invisible to a path-only check.
            gscope = gate_scope(norm)
            # V411-DISC-SAFE: destructive-GET vocabulary is never page-fetched
            # (the endpoint stays discovered; the planner gates any probe)
            if (DESTRUCTIVE_GET_RE.search(gscope)
                    or STATE_CHANGE_GET_RE.search(gscope)):
                self.crawl_skips = getattr(self, "crawl_skips", [])
                if gscope not in self.crawl_skips:
                    self.crawl_skips.append(gscope)
                ep = self._mk_endpoint(norm, DiscoverySource.CRAWL_HTML)
                endpoints[ep.id] = ep
                continue
            # MAX-10a (maximum internal test, live-caught on WebGoat 8.2.2):
            # LOGOUT links sit in the header of virtually every authenticated
            # page — the crawler page-fetched /WebGoat/logout at journal index
            # 6 of 4504, destroying the scan's own session; every re-auth then
            # re-logged-in and re-crawled into logout again (6 logins, 5
            # reauths, 3944 dead-session requests, the whole lesson surface
            # answered by login pages). Same doctrine as destructive-GET: the
            # logout endpoint stays DISCOVERED (never fetched).
            if LOGOUT_PATH_RE.search(gscope):
                self.crawl_skips = getattr(self, "crawl_skips", [])
                if gscope not in self.crawl_skips:
                    self.crawl_skips.append(gscope)
                ep = self._mk_endpoint(norm, DiscoverySource.CRAWL_HTML)
                endpoints[ep.id] = ep
                continue
            self._path_queued[capkey] = self._path_queued.get(capkey, 0) + 1
            resp = self.engine.send(self.engine.__class__ and _simple_get(norm))
            pages += 1
            if resp.error or not resp.body: continue
            # R19-1 (live-caught on WebGoat 2026.4): the SPA's ENTIRE
            # navigation model — its 40-lesson curriculum tree — is served
            # as JSON (service/lessonmenu.mvc), each node carrying a
            # "#lesson/X.lesson" route. The old gate admitted only
            # text/html / text/plain, so a JSON menu taught the crawler
            # NOTHING: the route-bearing payload was fetched and discarded.
            # JSON bodies are now mined for URL/route-shaped values (same
            # plausible_js_url precision gate as JS extraction; routes map
            # through _hash_route_target like HTML fragments). The JSON
            # itself is not treated as an HTML page — only mined.
            _ct = resp.headers.get("content-type", "")
            if "application/json" in _ct:
                # R19-1c: route-bearing JSON (a menu) can live on a
                # DIFFERENT path depth than the resources its routes
                # name (WebGoat: menu at /WebGoat/service/lessonmenu.mvc,
                # lessons at /WebGoat/X.lesson — the app root). Resolving
                # the leaf against the menu's directory alone yields
                # /WebGoat/service/X.lesson = 404 (live-verified). Both
                # anchors are offered — the menu's directory AND the
                # crawl's seed-root — and the target that actually
                # exists (a fetchable page) is the one that joins the
                # map; the miss simply 404s and teaches nothing.
                _seed_root = self._seed_url.rsplit("/", 1)[0] + "/"
                for frag in _json_route_values(resp.body):
                    target = self._route_from_value(norm, frag)
                    alt = self._route_from_value(_seed_root, frag) \
                        if _seed_root not in ("", "/") else ""
                    for cand in (target, alt):
                        if not cand:
                            continue
                        ok_rt, _ = self.engine._scope_ok(cand)
                        if not ok_rt:
                            continue
                        e_rt = self._mk_endpoint(cand, DiscoverySource.JS_STATIC)
                        if e_rt.id not in endpoints:
                            e_rt.tags.append("spa_route:" + frag[:80])
                            endpoints[e_rt.id] = e_rt
                        if (cand not in seen_pages
                                and not cand.lower().endswith(_SKIP_AS_PAGE)):
                            queue.append(cand)
                continue
            if not any(m in _ct for m in ("text/html", "text/plain", "")): continue
            ep = self._mk_endpoint(norm, DiscoverySource.SEED)
            # OWSP-08 (OWASP campaign, live-caught on the OWASP Benchmark): the
            # page's links joined the QUEUED url — for a slashless target root
            # that redirects (http://host/benchmark -> /benchmark/Index.html),
            # EVERY relative link escaped the app (cmdi-Index.html resolved to
            # /cmdi-Index.html at the server root; the Benchmark crawl surfaced
            # 16 endpoints instead of ~2756). Links join the FINAL response url
            # (resp.url is post-redirect — see _dispatch's redirect loop).
            link_base = resp.url if (resp.url and not resp.error) else norm
            # DETECT-16 (v4.2.3, live-caught on gruyere /saveprofile): the DISC-12
            # page-fetch of a GET-form's target lands on the SAME endpoint id as the
            # CRAWL_FORM endpoint created when the form was parsed — the
            # unconditional overwrite used to strip the CRAWL_FORM source and the
            # form_origin tag, and the stored-XSS detector silently skipped the
            # surface. A form registration is canonical for form-derived surfaces.
            if ep.id not in endpoints or endpoints[ep.id].source != DiscoverySource.CRAWL_FORM:
                endpoints[ep.id] = ep

            # ---- HTML parsing
            hp = _LinkParser(); hp.feed(resp.body)
            # R19-1: SPA hash-fragment routes on this page become
            # PROBEABLE endpoints via the route-target mapping, and the
            # mapped RESOURCE page (the lesson HTML with its forms) is
            # queued for page-fetch — same budget gates as any link. A
            # fragment is never fetched as itself (the server never sees
            # it); the mapped target is.
            for frag in hp.hash_routes:
                target = self._hash_route_target(link_base, frag)
                if not target:
                    continue
                ok_rt, _ = self.engine._scope_ok(target)
                if not ok_rt:
                    continue
                e_rt = self._mk_endpoint(target, DiscoverySource.CRAWL_HTML)
                if e_rt.id not in endpoints:
                    e_rt.tags.append("spa_route:" + frag[:80])
                    endpoints[e_rt.id] = e_rt
                if (target not in seen_pages
                        and not target.lower().endswith(_SKIP_AS_PAGE)):
                    queue.append(target)
            for href in hp.links:
                n = self._normalize(link_base, href)
                if n and urllib.parse.urlsplit(n).netloc == seed_host:
                    e2 = self._mk_endpoint(n, DiscoverySource.CRAWL_HTML)
                    if e2.id not in endpoints: endpoints[e2.id] = e2
                    # DISC-07 (live-caught on ginandjuice.shop): queue the FULL link URL
                    # including its query string. The old code queued e2.url — the
                    # endpoint's CLEANED url (query stripped) — so param'd pages were
                    # fetched as /catalog/product (HTTP 400) instead of
                    # /catalog/product?productId=1: every form, script and link on those
                    # pages was invisible (the whole XXE surface lived there).
                    # DISC-08: skip styling/media assets as page-fetches (budget waste).
                    # DISC-09 (live-caught on ginandjuice.shop): 18 near-identical
                    # product pages (?productId=1..18, same path) crowded the BFS queue
                    # and starved the JS assets behind them — xmlStockCheckPayload.js
                    # (the XXE hint) never got fetched. Template pages are capped per
                    # path; links beyond the cap stay ENDPOINTS (still probed), just not
                    # page-fetched.
                    if n not in seen_pages and not n.lower().endswith(_SKIP_AS_PAGE):
                        queue.append(n)
            for form in hp.forms:
                # OWSP-18b (OWASP campaign, live-caught on DVWA 3.x upload+csrf
                # forms): a fragment-only action="#" means SUBMIT TO SELF — the
                # standard HTML semantics. _normalize correctly drops fragments
                # for LINKS (a "#" anchor is a placeholder, not navigation), but
                # a FORM with action="#" still targets the current page; routing
                # it through _normalize returned "" and BOTH whole surfaces
                # (upload multipart, GET csrf) silently vanished from the static
                # map — the browser DOM path registered them later WITHOUT the
                # file-input marking and WITHOUT is_file.
                _act = (form["action"] or "").strip()
                if _act in ("", "#"):
                    _act = link_base
                action = self._normalize(link_base, _act)
                if not action: continue
                # OWSP-22: an off-scope form action (a donate form pointing
                # at a third-party host) is NOT our surface — live-caught on
                # Mutillidae: the PayPal donate form became an endpoint and
                # the batteries sent 140 unauthorized POSTs to production
                # PayPal. Skip at discovery; the transport-level _scope_ok is
                # the fail-closed second line.
                ok_act, _why = self.engine._scope_ok(action)
                if not ok_act:
                    self.crawl_skips = getattr(self, "crawl_skips", [])
                    if action not in self.crawl_skips:
                        self.crawl_skips.append(action)
                    continue
                # OWSP-03: the form's first submit control is flow control — its
                # name=value pair is required verbatim by gated routes (Spring
                # params="action=submit" filters); it must never be probed.
                _fc = {form["submitctl"]} if form.get("submitctl") else ()
                e3 = self._mk_endpoint(action, DiscoverySource.CRAWL_FORM,
                                       params=form["params"], method=form["method"],
                                       flow_control=_fc, file_names=form.get("files", ()))
                # DETECT-16 (v4.2.3): record WHERE the form was discovered — the
                # stored-XSS flow re-fetches this page for a fresh form round-trip
                # (rotating __VIEWSTATE / CSRF tokens) and uses it as a render
                # surface (a comment form's page is where the stored content renders).
                e3.tags.append("form_origin:" + norm)
                # same-id endpoints created earlier from a LINK or a page-fetch carry
                # the identical param-name set (the id hashes method+url+names) — the
                # form registration is the richer one (source + origin + the form's
                # own field values) and takes precedence.
                endpoints[e3.id] = e3
                # DISC-12 (live-caught on ginandjuice.shop /blog?search=): a GET form's
                # action URL IS a reachable page — the search-results page carries the
                # DOM source->sink script while the param-less index does NOT
                # (server-side conditional rendering). Forms only created ENDPOINTS,
                # never page-fetches, so the whole DOM surface was invisible: the
                # sink scanner never saw the script. Queue the form target with its
                # default params (same budget gates as links).
                if (form["method"] or "GET").upper() == "GET" and form["params"]:
                    sep = "&" if "?" in action else "?"
                    fq = action + sep + urllib.parse.urlencode(
                        [(n, v or "1") for n, v in form["params"][:6]])
                    if fq not in seen_pages and not fq.lower().endswith(_SKIP_AS_PAGE):
                        queue.append(fq)
            # DISC-10: div-based pseudo-forms (JS-driven submit) are real POST
            # surfaces — tagged so the JSON upgrade pass can find them later.
            for df in hp.divforms:
                action = self._normalize(link_base, df["action"] or link_base)
                if not action: continue
                # OWSP-22: div-pseudo-forms obey the same scope rule
                ok_df, _whydf = self.engine._scope_ok(action)
                if not ok_df:
                    continue
                e3b = self._mk_endpoint(action, DiscoverySource.CRAWL_FORM,
                                        params=df["params"], method=df["method"])
                e3b.tags.append("divform")
                if e3b.id not in endpoints: endpoints[e3b.id] = e3b
            # DISC-11: static DOM source->sink scan (inline scripts of THIS page)
            from .browser import scan_html_dom_sinks
            for sink in scan_html_dom_sinks(norm, resp.body):
                if sink.key() not in {s.key() for s in self.dom_sinks}:
                    self.dom_sinks.append(sink)
            # Phase 50: script-bearing HTML pages are the render candidates — runtime
            # forms/DOM logic only exist where scripts run (live-caught: the JS-built
            # form page fell outside a naive first-N selection and its surface was missed).
            if "<script" in resp.body.lower() and norm not in self.script_pages:
                self.script_pages.append(norm)

            # ---- JS static extraction
            if norm.endswith(".js") or "javascript" in resp.headers.get("content-type", ""):
                self._js_bodies.append((norm, resp.body))
                # DISC-11: DOM sinks in external JS assets too
                from .browser import scan_dom_sinks
                for sink in scan_dom_sinks(norm, resp.body):
                    if sink.key() not in {s.key() for s in self.dom_sinks}:
                        self.dom_sinks.append(sink)
                for pat in JS_PATTERNS:
                    for match in pat.findall(resp.body):
                        if not plausible_js_url(match):            # DISC-01 gate
                            continue
                        n = self._normalize(link_base, match)
                        if n and urllib.parse.urlsplit(n).netloc == seed_host:
                            js_hits.append(match)
                            e4 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                            if e4.id not in endpoints: endpoints[e4.id] = e4
                # DISC-06: learn JS-driven XML request transformations (XXE surface)
                if _JS_XML_CT.search(resp.body):
                    for root in _JS_XML_ROOT.findall(resp.body):
                        JS_XML_HINTS.add(root)
                # V411-WS: harvest WebSocket message shapes from JS assets (the
                # application's own client code is the observed schema source
                # for the WS elicitation/reflection battery)
                harvest_ws_shapes(resp.body)
                # V4.3.2: per-channel message builders (JSON keys + transforms)
                # for the active battery
                harvest_ws_bindings(resp.body)
                # V411-WS-DISC-2: observed ws:// channels — the DVWS pattern
                # (`var wsUri = "ws://host:8080/path"; new WebSocket(wsUri)`)`
                # hides the channel URL in a variable the literal-only
                # constructor pattern never saw; any quoted ws:// URL in the
                # app's own JS is an observed channel reference.
                for wu in observe_ws_urls(resp.body):
                    if wu not in self.ws_observed:
                        self.ws_observed.append(wu)
            else:
                # DISC-10 (part 2): the JSON-serialization hint may live in the
                # div-form page's OWN inline scripts (not only in external .js).
                # V411-WS: inline <script> bodies also carry the WebSocket
                # message builders — same observed-schema harvest.
                harvest_ws_shapes(resp.body)
                # V4.3.2: inline builders bind to their page's channels
                harvest_ws_bindings(resp.body)
                # V411-WS-DISC-2: inline <script> blocks are where DVWS keeps
                # `var wsUri = "ws://..."` — extract observed channels from
                # the SCRIPT bodies only (not the whole HTML: a ws:// string in
                # page TEXT would be documentation, not an observed channel).
                for blk in _INLINE_SCRIPT_RE.findall(resp.body):
                    for wu in observe_ws_urls(blk):
                        if wu not in self.ws_observed:
                            self.ws_observed.append(wu)
                if _JS_JSON_CT.search(resp.body) and _JS_JSONIFY.search(resp.body):
                    self._js_bodies.append((norm, resp.body))
                for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.body):
                    n = self._normalize(link_base, m)
                    if n and urllib.parse.urlsplit(n).netloc == seed_host and n not in seen_pages \
                            and not n.lower().endswith(_SKIP_AS_PAGE):
                        queue.append(n)
                # DISC-05: inline <script> bodies carry URL-shaped strings that the
                # link/form parsers never see (SPA config objects, category maps...).
                # Same plausible_js_url + same-host gates as .js asset extraction.
                # V411-WS-DISC (live-caught on DVGA): the WebSocket constructors
                # (`new WebSocket("ws://host/subscriptions")`) live in INLINE
                # scripts — running JS_PATTERNS on inline blocks is what surfaces
                # the subscriptions channel; the old query-only extraction
                # (requires a '?' in the URL) never saw it.
                for blk in _INLINE_SCRIPT_RE.findall(resp.body):
                    for pat in JS_PATTERNS:
                        for match in pat.findall(blk):
                            if not plausible_js_url(match):       # DISC-01 gate
                                continue
                            n = self._normalize(link_base, match)
                            if n and urllib.parse.urlsplit(n).netloc == seed_host:
                                e5 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                                if e5.id not in endpoints: endpoints[e5.id] = e5
                    for um in _INLINE_JS_URL_RE.findall(blk):
                        if not plausible_js_url(um):               # DISC-01 gate
                            continue
                        n = self._normalize(link_base, um)
                        if n and urllib.parse.urlsplit(n).netloc == seed_host:
                            e5 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                            if e5.id not in endpoints: endpoints[e5.id] = e5
        # ---- ENG-11 (Phase 56, live-caught during suite-isolation work): JS
        # assets discovered as ENDPOINTS (link/script-src extraction) but never
        # PAGE-FETCHED (the BFS page budget exhausted before their queue position)
        # used to teach NOTHING — the XXE XML-root teacher asset sat at queue
        # position ~35 behind a 30-page budget, so scans silently lost the whole
        # JS-learned surface whenever a bigger scan happened not to run first.
        # Every discovered same-host .js endpoint is now fetched (bounded) and
        # feeds the SAME hint extraction as page-fetched assets — deterministic,
        # independent of page-budget luck.
        js_eps = [ep for ep in endpoints.values()
                  if ep.url.split("?")[0].lower().endswith(".js")
                  and ep.url not in seen_pages][:12]
        for ep in js_eps:
            resp = self.engine.send(_simple_get(ep.url))
            if resp.error or not resp.body:
                continue
            self._js_bodies.append((ep.url, resp.body))
            for pat in JS_PATTERNS:
                for match in pat.findall(resp.body):
                    if not plausible_js_url(match):            # DISC-01 gate
                        continue
                    n = self._normalize(ep.url, match)
                    if n and urllib.parse.urlsplit(n).netloc == seed_host:
                        js_hits.append(match)
                        e4 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                        if e4.id not in endpoints: endpoints[e4.id] = e4
            # V411-WS-DISC-2: same observed-channel harvest for tail-fetched JS
            for wu in observe_ws_urls(resp.body):
                if wu not in self.ws_observed:
                    self.ws_observed.append(wu)
            # V4.3.2: same builder harvest for tail-fetched JS
            harvest_ws_bindings(resp.body)
            # DISC-06: learn JS-driven XML request transformations (XXE surface)
            if _JS_XML_CT.search(resp.body):
                for root in _JS_XML_ROOT.findall(resp.body):
                    JS_XML_HINTS.add(root)
        # ---- DISC-10 upgrade pass: div-forms whose JS serializes inputs as JSON
        # get ParamLocation.JSON (ENG-04 then renders them as JSON bodies — the
        # request shape the target's own JavaScript produces). Hint learned from
        # ANY fetched JS asset (deterministic set, same crawl order every run).
        if any(_JS_JSON_CT.search(b) and _JS_JSONIFY.search(b) for _, b in self._js_bodies):
            for ep in endpoints.values():
                if "divform" in ep.tags:
                    for p in ep.parameters:
                        p.location = ParamLocation.JSON
        return list(endpoints.values()), js_hits, {"pages": pages, "unique_endpoints": len(endpoints),
                                                   "dom_sink_candidates": len(self.dom_sinks)}

    def robots(self, base: str) -> list[Endpoint]:
        resp = self.engine.send(_simple_get(base.rstrip("/") + "/robots.txt"))
        out = []
        if resp.ok and resp.body:
            for line in resp.body.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")) and len(line.split(":", 1)[1].strip()) > 1:
                    n = self._normalize(base, line.split(":", 1)[1].strip())
                    if n:
                        e = self._mk_endpoint(n, DiscoverySource.ROBOTS)
                        out.append(e)
        return out

    def openapi(self, base: str) -> tuple[list[Endpoint], dict | None]:
        """DISC-13: probe the well-known spec locations, parse the first valid
        OpenAPI/Swagger document. Returns ([endpoints], info|None) — the info dict
        lands in stats.openapi for auditability (which document, which version,
        how many paths). Honest: no spec found -> ([], None), never a guess."""
        import json as _json
        for p in OPENAPI_PROBE_PATHS:
            resp = self.engine.send(_simple_get(base.rstrip("/") + p))
            if not resp.ok or not (resp.body or "").lstrip().startswith("{"):
                continue
            try:
                spec = _json.loads(resp.body)
            except ValueError:
                continue
            if "paths" not in spec:
                continue
            eps = parse_openapi(spec, base)
            return eps, _spec_info(spec, p, len(eps))
        return [], None


def _simple_get(url: str):
    from .http_engine import RequestMutation
    from .core import Endpoint as E, Parameter, ParamLocation
    # DISC-07 (part 2): _render rebuilds the request URL from ep.parameters, NOT from
    # ep.url's raw query — a bare Endpoint(url=...) silently DROPPED the query string,
    # so param'd pages were fetched without their params (live-caught on ginandjuice.shop:
    # /catalog/product?productId=1 fetched as /catalog/product -> 400, hiding the whole
    # product-page attack surface). Parse the query into parameters so it survives.
    from urllib.parse import parse_qsl, urlsplit
    q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    params = [Parameter(n, ParamLocation.QUERY, v).classify() for n, v in q]
    ep = E(url=url, parameters=params)
    return RequestMutation(endpoint=ep, note="discovery")


def extract_query_params(url: str) -> list[tuple[str, str]]:
    return [(k, v[0]) for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True).items()]


# ============================================================ DISC-13: OpenAPI seeding
OPENAPI_PROBE_PATHS = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs")


def _loopback_normalize(spec_root: str, base: str) -> str:
    """BFLA-2b (crAPI live round, 2026-11-02, run 41491090217): crAPI's own
    spec declares its server as localhost:8888 while the scan targets
    127.0.0.1:8888 — the resulting endpoints sat OUTSIDE the scan's host
    scope, every battery replay through a scope-checked engine was silently
    refused (HTTP 0), the BFLA privileged oracle read "failed" on a request
    that never left the engine, and the zombie family recorded a VACUOUS
    TESTED_NEGATIVE ("the spec and the live surface agree") over all-refused
    probes. Loopback<->loopback with matching scheme+port is the SAME
    machine by definition: normalize the spec root onto the scan base.
    Non-loopback mismatches keep DISC-13 semantics (the spec's declaration
    stands; the scope gate decides — and 3G now reports refused probes
    honestly instead of claiming agreement)."""
    try:
        a = urllib.parse.urlsplit(spec_root)
        b = urllib.parse.urlsplit(base)
        if not (a.scheme and a.netloc and b.scheme and b.netloc):
            return spec_root
        if a.scheme != b.scheme or a.port != b.port:
            return spec_root
        ah = (a.hostname or "").lower()
        bh = (b.hostname or "").lower()
        loopback = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if ah in loopback and bh in loopback and ah != bh:
            return urllib.parse.urlunsplit((b.scheme, b.netloc, a.path, "", ""))
    except Exception:
        pass
    return spec_root


def parse_openapi(spec: dict, base_url: str) -> list[Endpoint]:
    """DISC-13 (Phase 54): an OpenAPI/Swagger document is a machine-readable attack
    surface map the TARGET ITSELF publishes — endpoints invisible to any crawler
    (unlinked admin/legacy/API paths) are declared there with their parameters.
    Parses paths -> method -> parameters (query + path; JSON request bodies) into
    standard Endpoints. Scope-gating and dedup happen in the orchestrator exactly
    like crawl results — a spec entry is a LEAD, never a bypass of scope policy."""
    import json as _json
    out: list[Endpoint] = []
    base = base_url.rstrip("/")
    servers = spec.get("servers") or []
    root = base
    if servers and isinstance(servers, list) and servers[0].get("url", "").startswith("http"):
        root = servers[0]["url"].rstrip("/")
    root = _loopback_normalize(root, base)
    paths = spec.get("paths") or {}
    for path, ops in (paths.items() if isinstance(paths, dict) else []):
        if not isinstance(ops, dict):
            continue
        url = root + (path if path.startswith("/") else "/" + path)
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            params = []
            for prm in op.get("parameters", []) or []:
                if not isinstance(prm, dict) or "name" not in prm:
                    continue
                # MAX-05 (maximum internal test, live-caught on Juice Shop 20.2.0):
                # spec "in": "path" parameters were mapped to QUERY with an empty
                # value, so /rest/basket/{id} went out with LITERAL braces (404) —
                # the entire path-parameter REST surface was invisible to passive,
                # active AND the authz matrix (the Juice Shop BOLA basket class).
                # Path params are now PATH-located and carry a concrete default
                # (declared example, else "1") that _render substitutes into the
                # URL template on every request.
                #
                # OWSP-06 (OWASP campaign, live-caught on the OWASP Benchmark):
                # `in: header` and `in: cookie` parameters were BOTH collapsed to
                # QUERY — payloads aimed at getHeader()/getCookies() surfaces went
                # out as query strings and never reached the sink (on the
                # Benchmark: 657 declared header params + 216 cookie params, every
                # one of those tests un-probeable). The declared location is now
                # preserved; _render dispatches HEADER payloads as request headers
                # and COOKIE payloads as jar-overriding cookie values (OWSP-07).
                in_mode = prm.get("in", "query")
                if in_mode == "path":
                    loc = ParamLocation.PATH
                    default_val = str((prm.get("schema") or {}).get("example", "")
                                      or prm.get("example", "") or "1")
                elif in_mode == "header":
                    loc = ParamLocation.HEADER
                    default_val = str((prm.get("schema") or {}).get("example", "")
                                      or prm.get("example", "") or "burhan")
                elif in_mode == "cookie":
                    loc = ParamLocation.COOKIE
                    default_val = str((prm.get("schema") or {}).get("example", "")
                                      or prm.get("example", "") or "burhan")
                else:
                    loc = ParamLocation.QUERY
                    # LIVE-CAUGHT (crAPI live run 41424841547 — the first
                    # real-world spec through this parser): a query param
                    # may declare a NON-STRING example ("limit": 30, an
                    # int). The path/header/cookie branches above already
                    # str()-wrap theirs; the query branch did not, and
                    # Parameter.classify called .strip() on the raw int
                    # -> AttributeError, killing the whole scan. Every
                    # example value enters Parameter as a string.
                    default_val = str(prm.get("schema", {}).get("example", "")
                                      or "")
                params.append(Parameter(prm["name"], loc, default_val).classify())
            body = (op.get("requestBody") or {}).get("content", {})
            if "application/json" in body:
                for fld in ((body["application/json"].get("schema") or {}).get("properties") or {}).keys():
                    params.append(Parameter(fld, ParamLocation.JSON, "").classify())
            # OWSP-06 (cont.): application/x-www-form-urlencoded request bodies
            # were dropped ENTIRELY at import — 1311 Benchmark POST endpoints
            # lost their declared form fields (the spec declares form params in
            # requestBody, not in parameters). Form fields import as BODY params
            # exactly like a parsed HTML form would produce.
            # SQ-1 (sqli recall round, live-caught on the OWASP Benchmark master
            # = v1.2): the schema DEFAULT is the value the app's resolver hunts
            # — the benchmark's resolver servlets scan getParameterNames() for
            # the param whose VALUE equals the endpoint basename (declared as
            # `"whatever": {"type": "string", "default": "BenchmarkTest00037"}`)
            # and interpolate that param's NAME into the SQL. Importing fields
            # with a blank value dropped the burhan, so the name-channel
            # battery (nminj: payload-as-NAME, value verbatim) could never
            # resolve — live: 3/3 resolver FNs silent in the minispec round
            # until the default rode the probe. HTML forms already carried
            # their value= attributes; this mirrors that for specs.
            if "application/x-www-form-urlencoded" in body:
                for fld, fschema in ((body["application/x-www-form-urlencoded"]
                                      .get("schema") or {}).get("properties") or {}).items():
                    _dv = str((fschema or {}).get("default", "")
                              or (fschema or {}).get("example", "") or "")
                    params.append(Parameter(fld, ParamLocation.BODY, _dv).classify())
            out.append(Endpoint(url=url, method=method.upper(), parameters=params,
                                source=DiscoverySource.SEED, tags=["openapi"]))
    return out


def _spec_info(spec: dict, url: str, n_endpoints: int) -> dict:
    return {"source": url, "version": str(spec.get("openapi") or spec.get("swagger") or "?"),
            "title": str((spec.get("info") or {}).get("title") or ""), "paths": n_endpoints}
