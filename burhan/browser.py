"""Phase 50: Browser/DOM Engine — the documented browser phase.

Two layers, deliberately separated:

1) STATIC DOM analysis (browserless, always active): DomSinkScanner finds
   source->sink flows in inline/external JS (location.search/hash,
   URLSearchParams, document.referrer -> document.write, innerHTML, eval...).
   Live-proven necessity on ginandjuice.shop /blog?search: the param is read
   client-side from URLSearchParams and written straight into document.write —
   the SERVER NEVER REFLECTS IT, so a DOM-less DAST is structurally blind.

2) REAL browser (Playwright/Chromium, optional with graceful degradation):
   BrowserEngine renders pages (runtime forms incl. JS-built ones a static
   parser can never see), records XHR/fetch traffic, and proves DOM XSS by
   EXECUTION: the probe payload sets window.__BURHAN_XSS__=<canary> inside
   an onerror handler — the flag only exists if the payload was parsed as
   REAL MARKUP by a dangerous sink (reflection alone proves nothing).

Verification contract (BR-01): a candidate fires with canary A; verification
re-probes with a FRESH canary B — both must execute. Deterministic, no AI.
"""
from __future__ import annotations
import re, urllib.parse

from .core import DiscoverySource, Endpoint, Parameter, ParamLocation, Evidence

# ---------------------------------------------------------------- static scanner
# DOM sources: client-side readable attacker-controlled input channels.
_DOM_SOURCES = [
    ("location.search", "search"),
    ("location.hash", "hash"),
    ("URLSearchParams", "search"),          # reads from the query string
    ("document.referrer", "referrer"),
    ("window.name", "name"),
    ("document.URL", "search"),
    ("document.location", "search"),
]
# DOM sinks: anything that parses a string as HTML markup or JS code.
_DOM_SINKS = [
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "new Function", "srcdoc",
    "setTimeout('", "setInterval('", "$.html", ".html(", "DOMParser",
]

_GET_PARAM_RE = re.compile(r"""\.get\(\s*['"]([\w\-]{1,40})['"]\s*\)""")
# OWSP-19 (OWASP campaign, live-caught on DVWA 3.x /vulnerabilities/xss_d/):
# the href-slicing idiom — location.href.substring(location.href.indexOf("default=")+8)
# — reads the query param MANUALLY, with no URLSearchParams and no .get() call.
# The param-name extraction found nothing for such blocks, the probe list came
# back empty and the whole DOM XSS class was invisible on legacy apps (browser
# rendered 15 pages, dom_sink_candidates=4, browser_probes=0 — the silent-zero
# failure mode). Also covers split("param=") slicing.
_HREF_SLICE_PARAM_RE = re.compile(
    r"""(?:indexOf|lastIndexOf|split)\(\s*['"]([\w\-]{1,40})=['"]\s*\)""")
_SCRIPT_BLOCK_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)


class DomSink:
    __slots__ = ("url", "source", "sink", "params", "snippet")

    def __init__(self, url: str, source: str, sink: str, params: list, snippet: str):
        self.url, self.source, self.sink = url, source, sink
        self.params, self.snippet = params, snippet

    def key(self) -> str:
        return f"{self.url}|{self.source}|{self.sink}|{','.join(self.params)}"

    def __repr__(self):
        return f"DomSink({self.url} source={self.source} sink={self.sink} params={self.params})"


def scan_dom_sinks(url: str, js_code: str) -> list[DomSink]:
    """Static source->sink analysis over ONE script body (inline block or JS asset).
    A candidate requires BOTH a source pattern and a sink pattern in the SAME
    script — cross-file dataflow is out of scope (documented limit)."""
    out = []
    for src_pat, src_kind in _DOM_SOURCES:
        if src_pat not in js_code:
            continue
        for sink in _DOM_SINKS:
            if sink not in js_code:
                continue
            params = _GET_PARAM_RE.findall(js_code) if src_kind == "search" else []
            if src_kind == "search":
                _seen_p = set(params)
                for _pn in _HREF_SLICE_PARAM_RE.findall(js_code):
                    if _pn not in _seen_p:
                        params.append(_pn)
                        _seen_p.add(_pn)
            # deterministic snippet: 100 chars around the first sink occurrence
            i = js_code.find(sink)
            snippet = re.sub(r"\s+", " ", js_code[max(0, i - 60):i + 100]).strip()
            out.append(DomSink(url, src_kind, sink, params[:6], snippet[:160]))
            break        # one sink per source pattern is enough for planning
    # dedup by (source,sink) — a block may mention location.search twice
    seen, uniq = set(), []
    for s in out:
        k = f"{s.source}|{s.sink}"
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


def scan_html_dom_sinks(url: str, html: str) -> list[DomSink]:
    """Scan every inline <script> block of an HTML page (deterministic order)."""
    found = []
    for blk in _SCRIPT_BLOCK_RE.findall(html):
        found.extend(scan_dom_sinks(url, blk))
    return found


# ---------------------------------------------------------------- drivers
# R15-4 comprehensive root: EVERY synchronous playwright dispatch in the
# engine can wedge forever if SIGINT lands mid-dispatch (greenlet switch
# never resumes — proven live in render()'s page.close(), but the same
# _sync machinery guards goto/evaluate/content/... and impact.py's separate
# instance). Killing the NODE DRIVER process un-wedges whichever call is
# in flight. This module-level registry is the single place every driver
# reports to, so one kill sweep covers ALL of them.
_ACTIVE_DRIVERS: list = []      # [subprocess.Popen] — node drivers, alive

# The Python-level SIGINT handler CANNOT run while the main thread is
# blocked inside playwright's _sync (a C-level greenlet switch — the
# interpreter never regains control to dispatch the handler: proven live,
# stack pinned in the r15 evidence). signal.set_wakeup_fd() is the OS-level
# escape hatch: the kernel writes one byte into our pipe for EVERY signal
# the moment it arrives, regardless of what the main thread is doing. A
# dedicated monitor thread blocks on that pipe and kills all drivers on
# the first SIGINT byte — unwedging the main thread from OUTSIDE.
_WAKEUP_R, _WAKEUP_W = None, None
_MONITOR_THREAD = None

# Set by the CLI's SIGINT handler when a browser driver is alive: the abort
# is DEFERRED (no KeyboardInterrupt raised into the event-loop fiber — that
# kills the loop and wedges _sync forever; the pending task can then never
# complete no matter what dies). Instead the wakeup monitor kills the
# driver, the dead transport completes the task with a REAL error, the
# scan unwinds, and the CLI converts this flag into exit code 130.
_SIGINT_SEEN = None        # threading.Event | None (created lazily, main thread)


def sigint_seen() -> bool:
    return _SIGINT_SEEN is not None and _SIGINT_SEEN.is_set()


def mark_sigint_seen() -> None:
    global _SIGINT_SEEN
    import threading
    if _SIGINT_SEEN is None:
        _SIGINT_SEEN = threading.Event()
    _SIGINT_SEEN.set()


def any_driver_alive() -> bool:
    for proc in _ACTIVE_DRIVERS:
        try:
            alive = (proc.returncode is None) if hasattr(proc, "returncode") \
                else (proc.poll() is None)
            if alive:
                return True
        except Exception:  # noqa: BLE001
            pass
    return False


def register_driver(proc) -> None:
    """Report a live playwright node driver. Called by every code path that
    starts one (BrowserEngine._ensure, impact.py's browser replay). Also
    lazily arms the wakeup-pipe SIGINT monitor (idempotent)."""
    if proc is not None:
        _ACTIVE_DRIVERS.append(proc)
    _arm_sigint_monitor()


def _arm_sigint_monitor() -> None:
    """One wakeup-pipe + one monitor thread per PROCESS. The thread waits on
    the pipe; when SIGINT arrives the kernel drops a byte in it and the
    thread immediately SIGKILLs every registered driver (which un-wedges
    any in-flight _sync on the main thread — the transport died). The
    normal Python KeyboardInterrupt still fires afterwards as usual."""
    import os
    import signal as _signal
    import threading
    global _WAKEUP_R, _WAKEUP_W, _MONITOR_THREAD
    if _MONITOR_THREAD is not None and _MONITOR_THREAD.is_alive():
        return
    try:
        _WAKEUP_R, _WAKEUP_W = os.pipe()
        os.set_blocking(_WAKEUP_W, False)
        # keep the fd always-valid: set_wakeup_fd requires a non-blocking fd
        _signal.set_wakeup_fd(_WAKEUP_W)

        def _monitor():
            while True:
                try:
                    data = os.read(_WAKEUP_R, 64)
                except Exception:  # noqa: BLE001 — pipe closed at exit
                    return
                if not data:
                    return
                # os.read returns BYTES; iterating yields ints — the signal
                # NUMBER arrives as a raw byte (SIGINT == 2 == b"\x02").
                # The monitor must never die on a parse error: one TypeError
                # on the first signal left the driver alive and the main
                # thread wedged (live-caught in the r15 close-out).
                try:
                    if b"\x02" in data:        # SIGINT
                        kill_all_drivers()
                except Exception:  # noqa: BLE001 — keep watching regardless
                    continue

        _MONITOR_THREAD = threading.Thread(
            target=_monitor, daemon=True, name="sigint-driver-killer")
        _MONITOR_THREAD.start()
    except Exception:  # noqa: BLE001 — monitor is best-effort; handler still exists
        pass


import signal  # module-level: the monitor compares against SIGINT


def kill_all_drivers() -> int:
    """SIGKILL every registered driver still alive. Returns how many were
    signaled. Safe to call from a signal handler thread; killing the driver
    is process-level and needs no greenlet cooperation. Accepts both
    subprocess.Popen (classic) and asyncio's Process (playwright's driver —
    no .poll(); .returncode is the liveness oracle there)."""
    import signal as _signal
    killed = 0
    for proc in _ACTIVE_DRIVERS:
        try:
            alive = (proc.returncode is None) if hasattr(proc, "returncode") \
                else (proc.poll() is None)
            if alive:
                proc.send_signal(_signal.SIGKILL)
                killed += 1
        except Exception:  # noqa: BLE001 — best-effort unwedging
            pass
    _ACTIVE_DRIVERS.clear()
    return killed


# ---------------------------------------------------------------- availability
_AVAIL: bool | None = None


def browser_available() -> bool:
    """True iff Playwright + a launchable headless Chromium exist. Cached."""
    global _AVAIL
    if _AVAIL is not None:
        return _AVAIL
    try:
        from playwright.sync_api import sync_playwright
        p = sync_playwright().start()
        try:
            b = p.chromium.launch(headless=True,
                                  args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
            b.close()
            _AVAIL = True
        finally:
            p.stop()
    except Exception:
        _AVAIL = False
    return _AVAIL


# ---------------------------------------------------------------- browser engine
_FORM_JS = """() => {
  const out = [];
  document.querySelectorAll('form, [data-action]').forEach(el => {
    const action = el.getAttribute('action') || el.getAttribute('data-action') || location.pathname;
    const method = (el.getAttribute('method') || el.getAttribute('data-method') || 'GET').toUpperCase();
    const params = [];
    const files = [];
    let submitCtl = null;
    // OWSP-05 (OWASP campaign, live-caught on WrongSecrets 1.8.1): submit
    // controls (input[type=submit] AND <button>) carry the name=value pair the
    // route's params filter demands; dropping them made every browser-discovered
    // POST surface dead-on-arrival (uniform 405, wrong-session token replay).
    el.querySelectorAll('input[name], textarea[name], select[name], button[name]').forEach(i => {
      const t = (i.tagName === 'BUTTON') ? (i.type || 'submit') : (i.type || 'text');
      if (t === 'submit') {
        if (!submitCtl && i.name && i.value) { params.push([i.name, i.value]); submitCtl = i.name; }
      } else if (t === 'file') {
        // OWSP-18 (live-caught on DVWA 3.x upload form): file inputs are the
        // multipart upload surface — registered for the UploadDetector, never
        // probed as text by the string batteries.
        if (i.name) { params.push([i.name, '']); files.push(i.name); }
      } else if (t !== 'button' && t !== 'reset') {
        params.push([i.name, i.value || '']);
      }
    });
    if (params.length) out.push({action, method, params, files, tag: el.tagName, submitctl: submitCtl});
  });
  return out.slice(0, 25);
}"""

_LINKS_JS = """() => Array.from(document.querySelectorAll('a[href]'))
  .map(a => a.href).slice(0, 60)"""


class BrowserEngine:
    """Real-browser rendering + DOM XSS execution proofs. Scope-gated like the
    HTTP engine: navigation to out-of-scope hosts is refused before goto."""

    def __init__(self, engine, timeout: float = 12.0, extra_headers: dict | None = None):
        # engine: RequestEngine — owns the ScopeRule (single source of truth for scope)
        # extra_headers: session transport headers (Authorization: Bearer ...) the
        # context must mirror — otherwise every render of an auth-gated page bounces
        # to the login form exactly like a cookie-less render (AUTH-04 same lesson,
        # header flavor). LIVE-CAUGHT: orchestrator passed it before the engine
        # learned to accept it (9 tests red) — API contract fixed here permanently.
        self.engine, self.bus, self.timeout = engine, engine.bus, timeout
        self.extra_headers = {k: v for k, v in (extra_headers or {}).items()
                              if k.lower() != "user-agent"}
        self._pw = self._browser = self._context = None
        self.pages_rendered = 0
        self.probes_sent = 0

    # ---- lifecycle
    def _ensure(self):
        if self._context is not None:
            return
        # R15-4: never (re)start playwright after an interrupt — the old
        # dispatcher fiber is torn and every _sync call on it wedges.
        if sigint_seen():
            return
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
        # R15-4: this instance's node driver joins the module registry the
        # moment it exists — the SIGINT sweep must see it even if the signal
        # lands before the first render finishes.
        _d = self._browser_child_proc()
        if _d is not None:
            register_driver(_d)
        from .http_engine import USER_AGENT   # version-derived: one UA across engine+browser
        self._context = self._browser.new_context(ignore_https_errors=True,
                                                  user_agent=USER_AGENT)
        if self.extra_headers:
            # header-based auth must ride along with cookie-based sessions (AUTH-04)
            self._context.set_extra_http_headers(self.extra_headers)

    def _sync_session_cookies(self, url: str):
        """AUTH-04: the browser context must carry the SAME session as the HTTP
        engine — otherwise every render of an auth-gated page bounces to the
        login form and the whole authenticated DOM surface is invisible to the
        browser phase (live-caught class: jar cookies exist, Chromium starts
        anonymous). Syncs the engine jar into the Playwright context before each
        navigation; Playwright keeps cookies per-domain, mirroring the jar."""
        try:
            jar = getattr(self.engine, "cookie_jar", None) or {}
            host = urllib.parse.urlsplit(url).hostname or ""
            cks = []
            for jh, pairs in jar.items():
                if jh != host:
                    continue
                for n, v in pairs.items():
                    cks.append({"name": n, "value": v, "domain": jh, "path": "/"})
            if cks:
                self._context.add_cookies(cks)
        except Exception as e:
            self.bus.emit("BrowserCookieSyncError", error=f"{type(e).__name__}: {e}"[:150])

    # R15-4: SIGINT can land while the sync-playwright channel is mid-
    # dispatch; the greenlet switch never resumes and close() blocks forever
    # in playwright's _sync_base (live-proven: stack pinned in the r15
    # phase-D diagnosis — process alive 60s after Ctrl-C, main thread stuck
    # in playwright's _sync during browser.close()).
    # Constraints discovered the hard way:
    #   - sync-playwright CANNOT be driven from another thread
    #     (greenlet: "cannot switch to a different thread" — proven live), so
    #     a worker-thread watchdog is useless for CALLING close;
    #   - but KILLING the browser's child process from a watchdog thread is
    #     thread-safe and un-wedges the pending _sync dispatch (the transport
    #     dies, the call returns/raises, teardown completes).
    # So: close() runs on the caller's thread as before; a watchdog timer
    # arms before it and hard-kills the browser child if close() overstays.
    CLOSE_WATCHDOG_S = 10.0

    def _browser_child_proc(self):
        """The playwright-managed node driver process of this engine, if any.

        Path verified live against playwright 1.57: the SYNC wrapper keeps
        the implementation on ``_impl_obj`` (Playwright -> _connection ->
        PipeTransport -> _proc). Killing THIS process tears down the whole
        browser tree AND un-wedges any pending sync dispatch whose transport
        just died."""
        try:
            impl = getattr(self._pw, "_impl_obj", None)
            conn = getattr(impl, "_connection", None)
            proc = getattr(conn, "_transport", None)
            child = getattr(proc, "_proc", None)
            if child is not None and hasattr(child, "send_signal"):
                return child
        except Exception:  # noqa: BLE001
            pass
        return None

    def close(self):
        # explicit ordered teardown (attributes may be partially initialized)
        import threading
        # R15-4: after an interrupt the playwright sync channel is dead
        # (torn dispatcher fiber — ANY _sync call, even on a killed driver,
        # hangs forever: live-proven). The monitor already SIGKILLed the
        # driver; the browser tree died with it. Only clear our references.
        if sigint_seen():
            self._context = self._browser = self._pw = None
            return
        child = self._browser_child_proc()
        fired = threading.Event()

        def _watchdog():
            if not fired.wait(self.CLOSE_WATCHDOG_S):
                c = child or self._browser_child_proc()
                if c is not None:
                    self.bus.emit("BrowserCloseWatchdogFired",
                                  detail=f"playwright teardown exceeded "
                                         f"{self.CLOSE_WATCHDOG_S}s — killing the "
                                         f"browser child to un-wedge the close")
                    try:
                        import signal as _signal
                        c.send_signal(_signal.SIGKILL)
                    except Exception:  # noqa: BLE001
                        pass

        wd = threading.Thread(target=_watchdog, daemon=True,
                              name="browser-close-watchdog")
        wd.start()
        try:
            if self._context is not None:
                try:
                    self._context.close()
                except Exception:  # noqa: BLE001 — teardown must never raise
                    pass
            if self._browser is not None:
                try:
                    self._browser.close()
                except Exception:  # noqa: BLE001
                    pass
            if self._pw is not None:
                try:
                    self._pw.stop()
                except Exception:  # noqa: BLE001
                    pass
        finally:
            fired.set()  # disarm the watchdog
            self._context = self._browser = self._pw = None

    def _ok(self, url: str) -> bool:
        ok, why = self.engine._scope_ok(url)
        if not ok:
            self.bus.emit("BrowserNavBlocked", url=url, reason=why)
        return ok

    # ---- render (runtime discovery)
    def render(self, url: str, settle_ms: int = 500) -> dict:
        """Load a page in Chromium; return rendered DOM intelligence:
        {url, html, forms, links, xhrs, js_errors}. None = scope-blocked/failed."""
        # R15-4: after an interrupt the sync channel is dead — EVERY call
        # wedges. The whole browser phase stands down (the monitor already
        # killed the driver; pages die with it).
        if sigint_seen():
            return None
        if not self._ok(url):
            return None
        self._ensure()
        if self._context is None:
            # _ensure stood down post-interrupt (or failed): no browser work
            return None
        self._sync_session_cookies(url)
        xhrs: list[dict] = []
        # r18-8.8: the WHOLE render body is guarded now. The macOS run-6
        # log (job ...128718604644) showed the r15 SIGINT test failing
        # with rc=1 (not 130): the wakeup monitor SIGKILLs the driver the
        # instant SIGINT lands, and any playwright call raised BEFORE the
        # old try-block started — new_page()/page.on() sat outside it —
        # escaped render() through render_merge (unguarded) up to the
        # CLI's generic `except Exception: raise` => exit 1. Linux wins
        # the race differently (dispatch already inside goto), which is
        # why the same code passed locally: rc=130, browser cleaned.
        try:
            page = self._context.new_page()
            page.on("request", lambda req: xhrs.append({
                "method": req.method, "url": req.url,
                "post_data": req.post_data or "",
                "content_type": (req.headers or {}).get("content-type", ""),
            }) if req.resource_type in ("xhr", "fetch") else None)
            page.goto(url, wait_until="load", timeout=int(self.timeout * 1000))
            page.wait_for_timeout(settle_ms)
            self.pages_rendered += 1
            return {
                "url": url,
                "html": page.content(),
                "forms": page.evaluate(_FORM_JS) or [],
                "links": page.evaluate(_LINKS_JS) or [],
                "xhrs": xhrs,
            }
        except Exception as e:
            self.bus.emit("BrowserRenderError", url=url, error=f"{type(e).__name__}: {e}"[:200])
            return None
            # r18-8.8 note: no page.close() here — after an interrupt the
            # sync channel is dead and ANY further playwright call (even
            # close on an already-killed driver) wedges forever; the old
            # finally-block did this correctly for the sigint case and it
            # is preserved below for the ordinary (non-interrupt) one.
        finally:
            # R15-4: after an interrupt, ANY further sync-playwright call
            # wedges forever (the signal tore the dispatcher fiber; proven
            # live — page.close on a dead driver still hangs). The driver
            # is already SIGKILLed by the monitor, so the page dies with
            # it; calling page.close() here would hang the scan.
            if not sigint_seen() and "page" in locals() and page is not None:
                try:
                    page.close()
                except Exception:  # noqa: BLE001 — teardown must never raise
                    pass

    def render_merge(self, pages: list[str], seed_host: str, existing: dict) -> list[Endpoint]:
        """Render pages and return NEW endpoints discovered only at runtime
        (JS-built forms, rendered links, observed XHR/fetch). Dedup via endpoint id
        against `existing` (id -> Endpoint); caller merges the returned list."""
        new_eps: list[Endpoint] = []
        for url in pages:
            r = self.render(url)
            if not r:
                continue
            # runtime forms (JS-built included — invisible to the static parser)
            for f in r["forms"][:25]:
                ep = _mk_dom_endpoint(f["action"] if "://" in f["action"] else
                                      urllib.parse.urljoin(url, f["action"]),
                                      url, f["method"], f["params"], json_hint=None,
                                      submitctl=f.get("submitctl"),
                                      file_names=f.get("files") or ())
                if ep and ep.id not in existing and ep.id not in [e.id for e in new_eps]:
                    new_eps.append(ep)
            # rendered links (client-side routing / JS-generated anchors)
            for href in r["links"][:60]:
                full = urllib.parse.urljoin(url, href)
                if urllib.parse.urlsplit(full).netloc == seed_host:
                    ep = _mk_dom_endpoint(full, url, "GET", [], json_hint=None)
                    if ep and ep.id not in existing and ep.id not in [e.id for e in new_eps]:
                        new_eps.append(ep)
        return new_eps

    # ---- DOM XSS execution probe
    PROBE_FLAG = "window.__BURHAN_XSS__"

    def _probe_variants(self, canary: str) -> list[tuple[str, str]]:
        """(name, payload) battery — WAF-resistant (BR-02, live-proven on
        ginandjuice.shop /blog?search): the target's tag-name + event-handler
        blacklist (400 on <img/<svg/<x onfocus=...) is DEFEATED by attribute
        injection — no '<' at all: close the sink template's attribute, add
        onload/onerror to the SERVER'S OWN tag. onload fires when the sink
        resource loads (200), onerror when it fails (404). Breakout and raw
        variants cover non-WAF attribute and element contexts."""
        img = f'<img src=x onerror="{self.PROBE_FLAG}=\u0027{canary}\u0027">'
        # OWSP-19b (OWASP campaign, live-caught on DVWA /vulnerabilities/xss_d/):
        # the HTML spec's in-select insertion mode DROPS <img> (and most other
        # tags) — only option/optgroup/hr/script/template survive. A sink that
        # document.write's into a <select> (language selectors, dropdown builders)
        # executes NOTHING from the whole img battery; the DVWA-official payload
        # class is the <script> tag. Script variants run the SAME canary-only
        # flag (no alert(), no side effects) and only fire when parsed as markup
        # by the sink — the same execution proof, no wider blast radius.
        scr = f"<script>{self.PROBE_FLAG}='{canary}'</script>"
        return [
            ("attr_inject_onerror", f'" onerror="{self.PROBE_FLAG}=\u0027{canary}\u0027"'),
            ("attr_inject_onload",  f'" onload="{self.PROBE_FLAG}=\u0027{canary}\u0027"'),
            ("attr_breakout_double", f'">{img}'),
            ("raw_markup",           img),
            ("attr_breakout_single", f"'>{img}"),
            ("script_breakout_single", f"'>{scr}"),
            ("raw_script",              scr),
        ]

    def probe_dom_xss(self, url: str, param: str, canary: str, source: str = "search") -> dict | None:
        """Navigate with the execution-canary in the DOM source; return
        {fired, canary, variant, url, detail} when the flag is set (= payload
        executed as markup), else None. The flag can ONLY be set by the browser
        parsing our <img> tag — reflection without markup execution never fires."""
        variants = self._probe_variants(canary)
        for vname, payload in variants:
            if source == "hash":
                # OWSP-19c: minimal encoding — decodeURI-class DOM decoders do NOT
                # decode URI-reserved characters (%3D '=', %2F '/', %26 '&', %2B '+',
                # %2C ','): a fully-percent-encoded payload reaches the sink with
                # %3D in place of every assignment and %2F inside </script>, and
                # dies as a JS syntax error (live-caught on DVWA xss_d: the whole
                # battery fired 28 probes, 0 executions, because decodeURI kept
                # the operators encoded). JS-syntax characters stay RAW in the
                # fragment/query (browsers pass <, >, ', =, / through untouched);
                # only URL-structure breakers are percent-encoded.
                target = url.split("#")[0] + "#" + urllib.parse.quote(
                    payload, safe="()<>'=;,.:!*-")
            else:
                base = url.split("#")[0]
                # preserve the page's own query params; force our param in
                qs = urllib.parse.parse_qsl(urllib.parse.urlsplit(base).query, keep_blank_values=True)
                qs = [(k, v) for k, v in qs if k != param]
                parts = urllib.parse.urlsplit(base)
                _others = "&".join(
                    f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
                    for k, v in qs)
                # OWSP-19c (same as the hash branch): the probe payload keeps its
                # JS-syntax characters raw — see the comment above.
                _pq = urllib.parse.quote(payload, safe="()<>'=;,.:!*-")
                qstr = ((_others + "&") if _others else "") + f"{param}={_pq}"
                target = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                                  qstr, ""))
            if sigint_seen():
                return None      # R15-4: dead channel — stand down
            if not self._ok(target):
                return None
            self._ensure()
            if self._context is None:
                return None
            self._sync_session_cookies(target)
            # r18-8.8: same guard as render() — a SIGINT-kill of the driver
            # can land between new_page() and the try-block and escape as
            # an unhandled exception (the rc=1 leak, macOS run 6)
            try:
                page = self._context.new_page()
            except Exception as e:  # noqa: BLE001 — probe must never crash the scan
                self.bus.emit("BrowserRenderError", url=target,
                              error=f"new_page: {type(e).__name__}: {e}"[:150])
                return None
            try:
                page.goto(target, wait_until="load", timeout=int(self.timeout * 1000))
                page.wait_for_timeout(800)          # let onerror fire deterministically
                self.probes_sent += 1
                got = page.evaluate(f"({self.PROBE_FLAG} || '')")
                if got == canary:
                    return {"fired": True, "canary": canary, "variant": vname,
                            "url": url, "param": param, "source": source,
                            "detail": f"payload executed as markup via {vname} — "
                                      f"{self.PROBE_FLAG} set in live DOM"}
            except Exception as e:
                self.bus.emit("BrowserProbeError", url=target, error=f"{type(e).__name__}: {e}"[:200])
            finally:
                # R15-4: same interrupt guard as render() — a post-interrupt
                # page.close() wedges the engine forever.
                if not sigint_seen():
                    page.close()
        return None


def _mk_dom_endpoint(action_url: str, page_url: str, method: str, params: list,
                     json_hint, submitctl: str | None = None,
                     file_names: tuple | list = ()) -> Endpoint | None:
    """Build an Endpoint from a browser-observed form/link, mirroring the static
    discovery conventions (params classified; location follows the method)."""
    p = urllib.parse.urlsplit(action_url)
    if p.scheme not in ("http", "https"):
        return None
    qs = [(k, v[0]) for k, v in urllib.parse.parse_qs(p.query, keep_blank_values=True).items()]
    plist = [Parameter(n, ParamLocation.QUERY, v).classify() for n, v in qs]
    m = (method or "GET").upper()
    loc = ParamLocation.BODY if m in ("POST", "PUT", "PATCH") else ParamLocation.QUERY
    for n, v in (params or [])[:12]:
        pobj = Parameter(n, loc, v).classify()
        # OWSP-05: the form's first submit control is flow control — carried
        # verbatim, never probed (route params filters demand the literal).
        if submitctl and n == submitctl:
            pobj.flow_control = True
        # OWSP-18: file inputs are the upload surface, not text fields
        if n in (file_names or ()):
            pobj.is_file = True
        plist.append(pobj)
    clean = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    return Endpoint(url=clean, method=m, parameters=plist, source=DiscoverySource.DOM,
                    tags=["dom"])
