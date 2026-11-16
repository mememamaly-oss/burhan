"""Phase 48 (architecture continuation): REST API + Web UI for the Burhan platform.

Pure stdlib (ThreadingHTTPServer) — same zero-dependency contract as the core.

Endpoints:
  GET  /                     → web dashboard (single self-contained HTML page)
  GET  /api/health           → {status, version, uptime_s, scans_running}
  GET  /api/runs             → persisted runs (newest first)
  GET  /api/runs/{id}        → one run + findings + rejected candidates
  GET  /api/findings         → cross-run query (type, min_risk, run_id, status, limit)
  GET  /api/stats            → aggregate statistics + recurring + latest delta
  POST /api/scans            → launch a scan in a background thread → 202 {run_id}
  GET  /api/scans/{run_id}   → async scan status: queued|running|done|failed (+report)

Security posture (a scanner's control plane must not become the vulnerability):
  - Binds 127.0.0.1 by default.
  - Binding a non-loopback host REQUIRES --token; requests must carry X-Auth-Token.
  - The scan target is still enforced by the Scope engine (private-space blocked
    unless explicitly allowed per scan request).
"""
from __future__ import annotations
import json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from .core import VERSION
from .store import Store
from .orchestrator import BurhanScanner, ScanConfig

_STARTED = time.time()
_LOCK = threading.Lock()
_SCANS: dict[str, dict] = {}          # run_id -> {state, started, finished, report, error}
MAX_CONCURRENT_SCANS = 2


# ---------------------------------------------------------------- scan manager
def launch_scan(store: Store, target: str, max_pages: int = 25, allow_private: bool = False,
                timeout: float = 12.0, seed: str | None = None, strategy_path: str | None = None) -> dict:
    """Create the scanner, register its run_id, and execute in a daemon thread.
    Phase 52: channel-aware OAST arming — local listener for lab targets, PUBLIC
    webhook channel for remote targets (auto policy, honest None on outage).
    r19-2 (order 2026-11-16 item 1b): the ownership gate runs HERE, before
    the scanner is even built — an unauthorized target never gets a run_id
    and ZERO requests are sent (the API wrapper surfaces the refusal as a
    503-shaped error payload rather than exit code 2, which is the CLI's
    channel; the web UI shows the banner text)."""
    from .authorized_targets import authorize, _banner, DEFAULT_REGISTRY
    ok, reason, entry_id = authorize(target)
    if not ok:
        banner = _banner(DEFAULT_REGISTRY, "target refused", reason)
        print(banner, flush=True)   # server log
        return {"error": "scan refused by the authorization gate",
                "detail": reason, "refusal_banner": banner}
    from .core import is_private_ip
    from urllib.parse import urlparse
    from .oast import make_oast
    oast = make_oast(urlparse(target).hostname or "", mode="auto")
    cfg = ScanConfig(allow_private=allow_private, max_pages=max_pages,
                     timeout=timeout, seed=seed, strategy_path=strategy_path, oast=oast)
    sc = BurhanScanner(target, cfg)
    entry = {"state": "queued", "run_id": sc.run_id, "target": target,
             "started": time.time(), "finished": None, "report": None, "error": None}
    with _LOCK:
        running = sum(1 for s in _SCANS.values() if s["state"] in ("queued", "running"))
        if running >= MAX_CONCURRENT_SCANS:
            if oast is not None:
                oast.stop()
            return {"error": f"scan queue full (max {MAX_CONCURRENT_SCANS} concurrent)"}
        _SCANS[sc.run_id] = entry

    def _work():
        entry["state"] = "running"
        try:
            report = sc.run()
            store.save_run(report)               # auto-persist every API-launched scan
            entry["report"] = report
            entry["state"] = "done"
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {e}"
            entry["state"] = "failed"
        finally:
            entry["finished"] = time.time()
            if oast is not None:
                oast.stop()

    threading.Thread(target=_work, daemon=True, name=f"scan-{sc.run_id}").start()
    return {"run_id": sc.run_id, "state": "queued", "target": target}


def scan_status(run_id: str) -> dict | None:
    with _LOCK:
        e = _SCANS.get(run_id)
        return dict(e) if e else None


# ---------------------------------------------------------------- UI (single page)
def dashboard_html() -> str:
    return """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Burhan — DAST Console</title>
<style>
:root{--bg:#0d1117;--panel:#161c24;--line:#253040;--txt:#e6edf3;--dim:#8b98a5;--red:#e74c3c;--grn:#2ecc71;--ylw:#f1c40f;--blu:#3498db;--org:#e67e22}
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--txt)}
header{display:flex;align-items:center;gap:14px;padding:16px 26px;background:linear-gradient(135deg,#141b24,#1b2634);border-bottom:3px solid var(--red)}
header h1{font-size:19px;margin:0;letter-spacing:1px}header .tag{font-size:10.5px;color:var(--dim);border:1px solid var(--line);border-radius:12px;padding:3px 10px}
main{padding:20px 26px;max-width:1400px;margin:0 auto}
h2{font-size:13.5px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin:22px 0 10px}
.stats{display:flex;gap:12px;flex-wrap:wrap}.stat{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px 22px;min-width:120px;text-align:center}
.stat b{display:block;font-size:26px}.stat span{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
form{display:flex;gap:8px;flex-wrap:wrap;background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px}
input,select{background:#0b0f14;color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:13px}
input[name=target]{flex:1;min-width:260px}button{background:var(--red);color:#fff;border:0;border-radius:6px;padding:8px 18px;font-size:13px;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.15)}button:disabled{opacity:.5;cursor:default}
table{width:100%;border-collapse:collapse;font-size:12.5px}th{text-align:left;padding:8px;background:var(--panel);color:var(--dim);font-size:10.5px;text-transform:uppercase;letter-spacing:.5px}
td{padding:8px;border-bottom:1px solid #1d2733;vertical-align:top}.u{font-family:monospace;color:#7fd;font-size:11.5px;word-break:break-all}
code{color:#ffd479;font-family:monospace}.pill{border-radius:10px;padding:2px 9px;font-size:10px;font-weight:700;text-transform:uppercase;color:#fff}
.ev{font-size:10.5px;color:#9aa8b5;font-family:monospace}.bar{height:4px;background:#1d2733;border-radius:2px;overflow:hidden;margin-top:8px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--red),var(--org));width:0;transition:width .5s}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.ok{background:var(--grn)}.run{background:var(--ylw)}.fail{background:var(--red)}
#msg{font-size:12px;margin:8px 2px;color:var(--dim);min-height:16px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px 16px;font-size:12.5px;margin-top:10px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:900px){.grid{grid-template-columns:1fr}}
</style></head><body>
<header><h1>Burhan</h1><span class="tag">deterministic DAST · v""" + VERSION + """</span>
<span class="tag" id="health">checking…</span></header>
<main>
<div class="stats" id="stats"></div>

<h2>Launch authorized scan</h2>
<form id="scanform">
  <input name="target" placeholder="https://target.example/ (authorized targets only)" required>
  <input name="max_pages" type="number" value="25" min="1" max="60" style="width:90px" title="max pages">
  <select name="allow_private"><option value="">public only</option><option value="1">allow private/localhost</option></select>
  <button id="scanbtn">Scan</button>
</form>
<div class="bar"><i id="prog"></i></div><div id="msg"></div>
<div class="box" id="active" style="display:none"></div>

<div class="grid">
<div><h2>Runs</h2><table id="runs"><thead><tr><th>Run</th><th>Target</th><th>Findings</th><th>Requests</th><th>State</th></tr></thead><tbody></tbody></table></div>
<div><h2>Verified findings</h2><table id="finds"><thead><tr><th>Sev</th><th>Type</th><th>URL</th><th>Param</th><th>Risk</th></tr></thead><tbody></tbody></table></div>
</div>

<h2>Recurring &amp; delta intelligence</h2>
<div class="box" id="intel">—</div>
</main>
<script>
const SEV={critical:'#c0392b',high:'#e67e22',medium:'#f1c40f',low:'#3498db',info:'#95a5a6'};
const $=id=>document.getElementById(id);
let currentRun=null, timer=null;
async function api(p,opt){const r=await fetch(p,opt);return r.json()}
async function refresh(){
  try{
    const h=await api('/api/health');
    $('health').textContent=h.status+' · uptime '+Math.round(h.uptime_s)+'s · '+h.scans_running+' running';
    const s=await api('/api/stats');const st=s.summary||{};
    $('stats').innerHTML=[['Runs',st.runs||0],['Targets',st.targets_scanned||0],['Verified',st.verified_findings||0],['Recurring',st.recurring_fingerprints||0]]
      .map(x=>`<div class="stat"><b>${x[1]}</b><span>${x[0]}</span></div>`).join('');
    const runs=await api('/api/runs');
    $('runs').tBodies[0].innerHTML=(runs.runs||[]).slice(0,12).map(r=>{const sc=(r.stats||{});
      return `<tr><td><code>${r.run_id}</code></td><td class="u">${r.target}</td><td>${(sc.verified!=null?sc.verified:'—')}</td><td>${sc.requests||0}</td><td><span class="status-dot ok"></span>done</td></tr>`}).join('')
      ||'<tr><td colspan="5">no runs yet</td></tr>';
    const f=await api('/api/findings?limit=40');
    $('finds').tBodies[0].innerHTML=(f.findings||[]).slice(0,40).map(x=>{const c=SEV[x.severity]||'#95a5a6';
      return `<tr><td><span class="pill" style="background:${c}">${x.severity}</span></td><td><code>${x.type}</code></td><td class="u">${x.url}</td><td><code>${x.parameter||''}</code></td><td>${x.risk}</td></tr>`}).join('')
      ||'<tr><td colspan="5">none</td></tr>';
    const d=(s.latest_delta)||{};const rec=(s.recurring||[]);
    $('intel').innerHTML=`latest delta — <b style="color:var(--grn)">${(d.new||[]).length} new</b> · <b style="color:var(--blu)">${(d.fixed||[]).length} fixed</b> · <b style="color:var(--org)">${(d.recurring||[]).length} recurring</b>`
      +(rec.length?'<br>Recurring: '+rec.slice(0,6).map(r=>`<code>${r.type}</code> ${r.url} (${r.n_runs} runs)`).join('<br>'):'');
  }catch(e){$('health').textContent='API unreachable'}
}
$('scanform').onsubmit=async ev=>{ev.preventDefault();
  const fd=new FormData(ev.target);const body={target:fd.get('target'),max_pages:+fd.get('max_pages')};
  if(fd.get('allow_private'))body.allow_private=true;
  $('scanbtn').disabled=true;$('msg').textContent='submitting…';
  try{const r=await api('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(r.error){$('msg').textContent='ERROR: '+r.error;return}
    currentRun=r.run_id;$('msg').textContent='launched run '+r.run_id+' — polling…';
    $('active').style.display='block';$('prog').style.width='8%';poll();
  }catch(e){$('msg').textContent='launch failed: '+e}finally{$('scanbtn').disabled=false}
};
async function poll(){clearInterval(timer);
  timer=setInterval(async()=>{if(!currentRun)return;const s=await api('/api/scans/'+currentRun);
    if(s.state==='running'){$('prog').style.width='45%';$('msg').textContent='scanning '+s.target+'…'}
    else if(s.state==='done'){clearInterval(timer);$('prog').style.width='100%';
      const rep=s.report||{};const st=rep.stats||{};
      $('msg').innerHTML=`<b>${currentRun}</b> finished — ${st.verified||0} verified findings, ${st.requests||0} requests, ${Math.round(st.duration||0)}s`;
      currentRun=null;setTimeout(()=>{$('prog').style.width='0'},3000);refresh();}
    else if(s.state==='failed'){clearInterval(timer);$('prog').style.width='100%';$('msg').textContent='FAILED: '+s.error;currentRun=null}
  },2000);}
refresh();setInterval(refresh,8000);
</script></body></html>"""


# ---------------------------------------------------------------- HTTP handler
class ApiHandler(BaseHTTPRequestHandler):
    server_version = "burhan-api/" + VERSION
    store: Store = None            # injected by run_server
    token: str = ""                # non-empty => required for every request

    def log_message(self, fmt, *args):
        # stderr, NEVER stdout: the test suite / repair gate parse stdout as ONE JSON
        # object — access logs there would corrupt the machine-readable verdict
        # (live-caught by the full-suite run: repair_demo does json.loads(stdout)).
        import sys as _sys
        print(f"[api] {self.address_string()} {fmt % args}", file=_sys.stderr)

    # ---- helpers
    def _json(self, obj, code=200):
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text: str):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not self.token:
            return True
        return self.headers.get("X-Auth-Token", "") == self.token

    # ---- routing
    def do_GET(self):
        if not self._authorized():
            return self._json({"error": "unauthorized"}, 401)
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        parts = [p for p in u.path.split("/") if p]

        if u.path in ("/", "/index.html", "/ui"):
            return self._html(dashboard_html())
        if parts[:1] == ["api"]:
            parts = parts[1:]
            if parts == ["health"]:
                with _LOCK:
                    running = sum(1 for s in _SCANS.values() if s["state"] in ("queued", "running"))
                return self._json({"status": "ok", "version": VERSION,
                                   "uptime_s": round(time.time() - _STARTED, 1),
                                   "scans_running": running})
            if parts == ["runs"]:
                return self._json({"runs": self.store.list_runs(limit=int(q.get("limit", 50)))})
            if len(parts) == 2 and parts[0] == "runs":
                run = self.store.get_run(parts[1])
                live = scan_status(parts[1])
                if not run and not live:
                    return self._json({"error": "run not found"}, 404)
                if run:
                    run["state"] = (live or {}).get("state", "done")
                    return self._json(run)
                return self._json(live or {"error": "run not found"}, 404 if not live else 200)
            if len(parts) == 3 and parts[0] == "runs" and parts[2] == "sarif":
                # OP-02 (Phase 54): SARIF 2.1.0 export for CI pipelines (GitHub
                # code scanning uploads). Verification-gated like every other view.
                run = self.store.get_run(parts[1])
                if not run:
                    return self._json({"error": "run not found"}, 404)
                from .report import build_sarif
                return self._json(build_sarif(self.store, parts[1]))
            if parts == ["findings"]:
                rows = self.store.list_findings(
                    run_id=q.get("run_id", ""), type_=q.get("type", ""),
                    min_risk=int(q.get("min_risk", 0)),
                    status=q.get("status", "verified"),
                    limit=int(q.get("limit", 200)))
                return self._json({"count": len(rows), "findings": rows})
            if parts == ["stats"]:
                return self._json({"summary": self.store.stats_summary(),
                                   "recurring": self.store.recurring(),
                                   "latest_delta": self.store.delta()})
            if len(parts) == 2 and parts[0] == "scans":
                s = scan_status(parts[1])
                if not s:
                    return self._json({"error": "scan not found"}, 404)
                return self._json(s)
        return self._json({"error": "not found", "path": u.path}, 404)

    def do_POST(self):
        if not self._authorized():
            return self._json({"error": "unauthorized"}, 401)
        u = urlsplit(self.path)
        parts = [p for p in u.path.split("/") if p]
        if parts == ["api", "scans"]:
            try:
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._json({"error": "invalid JSON body"}, 400)
            target = (body.get("target") or "").strip()
            if not target:
                return self._json({"error": "target is required"}, 400)
            if not target.startswith(("http://", "https://")):
                return self._json({"error": "target must be an absolute http(s) URL"}, 400)
            res = launch_scan(self.store, target,
                              max_pages=int(body.get("max_pages", 25)),
                              allow_private=bool(body.get("allow_private", False)),
                              timeout=float(body.get("timeout", 12.0)),
                              seed=body.get("seed"))
            return self._json(res, 202 if "run_id" in res else 503)
        return self._json({"error": "not found"}, 404)


def run_server(host="127.0.0.1", port=8022, db_path="results/burhan.db",
               token: str = "") -> dict:
    """Start the REST API + UI. Loopback binds need no token; any other bind REQUIRES
    one (refuses to start otherwise) — a scanner control plane must not be the vuln."""
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise SystemExit("REFUSING to bind non-loopback without --token: "
                         "the scan API would allow arbitrary scan launches. "
                         "Pass --token <secret> to enable remote binding.")
    ApiHandler.store = Store(db_path)
    ApiHandler.token = token
    srv = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"[api] Burhan v{VERSION} REST API + UI on http://{host}:{port}/ "
          f"(db={db_path}, auth={'token' if token else 'loopback-only'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return {"served": True}
