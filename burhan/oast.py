"""Phase 49 + Phase 52: OAST engine — out-of-band interaction channels.

Closes the documented v2.0.x coverage gap: "blind XXE needs OOB/Collaborator
confirmation". Some vulnerability classes have NO response-based oracle (the
target's reply carries no information about whether our payload executed —
live-proven on ginandjuice.shop /catalog/product/stock, where five identical
probes returned 23/768/52/191/52 units). The ONLY evidence channel for such
vulns is the target making an outbound callback to a listener WE control.

Two interchangeable providers (same 3-call protocol: url / poll / stop —
the detector and verifier code never change):
  - OastServer (Phase 49): binds 127.0.0.1:<ephemeral> and records every HTTP
    hit as an interaction keyed by a caller-chosen id (the id IS the URL path).
    Optimal for lab/local targets: zero latency, fully deterministic.
  - PublicWebhookProvider (Phase 52): a PUBLIC channel via the webhook.site
    REST service — out-of-band interaction semantics WITHOUT owning any
    infrastructure. One channel token per scan; the interaction id rides in
    the callback's query string (?i=<id>); poll() reads the service's request
    log. Live-proven end-to-end: ginandjuice.shop's blind XXE fetched a
    webhook.site entity URL from 54.170.155.72 (the target's own AWS egress)
    with UA "ginandjuice.shop; support@portswigger.net" while the HTTP
    response stayed a content-free 400.

make_oast(): the selection policy. auto = local listener for targets that can
reach loopback, public channel for remote targets (degrades honestly to None
if the public service is unreachable — the scan proceeds exactly as before,
blind-OOB confirmation simply stays unavailable, as documented in v2.0.x).

Honesty contract preserved: an OOB callback IS independent evidence of
server-side payload execution (the fetch left the target's process), so an
OOB-confirmed finding is VERIFIED — never merely "candidate".
"""
from __future__ import annotations
import json as _json
import re as _re
import socket
import threading, time
import urllib.request as _urlreq
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# OWSP-32: canonical interaction-id shape ('oob-' + 12 hex) for prefix matching.
_IID_PREFIX_RE = _re.compile(r"^(oob-[0-9a-f]{12})")


class _OastHandler(BaseHTTPRequestHandler):
    oast: "OastServer" = None            # injected

    def log_message(self, *a):
        pass                              # silent — the interaction log IS the output

    def _record(self):
        raw = self.path.lstrip("/").split("?")[0]
        # OWSP-32 (NodeGoat round, live-caught on /research?url=&symbol=): the
        # target CONCATENATED the callback URL with another param value
        # (needle.get(url + symbol)), so the requested path arrived as
        # /oob-<id><suffix> — an exact-path lookup recorded the hit under a key
        # no poll() would ever use and the interaction silently vanished.
        # Interaction ids are ALWAYS 'oob-' + 12 hex chars (detector-side sha1
        # slices): match by PREFIX so URL-concatenated callbacks land, and keep
        # the full path as the fallback key for non-canonical shapes.
        m = _IID_PREFIX_RE.match(raw)
        iid = m.group(1) if m else raw
        # REPRO FIX (2026-10-31, caught by the CI reproducibility gate):
        # record the TCP PEER IP (portless) — detectors prefer it for source
        # attribution. The Host header fallback carried the listener's
        # EPHEMERAL port (port=0 bind), which moved the audit Merkle root on
        # every run for local targets.
        peer_ip = self.client_address[0] if self.client_address else ""
        self.oast._record(iid, method=self.command, raw_path=raw,
                          ua=self.headers.get("User-Agent", ""),
                          host=self.headers.get("Host", ""),
                          ip=peer_ip)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_PUT = _record


class OastServer:
    """Local OOB listener (Phase 49). Deterministic poll, thread-safe interaction log.
    Provider attributes: channel='local', public_base (the URL targets call back)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host, self.requested_port = host, port
        self._interactions: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        self._ready = threading.Event()
        h = type("BoundOastHandler", (_OastHandler,), {"oast": self})
        self._srv = ThreadingHTTPServer((host, port), h)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        # the URL the TARGET must be able to reach — loopback for lab targets;
        # a public bind/port-forward is required for remote targets.
        self.public_base = f"http://{host}:{self.port}"
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True, name="oast-listener")
        self._thread.start()
        self._ready.set()

    # ---------------------------------------------------------------- API
    def url(self, interaction_id: str) -> str:
        """Callback URL for one probe. The id is the path — poll() by the same id."""
        return f"{self.public_base}/{interaction_id}"

    def _record(self, iid: str, **meta):
        with self._lock:
            self._interactions.setdefault(iid, []).append(
                {"t": round(time.time(), 3), **meta})

    def poll(self, interaction_id: str, timeout: float = 2.0) -> list[dict] | None:
        """Block until the interaction arrives (returns hit list) or None on timeout.
        Checks immediately first — for local fixtures the callback lands before the
        probe request even returns."""
        deadline = time.time() + timeout
        while True:
            with self._lock:
                hits = self._interactions.get(interaction_id)
                if hits:
                    return list(hits)
            if time.time() >= deadline:
                return None
            time.sleep(0.05)

    def hits(self) -> dict[str, list[dict]]:
        with self._lock:
            return {k: list(v) for k, v in self._interactions.items()}

    def stop(self):
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:
            pass

    # provider metadata (uniform across channel implementations)
    channel = "local"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


# ================================================================ Phase 52
class PublicWebhookProvider:
    """Public OOB channel via the webhook.site REST service — Collaborator-class
    semantics with ZERO owned infrastructure. One channel token per instance; the
    interaction id rides in the callback query string (?i=<id>); poll() reads the
    service's request log over TLS and matches ids client-side.

    Protocol (live-proven 2026-09, see module docstring):
      POST   /token                         -> {"uuid": <channel token>}
      TARGET GET https://webhook.site/<token>?i=<iid>   -> recorded by the service
      GET    /token/<token>/requests?page=1 -> {"total": n, "data": [ {method, ip,
                                                          url, user_agent, ...} ]}

    Determinism note: the token is per-scan (not per-run reproducible), but the
    interaction ids remain deterministic (detector-side sha1), so evidence text
    stays stable across runs; only the channel identity differs. This mirrors a
    real collaborator deployment, where the domain also changes per deployment.
    """

    channel = "public-webhook"
    SERVICE = "https://webhook.site"
    # public-channel latency budget: the target's egress fetch + the service's log
    # indexing are slower than a loopback listener; callers written for the local
    # listener pass short timeouts, so enforce a channel-specific floor. Tests
    # shrink this attribute for speed.
    POLL_FLOOR = 5.0

    def __init__(self, timeout: float = 15.0, service: str | None = None,
                 token: str | None = None):
        self.timeout = timeout
        self._svc = service or self.SERVICE
        self._token = token or self._create_token()
        self.public_base = f"{self._svc}/{self._token}"
        self._polled = set()          # request uuids already seen (idempotent poll)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ internals
    def _http(self, path: str, method: str = "GET", body: dict | None = None):
        data = _json.dumps(body or {}).encode() if method == "POST" else None
        req = _urlreq.Request(self._svc + path, method=method, data=data,
                              headers={"Content-Type": "application/json"}
                              if data else {})
        with _urlreq.urlopen(req, timeout=self.timeout) as r:
            return _json.loads(r.read().decode("utf-8", "replace"))

    def _create_token(self) -> str:
        d = self._http("/token", method="POST", body={})
        tok = d.get("uuid")
        if not tok:
            raise RuntimeError(f"public OAST channel creation failed: {str(d)[:120]}")
        return tok

    # ------------------------------------------------------------ provider API
    def url(self, interaction_id: str) -> str:
        """Callback URL for one probe. The id rides in ?i= — poll() by the same id."""
        return f"{self.public_base}?i={interaction_id}"

    def poll(self, interaction_id: str, timeout: float = 3.0) -> list[dict] | None:
        """Poll the service request log until an entry carries our interaction id
        or the timeout expires. The service has no server-side filter, so we fetch
        the log page and match ?i=<id> client-side. Returns hit list (collaborator-
        style: method + source ip + ua + epoch) or None."""
        timeout = max(timeout, self.POLL_FLOOR)
        deadline = time.time() + timeout
        while True:
            try:
                d = self._http(f"/token/{self._token}/requests?page=1")
                with self._lock:
                    self._polled.update(str(x.get("uuid", "")) for x in d.get("data", []))
                hits = [self._hit(x) for x in d.get("data", [])
                        if f"i={interaction_id}" in str(x.get("url", ""))]
                if hits:
                    return hits
            except Exception:
                pass                       # transient network -> keep polling
            if time.time() >= deadline:
                return None
            time.sleep(0.6)

    @staticmethod
    def _hit(x: dict) -> dict:
        t = x.get("created_at", "")
        try:                                   # "2026-09-28 19:20:39" (UTC) -> epoch
            from datetime import datetime, timezone
            t = datetime.strptime(t, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc).timestamp()
        except Exception:
            pass
        return {"t": round(float(t) if isinstance(t, float) else time.time(), 3),
                "method": x.get("method", ""), "ip": x.get("ip", ""),
                "ua": x.get("user_agent", ""), "host": x.get("host", "")}

    def hits(self) -> dict[str, list[dict]]:
        """All interactions grouped by id (audit/telemetry view)."""
        out: dict[str, list[dict]] = {}
        try:
            d = self._http(f"/token/{self._token}/requests?page=1")
            for x in d.get("data", []):
                import re as _re
                m = _re.search(r"[?&]i=([^&]+)", str(x.get("url", "")))
                if m:
                    out.setdefault(m.group(1), []).append(self._hit(x))
        except Exception:
            pass
        return out

    def stop(self):
        """Nothing to shut down server-side (the service expires channels on its
        own); kept for the uniform provider protocol."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


def make_oast(target_host: str, mode: str = "auto", allow_private: bool = False,
              service: str | None = None) -> \
        "OastServer | InteractshProvider | PublicWebhookProvider | None":
    """Channel selection policy (this order, Part 4: interact.sh is the new
    DEFAULT public provider; webhook.site remains available behind the same
    protocol as the explicit `webhook` mode):
      local    -> loopback listener (lab targets only — remote hosts cannot call it)
      public   -> InteractshProvider (interact.sh / oast.fun; works for ANY
                  target; the DEFAULT public channel since Part 4)
      webhook  -> PublicWebhookProvider (webhook.site; the Phase-52 public
                  channel, kept swappable behind the same protocol)
      auto     -> local when the target can reach loopback (private/lab host),
                  interact.sh for remote hosts; honest None if the public
                  channel is unreachable (scan proceeds without OOB — never
                  crashes a scan for lack of a listener).
    """
    from .core import is_private_ip
    private = is_private_ip(target_host or "")
    if mode == "local" or (mode == "auto" and private):
        return OastServer()
    if mode in ("public", "auto"):
        try:
            return InteractshProvider(service=service)
        except Exception:
            if mode == "public":
                raise                       # explicit request -> loud failure
            return None                    # auto -> honest degradation
    if mode == "webhook":
        return PublicWebhookProvider(service=service)
    return None


# ================================================================ Part 4
class InteractshProvider:
    """interact.sh (projectdiscovery/interactsh) — the DEFAULT public OAST
    provider since this order's Part 4. Same 3-call provider protocol as
    OastServer / PublicWebhookProvider (url / poll / stop), so detectors and
    verifiers never change.

    Official interface (fetched and cited from the projectdiscovery/interactsh
    repository, main branch, 2026-11-05 — pkg/client/client.go and
    pkg/server/http_server.go; NOTHING assumed from memory):

      POST {server}/register       body {"public-key": <b64 PKIX PEM>,
            "secret-key": <secret>, "correlation-id": <20 hex>}
            -> {"message": "registration successful"}
            (RegisterRequest struct, http_server.go:415-422 — exact field
            names "public-key"/"secret-key"/"correlation-id")
      interaction URL = <iid>.<server host>  (client.go URL(): the official
            client issues correlation-id + random nonce + "." + host; any
            subdomain under the correlation id correlates server-side)
      GET {server}/poll?id=<correlation-id>&secret=<secret-key>
            -> {"data": [<b64 ciphertexts>], "extra": [...],
                "aes_key": <b64 RSA-OAEP(SHA256)-encrypted AES key>}
            (client.go getInteractions/decryptMessage: the AES key is
            RSA-OAEP-SHA256 unwrapped with the registered private key; each
            data item is base64(IV[16] || AES-CTR ciphertext))
      each decrypted interaction: {"protocol": "http"/"dns"/"smtp"/...,
            "unique-id": <full subdomain>, "raw-request": "...",
            "remote-address": "<ip>:<port>", "timestamp": "..."}

    THIRD-PARTY TRANSIT (stated plainly, per the order): interactions via
    this provider transit a third party (the public interact.sh
    infrastructure) BY DESIGN — the accepted tradeoff for
    zero-infrastructure live testing today. The self-hosted listener
    (SelfHostedListener below) is the documented future upgrade path,
    swappable behind this same provider interface: switching later is a
    config change, not a rewrite.

    Architectural rule enforced: NOTHING in the OAST layer is ever installed
    inside any scanned target's environment — the provider issues addresses,
    the TARGET performs its own outbound callback, and we poll the provider.
    """

    channel = "interactsh"
    # interact.sh's own client default list (README/usage docs): oast.fun /
    # oast.live / oast.site / oast.online / oast.pro / oast.me — the first
    # is the default here; others can be passed via service=
    DEFAULT_SERVER = "https://oast.fun"
    POLL_FLOOR = 5.0          # public-channel latency budget (same as webhook)
    # pkg/server/util.go (fetched, verbatim): "Correlation ids are produced
    # from xid (cidl prefix) and zbase32 (cidn suffix), so detection is
    # restricted to those alphabets" — xid = 0-9a-v, zbase32 =
    # ybndrfg8ejkmcpqxot1uwisza345h769. The server only CORRELATES a
    # subdomain whose GetIdLength() window passes isCorrelationID()
    # (xid-valid corr prefix + zbase32-valid nonce suffix), so the subdomain
    # we issue must be corr + a zbase32 nonce; OUR interaction id is carried
    # as a PATH/QUERY element and matched client-side against the recorded
    # raw-request (the subdomain itself is the server's correlation key).
    _ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

    def __init__(self, timeout: float = 15.0, service: str | None = None,
                 correlation_id: str | None = None, secret: str | None = None):
        import base64 as _b64
        import secrets as _secrets
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        self.timeout = timeout
        self._server = (service or self.DEFAULT_SERVER).rstrip("/")
        self._host = self._server.split("//", 1)[-1]
        self._correlation_id = correlation_id or _secrets.token_hex(10)
        self._secret = secret or _secrets.token_urlsafe(16)
        self._priv = _rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048)
        pub_pem = self._priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self._pub_b64 = _b64.b64encode(pub_pem).decode()
        self._issued: dict[str, str] = {}   # our iid -> issued subdomain
        self._lock = threading.Lock()
        self._register()

    # ------------------------------------------------------------ internals
    def _http(self, path: str, method: str = "GET", body: dict | None = None):
        data = _json.dumps(body).encode() if body is not None else None
        req = _urlreq.Request(self._server + path, method=method, data=data,
                              headers={"Content-Type": "application/json"}
                              if data else {})
        with _urlreq.urlopen(req, timeout=self.timeout) as r:
            return _json.loads(r.read().decode("utf-8", "replace"))

    def _register(self) -> None:
        d = self._http("/register", method="POST", body={
            "public-key": self._pub_b64,
            "secret-key": self._secret,
            "correlation-id": self._correlation_id,
        })
        if d.get("message") != "registration successful":
            raise RuntimeError(f"interact.sh registration failed: {str(d)[:120]}")

    def _decrypt(self, aes_key_b64: str, item_b64: str) -> dict:
        """client.go decryptMessage, ported exactly: RSA-OAEP(SHA256) unwrap
        of the AES key; each item is base64(IV[16] || AES-CTR ciphertext)."""
        import base64 as _b64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as _pad
        from cryptography.hazmat.primitives.ciphers import Cipher, \
            algorithms as _alg, modes as _mode
        aes_key = self._priv.decrypt(
            _b64.b64decode(aes_key_b64),
            _pad.OAEP(mgf=_pad.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(), label=None))
        blob = _b64.b64decode(item_b64)
        iv, ct = blob[:16], blob[16:]
        dec = Cipher(_alg.AES(aes_key), _mode.CTR(iv)).decryptor()
        return _json.loads((dec.update(ct) + dec.finalize())
                           .decode("utf-8", "replace"))

    # ------------------------------------------------------------ provider API
    def _nonce(self, n: int = 13) -> str:
        import secrets as _secrets
        return "".join(_secrets.choice(self._ZBASE32) for _ in range(n))

    def url(self, interaction_id: str) -> str:
        """Callback URL for one probe. The subdomain is <corr><zbase32
        nonce> — the exact shape the server correlates (see the util.go
        citation above); our interaction id rides the URL PATH
        (/i/<iid>), and poll() matches it client-side from the recorded
        raw-request. This keeps correlation server-verified AND id
        attribution exact (two ids sharing one subdomain stay distinct
        because their paths differ)."""
        sub = self._correlation_id + self._nonce()
        with self._lock:
            self._issued[interaction_id] = sub
        return f"http://{sub}.{self._host}/i/{interaction_id}"

    def https_url(self, interaction_id: str) -> str:
        sub = self._correlation_id + self._nonce()
        with self._lock:
            self._issued[interaction_id] = sub
        return f"https://{sub}.{self._host}/i/{interaction_id}"

    def poll(self, interaction_id: str, timeout: float = 3.0) -> list[dict] | None:
        """Poll /poll?id=&secret= until an interaction's raw-request carries
        our path marker (/i/<iid>), decrypting each item exactly like the
        official client. Returns collaborator-style hit dicts or None."""
        timeout = max(timeout, self.POLL_FLOOR)
        deadline = time.time() + timeout
        marker = f"/i/{interaction_id}"
        while True:
            try:
                d = self._http(f"/poll?id={self._correlation_id}"
                               f"&secret={self._secret}")
                hits = []
                for item in d.get("data", []):
                    try:
                        inter = self._decrypt(d.get("aes_key", ""), item)
                    except Exception:
                        continue
                    raw = str(inter.get("raw-request", ""))
                    if marker in raw or str(inter.get("unique-id", "")).startswith(interaction_id):
                        hits.append(self._hit(inter))
                if hits:
                    return hits
            except Exception:
                pass                       # transient network -> keep polling
            if time.time() >= deadline:
                return None
            time.sleep(1.0)

    @staticmethod
    def _hit(inter: dict) -> dict:
        t = str(inter.get("timestamp", ""))
        try:                                   # RFC3339 nano -> epoch
            from datetime import datetime
            t = datetime.fromisoformat(
                t.replace("Z", "+00:00")).timestamp()
        except Exception:
            t = time.time()
        ra = str(inter.get("remote-address", ""))
        return {"t": round(float(t), 3),
                "method": "DNS" if inter.get("protocol") == "dns" else "GET",
                "ip": ra.rsplit(":", 1)[0] if ":" in ra else ra,
                "ua": "", "host": str(inter.get("unique-id", "")),
                "protocol": str(inter.get("protocol", "")),
                "raw_request": str(inter.get("raw-request", ""))[:2000]}

    def hits(self) -> dict[str, list[dict]]:
        """All interactions grouped by the interaction ids this provider
        issued (audit/telemetry view)."""
        out: dict[str, list[dict]] = {}
        with self._lock:
            issued = dict(self._issued)
        if not issued:
            return out
        try:
            d = self._http(f"/poll?id={self._correlation_id}"
                           f"&secret={self._secret}")
            for item in d.get("data", []):
                try:
                    inter = self._decrypt(d.get("aes_key", ""), item)
                except Exception:
                    continue
                raw = str(inter.get("raw-request", ""))
                uid = str(inter.get("unique-id", ""))
                for iid in issued:
                    if f"/i/{iid}" in raw or uid.startswith(iid):
                        out.setdefault(iid, []).append(self._hit(inter))
        except Exception:
            pass
        return out

    def stop(self):
        """Deregister (POST /deregister, best-effort — the public server
        expires sessions on its own)."""
        try:
            self._http("/deregister", method="POST", body={
                "correlation-id": self._correlation_id,
                "secret-key": self._secret})
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


# ================================================================ Part 4.3
class SelfHostedListener:
    """The self-hosted OAST listener (DNS + HTTP) — the documented FUTURE
    upgrade path behind the same provider protocol as interact.sh.

    STATUS, stated plainly (per the order's 4.3/4.6): LOGIC-PROVEN-BUT-
    INFRASTRUCTURE-PENDING. The DNS+HTTP correlation logic is implemented
    and tested via local loopback simulation (see tests/test_oast_interactsh
    .py); running it against REAL targets needs operator infrastructure this
    repo does not own today:
      - HTTP: bind a port reachable by the target (port-forward/tunnel);
      - DNS: delegate a subdomain (NS record) to a host running the UDP/53
        responder below — the correlation encoding is what the test proves.

    Design (same correlation semantics as interact.sh, no server needed):
      url(iid)  -> http://<listener>:<port>/<iid>            (HTTP channel)
                -> <iid>.<dns-domain>                        (DNS channel)
      poll(iid) -> every interaction recorded by EITHER channel under that
                   iid, exactly like the local OastServer records HTTP hits.

    Swappability: identical url/poll/stop protocol to OastServer /
    InteractshProvider / PublicWebhookProvider — switching the deployment
    from interact.sh to self-hosted is a make_oast(service=...) config
    change, not a rewrite. NOTHING here is ever installed inside a scanned
    target's environment (the architectural rule of this Part).
    """

    channel = "self-hosted"
    POLL_FLOOR = 0.05          # loopback-responder latency budget

    def __init__(self, http_host: str = "127.0.0.1", http_port: int = 0,
                 dns_domain: str = "oast.local", dns_port: int = 0):
        self.dns_domain = dns_domain
        self._interactions: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        # ---- HTTP responder (loopback by default; a reachable bind is the
        # operator's deployment decision)
        h = type("BoundSelfHostedHandler", (_OastHandler,),
                 {"oast": _SelfHostedRecorder(self)})
        self._srv = ThreadingHTTPServer((http_host, http_port), h)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        self.public_base = f"http://{http_host}:{self.port}"
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True, name="selfhosted-http")
        self._thread.start()
        # ---- DNS responder (UDP): answers A 127.0.0.1 for ANY query under
        # the delegated domain, recording <first-label> as the interaction
        # id (same prefix-correlation as interact.sh's subdomain scheme)
        self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dns_sock.bind((http_host, dns_port))
        self.dns_port = self._dns_sock.getsockname()[1]
        self._dns_thread = threading.Thread(target=self._dns_loop,
                                            daemon=True,
                                            name="selfhosted-dns")
        self._dns_thread.start()

    # ------------------------------------------------------------ DNS side
    def _dns_loop(self):
        while True:
            try:
                data, addr = self._dns_sock.recvfrom(4096)
            except OSError:
                return                        # socket closed by stop()
            try:
                iid, qend = self._parse_query(data)
                if iid:
                    self._record(iid, method="DNS", raw_path=iid,
                                 ua="", host="", ip=addr[0])
                    self._dns_sock.sendto(self._a_response(data, qend),
                                          addr)
            except Exception:
                continue                     # malformed query -> drop

    def _parse_query(self, data: bytes) -> tuple[str, int]:
        """First QNAME label = interaction id (the correlation encoding the
        loopback test proves); returns (iid, offset-after-question)."""
        if len(data) < 12:
            return "", 0
        i = 12
        labels = []
        while i < len(data) and data[i] != 0:
            n = data[i]
            labels.append(data[i + 1:i + 1 + n].decode("latin-1"))
            i += 1 + n
        qend = i + 5                          # null label + QTYPE + QCLASS
        iid = labels[0] if labels else ""
        # only respond to queries under our delegated domain (or anything,
        # for the loopback simulation — the operator's NS delegation scopes
        # real traffic; the responder never touches the target anyway)
        return iid, qend

    @staticmethod
    def _a_response(query: bytes, qend: int) -> bytes:
        """Minimal DNS response: copy the question, one A record 127.0.0.1.
        (Flags QR+AA set; one answer; no recursion available.)"""
        tid = query[:2]
        header = tid + b"\x84\x00" + query[4:6] + b"\x00\x01" + \
            b"\x00\x00\x00\x00\x00\x00"
        question = query[12:qend]
        answer = b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + \
            b"\x00\x04" + bytes([127, 0, 0, 1])
        return header + question + answer

    # ------------------------------------------------------------ shared log
    def _record(self, iid: str, **meta):
        with self._lock:
            self._interactions.setdefault(iid, []).append(
                {"t": round(time.time(), 3), **meta})

    # ------------------------------------------------------------ provider API
    def url(self, interaction_id: str) -> str:
        """HTTP callback URL (the DNS channel uses dns_url())."""
        return f"{self.public_base}/{interaction_id}"

    def dns_url(self, interaction_id: str) -> str:
        """DNS callback domain: <iid>.<delegated domain>."""
        return f"{interaction_id}.{self.dns_domain}"

    def poll(self, interaction_id: str, timeout: float = 2.0) -> list[dict] | None:
        deadline = time.time() + timeout
        while True:
            with self._lock:
                hits = self._interactions.get(interaction_id)
                if hits:
                    return list(hits)
            if time.time() >= deadline:
                return None
            time.sleep(0.05)

    def hits(self) -> dict[str, list[dict]]:
        with self._lock:
            return {k: list(v) for k, v in self._interactions.items()}

    def stop(self):
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:
            pass
        try:
            self._dns_sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


class _SelfHostedRecorder:
    """Adapter: lets the shared _OastHandler record into a SelfHostedListener
    (the handler calls oast._record(iid, ...) — same protocol as OastServer)."""

    def __init__(self, listener: "SelfHostedListener"):
        self._listener = listener

    def _record(self, iid: str, **meta):
        self._listener._record(iid, **meta)
