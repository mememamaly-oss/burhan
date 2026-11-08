#!/usr/bin/env python3
"""Owner order part 3B: DNS-rebinding TOCTOU fixture (RED/BLUE fetcher twins).

The calibration harness for the rebind_toctou family — the exact bug class
proven real in this project's own WsClient (prior order, part 3.1):

  FlipDNS (burhan.modernsec2) — the flip-after-N responder: the first A query
  answers a PUBLIC address (passes a private-range validation), every later
  query answers the INTERNAL address.

  vuln fetcher  /fetch?url=… : resolves the hostname to VALIDATE the address,
               then resolves it AGAIN for the actual connection (rebindable
               TOCTOU — validation and connection see different IPs).

  safe fetcher  /fetch?url=… : resolves ONCE, validates the PINNED address,
               then connects to the PINNED address (fail-closed: the fetch
               fails rather than ever reaching a re-resolved address).

Run:
  python3 fixtures/rebind_fixture.py --role vuln --dns-port 15353 --http-port 18711
  python3 fixtures/rebind_fixture.py --role safe --dns-port 15354 --http-port 18712
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from burhan.modernsec2 import FlipDNS  # noqa: E402 — engine-side responder


def resolve(host: str, dns_ip: str, dns_port: int) -> str:
    """Minimal stub A query against the FlipDNS responder."""
    qid = b"\xab\xcd"
    q = qid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in host.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(q, (dns_ip, dns_port))
        data, _ = s.recvfrom(512)
    finally:
        s.close()
    return socket.inet_ntoa(data[-4:])


def _is_private(ip: str) -> bool:
    return (ip.startswith("127.") or ip.startswith("10.")
            or ip.startswith("192.168.") or ip.startswith("169.254.")
            or ip.startswith("172.16.") or ip.startswith("172.17.")
            or ip.startswith("172.18.") or ip.startswith("172.19.")
            or ip.startswith("172.2") or ip.startswith("172.30.")
            or ip.startswith("172.31.") or ip == "0.0.0.0")


class _Fetcher(BaseHTTPRequestHandler):
    role = "vuln"
    dns_port = 0

    def log_message(self, *a):        # noqa: N802
        pass

    def _send(self, code, doc):
        body = json.dumps(doc).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _connect_fetch(ip: str, port: int, path: str) -> str:
        s = socket.socket()
        s.settimeout(2.0)
        try:
            s.connect((ip, port))
            s.sendall(f"GET {path} HTTP/1.0\r\nHost: rebinding-probe\r\n"
                      f"\r\n".encode())
            return s.recv(256).decode("utf-8", "replace")
        finally:
            s.close()

    def do_GET(self):                 # noqa: N802
        if not self.path.startswith("/fetch"):
            return self._send(404, {"error": "not found"})
        qs = parse_qs(urlsplit(self.path).query)
        target = (qs.get("url") or [""])[0]
        if not target:
            return self._send(400, {"error": "url parameter required"})
        u = urlsplit(target)
        host, port, path = u.hostname, u.port or 80, u.path or "/"
        # -- the validation resolve (query 1: FlipDNS answers PUBLIC) -------
        ip_validated = resolve(host, "127.0.0.1", self.dns_port)
        if _is_private(ip_validated):
            return self._send(403, {
                "error": "private address blocked",
                "stage": "validation", "ip": ip_validated})
        if self.role == "vuln":
            # -- the re-resolve at USE time (query 2: FlipDNS flips) --------
            ip_fetch = resolve(host, "127.0.0.1", self.dns_port)
            try:
                out = self._connect_fetch(ip_fetch, port, path)
                return self._send(200, {"ok": True, "fetched_from": ip_fetch,
                                        "upstream": out[:80]})
            except OSError as e:
                return self._send(502, {"error": f"upstream unreachable: {e}",
                                        "stage": "fetch", "ip": ip_fetch})
        # -- safe: connect to the PINNED validated address, never re-resolve -
        try:
            out = self._connect_fetch(ip_validated, port, path)
            return self._send(200, {"ok": True, "fetched_from": ip_validated,
                                    "upstream": out[:80]})
        except OSError as e:
            return self._send(502, {"error": f"upstream unreachable: {e}",
                                    "stage": "fetch", "ip": ip_validated})


def serve(role: str, dns_port: int, http_port: int):
    handler = type(f"Fetcher_{role}", (_Fetcher,),
                   {"role": role, "dns_port": dns_port})
    srv = ThreadingHTTPServer(("127.0.0.1", http_port), handler)
    # the actual bound http port (r18-8.5): http_port may be 0 and the
    # parent reads this line to learn where we landed
    print(f"rebind-{role} listening on 127.0.0.1:{srv.server_address[1]}",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=["vuln", "safe"], required=True)
    ap.add_argument("--dns-port", type=int, required=True)
    # r18-8.5: default 0 = child-chosen ephemeral port, announced on
    # stdout (the parent no longer pre-picks and races)
    ap.add_argument("--http-port", type=int, default=0)
    a = ap.parse_args()
    serve(a.role, a.dns_port, a.http_port)
