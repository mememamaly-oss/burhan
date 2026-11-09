"""R19 — WebGoat live acceptance check (E2).

Drives the REAL WebGoat 2026.4 JAR through the full authenticated scan
pipeline with the r19 seed/expansion rules in effect, and asserts the
acceptance criteria of the SPA-discovery feature:
  - the lesson surface opens (40 lessons via spa_route carriers +
    the menu JSON channel), lessons appear in the findings,
  - the endpoint map stays >= 100 (the pre-r19 collapse was ~30).

Usage: python3 scripts/r19_webgoat_live_check.py [--base http://127.0.0.1:8080/WebGoat]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
from burhan.orchestrator import ScanConfig, BurhanScanner          # noqa: E402
from burhan.oast import OastServer                                  # noqa: E402
from burhan.auth import AuthProfile                                 # noqa: E402


def register(base: str, user: str, pw: str) -> None:
    data = urllib.parse.urlencode(
        {"username": user, "password": pw, "matchingPassword": pw,
         "agree": "agree"}).encode()
    req = urllib.request.Request(base + "/register.mvc", data=data)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op = urllib.request.build_opener(_NoRedirect)
    try:
        op.open(req, timeout=10)
    except urllib.error.HTTPError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8080/WebGoat")
    ap.add_argument("--max-requests", type=int, default=4500)
    ap.add_argument("--max-pages", type=int, default=30)
    a = ap.parse_args()

    user = f"scanbot{int(time.time()) % 100000}"
    pw = "Sc4nx9!q"
    register(a.base, user, pw)
    auth = AuthProfile(login_url=a.base + "/login", username=user,
                       password=pw, user_field="username",
                       pass_field="password")

    oast = OastServer()
    cfg = ScanConfig(allow_private=True, max_pages=a.max_pages,
                     timeout=10.0, seed="r19-verify-js", oast=oast,
                     auth=auth, max_requests=a.max_requests, browser=True)
    sc = BurhanScanner(a.base, cfg)
    try:
        rep = sc.run()
    finally:
        oast.stop()

    st = rep["stats"]
    urls = {(f.get("url") or "").split("?")[0] for f in rep.get("findings", [])}
    lessons = sorted(u for u in urls if u.endswith(".lesson"))
    ok_eps = st.get("endpoints", 0) >= 100
    ok_lessons = len(lessons) >= 35
    print(json.dumps({
        "endpoints": st.get("endpoints"),
        "requests": st.get("requests"),
        "findings": len(rep.get("findings", [])),
        "spa_expansion": st.get("spa_expansion"),
        "lesson_urls_in_findings": len(lessons),
        "lessons_sample": [u.rsplit("/", 1)[-1] for u in lessons[:6]],
    }, indent=1))
    print("VERDICT:", "PASS" if (ok_eps and ok_lessons) else
          f"FAIL (endpoints>=100: {ok_eps}, lessons>=35: {ok_lessons})")
    return 0 if (ok_eps and ok_lessons) else 1


if __name__ == "__main__":
    sys.exit(main())
