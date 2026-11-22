"""ginandjuice.shop engine run via the Python API (the CLI is a thin
wrapper over BurhanScanner) with an explicit request budget so the run
BOUNDS itself and always completes — the single-call process limit of this
environment kills anything that overruns, and the CLI exposes no
--max-requests switch.

All detector families stay enabled; knobs (max_pages / max_requests /
browser / websocket / timeout) come from the environment so the same
script serves diagnosis and the final bounded run.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from burhan.authorized_targets import require_authorized             # noqa: E402
from burhan.core import ScopeRule
from burhan.oast import make_oast
from burhan.orchestrator import ScanConfig, BurhanScanner
from burhan.store import Store

MAX_PAGES = int(os.environ.get("GJ_MAX_PAGES", "12"))
MAX_REQ = int(os.environ.get("GJ_MAX_REQ", "250"))
BROWSER = os.environ.get("GJ_BROWSER", "0") == "1"
WS = os.environ.get("GJ_WS", "1") == "1"
TIMEOUT = float(os.environ.get("GJ_TIMEOUT", "6.0"))

EV = Path("evidence/full-reverify/ginandjuice-shop")
EV.mkdir(parents=True, exist_ok=True)

# r19-2.17 (owner order 2026-11-20 PR-A/4): this script drives a LIVE
# EXTERNAL target — the same entry rule as every other entry point: the
# authorization gate runs BEFORE BurhanScanner is constructed. The target
# is registry-covered (ginandjuice.shop, scope-page proof), so the normal
# run is unchanged; what changes is that a registry without the entry (or
# an unverified proof page) now refuses loudly with zero requests instead
# of scanning anyway.
require_authorized("https://ginandjuice.shop/")

oast = make_oast("ginandjuice.shop", mode="auto")
print(f"config: max_pages={MAX_PAGES} max_requests={MAX_REQ} "
      f"browser={BROWSER} websocket={WS} timeout={TIMEOUT} "
      f"oast={type(oast).__name__}", flush=True)
cfg = ScanConfig(allow_private=False, max_pages=MAX_PAGES, timeout=TIMEOUT,
                 seed="gjreverify-2026-10-30-full-detector-bounded-run",
                 oast=oast, browser=BROWSER, websocket=WS,
                 max_requests=MAX_REQ)
t0 = time.time()
try:
    sc = BurhanScanner("https://ginandjuice.shop/", cfg)
    rep = sc.run()
finally:
    if oast is not None:
        oast.stop()
wall = time.time() - t0

(EV / "scan.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False),
                              encoding="utf-8")
n = Store(str(EV / "store.db")).save_run(rep)
s = rep["stats"]
print(f"DONE wall={wall:.1f}s requests={s.get('requests')} "
      f"endpoints={s.get('endpoints')} findings={len(rep['findings'])} "
      f"persisted={n}")
from collections import Counter
tc = Counter(f["type"] for f in rep["findings"])
print("finding types:", dict(tc))
