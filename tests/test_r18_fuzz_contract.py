"""R18 PART 4: the fuzz campaigns' no-crash contract, CI-scaled.

The full campaign (scripts/fuzz_parsers.py, 40s/target, 93k inputs)
ran as this round's time-boxed evidence pass; this file pins the SAME
contract at CI scale (~2s/target): every parser of untrusted input
either parses cleanly or rejects with a logged reason — never an
unhandled crash. A real fuzz finding regresses here with its exact
input preserved (the classic high-value outcome — don't discard the
crashing corpus).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.fuzz_parsers as fp  # noqa: E402


def test_fuzz_campaign_no_crash_ci_scale():
    rep = fp.run_campaigns(seconds_per_target=2)
    assert len(rep) == 7, "the 4.1 parser inventory targets"
    for name, s in rep.items():
        assert not s["crashes"], (name, s["crashes"])
        assert s["executed"] > 0, f"{name}: campaign ran zero inputs"
        # the contract: every input parsed OR cleanly rejected
        assert s["parsed"] + s["clean_reject"] == s["executed"], (name, s)
