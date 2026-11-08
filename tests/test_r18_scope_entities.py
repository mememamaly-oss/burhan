"""R18 PART 6: the scope-page gate must match the pinned quote across
HTML encoding artifacts — the live ginandjuice.shop finding.

The real page renders its permission sentence as
'web&nbsp;vulnerability&nbsp;scanners' while the pinned quote is plain
text; the verbatim match refused a target whose published permission
was UNCHANGED. The fix normalizes the PAGE side only (entity decoding,
tag stripping, whitespace collapse); the pinned quote is still compared
verbatim and a page that dropped the sentence still refuses —
fail-closed behavior preserved, encoding-artifact false refusals gone.

RED evidence: the first version of this test failed against the real
fetched page shape (entity-bearing HTML) before the fix.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from burhan.authorized_targets import authorize  # noqa: E402

LIVE_SHAPE = ('<section class="header-description"><p> This is a '
              'deliberately vulnerable web application designed for '
              'testing web&nbsp;vulnerability&nbsp;scanners. </p></section>')
QUOTED = ("This is a deliberately vulnerable web application designed "
          "for testing web vulnerability scanners")


def test_entity_page_matches_pinned_plain_quote():
    ok, reason, eid = authorize("https://ginandjuice.shop/",
                                fetch=lambda url: LIVE_SHAPE)
    assert ok, reason
    assert eid == "ginandjuice.shop"


def test_dropped_sentence_still_refuses_after_normalization():
    """Fail-closed preserved: removing the permission sentence from the
    page must still refuse, normalized page or not."""
    other = ('<p>Put your scanner to the test! We sell juice.</p>'
             '<p>Nothing about permission here.</p>')
    ok, reason, _ = authorize("https://ginandjuice.shop/",
                              fetch=lambda url: other)
    assert not ok
    assert "NO LONGER on the live page" in reason


def test_tags_and_whitespace_collapse_do_not_forge_a_match():
    """The normalization cannot manufacture the quote from pieces the
    page does not actually carry consecutively as its sentence."""
    franken = ('<p>web vulnerability</p><p>scanners designed for '
               'testing</p>')
    ok, reason, _ = authorize("https://ginandjuice.shop/",
                              fetch=lambda url: franken)
    assert not ok
