# Target ownership gate — implementation status

## Status: implemented before this work; verified, not rewritten

The client scan gate already exists in `burhan/authorized_targets.py` and is
called before live scan traffic. It verifies proof at scan time and does not
cache a previous approval. A missing, invalid, or stale proof refuses the scan,
prints the refusal banner, exits with code 2, and sends zero scan requests.

The existing proof classes are:

- self-hosted loopback/private development fixtures;
- a live DNS TXT record carrying the owner token;
- a live permission/scope page with a pinned quote;
- a signed authorization letter re-hashed at scan time.

The existing test suite in `tests/test_authorized_targets.py` covers the
unlisted-target refusal, exit code 2 and zero-request contract, DNS TXT success
and mismatch, live proof-page failure, redirect/userinfo/path lookalikes, case
normalization, trailing-dot normalization, IDN lookalikes, the apex, and true
subdomains. The rebinding behavior is covered by the local fixture tests in
`tests/test_modernsec2.py` and `tests/test_ssrf_live_refusal.py`.

This PR deliberately adds no new ownership mechanism, no new proof type, no
new target, and no detector. The requested v2 definition remains subject to
owner review before any redesign. A full CLI/web end-to-end reimplementation of
this gate was not claimed here because the repository already had the gate and
its relevant regression coverage.

## Verification performed

```text
python3 -m pytest -q tests/test_authorized_targets.py tests/test_modernsec2.py --no-header
38 passed in 24.27s
```
