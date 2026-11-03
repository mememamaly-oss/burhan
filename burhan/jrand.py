"""Burhan v4.3.0 — java.util.Random cryptanalysis (GTP-09).

The OWASP Benchmark labels 218 weakrand tests by the RNG CLASS the servlet
uses (java.util.Random / Math.random = vulnerable, SecureRandom = safe).
Black-box, the cookie VALUES look identical in every textual shape (decimal
fractions, integers, base64) — the class difference is only provable by
BREAKING THE GENERATOR:

  * Math.random() shares ONE static java.util.Random per JVM — consecutive
    requests advance the SAME LCG state, so two observed outputs determine
    the state and the THIRD is predicted before it is fetched (chain
    prediction: a predicted-then-matched value is mathematical proof).

  * new Random() seeds every instance with seedUniquifier() ^ nanoTime().
    The uniquifier advances by an EXACT multiplicative relation
    (u_next = u * 1181783497276652981 mod 2^64, JDK source), so two
    requests' exact states (recoverable whole from nextLong/nextBytes
    outputs, uniquely from nextDouble's 53 bits) plus a bounded nanoTime
    window admit a meet-in-the-middle solve anchored on the SHARED
    CLOCK_MONOTONIC domain (scanner and target on the same host — the
    agent-mode deployment model; against a remote host the anchor is lost
    and this family stays silent, documented honestly).

Constants and bit layout per the OpenJDK implementation (java.util.Random):
    seed = (seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
    next(bits) returns seed >>> (48 - bits)
    nextInt()  = next(32)
    nextLong() = (next(32) << 32) + next(32)
    nextDouble() = (((next(26)) << 27) + next(27)) / 2^53
    nextBytes fills 4-byte groups big-endian from next(32)
    seedUniquifier = uniquifier * 1181783497276652981 (mod 2^64)
"""
from __future__ import annotations

MULT = 0x5DEECE66D
ADD = 0xB
MASK48 = (1 << 48) - 1
UNIQ_MULT = 1181783497276652981
MOD64 = 1 << 64


def _inv48() -> int:
    inv = 1
    for _ in range(7):
        inv = (inv * (2 - MULT * inv)) & MASK48
    return inv


INV48 = _inv48()


def next_state(state: int) -> int:
    return (state * MULT + ADD) & MASK48


def seed_from_state(state_after_first: int) -> int:
    """The LOW-48 bits of the constructor seed. Java's setSeed does
    state0 = (seed ^ MULT) & MASK48 — the seed's HIGH 16 bits never enter the
    state and are unrecoverable. The seedUniquifier relation is therefore
    worked entirely in the 48-bit domain (u2 = u1 * C mod 2^64 implies
    u2_low48 = u1_low48 * C mod 2^48 — multiplication respects the modulus
    power-of-two truncation)."""
    state0 = ((state_after_first - ADD) * INV48) & MASK48
    return state0 ^ MULT


def parse_java_long(s: str) -> int:
    v = int(s.strip())
    return v & 0xFFFFFFFFFFFFFFFF if v >= 0 else (v + MOD64)


def recover_state_nextlong(val: int) -> int | None:
    """nextLong = (next(32) << 32) + next(32). The high half reveals the
    post-first-next state's top 32 bits (16 unknown); the low half must equal
    next(32) of the successor — consistency pins all 48 bits. Returns the
    state AFTER the first next() call, or None."""
    hi = (val >> 32) & 0xFFFFFFFF
    lo = val & 0xFFFFFFFF
    for x in range(1 << 16):
        s1 = (hi << 16) | x
        if next_state(s1) >> 16 == lo:
            return s1
    return None


def recover_state_nextbytes(bs: bytes) -> int | None:
    """10 base64-cookie bytes: bytes 0..3 = next(32) #1 (big-endian),
    bytes 4..7 = next(32) #2, bytes 8..9 = the TOP 16 bits of next(32) #3
    (i.e. bits 47..32 of the third state). Consistency pins the state."""
    if len(bs) < 8:
        return None
    n1 = int.from_bytes(bs[0:4], "big")
    n2 = int.from_bytes(bs[4:8], "big")
    n3_top = int.from_bytes(bs[8:10], "big") if len(bs) >= 10 else None
    for x in range(1 << 16):
        s1 = (n1 << 16) | x
        s2 = next_state(s1)
        if (s2 >> 16) != n2:
            continue
        if n3_top is not None:
            s3 = next_state(s2)
            if (s3 >> 32) != n3_top:
                continue
        return s1
    return None


def recover_state_nextdouble(d: int) -> list[int]:
    """d = the 53-bit double mantissa integer. Outputs next(26) (=d>>27)
    and next(27) (=d & 2^27-1) constrain the post-first state to ~1 of 2^22.
    numpy-vectorized; returns candidate post-first states (<= 4)."""
    a = (d >> 27) & 0x3FFFFFF
    b = d & 0x7FFFFFF
    try:
        import numpy as np
        low = np.arange(1 << 22, dtype=np.uint64)
        s1 = (np.uint64(a) << np.uint64(22)) | low
        s2 = (s1 * np.uint64(MULT) + np.uint64(ADD)) & np.uint64(MASK48)
        ok = np.nonzero((s2 >> np.uint64(21)) == np.uint64(b))[0]
        return [int(s1[i]) for i in ok[:4]]
    except Exception:
        out = []
        for low in range(1 << 22):
            s1 = (a << 22) | low
            if next_state(s1) >> 21 == b:
                out.append(s1)
                if len(out) >= 4:
                    break
        return out


def predict_double_int(s0: int) -> int:
    """The nextDouble()'s 53-bit mantissa integer produced from state s0
    (the state BEFORE the double's two next() calls)."""
    a = next_state(s0) >> 22
    b = next_state(next_state(s0)) >> 21
    return (a << 27) + b


def uniquifier_relation_solve(s1_low48: int, s2_low48: int, t1_center: int,
                              t2_center: int, window: int = 1 << 22,
                              gap_max: int = 300_000_000) -> list[tuple[int, int, int]]:
    """Meet-in-the-middle solve of the seed relation in the 48-BIT domain:
        seed_low48 = (u ^ t) & MASK48,  u2_low48 = u1_low48 * UNIQ_MULT mod 2^48
    Given the recovered low-48 seeds of two requests and monotonic-clock
    centers (same clock domain as the JVM's nanoTime on a shared host), find
    (u1, t1, t2) with t1 low-48 inside the window, the gap inside [0, gap_max]
    (mod-2^48 difference), and t2 within its own window. numpy-vectorized.

    FM-21c (first-match audit follow-up, CI live-caught 2026-11-03): the
    solver used to return the FIRST window-scan match only — when a false
    positive preceded the true solution, the caller's third-sample
    confirmation killed it and the TRUE solution (same candidate pair,
    later in the scan) was never seen: the family died on an ordering
    accident (passed locally, failed in CI — the scan order is
    environment-stable but the false-positive LAYOUT is fixture-sensitive).
    The solver now returns EVERY solution (bounded at SOL_CAP), and the
    caller's forward confirmation arbitrates among them — the confirmation
    is the self-verifying oracle, so "first confirmed" is exact."""
    try:
        import numpy as np
    except Exception:
        return []
    M48 = np.uint64(MASK48)
    C48 = np.uint64(UNIQ_MULT & MASK48)
    S1 = np.uint64(s1_low48)
    S2 = np.uint64(s2_low48)
    t1c = np.uint64(t1_center & MASK48)
    t2c = np.uint64(t2_center & MASK48)
    W = np.uint64(window)
    # modular window membership (no wrap on <3.5-day uptimes, but be safe)
    def _near(a, c, w):
        d = (a - c) & M48
        return (d <= w) | (d >= (M48 - w))
    # full-range scan in chunks: t1 = t1c + [-W, +W) (mod 2^48)
    CH = 1 << 20
    n = 2 * window
    done = 0
    out: list[tuple[int, int, int]] = []
    SOL_CAP = 8
    while done < n and len(out) < SOL_CAP:
        m = min(CH, n - done)
        idx = np.arange(done, done + m, dtype=np.int64)
        delta = idx - window
        t1 = (np.uint64(t1_center & MASK48) + np.uint64(0) + delta.astype(np.uint64)) & M48
        u1 = (S1 ^ t1) & M48
        u2 = (u1 * C48) & M48
        t2 = (S2 ^ u2) & M48
        d2 = (t2 - t1) & M48
        ok = np.nonzero(_near(t2, t2c, W) & ((d2 <= np.uint64(gap_max)) | (d2 >= M48 - np.uint64(gap_max))))[0]
        for i in ok[:SOL_CAP - len(out)]:
            out.append((int(u1[i]), int(t1[i]), int(t2[i])))
        done += m
    return out


def double_from_cookie(cookie: str) -> int | None:
    """A java Double.toString(x).substring(2) cookie ('7293719974866507')
    -> the exact 53-bit mantissa integer of x. Shortest-repr round-trips
    through float('0.'+digits)."""
    s = cookie.strip()
    # GTP-09b (wave 3): the cap was 17 — Double.toString of values < 0.1 emits
    # a LEADING ZERO ('0.0253...' -> substring(2) '0253...', 18 chars) and the
    # parse rejected exactly those (~20% of samples), killing the chain at
    # c1/c2 ~40% of the time. 20 covers every shortest-repr shape in [0,1).
    if not s.isdigit() or len(s) < 3 or len(s) > 20:
        return None
    try:
        d = float("0." + s)
    except ValueError:
        return None
    return int(round(d * (1 << 53)))


def double_int_to_cookie(d53: int) -> str:
    """Inverse of double_from_cookie for the SHORTEST-REPR shapes: the
    predicted mantissa -> the decimal digits Double.toString would emit.
    Implemented by reconstructing the double and formatting like Java
    (shortest repr): Python's repr matches Java's algorithm for values in
    [0.1, 1) — both produce the shortest string that round-trips."""
    d = d53 / float(1 << 53)
    s = repr(d)
    if s.startswith("0."):
        return s[2:]
    return s
