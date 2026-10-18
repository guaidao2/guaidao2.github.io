#!/usr/bin/env python3
"""task.py solver.

Insight: e=8, n=p*q*r, hint=p*q  =>  r = n // hint is known (512-bit prime).
C = m^8 mod n, so C = m^8 (mod r).  gcd(8, r-1) = 2, so x^8 = C (mod r) has
exactly two roots; if the plaintext m < r (flag < 64 bytes) one of them IS m.
No need to factor p*q at all; the answer is then verified by x^8 == C (mod n).
"""
import re, sys

def roots8(Cv, P):
    """all x with x^8 == Cv (mod P); P prime, P % 4 == 3."""
    Cv %= P
    if Cv == 0:
        return [0]
    if pow(Cv, (P - 1) // 2, P) != 1:      # C must be a QR
        return []
    out = set()
    y0 = pow(Cv, (P + 1) // 4, P)          # y0^2 = C
    for y in (y0, P - y0):
        if pow(y, (P - 1) // 2, P) != 1:   # need y QR  (x^4 = y)
            continue
        s0 = pow(y, (P + 1) // 4, P)       # s0^2 = y
        for s in (s0, P - s0):
            if pow(s, (P - 1) // 2, P) != 1:   # need s QR (x^2 = s)
                continue
            x0 = pow(s, (P + 1) // 4, P)
            for x in (x0, P - x0):
                if pow(x, 8, P) == Cv:
                    out.add(x)
    return sorted(out)

src = open(sys.argv[1] if len(sys.argv) > 1 else "task.py").read()
C    = int(re.search(r"^C=(\d+)", src, re.M).group(1))
n    = int(re.search(r"^n=(\d+)", src, re.M).group(1))
hint = int(re.search(r"^hint=(\d+)", src, re.M).group(1))

r, rem = divmod(n, hint)
print("r = n/hint  exact=%s  bits=%d" % (rem == 0, r.bit_length()))

for x in roots8(C, r):
    m = x.to_bytes((x.bit_length() + 7) // 8, "big")
    ok = pow(x, 8, n) == C
    print("candidate bits=%d  verify_mod_n=%s  text=%r" % (x.bit_length(), ok, m))
    if ok and all(32 <= c < 127 for c in m):
        print("FLAG:", m.decode())
