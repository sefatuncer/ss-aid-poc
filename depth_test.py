# -*- coding: utf-8 -*-
"""Check whether the depth-10 deviation is a real effect or sampling noise.

The delegation-depth model has exactly one failure source, an independent
Bernoulli draw per hop, so the number of intact chains is Binomial with
success probability (1-p)^d. This script asks two questions. First, does the
empirical value converge to the analytic curve as the number of trials grows?
Second, how often would a deviation as large as the one originally reported at
depth 10 arise under pure independence?

Result: it converges, and a deviation that large arises in roughly one run in a
hundred. The claim built on it has been withdrawn from the article.
"""
import math
import random

P = 0.01
TRIALS_PAPER = 500
SEED = 42


def simulate(depth, trials, seed):
    rng = random.Random(seed)
    intact = 0
    for _ in range(trials):
        compromised = False
        for _ in range(depth):
            if rng.random() < P:
                compromised = True
        if not compromised:
            intact += 1
    return intact / trials


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


print("Makaledeki degerler: depth5 = 0.954 (teorik 0.951), depth10 = 0.872 (teorik 0.9044)")
print()
print("%-6s %-8s %-10s %-10s %-22s %s" % ("depth", "trials", "teorik", "gozlenen", "%95 CI", "teorik CI icinde?"))
for depth in (5, 10):
    th = (1 - P) ** depth
    for trials in (500, 5000, 50000, 200000):
        emp = simulate(depth, trials, SEED)
        lo, hi = wilson(round(emp * trials), trials)
        ok = "EVET" if lo <= th <= hi else "HAYIR"
        print("%-6d %-8d %-10.4f %-10.4f [%.4f, %.4f]   %s" % (depth, trials, th, emp, lo, hi, ok))
    print()

# 500 denemede boyle bir sapmanin ne siklikta cikacagi
depth = 10
th = (1 - P) ** depth
worse = 0
REPS = 20000
rng = random.Random(12345)
for _ in range(REPS):
    intact = 0
    for _ in range(TRIALS_PAPER):
        comp = False
        for _ in range(depth):
            if rng.random() < P:
                comp = True
        if not comp:
            intact += 1
    if intact / TRIALS_PAPER <= 0.872:
        worse += 1
print("Saf bagimsizlik altinda 500 denemede >= gozlenen kadar dusuk integrity")
print("cikma olasiligi: %.3f  (%d/%d tekrar)" % (worse / REPS, worse, REPS))
