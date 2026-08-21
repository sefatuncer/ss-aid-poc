"""
SS-AID PoC - BLS12-381 timings used as a proxy for the BBS+ proof path.

WHAT THIS DOES NOT MEASURE. This module does not implement BBS+ and does not
measure BBS+ proof generation or verification. It measures BLS12-381 aggregate
signature operations with blspy and uses them as a stand-in for the pairing
cost of the Tier-1 path. The "selective disclosure" figure is a partial
aggregate over a subset of separately signed messages. It carries no
zero-knowledge property, no proof re-randomization and no unlinkability, which
are exactly the properties BBS+ provides.

WHY. A reference BBS+ implementation is included in bbs_benchmark.py using
py_ecc. It is correct but pure Python, and its verification takes seconds per
operation, which is too slow to characterise the path a production library
would take. The numbers here bound the pairing cost from below; the article
states this where the figures appear.

Measured here:
  - Key generation
  - BLS signing and verification (AugSchemeMPL)
  - Aggregate signature and aggregate verification over four messages
  - Partial aggregate over two of four messages (the stand-in figure)
  - Ed25519 sign and verify, for the routine-path comparison

Latency figures are hardware dependent. The values reported in the article were
produced on an Intel Xeon E5-2680 v4; other machines will differ, and the
results/rerun-* folders record runs on other hardware.
"""

import json
import os
import time
import statistics

from blspy import PrivateKey, AugSchemeMPL
from nacl.signing import SigningKey

ITERATIONS = 1000
WARMUP = 100


def time_op(func, iterations=ITERATIONS, warmup=WARMUP):
    """Benchmark a function with warmup and detailed statistics."""
    for _ in range(warmup):
        func()
    times = []
    for _ in range(iterations):
        s = time.perf_counter_ns()
        func()
        times.append((time.perf_counter_ns() - s) / 1_000_000)
    return {
        "median_ms": round(statistics.median(times), 3),
        "mean_ms": round(statistics.mean(times), 3),
        "p95_ms": round(sorted(times)[int(len(times) * 0.95)], 3),
        "p99_ms": round(sorted(times)[int(len(times) * 0.99)], 3),
        "stddev_ms": round(statistics.stdev(times), 3),
        "min_ms": round(min(times), 3),
        "max_ms": round(max(times), 3),
        "iterations": iterations,
    }


def run_bls_benchmarks():
    """Benchmark BLS12-381 operations via blspy."""
    print(f"\n{'='*60}")
    print(f"BLS12-381 BENCHMARKS via blspy ({ITERATIONS} iterations)")
    print(f"{'='*60}")

    seed = bytes([42] * 32)
    sk = AugSchemeMPL.key_gen(seed)
    pk = sk.get_g1()

    # Single message (agent action authorization)
    msg_single = b"capability:market_analysis|constraint:maxValue=50000"

    # Multi-message credential (4 attributes)
    msgs = [
        b"capability:market_analysis",
        b"capability:portfolio_rebalance",
        b"constraint:maxTransactionValue=50000",
        b"subject:did:web:org.example:agent-01",
    ]

    results = {}

    # 1. Key Generation
    print("\n[1/6] BLS Key Generation...")
    results["keygen"] = time_op(lambda: AugSchemeMPL.key_gen(os.urandom(32)))
    print(f"  Median: {results['keygen']['median_ms']:.3f} ms")

    # 2. Sign (single message)
    print("[2/6] BLS Sign (single message)...")
    results["sign_single"] = time_op(lambda: AugSchemeMPL.sign(sk, msg_single))
    print(f"  Median: {results['sign_single']['median_ms']:.3f} ms")

    # 3. Verify (single message)
    print("[3/6] BLS Verify (single message)...")
    sig_single = AugSchemeMPL.sign(sk, msg_single)
    results["verify_single"] = time_op(lambda: AugSchemeMPL.verify(pk, msg_single, sig_single))
    print(f"  Median: {results['verify_single']['median_ms']:.3f} ms")

    # 4. Aggregate Sign (4 messages — models BBS+ credential issuance)
    print("[4/6] BLS Aggregate Sign (4 messages)...")
    def agg_sign():
        sigs = [AugSchemeMPL.sign(sk, m) for m in msgs]
        return AugSchemeMPL.aggregate(sigs)
    results["aggregate_sign"] = time_op(agg_sign)
    print(f"  Median: {results['aggregate_sign']['median_ms']:.3f} ms")

    # 5. Aggregate Verify (4 messages — models BBS+ presentation verify)
    print("[5/6] BLS Aggregate Verify (4 messages)...")
    agg_sig = agg_sign()
    results["aggregate_verify"] = time_op(
        lambda: AugSchemeMPL.aggregate_verify([pk] * 4, msgs, agg_sig)
    )
    print(f"  Median: {results['aggregate_verify']['median_ms']:.3f} ms")

    # 6. Selective Disclosure (2 of 4 messages — partial aggregate)
    print("[6/6] Selective Disclosure (2/4 revealed)...")
    disclosed_msgs = msgs[:2]  # Reveal first 2
    disclosed_sigs = [AugSchemeMPL.sign(sk, m) for m in disclosed_msgs]
    partial_agg = AugSchemeMPL.aggregate(disclosed_sigs)
    results["selective_disclosure_verify"] = time_op(
        lambda: AugSchemeMPL.aggregate_verify([pk] * 2, disclosed_msgs, partial_agg)
    )
    print(f"  Median: {results['selective_disclosure_verify']['median_ms']:.3f} ms")

    return results


def run_ed25519_benchmarks():
    """Benchmark Ed25519 for Tier 1 comparison."""
    print(f"\n{'='*60}")
    print(f"Ed25519 BENCHMARKS ({ITERATIONS} iterations)")
    print(f"{'='*60}")

    sk = SigningKey.generate()
    vk = sk.verify_key
    msg = b"capability:market_analysis|constraint:maxValue=50000"
    signed = sk.sign(msg)

    results = {}

    print("\n[1/2] Ed25519 Sign...")
    results["sign"] = time_op(lambda: sk.sign(msg))
    print(f"  Median: {results['sign']['median_ms']:.3f} ms")

    print("[2/2] Ed25519 Verify...")
    results["verify"] = time_op(lambda: vk.verify(signed))
    print(f"  Median: {results['verify']['median_ms']:.3f} ms")

    return results


def main():
    bls = run_bls_benchmarks()
    ed = run_ed25519_benchmarks()

    # Comparison
    print(f"\n{'='*60}")
    print("TIER 1 (Ed25519) vs TIER 2 (BLS12-381) COMPARISON")
    print(f"{'='*60}")
    print(f"{'Operation':<30} {'Ed25519':>10} {'BLS12-381':>10} {'Overhead':>10}")
    print("-" * 60)
    print(f"{'Sign (single)':<30} {ed['sign']['median_ms']:>9.3f}ms {bls['sign_single']['median_ms']:>9.3f}ms {bls['sign_single']['median_ms']/max(ed['sign']['median_ms'],0.001):>9.1f}x")
    print(f"{'Verify (single)':<30} {ed['verify']['median_ms']:>9.3f}ms {bls['verify_single']['median_ms']:>9.3f}ms {bls['verify_single']['median_ms']/max(ed['verify']['median_ms'],0.001):>9.1f}x")
    print(f"{'Credential Issue (4 msg)':<30} {'N/A':>10} {bls['aggregate_sign']['median_ms']:>9.3f}ms {'':>10}")
    print(f"{'Present Verify (4 msg)':<30} {'N/A':>10} {bls['aggregate_verify']['median_ms']:>9.3f}ms {'':>10}")
    print(f"{'Selective Disc. (2/4)':<30} {'N/A':>10} {bls['selective_disclosure_verify']['median_ms']:>9.3f}ms {'':>10}")

    results = {
        "bls12_381": bls,
        "ed25519": ed,
        "comparison": {
            "sign_overhead": round(bls["sign_single"]["median_ms"] / max(ed["sign"]["median_ms"], 0.001), 1),
            "verify_overhead": round(bls["verify_single"]["median_ms"] / max(ed["verify"]["median_ms"], 0.001), 1),
        },
        "metadata": {
            "library": "blspy 2.0.3 (Chia BLS12-381 C implementation)",
            "iterations": ITERATIONS,
            "warmup": WARMUP,
            "note": "Real BLS12-381 operations, not estimates. blspy uses optimized C/ASM pairings.",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    }

    os.makedirs("results", exist_ok=True)
    with open("results/bbs_real_benchmark.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to results/bbs_real_benchmark.json")


if __name__ == "__main__":
    main()
