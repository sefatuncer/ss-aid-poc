"""
SS-AID PoC — Scalability Benchmark (2-64 Concurrent Agents)

Measures how authentication latency scales with the number of concurrent agents:
  - API-Key: O(1) trivial hash check — no shared state, constant time
  - OAuth 2.1: Centralized AS serializes requests through shared lock
  - SS-AID: Independent per-agent DID verification — no shared bottleneck

FAIR COMPARISON: Both OAuth and SS-AID use multiprocessing.Pool for
platform-level parallelism. The architectural difference is modeled
through shared vs independent resources:
  - OAuth: workers acquire a multiprocessing.Lock (models centralized AS)
  - SS-AID: workers operate independently (models decentralized verification)

This ensures the scaling difference reflects architectural properties,
not Python threading artifacts (GIL).

Methodology:
  - Measure per-operation latency without concurrency first (baseline)
  - Then simulate N concurrent agents via multiprocessing.Pool
  - 30 trials per concurrency level
"""

import json
import math
import os
import time
import statistics
import hashlib
import hmac
# threading no longer needed — using multiprocessing for both systems
from multiprocessing import Pool, Lock as MPLock, Manager, cpu_count
from dataclasses import dataclass
from typing import List

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

# Global multiprocessing lock for OAuth centralized server simulation
_oauth_lock = None
_oauth_secret = None

CONCURRENCY_LEVELS = [2, 4, 8, 16, 32, 64]
TRIALS_PER_LEVEL = 30
WARMUP_TRIALS = 5
NUM_CPUS = cpu_count()


# =============================================================================
# Single-Operation Baselines (no concurrency)
# =============================================================================

def _apikey_single_op() -> float:
    """Single API-key verification. Returns ms."""
    start = time.perf_counter_ns()
    key = hashlib.sha256(b"agent-shared-key").hexdigest()
    _ = hmac.compare_digest(key, hashlib.sha256(b"agent-shared-key").hexdigest())
    return (time.perf_counter_ns() - start) / 1_000_000


def _oauth_single_op() -> float:
    """Single OAuth token issue+verify cycle. Returns ms."""
    server_secret = os.urandom(32)
    start = time.perf_counter_ns()

    # Token issuance
    token_id = hashlib.sha256(f"agent-01{time.time_ns()}".encode()).hexdigest()[:32]
    payload = json.dumps({
        "tid": token_id, "cid": "agent-01",
        "scope": ["market_analysis"], "exp": time.time() + 3600
    }, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(server_secret, payload, hashlib.sha256).digest()

    # Token verification
    expected = hmac.new(server_secret, payload, hashlib.sha256).digest()
    _ = hmac.compare_digest(signature, expected)

    # Scope check
    _ = "market_analysis" in ["market_analysis"]

    return (time.perf_counter_ns() - start) / 1_000_000


def _ssaid_single_op() -> float:
    """Single SS-AID full auth cycle. Returns ms."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    pk_hex = vk.encode(encoder=HexEncoder).decode()
    cred_data = b"capability:market_analysis|constraint:maxValue=50000"

    start = time.perf_counter_ns()

    # 1. DID resolution (dict lookup)
    _ = pk_hex

    # 2. Credential verification (Ed25519)
    signature = sk.sign(cred_data).signature
    vk_check = VerifyKey(bytes.fromhex(pk_hex))
    vk_check.verify(cred_data, signature)

    # 3. PEP scope check
    _ = "market_analysis" in ["market_analysis", "portfolio_rebalance"]

    # 4. DCT generation
    nonce = hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:16]
    dct_payload = json.dumps({
        "action": "market_analysis", "did": "did:web:org:agent",
        "exp": time.time() + 60, "nonce": nonce
    }, sort_keys=True, separators=(",", ":")).encode()
    _ = sk.sign(dct_payload)

    # 5. Revocation check (accumulator simulation)
    witness = hashlib.sha256(cred_data).hexdigest()
    for _ in range(100):
        witness = hashlib.sha256(witness.encode()).hexdigest()

    return (time.perf_counter_ns() - start) / 1_000_000


# =============================================================================
# Concurrent Authentication Simulation (Fair: both use multiprocessing)
# =============================================================================

def _init_oauth_worker(lock, secret):
    """Initialize global lock and secret for OAuth worker processes."""
    global _oauth_lock, _oauth_secret
    _oauth_lock = lock
    _oauth_secret = secret


def _oauth_parallel_worker(args) -> float:
    """
    OAuth auth cycle in a separate process, serialized through shared lock.
    Models: centralized AS where all requests must pass through one server.
    Uses multiprocessing.Lock (not threading.Lock) for fair comparison.
    """
    agent_id, _ = args
    start = time.perf_counter_ns()

    # Acquire centralized server lock (models single AS bottleneck)
    with _oauth_lock:
        # Token issuance
        token_id = hashlib.sha256(
            f"agent-{agent_id}{time.time_ns()}".encode()
        ).hexdigest()[:32]
        payload = json.dumps({
            "tid": token_id, "cid": f"agent-{agent_id}",
            "scope": ["market_analysis"], "exp": time.time() + 3600
        }, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(_oauth_secret, payload, hashlib.sha256).digest()

        # Token verification
        expected = hmac.new(_oauth_secret, payload, hashlib.sha256).digest()
        _ = hmac.compare_digest(sig, expected)

        # Server-side processing (DB lookup, audit, rate limit)
        for _ in range(300):
            hashlib.sha256(payload).digest()

    return (time.perf_counter_ns() - start) / 1_000_000


def _ssaid_parallel_worker(args) -> float:
    """Worker function for multiprocessing SS-AID auth."""
    agent_id, seed_offset = args
    # Each worker creates its own keys (simulating independent agents)
    import os as _os
    # Use deterministic seed for reproducibility
    sk = SigningKey(hashlib.sha256(f"agent-{agent_id}-{seed_offset}".encode()).digest())
    vk = sk.verify_key
    cred_data = b"capability:market_analysis|constraint:maxValue=50000"

    start = time.perf_counter_ns()

    # Full SS-AID auth cycle (completely independent, no shared state)
    # 1. DID resolution
    pk_hex = vk.encode(encoder=HexEncoder).decode()

    # 2. Credential verification
    signature = sk.sign(cred_data).signature
    vk_check = VerifyKey(bytes.fromhex(pk_hex))
    vk_check.verify(cred_data, signature)

    # 3. PEP scope check
    _ = "market_analysis" in ["market_analysis", "portfolio_rebalance"]

    # 4. DCT generation
    nonce = hashlib.sha256(f"{time.time_ns()}did:web:org:agent-{agent_id}".encode()).hexdigest()[:16]
    dct_payload = json.dumps({
        "action": "market_analysis", "did": f"did:web:org:agent-{agent_id}",
        "exp": time.time() + 60, "nonce": nonce
    }, sort_keys=True, separators=(",", ":")).encode()
    _ = sk.sign(dct_payload)

    # 5. Revocation check
    witness = hashlib.sha256(cred_data).hexdigest()
    for _ in range(100):
        witness = hashlib.sha256(witness.encode()).hexdigest()

    return (time.perf_counter_ns() - start) / 1_000_000


def run_batch_auth(num_agents: int, trial: int) -> dict:
    """
    Run a batch of N concurrent agent authentications.
    FAIR: Both OAuth and SS-AID use multiprocessing.Pool.
    OAuth workers share a multiprocessing.Lock (centralized server model).
    SS-AID workers operate independently (decentralized verification model).
    """
    result = {}
    workers = min(num_agents, NUM_CPUS)
    worker_args = [(i, trial) for i in range(num_agents)]

    # --- API-Key (trivial, sequential) ---
    batch_start = time.perf_counter_ns()
    apikey_times = [_apikey_single_op() for _ in range(num_agents)]
    batch_wall = (time.perf_counter_ns() - batch_start) / 1_000_000
    result["apikey"] = {
        "per_agent_median_ms": statistics.median(apikey_times),
        "wall_clock_ms": batch_wall,
    }

    # --- OAuth (multiprocessing + shared lock = centralized bottleneck) ---
    mp_lock = MPLock()
    server_secret = os.urandom(32)
    batch_start = time.perf_counter_ns()
    with Pool(processes=workers, initializer=_init_oauth_worker,
              initargs=(mp_lock, server_secret)) as pool:
        oauth_times = pool.map(_oauth_parallel_worker, worker_args)
    batch_wall = (time.perf_counter_ns() - batch_start) / 1_000_000
    result["oauth"] = {
        "per_agent_median_ms": statistics.median(oauth_times),
        "per_agent_max_ms": max(oauth_times),
        "wall_clock_ms": batch_wall,
    }

    # --- SS-AID (multiprocessing, no shared lock = independent verification) ---
    batch_start = time.perf_counter_ns()
    with Pool(processes=workers) as pool:
        ssaid_times = pool.map(_ssaid_parallel_worker, worker_args)
    batch_wall = (time.perf_counter_ns() - batch_start) / 1_000_000
    result["ssaid"] = {
        "per_agent_median_ms": statistics.median(ssaid_times),
        "per_agent_max_ms": max(ssaid_times),
        "wall_clock_ms": batch_wall,
    }

    return result


def run_scalability_suite() -> dict:
    """Run full scalability benchmark across all concurrency levels."""
    print(f"\n{'='*70}")
    print(f"SCALABILITY BENCHMARK: Concurrent Agent Authentication")
    print(f"Concurrency: {CONCURRENCY_LEVELS} | Trials: {TRIALS_PER_LEVEL}")
    print(f"CPU cores: {NUM_CPUS}")
    print(f"{'='*70}")

    # Baseline: single-operation latency
    print("\nBaseline (single operation, 100 iterations)...")
    apikey_base = [_apikey_single_op() for _ in range(100)]
    oauth_base = [_oauth_single_op() for _ in range(100)]
    ssaid_base = [_ssaid_single_op() for _ in range(100)]

    baseline = {
        "apikey_ms": round(statistics.median(apikey_base), 3),
        "oauth_ms": round(statistics.median(oauth_base), 3),
        "ssaid_ms": round(statistics.median(ssaid_base), 3),
    }
    print(f"  API-Key: {baseline['apikey_ms']:.3f} ms")
    print(f"  OAuth:   {baseline['oauth_ms']:.3f} ms")
    print(f"  SS-AID:  {baseline['ssaid_ms']:.3f} ms")

    # Warmup
    print(f"\nWarmup ({WARMUP_TRIALS} trials at 4 agents)...")
    for _ in range(WARMUP_TRIALS):
        _ = run_batch_auth(4, -1)

    # Main benchmark
    results = {}
    for n in CONCURRENCY_LEVELS:
        print(f"\n--- {n} concurrent agents ---")

        trial_data = {
            "apikey_wall": [], "oauth_wall": [], "ssaid_wall": [],
            "apikey_per": [], "oauth_per": [], "ssaid_per": [],
        }

        for t in range(TRIALS_PER_LEVEL):
            r = run_batch_auth(n, t)
            trial_data["apikey_wall"].append(r["apikey"]["wall_clock_ms"])
            trial_data["oauth_wall"].append(r["oauth"]["wall_clock_ms"])
            trial_data["ssaid_wall"].append(r["ssaid"]["wall_clock_ms"])
            trial_data["apikey_per"].append(r["apikey"]["per_agent_median_ms"])
            trial_data["oauth_per"].append(r["oauth"]["per_agent_median_ms"])
            trial_data["ssaid_per"].append(r["ssaid"]["per_agent_median_ms"])

        def agg(data):
            return {
                "median_ms": round(statistics.median(data), 3),
                "mean_ms": round(statistics.mean(data), 3),
                "stddev_ms": round(statistics.stdev(data), 3) if len(data) > 1 else 0,
                "p95_ms": round(sorted(data)[int(len(data) * 0.95)], 3),
            }

        results[n] = {
            "num_agents": n,
            "apikey": {
                "wall_clock": agg(trial_data["apikey_wall"]),
                "per_agent": agg(trial_data["apikey_per"]),
            },
            "oauth": {
                "wall_clock": agg(trial_data["oauth_wall"]),
                "per_agent": agg(trial_data["oauth_per"]),
            },
            "ssaid": {
                "wall_clock": agg(trial_data["ssaid_wall"]),
                "per_agent": agg(trial_data["ssaid_per"]),
            },
        }

        r = results[n]
        print(f"  API-Key  wall: {r['apikey']['wall_clock']['median_ms']:>8.3f} ms  per-agent: {r['apikey']['per_agent']['median_ms']:>8.3f} ms")
        print(f"  OAuth    wall: {r['oauth']['wall_clock']['median_ms']:>8.3f} ms  per-agent: {r['oauth']['per_agent']['median_ms']:>8.3f} ms")
        print(f"  SS-AID   wall: {r['ssaid']['wall_clock']['median_ms']:>8.3f} ms  per-agent: {r['ssaid']['per_agent']['median_ms']:>8.3f} ms")

    # Compute scaling factors (wall-clock relative to 2-agent)
    base_n = 2
    scaling = {}
    for n in CONCURRENCY_LEVELS:
        scaling[n] = {
            "apikey_wall_factor": round(
                results[n]["apikey"]["wall_clock"]["median_ms"] /
                max(results[base_n]["apikey"]["wall_clock"]["median_ms"], 0.001), 2
            ),
            "oauth_wall_factor": round(
                results[n]["oauth"]["wall_clock"]["median_ms"] /
                max(results[base_n]["oauth"]["wall_clock"]["median_ms"], 0.001), 2
            ),
            "ssaid_wall_factor": round(
                results[n]["ssaid"]["wall_clock"]["median_ms"] /
                max(results[base_n]["ssaid"]["wall_clock"]["median_ms"], 0.001), 2
            ),
        }

    print(f"\n{'='*70}")
    print("WALL-CLOCK SCALING (all agents complete, relative to 2-agent)")
    print(f"{'='*70}")
    print(f"{'Agents':<8} {'API-Key':>10} {'OAuth':>10} {'SS-AID':>10}  {'OAuth/SS-AID':>14}")
    print("-" * 52)
    for n in CONCURRENCY_LEVELS:
        s = scaling[n]
        ratio = results[n]["oauth"]["wall_clock"]["median_ms"] / max(results[n]["ssaid"]["wall_clock"]["median_ms"], 0.001)
        print(f"{n:<8} {s['apikey_wall_factor']:>9.2f}x {s['oauth_wall_factor']:>9.2f}x {s['ssaid_wall_factor']:>9.2f}x  {ratio:>13.2f}x")

    return {
        "baseline": baseline,
        "results": {str(k): v for k, v in results.items()},
        "scaling_factors": {str(k): v for k, v in scaling.items()},
        "metadata": {
            "concurrency_levels": CONCURRENCY_LEVELS,
            "trials_per_level": TRIALS_PER_LEVEL,
            "warmup_trials": WARMUP_TRIALS,
            "cpu_cores": NUM_CPUS,
            "oauth_model": "multiprocessing.Pool + shared Lock (centralized AS model)",
            "ssaid_model": "multiprocessing.Pool, no shared lock (independent verification)",
            "fairness_note": "Both use multiprocessing.Pool; difference is shared vs independent resources",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    }


if __name__ == "__main__":
    results = run_scalability_suite()

    os.makedirs("results", exist_ok=True)
    with open("results/scalability_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to results/scalability_results.json")
