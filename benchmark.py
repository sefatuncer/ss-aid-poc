"""
SS-AID PoC — Benchmark Module
Measures per-operation latency for Table 3 (Performance Evaluation).
"""

import time
import statistics
import json
from identity import generate_did_key, generate_did_web, DIDRegistry
from credentials import issue_credential, issue_delegation, verify_credential
from pep import PolicyEnforcementPoint, ActionRequest
from dct import IdentityWallet, DynamicCapabilityToken
from revocation import RevocationRegistry
from oauth_baseline import OAuthServer


def time_operation(func, iterations=1000):
    """Run an operation N times and return timing statistics in milliseconds."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        times.append(elapsed_ms)
    return {
        "median_ms": round(statistics.median(times), 3),
        "mean_ms": round(statistics.mean(times), 3),
        "p95_ms": round(sorted(times)[int(len(times) * 0.95)], 3),
        "p99_ms": round(sorted(times)[int(len(times) * 0.99)], 3),
        "stddev_ms": round(statistics.stdev(times), 3),
        "min_ms": round(min(times), 3),
        "max_ms": round(max(times), 3),
        "iterations": iterations
    }


def run_ssaid_benchmarks(iterations=1000):
    """Benchmark all SS-AID operations."""
    print(f"\n{'='*60}")
    print(f"SS-AID BENCHMARKS ({iterations} iterations)")
    print(f"{'='*60}")

    # Setup
    registry = DIDRegistry()
    revocation = RevocationRegistry()

    principal = generate_did_web("org.example", "principal")
    agent = generate_did_web("org.example", "agent-01")
    peer = generate_did_web("peer.example", "agent-02")

    registry.register(principal)
    registry.register(agent)
    registry.register(peer)

    # Pre-create credential for verification benchmarks
    cred = issue_credential(
        issuer=principal,
        subject_did=agent.did,
        capabilities=["market_analysis", "portfolio_rebalance"],
        constraints={"maxTransactionValue": 50000, "allowedMarkets": ["NYSE", "NASDAQ"]},
        max_delegation_depth=3
    )

    wallet = IdentityWallet(agent, cred, registry)

    results = {}

    # 1. Credential Issuance
    print("\n[1/6] Credential Issuance...")
    results["credential_issue"] = time_operation(
        lambda: issue_credential(
            issuer=principal,
            subject_did=agent.did,
            capabilities=["market_analysis"],
            constraints={"maxTransactionValue": 50000},
        ),
        iterations
    )
    print(f"  Median: {results['credential_issue']['median_ms']:.3f} ms")

    # 2. Credential Verification (Auth/Present)
    print("[2/6] Credential Verification (Auth/Present)...")
    results["credential_verify"] = time_operation(
        lambda: verify_credential(cred, registry),
        iterations
    )
    print(f"  Median: {results['credential_verify']['median_ms']:.3f} ms")

    # 3. Signature Verification Only
    print("[3/6] Ed25519 Signature Verify...")
    msg = b"test message for signature verification"
    sig = agent.sign(msg)
    results["signature_verify"] = time_operation(
        lambda: registry.verify_signature(agent.did, msg, sig),
        iterations
    )
    print(f"  Median: {results['signature_verify']['median_ms']:.3f} ms")

    # 4. PEP Scope Check
    print("[4/6] PEP Scope Check...")
    pep = PolicyEnforcementPoint(cred)
    action = ActionRequest(
        action_type="market_analysis",
        parameters={"market": "NYSE", "amount": 5000},
        requesting_agent_did=agent.did
    )
    results["pep_scope_check"] = time_operation(
        lambda: pep.evaluate(action),
        iterations
    )
    print(f"  Median: {results['pep_scope_check']['median_ms']:.3f} ms")

    # 5. DCT Generation + PEP (Full auth cycle for SS-AID)
    print("[5/6] DCT Generation (includes PEP)...")
    results["dct_generation"] = time_operation(
        lambda: wallet.request_action("market_analysis", {"market": "NYSE", "amount": 5000}),
        iterations
    )
    print(f"  Median: {results['dct_generation']['median_ms']:.3f} ms")

    # 6. Revocation Check
    print("[6/6] Revocation Check...")
    cred_bytes = cred.canonical_bytes()
    results["revocation_check"] = time_operation(
        lambda: revocation.generate_non_revocation_proof(cred_bytes),
        iterations
    )
    print(f"  Median: {results['revocation_check']['median_ms']:.3f} ms")

    # Total auth cycle
    total = (results["credential_verify"]["median_ms"] +
             results["pep_scope_check"]["median_ms"] +
             results["dct_generation"]["median_ms"] +
             results["revocation_check"]["median_ms"])
    results["total_auth_cycle"] = {"median_ms": round(total, 3)}

    return results


def run_oauth_benchmarks(iterations=1000):
    """Benchmark OAuth 2.1 baseline operations."""
    print(f"\n{'='*60}")
    print(f"OAUTH 2.1 BENCHMARKS ({iterations} iterations)")
    print(f"{'='*60}")

    server = OAuthServer()
    server.register_client("agent-01", ["market_analysis", "portfolio_rebalance"])

    # Pre-create token for verification benchmarks
    token = server.issue_token("agent-01", ["market_analysis", "portfolio_rebalance"])

    results = {}

    # 1. Token Issuance
    print("\n[1/4] Token Issuance...")
    results["token_issue"] = time_operation(
        lambda: server.issue_token("agent-01", ["market_analysis"]),
        iterations
    )
    print(f"  Median: {results['token_issue']['median_ms']:.3f} ms")

    # 2. Token Verification
    print("[2/4] Token Verification...")
    results["token_verify"] = time_operation(
        lambda: server.verify_token(token),
        iterations
    )
    print(f"  Median: {results['token_verify']['median_ms']:.3f} ms")

    # 3. Scope Check
    print("[3/4] Scope Check...")
    results["scope_check"] = time_operation(
        lambda: server.check_scope(token, "market_analysis"),
        iterations
    )
    print(f"  Median: {results['scope_check']['median_ms']:.3f} ms")

    # 4. Revocation Check (centralized — immediate)
    print("[4/4] Revocation Check...")
    results["revocation_check"] = time_operation(
        lambda: token.token_id not in server._revoked_tokens,
        iterations
    )
    print(f"  Median: {results['revocation_check']['median_ms']:.3f} ms")

    total = (results["token_verify"]["median_ms"] +
             results["scope_check"]["median_ms"] +
             results["revocation_check"]["median_ms"])
    results["total_auth_cycle"] = {"median_ms": round(total, 3)}

    return results


def run_apikey_benchmarks(iterations=1000):
    """Benchmark API-Key baseline."""
    print(f"\n{'='*60}")
    print(f"API-KEY BENCHMARKS ({iterations} iterations)")
    print(f"{'='*60}")

    import hmac, hashlib, os
    secret = os.urandom(32)
    api_key = hashlib.sha256(b"agent-01-key").hexdigest()

    results = {}

    print("\n[1/1] API-Key Verify...")
    results["key_verify"] = time_operation(
        lambda: hmac.compare_digest(api_key, hashlib.sha256(b"agent-01-key").hexdigest()),
        iterations
    )
    print(f"  Median: {results['key_verify']['median_ms']:.3f} ms")

    results["total_auth_cycle"] = results["key_verify"]
    return results


if __name__ == "__main__":
    ITERATIONS = 1000

    apikey = run_apikey_benchmarks(ITERATIONS)
    oauth = run_oauth_benchmarks(ITERATIONS)
    ssaid = run_ssaid_benchmarks(ITERATIONS)

    print(f"\n{'='*60}")
    print("SUMMARY — Total Auth Cycle (median ms)")
    print(f"{'='*60}")
    print(f"  API-Key:   {apikey['total_auth_cycle']['median_ms']:.3f} ms")
    print(f"  OAuth 2.1: {oauth['total_auth_cycle']['median_ms']:.3f} ms")
    print(f"  SS-AID:    {ssaid['total_auth_cycle']['median_ms']:.3f} ms")
    print(f"  SS-AID overhead vs OAuth: {ssaid['total_auth_cycle']['median_ms'] / max(oauth['total_auth_cycle']['median_ms'], 0.001):.1f}x")

    all_results = {
        "api_key": apikey,
        "oauth": oauth,
        "ssaid": ssaid,
        "metadata": {
            "iterations": ITERATIONS,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    }

    with open("results/benchmark_results.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to results/benchmark_results.json")
