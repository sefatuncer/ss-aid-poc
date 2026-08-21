#!/usr/bin/env python3
"""
SS-AID PoC — Run All Experiments
Generates data for Table 2 (attacks) and Table 3 (performance) in the paper.
"""

import json
import os
import sys
import time
import platform

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark import run_apikey_benchmarks, run_oauth_benchmarks, run_ssaid_benchmarks
from attacks import run_all_attacks

ITERATIONS = 1000


def get_system_info():
    """Collect system information for reproducibility."""
    import nacl
    import cryptography
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
        "pynacl_version": nacl.__version__,
        "cryptography_version": cryptography.__version__,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


def main():
    print("=" * 60)
    print("SS-AID Proof-of-Concept — Full Experiment Suite")
    print("=" * 60)

    os.makedirs("results", exist_ok=True)
    sysinfo = get_system_info()
    print(f"\nSystem: {sysinfo['platform']}")
    print(f"Python: {sysinfo['python_version']}")

    # Phase 1: Performance Benchmarks
    print("\n\n" + "=" * 60)
    print("PHASE 1: PERFORMANCE BENCHMARKS")
    print("=" * 60)

    apikey_perf = run_apikey_benchmarks(ITERATIONS)
    oauth_perf = run_oauth_benchmarks(ITERATIONS)
    ssaid_perf = run_ssaid_benchmarks(ITERATIONS)

    # Phase 2: Attack Simulations
    print("\n\n" + "=" * 60)
    print("PHASE 2: ATTACK SIMULATIONS")
    print("=" * 60)

    attack_results = run_all_attacks(ITERATIONS)

    # Summary
    print("\n\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)

    print("\n--- Table 3: Per-Operation Latency (median ms) ---")
    print(f"{'Operation':<25} {'API-Key':>10} {'OAuth 2.1':>10} {'SS-AID':>10}")
    print("-" * 55)
    print(f"{'Key/Token Issue':<25} {'N/A':>10} {oauth_perf['token_issue']['median_ms']:>10.3f} {ssaid_perf['credential_issue']['median_ms']:>10.3f}")
    print(f"{'Auth/Verify':<25} {apikey_perf['key_verify']['median_ms']:>10.3f} {oauth_perf['token_verify']['median_ms']:>10.3f} {ssaid_perf['credential_verify']['median_ms']:>10.3f}")
    print(f"{'Scope Check':<25} {'N/A':>10} {oauth_perf['scope_check']['median_ms']:>10.3f} {ssaid_perf['pep_scope_check']['median_ms']:>10.3f}")
    print(f"{'Revocation Check':<25} {'N/A':>10} {oauth_perf['revocation_check']['median_ms']:>10.3f} {ssaid_perf['revocation_check']['median_ms']:>10.3f}")
    print(f"{'Total Auth Cycle':<25} {apikey_perf['total_auth_cycle']['median_ms']:>10.3f} {oauth_perf['total_auth_cycle']['median_ms']:>10.3f} {ssaid_perf['total_auth_cycle']['median_ms']:>10.3f}")

    overhead = ssaid_perf['total_auth_cycle']['median_ms'] / max(oauth_perf['total_auth_cycle']['median_ms'], 0.001)
    print(f"\nSS-AID overhead vs OAuth: {overhead:.1f}x")

    print("\n--- Table 2: Attack Success Rates (%) ---")
    print(f"{'Attack':<25} {'No-Auth':>8} {'API-Key':>8} {'OAuth':>8} {'SS-AID':>8}")
    print("-" * 57)
    print(f"{'Spoofing':<25} {attack_results['spoofing_noauth']:>7.1f}% {attack_results['spoofing_apikey']:>7.1f}% {attack_results['spoofing_oauth']:>7.1f}% {attack_results['spoofing_ssaid']:>7.1f}%")
    print(f"{'Delegation Cascade':<25} {'N/A':>8} {'N/A':>8} {attack_results['delegation_oauth']:>7.1f}% {attack_results['delegation_ssaid']:>7.1f}%")
    print(f"{'Revoked Credential':<25} {'N/A':>8} {'N/A':>8} {attack_results['revoked_oauth']:>7.1f}% {attack_results['revoked_ssaid']:>7.1f}%")

    # Save all results
    all_results = {
        "system_info": sysinfo,
        "performance": {
            "api_key": apikey_perf,
            "oauth": oauth_perf,
            "ssaid": ssaid_perf,
            "overhead_vs_oauth": round(overhead, 1)
        },
        "attacks": attack_results,
        "iterations": ITERATIONS
    }

    output_file = "results/full_results.json"
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n\nAll results saved to {output_file}")


if __name__ == "__main__":
    main()
