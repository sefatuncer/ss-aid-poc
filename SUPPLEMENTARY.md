# Supplementary Material — Reviewer Guide

**Paper:** Boundary Conditions for Decentralized Identity in Autonomous Agent Networks
**Target:** IEEE Security & Privacy magazine
**License:** MIT

## What This Archive Contains

- **`/`** — Reference implementation (Python 3.11) of the SS-AID framework: identity issuance, verifiable credentials, Policy Enforcement Point, Dynamic Capability Tokens, accumulator-based revocation, and an OAuth 2.1 baseline.
- **`/results/`** — Pre-computed JSON output files corresponding to every numerical claim in the paper (10.5% OAuth spoofing, 95.4% chain integrity, 32-agent crossover, BBS+ latency, etc.).
- **`README.md`** — Full module overview, paper-claim ↔ script ↔ result-file mapping, and methodology notes.
- **`LICENSE`** — MIT license terms.

## Quick Reviewer Verification (5 minutes)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python run_all.py                  # Reproduces Table II per-operation latency
```

Compare the printed totals against Table II in the paper:

| Operation | Paper (ms) | run_all.py output |
|-----------|-----------:|-------------------|
| API-Key total auth cycle | 0.001 | (printed) |
| OAuth 2.1 total auth cycle | 0.034 | (printed) |
| SS-AID total auth cycle | 0.319 | (printed) |

Magnitude agreement (within experimental variance) confirms the basic system pipeline runs end-to-end.

## Mapping Paper Claims to Result Files

Every numerical claim in the paper is backed by a JSON file under `results/`. See `README.md` § "Paper claim ↔ PoC mapping" for the complete table.

Most-cited result files:
- `crossorg_attack_results.json` — Scenario B/C attack rates (10.5% OAuth spoofing, 6% delegation cascade, 5–6% revocation acceptance)
- `extended_attack_results.json` — Delegation depth chain integrity (95.4% at depth 5, 87.2% at depth 10) + per-hop $(1-p)^d$ model
- `scalability_results.json` — Wall-clock measurements across 2-64 concurrent agents (Fig. 4)
- `bbs_real_benchmark.json` — BLS12-381 BBS+ measurements (Fig. 3)
- `statistical_analysis.json` — Wilson 95% CIs and bootstrap latency intervals
- `full_results.json` — Table II per-operation latency

## Reproducibility Settings

- **Random seed:** 42 (set in every script with synthetic adversaries)
- **Iterations:** 1000 per attack-configuration pair, 30 wall-clock measurements per agent count
- **Hardware (paper numbers):** Intel Xeon E5-2680 v4, 64 GB RAM, Ubuntu 22.04, Python 3.10.12
- **Network I/O excluded** to isolate cryptographic overhead — see `README.md` § Limitations.

## Anonymization

All synthetic identifiers in result files (DIDs, credential subjects, agent IDs) use deterministic seeds without personal information. No real organizational identities, user data, or production credentials appear anywhere in this archive.

## Known Limitations (Magazine-Acknowledged)

1. **BBS+ pure-Python (py_ecc)** is ~500× slower than production C libraries; canonical numbers come from `bbs_benchmark_real.py` via blspy.
2. **Groth16 proof timing (8-40 s)** is reported from team measurements; circuit-level benchmarking is left for follow-up work.
3. **Revocation propagation** is modeled probabilistically rather than over a live distributed ledger.
4. **Single-server testbed** — the 32-agent crossover is hardware-bound to the Intel Xeon environment, not a deployment threshold.

These limitations are explicitly discussed in the paper's *Scope and Limitations* paragraph and the *What We Got Wrong, and What Surprised Us* discussion subsection.

## Contact

Code questions and reproduction issues will be addressed via the public repository (URL to be assigned upon acceptance) and the paper's corresponding-author channel established at camera-ready.
