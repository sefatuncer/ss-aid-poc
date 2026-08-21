# SS-AID Proof-of-Concept

Reference implementation and experimental harness for the paper:

> **Boundary Conditions: When AI Agents Need Decentralized Identity**
> IEEE Security & Privacy (Magazine), manuscript SP-2026-06-0276

This package produces the data behind the per-operation latency table, the
communication-cost figures, the scaling sweep and the attack rates reported in
the article. The mapping below names the script and the result file for each
claim and says what kind of evidence it is.

License: MIT (see `LICENSE`).

## System Requirements

- Python 3.10 (tested on 3.10.12; 3.11 also works)
- Linux/macOS preferred for blspy compatibility; Windows works for Python-only modules

The reported numbers in the paper were generated on:
- CPU: Intel Xeon E5-2680 v4
- RAM: 64 GB
- OS: Ubuntu 22.04
- Python: 3.10.12

## Installation

```bash
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
# .venv\Scripts\activate      # Windows PowerShell
pip install -r requirements.txt
```

## Reproducing Paper Claims

### Quick verification (~5 minutes)

```bash
python run_all.py
```

Outputs the per-operation latency numbers (Ed25519, OAuth 2.1, SS-AID) and the illustrative attack rates to `results/full_results.json`.

### Full suite (~15 minutes)

```bash
python run_all.py                 # per-operation latency (hardware dependent)
python attacks_crossorg.py        # 10.5% OAuth spoofing, 5–6% revocation
python attacks_extended.py        # depth-5 chain integrity, depth-10 deviation
python scalability.py             # scaling sweep (2-64 agents)
python bbs_benchmark_real.py      # Tier-1 proxy timings (BLS12-381 via blspy)
python generate_figures.py        # Render figures to ../paper/figures/
```

### Paper claim to PoC mapping

The evidence column matters as much as the file name. A **measurement** is a
timing or a size taken from code that really performs the operation. A **model
output** is produced by drawing against a rate or a delay that we stipulated;
it describes our model, not any deployment. A **derived** value is computed
from other values rather than observed.

| Paper claim | Script | Result file | Evidence |
|---|---|---|---|
| Per-operation latency table (API-key, OAuth, SS-AID) | `run_all.py` | `results/full_results.json` | measurement, hardware dependent |
| Communication cost in bytes (DID document, credential, token, chain) | `measure_bytes.py` | `results/comm_cost_results.json` | measurement |
| Tier-1 figure, 2.5 ms median and 4.2 ms p95 | `bbs_benchmark_real.py` | `results/bbs_real_benchmark.json` | measurement of a **proxy**: BLS aggregate verification standing in for BBS+ proof verification |
| Scaling from 2 to 64 agents (OAuth 7.3x, SS-AID 4.2x) | `scalability.py` | `results/scalability_results.json` | measurement under a modelling choice: OAuth workers share a lock that represents a single authorization server |
| 10.5% OAuth spoofing, cross-organizational | `attacks_crossorg.py` | `results/crossorg_attack_results.json` | model output, drawn against the stipulated rates in `MODEL_RATES` |
| 6.4% delegation cascade, cross-organizational | `attacks_crossorg.py` | `results/crossorg_attack_results.json` | model output |
| Revocation window, 4.5-5.8% SS-AID against 1.7-3.2% OAuth | `attacks_crossorg.py` | `results/crossorg_attack_results.json` | model output, driven by the assumed propagation window |
| Sensitivity of the above to the assumed rates | `attacks_crossorg.py --sweep` | `results/sensitivity_sweep.json` | model output |
| 95.4% chain integrity at depth 5 | `attacks_extended.py` | `results/extended_attack_results.json` | model output; each hop is an independent Bernoulli draw, so the sweep reproduces the analytic curve by construction |
| Wilson confidence intervals, bootstrap latency | `attacks_extended.py` | `results/statistical_analysis.json` | derived |
| Delegation rules, Tamarin theory | `formal/ssaid.spthy` | none | **not executed.** The article does not claim these lemmas are machine-checked. See `formal/README.md` for the model's limitations before running it |

**Withdrawn claim.** An earlier version of the article reported 87.2% chain
integrity at depth 10 against an independence prediction of 90.4% and treated
the gap as accelerated degradation. Re-running the sweep with 3,000 trials per
depth removes it, empirical and modelled integrity then agree to within half a
percentage point, and the model contains no mechanism that could produce
super-independent decay. The claim has been withdrawn from the article.

### Reproducibility notes

- **Attack rates reproduce bit for bit.** `attacks_crossorg.py` and
  `attacks_extended.py` are seeded and were re-run on different hardware in
  August 2026, reproducing every rate in the archived result files exactly.
- **Latency figures do not, and should not be expected to.** They depend on the
  machine. The article's figures come from an Intel Xeon E5-2680 v4. Runs on
  other hardware are kept under `results/rerun-*` so the difference is visible
  rather than hidden.
- **`attacks.py` is illustrative and is not the source of any figure in the
  article.** Two of its outputs are easy to misread. Its OAuth spoofing case
  counts the replay of a legitimately issued, unexpired token as a success,
  which is ordinary token use rather than spoofing, so it reports roughly 33%.
  Its revoked-credential case checks the registry inside the propagation window
  by construction and therefore reports 100%. The article's corresponding
  figures come from `attacks_crossorg.py`, which models both cases explicitly.

## Module Overview

| Module | Role |
|--------|------|
| `identity.py` | DID generation (`did:key`, `did:web`), Ed25519 keys |
| `credentials.py` | W3C-style VC issuance, monotonic delegation |
| `pep.py` | Policy Enforcement Point — scope verification |
| `dct.py` | Dynamic Capability Tokens — short-lived, nonce-protected |
| `revocation.py` | Hash-based status registry standing in for the accumulator; no accumulator is implemented |
| `oauth_baseline.py` | OAuth 2.1 simulation (HMAC-SHA256, centralized authorization server) |
| `benchmark.py` | Per-operation latency measurement (1000 iterations) |
| `attacks.py` | Illustrative attack scenarios; not the source of any figure in the article, see Reproducibility notes |
| `attacks_crossorg.py` | Scenario B (cross-org) attack model with three federation weakness classes (RFC 9700 §4) |
| `attacks_extended.py` | Delegation depth $(1-p)^d$ chain integrity, statistical analysis |
| `scalability.py` | Concurrent agent scaling (2-64 agents, multiprocessing) |
| `bbs_benchmark_real.py` | BLS12-381 aggregate timings via blspy, used as a proxy for the BBS+ proof path (see the module docstring) |
| `bbs_benchmark.py` | Reference BBS+ implementation via py_ecc; correct but pure Python, seconds per verification |
| `agent_integration.py` | End-to-end agent flow with all components |
| `generate_figures.py` | Renders Fig. 1, 3, 4 + architecture TikZ |
| `generate_figures_extra.py` | Optional supplementary figures |
| `run_all.py` | Top-level driver for `full_results.json` |
| `measure_bytes.py` | Wire-size measurement for the communication-cost table |
| `depth_test.py` | Convergence check behind the withdrawn depth-10 claim |
| `regen_scalability.py` | Redraws the scaling figure without the unsupported 32-agent marker |

## Methodology

- **Iterations:** 1000 per attack-configuration pair; 30 wall-clock measurements per agent count for scaling.
- **Random seed:** 42 (deterministic reproducibility).
- **Confidence intervals:** Wilson 95% for binomial proportions, bootstrap (10,000 resamples) for continuous latency.
- **No real personal data:** All identifiers and credentials are synthetic.

## Limitations

- **BBS+ benchmarks** rely on blspy (canonical) and py_ecc (legacy fallback). Production C libraries (e.g., blst) are 100–500× faster than py_ecc; results from `bbs_benchmark_real.py` are the canonical magnitudes.
- **Groth16 proof generation timing (8–40 s)** is reported from this team's measurements outside the main PoC harness; timing variance is implementation-dependent (circuit complexity, witness size, library JIT).
- **Network I/O** (DID resolution, DIDComm transport) is excluded from the latency loop to isolate cryptographic overhead. Production DID resolution adds ~50–500 ms.
- **Revocation propagation** is modeled probabilistically as a 5-minute global-consistency window rather than measured on a live distributed ledger.
- **Federation weakness model** for OAuth's 10.5% spoofing rate is grounded in RFC 9700 §4 (token misuse, redirect attacks, mix-up, credential leakage) but synthetic; production federation rates depend on deployment hardening.

See the paper's "Scope and Limitations" paragraph and "What We Got Wrong" section for the corresponding discussion.

## Repository Layout

```
poc/
├── README.md                  # This file
├── SUPPLEMENTARY.md           # 1-page guide for IEEE reviewers
├── LICENSE                    # MIT
├── requirements.txt           # Python dependencies
├── .gitignore                 # __pycache__, *.pyc exclusions
├── run_all.py                 # Top-level driver
├── identity.py                # Module sources (see Module Overview above)
├── credentials.py
├── pep.py
├── dct.py
├── revocation.py
├── oauth_baseline.py
├── benchmark.py
├── attacks.py
├── attacks_crossorg.py
├── attacks_extended.py
├── scalability.py
├── bbs_benchmark.py
├── bbs_benchmark_real.py
├── agent_integration.py
├── generate_figures.py
├── generate_figures_extra.py
├── formal/                    # Tamarin Prover theory (delegation monotonicity, revocation soundness)
│   ├── ssaid.spthy            #   Multi-set rewriting theory file
│   └── README.md              #   Reproduction instructions: tamarin-prover --prove
├── network_sim/               # Heterogeneous 3-region x 2-provider emulator
│   ├── heterogeneous_sim.py   #   Python emulation (no Docker required)
│   └── README.md              #   Topology, seed, output schema
└── results/                   # Generated empirical data
    ├── full_results.json
    ├── crossorg_attack_results.json
    ├── extended_attack_results.json
    ├── scalability_results.json
    ├── bbs_real_benchmark.json
    ├── bbs_benchmark_results.json
    ├── statistical_analysis.json
    └── heterogeneous_network_results.json
```

The Tamarin theory in `formal/` states the monotonicity and revocation-soundness lemmas as a specification. **It has not been machine-checked, and the article makes no claim that it has.** Read `formal/README.md` before running the prover: the model has no adversary channel and `Verify_Action` checks no signature, so closing the lemmas would show internal consistency of the rule system rather than security against an active adversary. The synthetic model in `network_sim/` produces the multi-region comparison discussed in the article (3 regions, 2 providers, 800 samples per cell); no packets cross a real network there.

## Citing This Code

Please cite both the article and this archive.

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22045011.svg)](https://doi.org/10.5281/zenodo.22045011)

- **This version (v1.0.0), the state behind the numbers in the article:** [10.5281/zenodo.22045011](https://doi.org/10.5281/zenodo.22045011)
- **All versions:** [10.5281/zenodo.22045010](https://doi.org/10.5281/zenodo.22045010)

`CITATION.cff` carries the full metadata.
