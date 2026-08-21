# Reviewer guide to this archive

**Paper:** Boundary Conditions: When AI Agents Need Decentralized Identity
**Manuscript:** SP-2026-06-0276, IEEE Security & Privacy (Magazine)
**License:** MIT

Read `README.md` first. It maps every claim in the article to the script and
result file behind it and labels each number as a measurement, a model output
or a derived value. This file is a short orientation for a reviewer.

## What this archive contains

- **`/`** — reference implementation in Python: DID and verifiable credential
  issuance, the Policy Enforcement Point, Dynamic Capability Tokens, a
  revocation registry, and an OAuth 2.1 baseline.
- **`/results/`** — the JSON output files behind the numbers in the article,
  plus `rerun-2026-08-21-laptop/` holding a re-run on different hardware.
- **`/formal/`** — a Tamarin specification of the delegation rules, with its
  own README setting out what the model does and does not establish.
- **`/network_sim/`** — a synthetic multi-region model used in the discussion.

## Two things to know before reading the numbers

**Not every number here is a measurement.** The OAuth baseline draws its attack
outcomes against rates we stipulate in `MODEL_RATES` in `attacks_crossorg.py`;
SS-AID's outcomes come from executing real signature verification. Run
`python attacks_crossorg.py --sweep` to see how the comparison moves as those
stipulated rates are scaled. It moves in magnitude and not in ordering.

**Two claims were withdrawn during revision.** An earlier version reported
87.2% chain integrity at depth 10 against an independence prediction of 90.4%,
and a crossover between the OAuth and SS-AID curves near 32 concurrent agents.
Neither survived re-examination. The depth-10 gap disappears at 3,000 trials
per depth, and the scaling data locates no crossing point. Both are recorded in
`README.md` and in `depth_test.py`. Result files under `results/` still contain
the original runs, which is why the depth-10 figure is visible there.

## Quick verification, about five minutes

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python attacks_crossorg.py                             # seeded, reproduces exactly
python measure_bytes.py                                # byte sizes, reproduces exactly
```

`attacks_crossorg.py` and `measure_bytes.py` are the two that should reproduce
the article's numbers exactly on any machine, because they are seeded or
deterministic. They were re-run on unrelated hardware in August 2026 and every
rate and every byte figure matched.

`python run_all.py` also runs, but its latency figures depend on the machine
and will not match the article on different hardware. The article's timings
come from an Intel Xeon E5-2680 v4. Note that `run_all.py` overwrites
`results/full_results.json`; copy it first if you want to keep the archived run.

## Reproducibility settings

- **Random seed:** 42, set in every script with synthetic adversaries
- **Iterations:** 1,000 per attack configuration, 30 wall-clock measurements per
  agent count
- **Hardware for the article's figures:** Intel Xeon E5-2680 v4, 64 GB RAM,
  Ubuntu 22.04
- **Network I/O is excluded** from the latency loop to isolate cryptographic
  overhead

## Anonymization

Every identifier in the result files is synthetic and generated from a fixed
seed. No real organizational identity, user data or production credential
appears anywhere in this archive.

## Known limitations

1. **The Tier-1 figures measure a proxy.** `bbs_benchmark_real.py` times
   BLS12-381 aggregate operations standing in for BBS+ proof verification. A
   reference BBS+ implementation is in `bbs_benchmark.py`, but its pure-Python
   verification takes seconds and cannot characterise the path a production
   library would take.
2. **No accumulator is implemented.** `revocation.py` is a hash-based status
   registry, so the revocation latency reported in the article is a registry
   lookup rather than accumulator witness verification.
3. **Groth16 timing (8 to 40 s)** comes from library reports rather than an
   end-to-end benchmark here.
4. **Revocation propagation is modelled**, not observed on a live network.
5. **`attacks.py` is illustrative** and is not the source of any figure. See the
   reproducibility notes in `README.md` for why two of its outputs are easy to
   misread.

## Contact

Reproduction issues are best raised as an issue on this repository.
