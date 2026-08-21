# Heterogeneous Cross-Cloud Network Emulation

Synthetic emulation requested by IEEE S&P Reviewer 2 §2.2.

## What it is

`heterogeneous_sim.py` injects per-link latency, jitter, and packet-loss
profiles drawn from a 3-region x 2-provider topology onto the cryptographic
costs measured in the local PoC.  It is not a live testbed; it is a
parametric emulator that lets us answer "where does the OAuth-vs-SS-AID
crossover move when the network is no longer trivial?"

## Topology

| Region        | Providers | Intra-region RTT | Cross-provider penalty |
|---------------|-----------|------------------|------------------------|
| us-east       | A, B      | 5 ms             | +20 ms                 |
| eu-west       | A, B      | 5 ms             | +20 ms                 |
| ap-southeast  | A, B      | 5 ms             | +20 ms                 |

Cross-region one-way: us-east <-> eu-west 80 ms, us-east <-> ap-southeast
180 ms, eu-west <-> ap-southeast 160 ms.

## Scenarios

| Name      | Packet loss | Jitter sigma |
|-----------|-------------|--------------|
| clean     | 0.1%        | 2 ms         |
| typical   | 0.5%        | 5 ms         |
| degraded  | 2.0%        | 12 ms        |

## Running

```sh
python heterogeneous_sim.py
```

Writes `poc/results/heterogeneous_network_results.json` with p50/p95/p99
latency for each (scenario, fleet size, scheme) cell.

Seed is pinned to 20260508 for determinism.

## Scope

- Real cloud providers are not contacted.
- Consensus mechanism is not varied; gossip is parametrized as latency only.
- Adversarial network (NetOps-level) attacks are out of scope; only
  operational network conditions.
- ZKP cache scenarios are addressed in `poc/` discussion of todo 101.
