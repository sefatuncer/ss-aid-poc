# -*- coding: utf-8 -*-
"""Regenerate the scaling figure from scalability_results.json.

An earlier version of this figure carried a vertical marker labelled
"32-agent threshold". That marker was drawn in rather than computed, and the
data locates no crossing point there: the wall-clock curves are level at the
smallest fleet and SS-AID leads at every larger size. This script redraws the
figure without the marker and prints the underlying ratios so the reader can
check them.
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

POC = r"C:\Users\tuncer\Desktop\Sefa\autonomous-sovereignity\poc"
OUT = r"C:\Users\tuncer\Desktop\overleaf-autonomous-sovereignity\figures"

SSAID_BLUE = '#0072B2'
SSAID_VERMILION = '#D55E00'
SSAID_GREEN = '#009E73'

matplotlib.rcParams.update({
    "font.family": "serif",
    "font.size": 8,
    "axes.linewidth": 0.6,
    "savefig.dpi": 400,
    "savefig.bbox": "tight",
})

data = json.load(open(os.path.join(POC, "results", "scalability_results.json")))
results = data["results"]
agents = sorted(int(k) for k in results)

apikey = [results[str(n)]["apikey"]["wall_clock"]["median_ms"] for n in agents]
oauth = [results[str(n)]["oauth"]["wall_clock"]["median_ms"] for n in agents]
ssaid = [results[str(n)]["ssaid"]["wall_clock"]["median_ms"] for n in agents]

fig, ax = plt.subplots(figsize=(3.4, 2.3))
ax.plot(agents, apikey, 'D-', color=SSAID_GREEN, label='API-Key', markersize=3.5, linewidth=1.0)
ax.plot(agents, oauth, 's--', color=SSAID_VERMILION, label='OAuth 2.1', markersize=3.5, linewidth=1.0)
ax.plot(agents, ssaid, 'o-', color=SSAID_BLUE, label='SS-AID', markersize=3.5, linewidth=1.0)

x_ref = np.array(agents, dtype=float)
ax.plot(x_ref, oauth[0] * (x_ref / agents[0]), ':', color=SSAID_VERMILION,
        alpha=0.4, linewidth=0.7, label='$O(n)$ reference')

ax.set_xlabel('Concurrent Agents', fontsize=8)
ax.set_ylabel('Wall-Clock Time (ms)', fontsize=8)
ax.tick_params(axis='both', labelsize=7)
ax.set_xscale('log', base=2)
ax.set_xticks(agents)
ax.set_xticklabels([str(n) for n in agents])
ax.legend(loc='upper left', fontsize=6.5, framealpha=0.9)
ax.set_xlim(1.5, 80)
plt.tight_layout()

for ext in ("png", "pdf"):
    path = os.path.join(OUT, "scalability." + ext)
    plt.savefig(path)
    print("written:", path)
plt.close()

print()
print("underlying data (wall-clock, ms):")
for n, o, s in zip(agents, oauth, ssaid):
    print("  n=%-3d oauth=%8.3f ssaid=%8.3f oran=%.2fx" % (n, o, s, o / s))
