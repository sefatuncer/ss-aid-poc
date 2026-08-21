#!/usr/bin/env python3
"""
SS-AID PoC — Additional Figure Generation

Generates missing figures identified by peer review:
  - Figure: DID Lifecycle (TikZ LaTeX)
  - Figure: Attack success heatmap (intra vs cross, all mechanisms)
"""

import json
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

plt.rcParams.update({
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
    'font.family': 'serif',
    'font.size': 9,
    'axes.labelsize': 10,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
})

FIGURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'paper-v2', 'figures')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')


def generate_attack_heatmap():
    """
    Heatmap showing attack success rates across all mechanisms and scenarios.
    Provides a visual summary complementing Table 2.
    """
    with open(os.path.join(RESULTS_DIR, 'crossorg_attack_results.json')) as f:
        data = json.load(f)

    # Build matrix: rows = attack×scenario, cols = mechanism
    labels_row = [
        'Spoofing\n(intra)', 'Spoofing\n(cross)',
        'Delegation\n(intra)', 'Delegation\n(cross)',
        'Revoked\n(intra)', 'Revoked\n(cross)',
    ]
    labels_col = ['No-Auth', 'API-Key', 'OAuth', 'SS-AID']

    matrix = np.array([
        [100, 35, 0, 0],      # spoofing intra
        [100, 43, 11, 0],     # spoofing cross
        [np.nan, np.nan, 0, 0],  # delegation intra
        [np.nan, np.nan, 6, 0],  # delegation cross
        [np.nan, np.nan, 3, 5],  # revoked intra
        [np.nan, np.nan, 2, 6],  # revoked cross
    ])

    fig, ax = plt.subplots(figsize=(3.5, 3.2))

    # Custom colormap: 0=green, low=yellow, high=red
    cmap = plt.cm.RdYlGn_r
    im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=100, aspect='auto')

    ax.set_xticks(range(len(labels_col)))
    ax.set_xticklabels(labels_col, fontsize=8)
    ax.set_yticks(range(len(labels_row)))
    ax.set_yticklabels(labels_row, fontsize=7)

    # Add text annotations
    for i in range(len(labels_row)):
        for j in range(len(labels_col)):
            val = matrix[i, j]
            if np.isnan(val):
                ax.text(j, i, '---', ha='center', va='center', fontsize=7, color='gray')
            else:
                color = 'white' if val > 50 else 'black'
                ax.text(j, i, f'{val:.0f}%', ha='center', va='center',
                       fontsize=7, fontweight='bold', color=color)

    cbar = plt.colorbar(im, ax=ax, shrink=0.8, pad=0.02)
    cbar.set_label('Attack Success (%)', fontsize=8)
    cbar.ax.tick_params(labelsize=7)

    plt.tight_layout()
    outpath = os.path.join(FIGURE_DIR, 'attack-heatmap.pdf')
    plt.savefig(outpath)
    plt.close()
    print(f'  Saved: {outpath}')


def generate_lifecycle_tikz():
    """
    TikZ diagram for DID lifecycle: Provisioning → Issuance → Operation → Revocation.
    """
    tikz = r"""\begin{tikzpicture}[
    node distance=0.8cm and 2.0cm,
    phase/.style={rectangle, draw=black, thick, minimum width=2.4cm, minimum height=0.7cm, align=center, font=\small, rounded corners=2pt},
    arrow/.style={-{Stealth[length=5pt]}, thick},
    note/.style={font=\scriptsize, text=gray!60!black, align=center},
  ]

  % Phases
  \node[phase, fill=blue!10] (p1) {1. Provisioning};
  \node[phase, fill=green!10, right=1.5cm of p1] (p2) {2. Issuance};
  \node[phase, fill=orange!10, right=1.5cm of p2] (p3) {3. Operation};
  \node[phase, fill=red!10, right=1.5cm of p3] (p4) {4. Revocation};

  % Arrows
  \draw[arrow] (p1) -- node[above, note] {DID registered\\on $\mathcal{N}$} (p2);
  \draw[arrow] (p2) -- node[above, note] {VC stored in\\Identity Wallet} (p3);
  \draw[arrow] (p3) -- node[above, note] {Principal\\updates $\mathcal{N}$} (p4);

  % Loop back for re-issuance
  \draw[arrow, dashed, gray] (p3.south) to[bend right=30] node[below, note] {credential refresh} (p2.south);

  % Details below each phase
  \node[note, below=0.3cm of p1] {DID:web/key\\Ed25519 + BLS12-381};
  \node[note, below=0.3cm of p2] {AgentCapability\\DelegationCred};
  \node[note, below=0.3cm of p3] {PEP $\rightarrow$ DCT\\BBS+ / ZKP};
  \node[note, below=0.3cm of p4] {Accumulator\\update on $\mathcal{N}$};

\end{tikzpicture}"""

    outpath = os.path.join(FIGURE_DIR, 'lifecycle.tex')
    with open(outpath, 'w') as f:
        f.write(tikz)
    print(f'  Saved: {outpath}')


if __name__ == '__main__':
    os.makedirs(FIGURE_DIR, exist_ok=True)
    print('Generating additional figures...')
    print('[1/2] Attack heatmap...')
    generate_attack_heatmap()
    print('[2/2] DID lifecycle (TikZ)...')
    generate_lifecycle_tikz()
    print('Done.')
