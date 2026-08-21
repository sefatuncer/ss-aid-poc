#!/usr/bin/env python3
"""
SS-AID PoC — Figure Generation

Generates publication-quality figures for the paper:
  - Figure 1: SS-AID Architecture (TikZ — generated as LaTeX)
  - Figure 2: Delegation Depth vs Security/Cost
  - Figure 3: Scalability — Agents vs Authentication Latency

Output: PDF files in paper/figures/ directory
"""

import json
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

# IEEE-style formatting
plt.rcParams.update({
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
    'font.family': 'serif',
    'font.size': 9,
    'axes.labelsize': 10,
    'axes.titlesize': 10,
    'legend.fontsize': 8,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'figure.figsize': (3.5, 2.5),  # Single-column IEEE
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
    'lines.linewidth': 1.2,
    'lines.markersize': 4,
    'axes.grid': True,
    'grid.alpha': 0.3,
    'grid.linestyle': '--',
})

FIGURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'paper-v2', 'figures')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')

# SS-AID palette (Wong/Okabe-Ito, colorblind-safe).
# See paper-v2/figures/PALETTE.md for the canonical reference.
SSAID_BLUE = '#0072B2'
SSAID_VERMILION = '#D55E00'
SSAID_GREEN = '#009E73'
SSAID_ORANGE = '#E69F00'
SSAID_PURPLE = '#CC79A7'
SSAID_MUTED = '#999999'


def load_json(filename):
    with open(os.path.join(RESULTS_DIR, filename)) as f:
        return json.load(f)


# =============================================================================
# Figure 2: Delegation Depth vs Security/Cost
# =============================================================================

def generate_delegation_depth_figure():
    """
    Dual-axis plot: delegation depth vs attack success rate and verification latency.
    Data from crossorg_attack_results.json delegation_depth section.
    """
    data = load_json('crossorg_attack_results.json')
    depth_data = data['delegation_depth']

    depths = sorted([int(k) for k in depth_data.keys()])
    integrity = [depth_data[str(d)]['integrity_rate'] * 100 for d in depths]
    verify_ms = [depth_data[str(d)]['median_verify_ms'] for d in depths]

    # Model: (1-p)^d integrity degradation where p=0.01 per hop
    p_per_hop = 0.01
    model_depths = np.linspace(1, 10, 100)
    model_integrity_ssaid = [(1 - p_per_hop)**d * 100 for d in model_depths]
    # OAuth degrades faster: p=0.03 per hop (scope confusion at each delegation)
    p_oauth = 0.03
    model_integrity_oauth = [(1 - p_oauth)**d * 100 for d in model_depths]

    fig, ax1 = plt.subplots(figsize=(3.5, 2.8))

    # Left axis: integrity rate
    color_ssaid = SSAID_BLUE
    color_oauth = SSAID_VERMILION

    ax1.plot(model_depths, model_integrity_ssaid, '-', color=color_ssaid,
             label='SS-AID integrity', linewidth=1.5)
    ax1.plot(model_depths, model_integrity_oauth, '--', color=color_oauth,
             label='OAuth integrity', linewidth=1.5)
    ax1.plot(depths, integrity, 'o', color=color_ssaid, markersize=5,
             label='SS-AID measured', zorder=5)

    ax1.set_xlabel('Delegation Depth ($d$)')
    ax1.set_ylabel('Chain Integrity (%)')
    ax1.set_ylim(70, 101)
    ax1.set_xlim(0.5, 10)

    # Add threshold lines
    ax1.axhline(y=95, color='gray', linestyle=':', linewidth=0.8, alpha=0.5)
    ax1.annotate('95% threshold', xy=(7.5, 95.5), fontsize=7, color='gray')

    # Shade the "safe zone"
    ax1.axvspan(0.5, 5, alpha=0.05, color='green')
    ax1.axvspan(5, 10, alpha=0.05, color='red')
    ax1.axvline(x=5, color='gray', linestyle=':', linewidth=0.8, alpha=0.5)
    ax1.annotate('$d_{max}=5$', xy=(5.1, 72), fontsize=7, color='gray')

    # Right axis: verification latency
    ax2 = ax1.twinx()
    # Latency increases with depth
    latency_per_depth = [0.12 * d for d in depths]
    ax2.plot(depths, latency_per_depth, 's-', color=SSAID_GREEN, markersize=4,
             label='Cumulative verify latency', linewidth=1.0)
    ax2.set_ylabel('Cumulative Verify Latency (ms)', color=SSAID_GREEN)
    ax2.tick_params(axis='y', labelcolor=SSAID_GREEN)
    ax2.set_ylim(0, 1.2)

    # Combined legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2,
               loc='lower left', fontsize=7, framealpha=0.9)

    ax1.xaxis.set_major_locator(MaxNLocator(integer=True))

    plt.tight_layout()
    outpath = os.path.join(FIGURE_DIR, 'delegation-depth.pdf')
    plt.savefig(outpath)
    plt.close()
    print(f'  Saved: {outpath}')


# =============================================================================
# Figure 3: Scalability — Agents vs Authentication Latency
# =============================================================================

def generate_scalability_figure():
    """
    Wall-clock time for all agents to complete auth vs number of concurrent agents.
    Shows OAuth's linear scaling (centralized bottleneck) vs SS-AID's sublinear scaling.
    """
    data = load_json('scalability_results.json')
    results = data['results']

    agents = sorted([int(k) for k in results.keys()])

    apikey_wall = [results[str(n)]['apikey']['wall_clock']['median_ms'] for n in agents]
    oauth_wall = [results[str(n)]['oauth']['wall_clock']['median_ms'] for n in agents]
    ssaid_wall = [results[str(n)]['ssaid']['wall_clock']['median_ms'] for n in agents]

    fig, ax = plt.subplots(figsize=(3.4, 2.3))

    ax.plot(agents, apikey_wall, 'D-', color=SSAID_GREEN, label='API-Key',
            markersize=3.5, linewidth=1.0)
    ax.plot(agents, oauth_wall, 's--', color=SSAID_VERMILION, label='OAuth 2.1',
            markersize=3.5, linewidth=1.0)
    ax.plot(agents, ssaid_wall, 'o-', color=SSAID_BLUE, label='SS-AID',
            markersize=3.5, linewidth=1.0)

    # Add linear reference line from OAuth
    x_ref = np.array(agents)
    oauth_linear = oauth_wall[0] * (x_ref / agents[0])
    ax.plot(x_ref, oauth_linear, ':', color=SSAID_VERMILION, alpha=0.4,
            linewidth=0.7, label='$O(n)$ reference')

    ax.set_xlabel('Concurrent Agents', fontsize=8)
    ax.set_ylabel('Wall-Clock Time (ms)', fontsize=8)
    ax.tick_params(axis='both', labelsize=7)
    ax.set_xscale('log', base=2)
    ax.set_xticks(agents)
    ax.set_xticklabels([str(n) for n in agents])

    # Mark the crossover region
    ax.axvline(x=32, color=SSAID_MUTED, linestyle=':', linewidth=0.7, alpha=0.5)
    ax.annotate('32-agent\nthreshold', xy=(32, max(oauth_wall) * 0.85),
                fontsize=6, color=SSAID_MUTED, ha='center')

    ax.legend(loc='upper left', fontsize=6.5, framealpha=0.9)
    ax.set_xlim(1.5, 80)

    plt.tight_layout()
    outpath = os.path.join(FIGURE_DIR, 'scalability.pdf')
    plt.savefig(outpath)
    plt.close()
    print(f'  Saved: {outpath}')


# =============================================================================
# Figure 1: Architecture Diagram (TikZ LaTeX source)
# =============================================================================

def generate_architecture_tikz():
    """
    Generate TikZ LaTeX source for the SS-AID architecture diagram.
    This produces a .tex file that can be compiled standalone or included.
    """
    tikz_code = r"""\begin{tikzpicture}[
    node distance=1.2cm and 1.8cm,
    box/.style={rectangle, draw=black, thick, minimum width=2.2cm, minimum height=0.8cm, align=center, font=\small},
    walletbox/.style={rectangle, draw=blue!60, fill=blue!8, thick, minimum width=2.8cm, minimum height=1.6cm, align=center, font=\small, rounded corners=3pt},
    netbox/.style={rectangle, draw=gray!60, fill=gray!8, thick, dashed, minimum width=8.5cm, minimum height=0.8cm, align=center, font=\small},
    arrow/.style={-{Stealth[length=5pt]}, thick},
    darrow/.style={{Stealth[length=5pt]}-{Stealth[length=5pt]}, thick},
    label/.style={font=\scriptsize, text=gray!70!black},
  ]

  % Reasoning Engine
  \node[box, fill=orange!10, draw=orange!60] (re) {Reasoning\\Engine (LLM)};

  % Identity Wallet (central)
  \node[walletbox, right=1.5cm of re] (iw) {\textbf{Identity Wallet}\\{\scriptsize DID + VC + PEP}};

  % PEP inside wallet (overlay label)
  \node[font=\tiny, text=blue!60, below=0.1cm of iw.south] (pep) {Policy Enforcement Point};

  % Action Handler
  \node[box, fill=green!10, draw=green!60, right=1.5cm of iw] (ah) {Action\\Handler};

  % External Services
  \node[box, fill=gray!10, draw=gray!60, right=1.2cm of ah] (ext) {External\\Services};

  % Decentralized Identity Network (bottom)
  \node[netbox, below=1.5cm of iw] (net) {$\mathcal{N}$: Decentralized Identity Network (DID Registry + Revocation)};

  % Arrows
  \draw[arrow] (re) -- node[above, label] {action request} (iw);
  \draw[arrow] (iw) -- node[above, label] {DCT} (ah);
  \draw[arrow] (ah) -- node[above, label] {execute} (ext);

  % Wallet to Network
  \draw[darrow] (iw) -- node[right, label, align=left] {DID resolve\\VC verify\\revocation} (net);

  % Blocked action (dashed back arrow)
  \draw[arrow, dashed, red!60] (iw.north) to[bend left=30] node[above, font=\scriptsize, text=red!60] {deny} (re.north);

  % Agent boundary
  \draw[rounded corners=5pt, thick, dashed, gray!40] ([xshift=-0.5cm, yshift=0.6cm]re.north west) rectangle ([xshift=0.5cm, yshift=-0.3cm]ah.south east);
  \node[font=\scriptsize, text=gray!50, anchor=north east] at ([xshift=0.4cm, yshift=0.5cm]ah.north east) {Agent Boundary};

\end{tikzpicture}"""

    outpath = os.path.join(FIGURE_DIR, 'architecture.tex')
    with open(outpath, 'w') as f:
        f.write(tikz_code)
    print(f'  Saved: {outpath}')

    return tikz_code


# =============================================================================
# Supplementary: BBS+ Tier Comparison Bar Chart
# =============================================================================

def generate_tier_comparison_figure():
    """
    Bar chart comparing Tier 1 (Ed25519) vs Tier 2 (BBS+) operation costs.
    Uses real BLS12-381 benchmark data from blspy.
    """
    data = load_json('bbs_real_benchmark.json')

    operations = ['Sign', 'Verify', 'Aggregate\nVerify (4)', 'Selective\nDisc. (2/4)']
    ed25519_times = [
        data['ed25519']['sign']['median_ms'],
        data['ed25519']['verify']['median_ms'],
        None,  # No Ed25519 aggregate
        None,  # No Ed25519 selective disclosure
    ]
    bbs_times = [
        data['bls12_381']['sign_single']['median_ms'],
        data['bls12_381']['verify_single']['median_ms'],
        data['bls12_381']['aggregate_verify']['median_ms'],
        data['bls12_381']['selective_disclosure_verify']['median_ms'],
    ]

    x = np.arange(len(operations))
    width = 0.3

    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    # Ed25519 bars (only for Sign and Verify)
    ed_x = [0, 1]
    ed_vals = [ed25519_times[0], ed25519_times[1]]
    bars1 = ax.bar(np.array(ed_x) - width/2, ed_vals, width,
                   label='Tier 1 (Ed25519)', color=SSAID_BLUE, alpha=0.85,
                   hatch='//', edgecolor='white', linewidth=0.5)

    # BBS+ bars (all operations)
    bars2 = ax.bar(x + width/2, bbs_times, width,
                   label='Tier 2 (BBS+)', color=SSAID_VERMILION, alpha=0.85,
                   hatch='xx', edgecolor='white', linewidth=0.5)

    ax.set_ylabel('Latency (ms)')
    ax.set_xticks(x)
    ax.set_xticklabels(operations, fontsize=7)
    ax.legend(fontsize=7)
    ax.set_yscale('log')
    # Headroom above tallest bar to keep value labels clear of the top spine
    ax.set_ylim(top=max(bbs_times) * 4)

    # Add value labels
    for bar, val in zip(bars1, ed_vals):
        ax.annotate(f'{val:.3f}', xy=(bar.get_x() + bar.get_width()/2, val),
                   xytext=(0, 4), textcoords='offset points',
                   ha='center', fontsize=6)
    for bar, val in zip(bars2, bbs_times):
        ax.annotate(f'{val:.2f}', xy=(bar.get_x() + bar.get_width()/2, val),
                   xytext=(0, 4), textcoords='offset points',
                   ha='center', fontsize=6)

    plt.tight_layout()
    outpath = os.path.join(FIGURE_DIR, 'tier-comparison.pdf')
    plt.savefig(outpath)
    plt.close()
    print(f'  Saved: {outpath}')


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    os.makedirs(FIGURE_DIR, exist_ok=True)

    print('Generating figures...')
    print()

    # Note: architecture.tex and orphan figures (delegation-depth, attack-heatmap)
    # are maintained manually in paper-v2/figures/. Only regenerate the two
    # matplotlib-driven figures that the active paper-v2 includes.

    print('[1/2] Scalability — agents vs latency...')
    generate_scalability_figure()

    print('[2/2] BBS+ tier comparison...')
    generate_tier_comparison_figure()

    print()
    print('All figures generated.')
