import sys
import argparse

import pandas as pd
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
from scipy.cluster.hierarchy import linkage, dendrogram

# Ensure dependencies
try:
    import community.community_louvain as community_louvain
except ImportError:
    raise ImportError(
        "python-louvain not found. Install with `pip install python-louvain` and scipy: `pip install scipy`"
    )


def build_weighted_graph(df):
    """Build a weighted undirected graph from Source/Destination pairs."""
    G = nx.Graph()
    for (src, dst), group in df.groupby(["Source", "Destination"]):
        if pd.notna(src) and pd.notna(dst):
            w = len(group)
            if G.has_edge(src, dst):
                G[src][dst]["weight"] += w
            else:
                G.add_edge(src, dst, weight=w)
    return G


def compute_distances(G):
    """Compute condensed distance array for SciPy clustering: inverse weight or large for missing."""
    nodes = list(G.nodes())
    n = len(nodes)

    # find maximum inverse‐weight to use for non‐edges
    inv_weights = [1.0 / d["weight"] for _, _, d in G.edges(data=True)]
    max_inv = max(inv_weights) if inv_weights else 1.0

    # build condensed distance array
    dist_arr = np.zeros(n * (n - 1) // 2)
    idx = 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            u, v = nodes[i], nodes[j]
            if G.has_edge(u, v):
                dist = 1.0 / G[u][v]["weight"]
            else:
                dist = max_inv * 1.5
            dist_arr[idx] = dist
            idx += 1

    return dist_arr, nodes


def plot_hierarchical_dendrogram(dist_arr, labels, max_leaves=None):
    """
    Perform hierarchical clustering and plot the full dendrogram with no threshold.
    If max_leaves is set and there are more labels than that, truncate the tree display.
    """
    # compute linkage
    Z = linkage(dist_arr, method="average")

    plt.figure(figsize=(12, 6))
    # basic dendrogram kwargs, no color_threshold
    dd_kwargs = dict(
        labels=labels,
        orientation="top",
        leaf_rotation=90,
    )
    if max_leaves and len(labels) > max_leaves:
        dd_kwargs.update({
            "truncate_mode": "lastp",
            "p": max_leaves,
            "show_leaf_counts": True
        })

    dendrogram(Z, **dd_kwargs)
    plt.title("Cluster Dendrogram (no threshold)")
    plt.ylabel("Distance")
    plt.xlabel("")  # optional, to remove default x‑label
    plt.tight_layout()
    plt.show()



def main():
    p = argparse.ArgumentParser(
        description="Build a weighted graph, cluster it, and plot a (possibly capped) dendrogram"
    )
    p.add_argument("--input", "-i", required=True,
                   help="Path to CSV file with Source,Destination columns")
    p.add_argument("--max-nodes", type=int, default=200,
                   help="If the graph has more than this many nodes, sample the top‐degree ones")
    p.add_argument("--truncate", action="store_true",
                   help="If set, will *not* sample nodes but will truncate the dendrogram to --max-nodes leaves")
    args = p.parse_args()

    df = pd.read_csv(args.input)
    print(f"Loaded {len(df)} rows from '{args.input}'")

    G_full = build_weighted_graph(df)
    print(f"Original graph: {G_full.number_of_nodes()} nodes, {G_full.number_of_edges()} edges")

    # decide whether to sample a subgraph or just truncate the dendrogram
    if G_full.number_of_nodes() > args.max_nodes:
        if args.truncate:
            print(f"Too many nodes ({G_full.number_of_nodes()}), "
                  f"but truncating dendrogram to {args.max_nodes} leaves instead of sampling.")
            G = G_full
        else:
            # sample the highest‐degree nodes
            deg = dict(G_full.degree(weight="weight"))
            top_nodes = sorted(deg, key=deg.get, reverse=True)[: args.max_nodes]
            G = G_full.subgraph(top_nodes).copy()
            print(f"Using subgraph of top {args.max_nodes} nodes: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    else:
        G = G_full

    # run Louvain on whichever graph we're visualizing
    partition = community_louvain.best_partition(G, weight="weight", resolution=2.5)
    clusters = {}
    for node, comm in partition.items():
        clusters.setdefault(comm, []).append(node)
    k = len(clusters)
    print(f"Louvain found {k} clusters (resolution=2.5)")

    # compute distances & labels
    dist_arr, labels = compute_distances(G)

    # plot, passing max_leaves if we're truncating
    max_leaves = args.max_nodes if args.truncate else None
    plot_hierarchical_dendrogram(dist_arr, labels, k, max_leaves=max_leaves)


if __name__ == "__main__":
    main()
