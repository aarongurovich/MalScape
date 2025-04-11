#!/usr/bin/env python3
import pandas as pd
import networkx as nx
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import community.community_louvain as community_louvain
from collections import Counter

def build_graph(df):
    """
    Build an undirected networkx graph from the DataFrame.
    Each edge is created between Source and Destination with a weight equal to the count of communications.
    """
    # Ensure 'Length' is numeric (not used for weight)
    df['Length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0)
    
    # Group by Source and Destination to count communications and rename count to 'weight'
    grouped = df.groupby(['Source', 'Destination']).agg({'No.': 'count'}).reset_index().rename(columns={'No.': 'weight'})
    
    # Create the graph directly from the grouped DataFrame
    G = nx.from_pandas_edgelist(grouped, source='Source', target='Destination', edge_attr='weight')
    return G

def plot_network(G, partition, title_suffix=""):
    """
    Plot the network graph with nodes colored by their community partition.
    Adjusts parameters for huge graphs.
    """
    # Choose layout parameters based on graph size
    if len(G) > 1000:
        pos = nx.spring_layout(G, seed=42, k=0.1, iterations=50)
        node_size = 50
    else:
        pos = nx.spring_layout(G, seed=42)
        node_size = 500

    cmap = plt.cm.Set3  # Qualitative colormap

    plt.figure(figsize=(12, 8))
    nx.draw_networkx_nodes(G, pos,
                           node_color=list(partition.values()),
                           cmap=cmap,
                           node_size=node_size)
    nx.draw_networkx_edges(G, pos, alpha=0.5)
    # Draw labels only for smaller graphs
    if len(G) <= 1000:
        nx.draw_networkx_labels(G, pos, font_size=10)
    plt.title(f'Network Graph with Community Detection {title_suffix}')
    plt.axis('off')
    plt.show()

def plot_cluster_size_distribution(partition, title_suffix=""):
    """
    Plot the distribution of cluster sizes.
    """
    cluster_sizes = Counter(partition.values())
    clusters = list(cluster_sizes.keys())
    sizes = list(cluster_sizes.values())
    
    plt.figure(figsize=(10, 6))
    plt.bar(clusters, sizes, color='skyblue')
    plt.xlabel('Cluster')
    plt.ylabel('Number of Nodes')
    plt.title(f'Cluster Size Distribution {title_suffix}')
    plt.show()

def plot_degree_distribution(G):
    """
    Plot the histogram of node degrees.
    """
    degrees = [degree for _, degree in G.degree()]
    plt.figure(figsize=(10, 6))
    plt.hist(degrees, bins=range(min(degrees), max(degrees)+2), color='green', alpha=0.7)
    plt.xlabel('Degree')
    plt.ylabel('Frequency')
    plt.title('Degree Distribution of the Network')
    plt.show()

def plot_clustering_coefficients(G):
    """
    Plot the distribution of clustering coefficients.
    """
    clustering_coeff = nx.clustering(G)
    plt.figure(figsize=(10, 6))
    plt.hist(list(clustering_coeff.values()), bins=10, color='orange', alpha=0.7)
    plt.xlabel('Clustering Coefficient')
    plt.ylabel('Frequency')
    plt.title('Clustering Coefficient Distribution')
    plt.show()

def get_label_propagation_partition(G):
    """
    Get community partition using the Label Propagation algorithm.
    Returns a dict {node: community_id}.
    """
    communities = nx.algorithms.community.label_propagation_communities(G)
    partition = {}
    for i, comm in enumerate(communities):
        for node in comm:
            partition[node] = i
    return partition

def get_greedy_modularity_partition(G):
    """
    Get community partition using the Greedy Modularity algorithm.
    Returns a dict {node: community_id}.
    """
    communities = nx.algorithms.community.greedy_modularity_communities(G)
    partition = {}
    for i, comm in enumerate(communities):
        for node in comm:
            partition[node] = i
    return partition

def tune_louvain_resolution(G, resolutions=[0.5, 1.0, 1.5, 2.0]):
    """
    Tune the resolution parameter for Louvain community detection.
    For each resolution, compute the partition, modularity, and number of communities.
    """
    results = {}
    print("Tuning Louvain Resolution:")
    for r in resolutions:
        partition = community_louvain.best_partition(G, weight='weight', resolution=r)
        modularity = community_louvain.modularity(partition, G, weight='weight')
        n_comms = len(set(partition.values()))
        results[r] = {'partition': partition, 'modularity': modularity, 'n_communities': n_comms}
        print(f"  Resolution: {r:>4} -> {n_comms:>3} communities, modularity: {modularity:.4f}")
    return results

def main():
    # Load the CSV file (update the path/filename as needed)
    df = pd.read_csv(r'C:\Users\Aaron\MalScape\tools\mypcap_20091103082335.csv')
    
    # Build the graph from the data
    G = build_graph(df)
    
    # -----------------------
    # Louvain Community Detection (with parameter tuning)
    # -----------------------
    louvain_results = tune_louvain_resolution(G, resolutions=[0.5, 1.0, 1.5, 2.0])
    # For further analysis, choose one resolution (here we choose 1.0 as an example)
    chosen_resolution = 1.0
    louvain_partition = louvain_results[chosen_resolution]['partition']
    print(f"\nChosen Louvain Resolution: {chosen_resolution}")
    print(f"  -> {louvain_results[chosen_resolution]['n_communities']} communities, modularity: {louvain_results[chosen_resolution]['modularity']:.4f}")
    
    # -----------------------
    # Label Propagation Community Detection
    # -----------------------
    lp_partition = get_label_propagation_partition(G)
    lp_communities = list(nx.algorithms.community.label_propagation_communities(G))
    lp_modularity = nx.algorithms.community.quality.modularity(G, lp_communities, weight='weight')
    print(f"Label Propagation -> {len(set(lp_partition.values()))} communities, modularity: {lp_modularity:.4f}")
    
    # -----------------------
    # Greedy Modularity Community Detection
    # -----------------------
    greedy_partition = get_greedy_modularity_partition(G)
    greedy_communities = list(nx.algorithms.community.greedy_modularity_communities(G))
    greedy_modularity = nx.algorithms.community.quality.modularity(G, greedy_communities, weight='weight')
    print(f"Greedy Modularity -> {len(set(greedy_partition.values()))} communities, modularity: {greedy_modularity:.4f}")
    
    # -----------------------
    # Visualize results (if graph size permits)
    # -----------------------
    if len(G) <= 5000:
        print("\nPlotting network graph using chosen Louvain partition")
        plot_network(G, louvain_partition, title_suffix="(Louvain)")
    else:
        print("Graph too large for network visualization, skipping network plot.")
    
    # Plot Cluster Size Distributions for each method for qualitative validation
    plot_cluster_size_distribution(louvain_partition, title_suffix="(Louvain)")
    plot_cluster_size_distribution(lp_partition, title_suffix="(Label Propagation)")
    plot_cluster_size_distribution(greedy_partition, title_suffix="(Greedy Modularity)")
    
    # Overall network metrics independent of community detection
    plot_degree_distribution(G)
    plot_clustering_coefficients(G)
    
    # Alternative Metrics: Here we print extra details.
    # You can extend this section with domain-specific validations.
    print("\nAlternative Metrics Summary:")
    print(f"Total nodes in graph: {len(G.nodes())}")
    print(f"Average clustering coefficient: {nx.average_clustering(G):.4f}")
    
if __name__ == '__main__':
    main()
    input("Press Enter to exit...")
