from flask import Flask, request, Response, jsonify, send_from_directory
import csv
import pandas as pd
from ipaddress import ip_address, ip_network
from io import StringIO
import re
import networkx as nx
import community.community_louvain as community_louvain
import numpy as np
from flask_cors import CORS
import argparse
import sys
import logging
import os
from scipy.cluster.hierarchy import linkage, to_tree

global_df = None
global_start_time = None
global_end_time = None
global_duration_seconds = None

# Set up logging so that we only see errors (keeps things quiet during normal use)
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Precompute internal subnets with their ranges to quickly classify IP addresses
internal_subnets = [
    ip_network('172.28.0.0/16'),
    ip_network('192.168.61.0/24')
]
internal_ranges = [(int(net.network_address), int(net.broadcast_address)) for net in internal_subnets]

# Classify an IP as "Internal" or "External" based on precomputed subnet ranges
def classify_ip_vector(ip):
    try:
        ip_int = int(ip_address(ip))
    except Exception:
        return "External"
    for rmin, rmax in internal_ranges:
        if rmin <= ip_int <= rmax:
            return "Internal"
    return "External"


# Extract payload information using vectorized regex; returns a new DataFrame with parsed columns.
def parse_payload_vectorized(payload_series):
    cols = ["SourcePort", "DestinationPort", "Flags", "Seq", "Ack", "Win", "Len", "TSval", "TSecr"]
    df_extracted = pd.DataFrame(index=payload_series.index, columns=cols)
    
    # Updated regex that accepts either '>' or '→' between ports
    sp_dp_flags = payload_series.str.extract(r'^\s*:?\s*(\d+)\s*(?:>|→)\s*(\d+)\s*\[([^\]]+)\]', expand=True)
    
    df_extracted["SourcePort"]      = sp_dp_flags[0]
    df_extracted["DestinationPort"] = sp_dp_flags[1]
    df_extracted["Flags"]           = sp_dp_flags[2]
    df_extracted["Seq"]             = payload_series.str.extract(r'Seq=(\d+)',   expand=False)
    df_extracted["Ack"]             = payload_series.str.extract(r'Ack=(\d+)',   expand=False)
    df_extracted["Win"]             = payload_series.str.extract(r'Win=(\d+)',   expand=False)
    df_extracted["Len"]             = payload_series.str.extract(r'Len=(\d+)',   expand=False)
    df_extracted["TSval"]           = payload_series.str.extract(r'TSval=(\d+)', expand=False)
    df_extracted["TSecr"]           = payload_series.str.extract(r'TSecr=(\d+)', expand=False)
    df_extracted.fillna("N/A", inplace=True)
    return df_extracted

# Compute clusters using Louvain community detection on a graph of Source and Destination pairs
def compute_clusters(df, resolution=2.5):
    G = nx.Graph()
    # Filter out self-connections BEFORE grouping
    df_filtered = df[df["Source"] != df["Destination"]].copy() # Added this line
    if df_filtered.empty: # Handle case where only self-connections exist
        print("Warning: No non-self-connections found for clustering.")
        # Return an empty partition or handle as appropriate
        # For now, let's assign all nodes to a default cluster 'N/A' or '0'
        # This part might need adjustment based on desired behavior for pure self-connection data
        partition = {node: '0' for node in pd.concat([df['Source'], df['Destination']]).unique() if pd.notna(node)}
        return partition

    # Group by Source/Destination using the filtered DataFrame
    groups = df_filtered.groupby(["Source", "Destination"])
    for (src, dst), group in groups:
        # Basic check for non-null src/dst (already implicitly handled by groupby but good practice)
        if pd.notna(src) and pd.notna(dst):
            # No need to check src != dst here anymore, as df_filtered ensures it
            weight = group.shape[0] # Use number of connections as weight
            G.add_edge(src, dst, weight=weight)

    # Handle nodes that might only appear in self-connections (and were filtered out)
    # or nodes that don't form edges in the filtered graph. Assign them a default cluster.
    all_nodes = pd.concat([df['Source'], df['Destination']]).unique()
    partition = {}
    if G.number_of_nodes() > 0: # Only run Louvain if graph has nodes/edges
         # Run Louvain community detection on the graph without self-loops
         try:
             partition = community_louvain.best_partition(G, weight='weight', resolution=resolution)
         except Exception as e:
              print(f"Error during Louvain clustering: {e}. Proceeding without partition.")
              partition = {} # Fallback to empty partition on error

    # Ensure all nodes from the original dataframe get a cluster ID
    # Nodes not in the partition (e.g., isolated nodes or those only in self-loops) get 'N/A'
    final_partition = {
        str(node): str(partition.get(node, 'N/A'))
        for node in all_nodes if pd.notna(node)
    }

    return final_partition

def load_attack_pairs(path: str = r"backend\GroundTruth.csv") -> set:
    """Returns a set of (src,dst) tuples for each attack row, both directions."""
    pairs = set()
    if os.path.exists(path):
        try:
            gt = pd.read_csv(path, dtype=str)
            for _, r in gt.iterrows():
                s, d = r["Source IP"], r["Destination IP"]
                pairs.add((s, d))
                pairs.add((d, s))  # cover reverse traffic
        except Exception as e:
            logging.error(f"GroundTruth.csv read error: {e}")
    return pairs

attack_pairs_cache = load_attack_pairs()


# Compute the entropy of a given pandas Series using its value distribution
def compute_entropy(series):
    counts = series.value_counts()
    p = counts / counts.sum()
    return -np.sum(p * np.log(p))

def process_csv_to_df(csv_text):
    """
    Processes raw CSV text into a pandas DataFrame with computed features.

    Args:
        csv_text (str): The CSV data as a string.

    Returns:
        pd.DataFrame: The processed DataFrame with added columns for analysis.

    Raises:
        ValueError: If required columns 'Source' or 'Destination' are missing.
    """
    df = pd.read_csv(StringIO(csv_text), dtype=str)
    if not all(col in df.columns for col in ["Source", "Destination"]):
        error_msg = "Missing required column: Source or Destination"
        logging.error(error_msg)
        raise ValueError(error_msg)

    # If already processed (contains extra computed columns), return as is.
    # Checking a subset of processed columns might be sufficient
    processed_cols_subset = ["SourceClassification", "DestinationClassification",
                             "ClusterID", "ConnectionID", "ClusterAnomaly"]
    if all(col in df.columns for col in processed_cols_subset):
        logging.info("DataFrame appears to be already processed. Skipping reprocessing.")
        return df

    # Rename column if needed ('Info' often used instead of 'Payload' in Wireshark exports)
    if "Info" in df.columns and "Payload" not in df.columns:
        df.rename(columns={"Info": "Payload"}, inplace=True)

    # Process the Payload column if present
    if "Payload" in df.columns:
        # Fill NaNs and replace commas to avoid issues during parsing/display
        df["Payload"] = df["Payload"].fillna("").astype(str).str.replace(',', '/', regex=False)
        extracted = parse_payload_vectorized(df["Payload"])
        df = pd.concat([df, extracted], axis=1)

        # Compute flag-based columns if Flags exists from payload parsing
        if "Flags" in df.columns:
            # Ensure Flags column is treated as string and handle potential NaNs
            flags_str = df["Flags"].fillna("").astype(str)
            df["IsSYN"] = flags_str.str.contains("SYN", na=False).astype(int)
            df["IsRST"] = flags_str.str.contains("RST", na=False).astype(int)
            df["IsACK"] = flags_str.str.contains("ACK", na=False).astype(int)
            df["IsPSH"] = flags_str.str.contains("PSH", na=False).astype(int)
            # --- Placeholder for IsRetransmission ---
            # Actual retransmission detection often requires comparing Seq numbers
            # against expected Ack numbers within a connection, which is more complex.
            # We'll add a placeholder column for now if needed by filters.
            if 'isRetransmissionOnly' in request.get_json() if request else False: # Check if filter needs it
                 df["IsRetransmission"] = 0 # Default to 0/False; implement proper logic if needed
            # --- End Placeholder ---

    # Compute normalized NodeWeight based on connection counts (Source+Destination pairs)
    # Fill NaN Source/Destination with placeholders if necessary before grouping
    df[['Source', 'Destination']] = df[['Source', 'Destination']].fillna('Unknown_IP')
    connection_counts = df.groupby(["Source", "Destination"])["Source"].transform("count")
    if not connection_counts.empty and connection_counts.max() != connection_counts.min():
        # Normalize weights between 0 and 1
        node_weights = (connection_counts - connection_counts.min()) / (connection_counts.max() - connection_counts.min())
    elif not connection_counts.empty:
         # If all counts are the same, assign a default weight (e.g., 1.0 or 0.5)
         node_weights = pd.Series(1.0, index=connection_counts.index)
    else:
         # Handle empty connection_counts (e.g., if df was empty initially)
         node_weights = pd.Series(dtype=float) # Empty series
    df["NodeWeight"] = node_weights.reindex(df.index).fillna(0.5) # Align and fill NaNs

    # Classify IPs as internal or external
    df["SourceClassification"] = df["Source"].apply(classify_ip_vector)
    df["DestinationClassification"] = df["Destination"].apply(classify_ip_vector)

    # Create a composite ConnectionID for grouping related packets
    df["ConnectionID"] = (df["Source"].astype(str) + ":" + df["SourcePort"].fillna("N/A").astype(str) + "-" +
                          df["Destination"].astype(str) + ":" + df["DestinationPort"].fillna("N/A").astype(str))

    # Convert Time to datetime and handle potential errors
    # Ensure 'Time' column exists before trying conversion
    if "Time" in df.columns:
        df["Time"] = pd.to_datetime(df["Time"], errors='coerce') # Coerce errors to NaT
    else:
        # If Time column is missing, maybe create a dummy one or log a warning
        logging.warning("Time column missing. Timing features will be unavailable.")
        df['Time'] = pd.NaT # Assign NaT to all rows

    # Convert numeric columns safely
    numeric_cols = ["Length", "Seq", "Ack", "Win", "Len", "TSval", "TSecr"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        else:
            df[col] = np.nan # Add column as NaN if it's missing

    # Compute time differences and derived features (handle potential NaT in Time)
    # Calculate InterArrivalTime only if Time column is valid datetime
    if pd.api.types.is_datetime64_any_dtype(df["Time"]):
        # Sort by ConnectionID and Time to ensure correct diff calculation
        df = df.sort_values(by=["ConnectionID", "Time"])
        # Use transform for potentially better performance on large groups
        df["InterArrivalTime"] = df.groupby("ConnectionID")["Time"].transform(lambda x: x.diff().dt.total_seconds())
        df["InterArrivalTime"] = df["InterArrivalTime"].fillna(0) # Fill first packet's NaN IAT with 0
    else:
        df["InterArrivalTime"] = 0.0 # Set to 0 if Time is not valid

    # BytesPerSecond Calculation
    # Ensure Length is numeric before division
    df["Length"] = pd.to_numeric(df["Length"], errors='coerce').fillna(0)
    # Avoid division by zero or by NaN InterArrivalTime
    df["BytesPerSecond"] = df.apply(lambda row: row["Length"] / row["InterArrivalTime"] if row["InterArrivalTime"] and row["InterArrivalTime"] > 0 else 0, axis=1)
    # Replace any resulting infinities (though the check above should prevent them)
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf], 0)

    df["IsLargePacket"] = (df["Length"] > 1000).astype(int) # Boolean -> Int (0 or 1)
    df["PayloadLength"] = df["Len"].fillna(0) # Use 'Len' if available, else 0

    # Burst ID calculation (based on InterArrivalTime threshold)
    if "InterArrivalTime" in df.columns:
         df["BurstID"] = df.groupby("ConnectionID")["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum())
    else:
         df["BurstID"] = 0 # Default if no IAT

    # Suspicious ACK check (requires Seq and Ack)
    if "Seq" in df.columns and "Ack" in df.columns and pd.api.types.is_datetime64_any_dtype(df["Time"]):
        # Need previous Seq number within the same connection
        df["PrevSeq"] = df.groupby("ConnectionID")["Seq"].shift(1)
        # Check if Ack is less than the previous Seq (potential sign of issues)
        df["IsSuspiciousAck"] = df.apply(
            lambda row: 1 if pd.notnull(row["PrevSeq"]) and pd.notnull(row["Ack"]) and row["Ack"] < row["PrevSeq"] else 0,
            axis=1
        )
        df.drop(columns=["PrevSeq"], inplace=True) # Remove temporary column
    else:
        df["IsSuspiciousAck"] = 0 # Default if columns missing or time unsorted

    # Compute clusters using Louvain community detection
    # Ensure df is not empty before clustering
    if not df.empty:
        try:
            node_cluster = compute_clusters(df, resolution=2.5) # Use default resolution
            # Map cluster IDs back to the DataFrame, handling potential missing nodes
            df["ClusterID"] = df["Source"].apply(lambda x: str(node_cluster.get(str(x), 'N/A')))
        except Exception as e:
             print(f"Error during initial clustering: {e}. Assigning 'N/A' to ClusterID.")
             df["ClusterID"] = 'N/A' # Fallback cluster ID on error
    else:
        df["ClusterID"] = 'N/A' # Assign N/A if DataFrame is empty

    # Calculate average entropy per cluster based on Protocol, SourcePort, and DestinationPort
    cluster_entropy = {}
    # Check if DataFrame and ClusterID column are valid before grouping
    if not df.empty and "ClusterID" in df.columns:
        for cluster, group in df.groupby("ClusterID"):
            # Skip N/A cluster if needed, or handle it explicitly
            if cluster == 'N/A': continue

            ent_protocol = 0
            ent_srcport = 0
            ent_dstport = 0

            # Check for column existence and non-empty, non-NA group before calculating entropy
            if "Protocol" in group.columns and not group["Protocol"].dropna().empty:
                ent_protocol = compute_entropy(group["Protocol"].dropna())
            if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty:
                ent_srcport = compute_entropy(group["SourcePort"].dropna())
            if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty:
                ent_dstport = compute_entropy(group["DestinationPort"].dropna())

            # Average the non-zero entropies
            valid_entropies = [e for e in [ent_protocol, ent_srcport, ent_dstport] if e > 0]
            cluster_entropy[cluster] = np.mean(valid_entropies) if valid_entropies else 0
    # Map computed entropies back to the DataFrame
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy).fillna(0) # Fill NaN entropy with 0

    # ----  Anomaly flagging  ----
    # MODIFIED line: Only flag as anomaly based on ground truth if Source != Destination
    df["Anomaly"] = df.apply(
        lambda r: "anomaly" if (r["Source"] != r["Destination"]) and ((str(r["Source"]), str(r["Destination"])) in attack_pairs_cache) else "normal",
        axis=1
    )
    # --- End Modification ---

    # Calculate ClusterAnomaly based on the Anomaly flags within each cluster
    # Ensure DataFrame is not empty before grouping
    if not df.empty and "ClusterID" in df.columns:
        df["ClusterAnomaly"] = df.groupby("ClusterID")["Anomaly"].transform(
            lambda s: "anomaly" if (s == "anomaly").any() else "normal"
        )
    else:
        # Assign default 'normal' if DataFrame is empty or ClusterID missing
        df["ClusterAnomaly"] = "normal"

    # Ensure specific columns expected by frontend exist, even if calculation failed
    expected_cols = ["Source", "Destination", "Payload", "SourcePort", "DestinationPort", "Flags",
                     "Seq", "Ack", "Win", "Len", "TSval", "TSecr", "Protocol", "Length", "Time",
                     "SourceClassification", "DestinationClassification", "ClusterID",
                     "ConnectionID", "BurstID", "IsSuspiciousAck", "IsLargePacket", "NodeWeight",
                     "ClusterEntropy", "Anomaly", "ClusterAnomaly",
                     "IsSYN", "IsRST", "IsACK", "IsPSH", "InterArrivalTime", "BytesPerSecond", "PayloadLength"]
                     # Add "IsRetransmission" if the placeholder was added
    if "IsRetransmission" in df.columns:
        expected_cols.append("IsRetransmission")

    for col in expected_cols:
        if col not in df.columns:
            df[col] = None # Or np.nan, or 0 depending on expected type

    # Optional: Convert specific columns to appropriate types before returning
    # Example: df['Length'] = df['Length'].astype(float) # If you need numeric type guarantee

    # Reorder columns for consistency (optional)
    # df = df[expected_cols + [c for c in df.columns if c not in expected_cols]]

    logging.info(f"CSV processing complete. DataFrame shape: {df.shape}")
    return df

def process_csv(csv_text):
    df = process_csv_to_df(csv_text)
    out = StringIO()
    df.to_csv(out, index=False, quoting=csv.QUOTE_MINIMAL)
    return out.getvalue()

# -------------------------------
# Flask endpoints and additional routes
app = Flask(__name__)
CORS(app)  # Enable CORS so that requests from our web app can be processed

# Endpoint to filter and aggregate data by different metrics based on user filters
@app.route('/filter_and_aggregate', methods=['POST'])
def filter_and_aggregate():
    global global_df
    if global_df is None:
        return jsonify([])

    # ----- new anomaly map construction -----
    # for each ClusterID, record "anomaly" if any row in the full global_df had Anomaly=="anomaly"
    anomaly_map = (
        global_df
        .groupby("ClusterID")["Anomaly"]
        .apply(lambda s: "anomaly" if (s == "anomaly").any() else "normal")
        .to_dict()
    )
    # -----------------------------------------

    data = request.get_json()
    payloadKeyword      = data.get("payloadKeyword", "").lower()
    sourceFilter        = data.get("sourceFilter", "").lower()
    destinationFilter   = data.get("destinationFilter", "").lower()
    protocolFilter      = data.get("protocolFilter", "").lower()

    try:
        entropyMin = float(data.get("entropyMin", float('-inf')))
    except:
        entropyMin = float('-inf')
    try:
        entropyMax = float(data.get("entropyMax", float('inf')))
    except:
        entropyMax = float('inf')

    isLargePacketOnly    = data.get("isLargePacketOnly", False)
    isRetransmissionOnly = data.get("isRetransmissionOnly", False)
    isSuspiciousAckOnly  = data.get("isSuspiciousAckOnly", False)
    metric               = data.get("metric", "count")

    min_source_amt = int(data["minSourceAmt"])    if data.get("minSourceAmt","").strip()    != "" else 0
    max_source_amt = int(data["maxSourceAmt"])    if data.get("maxSourceAmt","").strip()    != "" else float('inf')
    min_dest_amt   = int(data["minDestinationAmt"]) if data.get("minDestinationAmt","").strip() != "" else 0
    max_dest_amt   = int(data["maxDestinationAmt"]) if data.get("maxDestinationAmt","").strip() != "" else float('inf')

    df = global_df.copy()
    if payloadKeyword:
        df = df[df["Payload"].str.lower().str.contains(payloadKeyword, na=False)]
    if sourceFilter:
        df = df[df["Source"].str.lower().str.contains(sourceFilter, na=False)]
    if destinationFilter:
        df = df[df["Destination"].str.lower().str.contains(destinationFilter, na=False)]
    if protocolFilter and "Protocol" in df.columns:
        df = df[df["Protocol"].str.lower().str.contains(protocolFilter, na=False)]

    df["ClusterEntropy"] = pd.to_numeric(df["ClusterEntropy"], errors='coerce')
    df = df[(df["ClusterEntropy"] >= entropyMin) & (df["ClusterEntropy"] <= entropyMax)]

    if isLargePacketOnly:
        df = df[df["IsLargePacket"] == True]
    if isRetransmissionOnly:
        df = df[df["IsRetransmission"] == True]
    if isSuspiciousAckOnly:
        df = df[df["IsSuspiciousAck"] == True]

    # Compute aggregated metric values for each cluster
    if metric == "count":
        agg = df.groupby("ClusterID").size()
    elif metric == "% SYN packets":
        grouped = df.groupby("ClusterID")
        agg = grouped["IsSYN"].sum() / grouped.size() * 100
    elif metric == "% RST packets":
        grouped = df.groupby("ClusterID")
        agg = grouped["IsRST"].sum() / grouped.size() * 100
    elif metric == "% ACK packets":
        grouped = df.groupby("ClusterID")
        agg = grouped["IsACK"].sum() / grouped.size() * 100
    elif metric == "% PSH packets":
        grouped = df.groupby("ClusterID")
        agg = grouped["IsPSH"].sum() / grouped.size() * 100
    elif metric == "Unique Destinations":
        agg = df.groupby("ClusterID")["Destination"].nunique()
    elif metric == "Unique Sources":
        agg = df.groupby("ClusterID")["Source"].nunique()
    elif metric == "Unique IPs":
        agg = df.groupby("ClusterID").apply(
            lambda g: len(set(g["Source"]).union(set(g["Destination"])))
        )
    elif metric == "Payload Size Variance":
        df["PayloadLength"] = pd.to_numeric(df["PayloadLength"], errors="coerce").fillna(0)
        agg = df.groupby("ClusterID")["PayloadLength"].var(ddof=0)
    elif metric == "Packets per Second":
        grouped = df.groupby("ClusterID")
        def packets_per_second(g):
            if g["Time"].count() < 2:
                return 0
            duration = (g["Time"].max() - g["Time"].min()).total_seconds()
            return len(g) / duration if duration > 0 else 0
        agg = grouped.apply(packets_per_second)
    elif metric == "Total Data Sent":
        agg = df.groupby("ClusterID")["Length"].sum()
    elif metric == "Start Time":
        # Ensure Time is datetime
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        # Find the minimum time per cluster (returns timestamps)
        # For heatmap display, maybe convert to seconds since epoch or relative time?
        # Let's convert to seconds since the overall minimum time for numerical representation
        overall_min_time = df['Time'].min()
        agg = df.groupby("ClusterID")["Time"].min()
        # Calculate seconds since the very first packet in the dataset
        agg = (agg - overall_min_time).dt.total_seconds()
        agg = agg.fillna(0) # Handle clusters with no valid time data

    elif metric == "Duration":
        # Ensure Time is datetime
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        grouped = df.groupby("ClusterID")["Time"]
        agg = (grouped.max() - grouped.min()).dt.total_seconds()
        agg = agg.fillna(0) # Clusters with one packet have 0 duration

    elif metric == "Average Inter-Arrival Time":
        # Ensure InterArrivalTime is numeric
        df["InterArrivalTime"] = pd.to_numeric(df["InterArrivalTime"], errors='coerce')
        # Calculate the mean inter-arrival time per cluster
        agg = df.groupby("ClusterID")["InterArrivalTime"].mean()
        agg = agg.fillna(0) # Handle clusters where mean cannot be calculated
    else:
        df[metric] = pd.to_numeric(df[metric], errors='coerce').fillna(0)
        agg = df.groupby("ClusterID")[metric].sum()

    unique_sources      = df.groupby("ClusterID")["Source"].nunique()
    unique_destinations = df.groupby("ClusterID")["Destination"].nunique()

    filtered_pivot = []
    for cluster, value in agg.items():
        src_count = unique_sources.get(cluster, 0)
        dst_count = unique_destinations.get(cluster, 0)
        if src_count < min_source_amt or src_count > max_source_amt:
            continue
        if dst_count < min_dest_amt or dst_count > max_dest_amt:
            continue

        # ----- include anomaly flag for this cluster -----
        filtered_pivot.append({
            "cluster":         cluster,
            "value":           value,
            "clusterAnomaly":  anomaly_map.get(cluster, "normal")
        })
        # ---------------------------------------------------
    return jsonify(filtered_pivot)

@app.route('/hierarchical_clusters', methods=['GET'])
def hierarchical_clusters():
    global global_df
    if global_df is None:
        # If no data loaded, maybe return an empty structure or error
        # Returning minimal structure to avoid client-side errors
        return jsonify({"id": "root", "dist": 0, "children": []})

    # --- Recalculate clusters based on optional resolution ---
    # Use resolution from query param or default
    resolution = 2.5 # Default resolution
    try:
        resolution_param = request.args.get("resolution")
        if resolution_param is not None:
            resolution = float(resolution_param)
            if resolution <= 0:
                raise ValueError("Resolution must be positive")
            print(f"Using custom resolution: {resolution}") # For debugging
    except (TypeError, ValueError) as e:
        print(f"Invalid resolution parameter, using default 2.5: {e}")
        resolution = 2.5 # Fallback to default

    # Recompute clusters and update global_df (important!)
    # Ensure compute_clusters function is available in the scope
    try:
        node_cluster = compute_clusters(global_df, resolution=resolution)
        global_df["ClusterID"] = global_df["Source"].apply(lambda x: str(node_cluster.get(x, 'N/A')))

        # Recalculate entropy after re-clustering
        # Ensure compute_entropy function is available
        cluster_entropy = {}
        if not global_df.empty: # Check if DataFrame is not empty before grouping
            for cluster, group in global_df.groupby("ClusterID"):
                ent_protocol = 0
                ent_srcport = 0
                ent_dstport = 0
                # Check for column existence and non-empty group before calculating entropy
                if "Protocol" in group.columns and not group["Protocol"].dropna().empty:
                    ent_protocol = compute_entropy(group["Protocol"].dropna())
                if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty:
                    ent_srcport = compute_entropy(group["SourcePort"].dropna())
                if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty:
                    ent_dstport = compute_entropy(group["DestinationPort"].dropna())
                # Average the non-zero entropies
                valid_entropies = [e for e in [ent_protocol, ent_srcport, ent_dstport] if e > 0]
                cluster_entropy[cluster] = np.mean(valid_entropies) if valid_entropies else 0

        global_df["ClusterEntropy"] = global_df["ClusterID"].map(cluster_entropy).fillna(0) # Fill NaN entropy with 0


         # Also re-calculate ClusterAnomaly based on the potentially new clusters
         # Ensure load_attack_pairs function is available
        attack_pairs = load_attack_pairs() # Ensure latest attack pairs are loaded
        global_df["Anomaly"] = global_df.apply(
             lambda r: "anomaly" if (str(r["Source"]), str(r["Destination"])) in attack_pairs else "normal", axis=1)
        if not global_df.empty: # Check if DataFrame is not empty before grouping
             global_df["ClusterAnomaly"] = global_df.groupby("ClusterID")["Anomaly"].transform(
                 lambda s: "anomaly" if (s == "anomaly").any() else "normal"
             )
        else:
             global_df["ClusterAnomaly"] = "normal" # Default if df is empty

        print(f"Recomputed clusters with resolution {resolution}. {global_df['ClusterID'].nunique()} clusters found.") # Debugging
    except Exception as e:
        print(f"Error during re-clustering or entropy calculation: {e}")
        # Handle error appropriately, maybe return last known good state or error message
        return jsonify({"error": f"Failed to recluster: {e}"}), 500
    # --- End Recalculation ---


    # Proceed with hierarchical clustering based on the *new* clusters
    stats = (
        global_df
        .groupby('ClusterID')
        .agg(total_packets=('ClusterID', 'size'),
             # Use the newly computed entropy
             avg_entropy=('ClusterEntropy', 'mean'))
        .reset_index()
    )

    # Need a stable order that linkage can use. Default groupby might not be sorted.
    # Sort by ClusterID numerically if possible, otherwise string sort.
    try:
        stats['ClusterID_num'] = pd.to_numeric(stats['ClusterID'])
        stats = stats.sort_values('ClusterID_num').reset_index(drop=True)
    except ValueError:
        stats = stats.sort_values('ClusterID').reset_index(drop=True)


    # Prepare data for linkage (ensure no NaNs)
    linkage_data = stats[['total_packets', 'avg_entropy']].fillna(0).to_numpy()

    if linkage_data.shape[0] < 2:
         print("Not enough clusters (<2) to perform hierarchical clustering.")
         # Return a minimal structure if only one cluster exists
         cluster_id = stats.loc[0, 'ClusterID'] if not stats.empty else "N/A"
         return jsonify({"id": f"Cluster {cluster_id}", "cluster_id": cluster_id, "dist": 0})


    # Perform hierarchical clustering
    try:
        # Using average linkage as in the source file
        Z = linkage(linkage_data, method='average')
        root, _ = to_tree(Z, rd=True) # rd=True to get node objects
    except Exception as e:
        print(f"Error during hierarchical clustering: {e}")
        return jsonify({"error": f"Hierarchical clustering failed: {e}"}), 500


    # Function to convert the SciPy tree node to the desired dictionary format
    def node_to_dict(node):
        if node.is_leaf():
            # Get the original index from the sorted stats DataFrame
            # node.id corresponds to the row index in the linkage_data, which matches the sorted stats index
            try:
                cluster_id = stats.loc[node.id, 'ClusterID']
                return {
                    "id": f"Cluster {cluster_id}",  # Leaf node ID includes cluster number
                    "cluster_id": str(cluster_id),  # Store the actual cluster ID as string
                    "dist": float(node.dist)
                }
            except IndexError:
                 print(f"Error: Leaf node id {node.id} out of bounds for stats DataFrame (size: {len(stats)}).")
                 # Fallback or error representation
                 return {"id": f"Unknown Leaf {node.id}", "cluster_id": "Error", "dist": float(node.dist)}
        else:
            # Recursive call for non-leaf nodes
            left = node_to_dict(node.get_left())
            right = node_to_dict(node.get_right())
            return {
                # Non-leaf nodes don't have a specific cluster ID in the label/id
                "id": f"Internal_{node.id}", # Use SciPy's internal node ID
                "dist": float(node.dist),
                "children": [left, right]
            }

    # Convert the tree and return as JSON
    tree_dict = node_to_dict(root)
    return jsonify(tree_dict)

# Endpoint to return network data for a given cluster
@app.route('/cluster_network', methods=['GET'])
def cluster_network():
    global global_df
    if global_df is None:
        return jsonify({"nodes": [], "edges": []})
    
    cluster_id_param = request.args.get("cluster_id")
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id_param)]
    
    nodes = {}
    edges = {}
    for idx, row in df_cluster.iterrows():
        source = str(row.get("Source", "")).strip()
        destination = str(row.get("Destination", "")).strip()
        protocol = str(row.get("Protocol", "")).strip()
        if not source or not destination or not protocol:
            continue
        let_source_class = row.get("SourceClassification") or classify_ip_vector(source)
        let_destination_class = row.get("DestinationClassification") or classify_ip_vector(destination)
        
        if source not in nodes:
            nodes[source] = {
                "data": {
                    "id": source,
                    "label": source,
                    "Classification": let_source_class,
                    "NodeWeight": row.get("NodeWeight", 0)
                }
            }
        if destination not in nodes:
            nodes[destination] = {
                "data": {
                    "id": destination,
                    "label": destination,
                    "Classification": let_destination_class,
                    "NodeWeight": row.get("NodeWeight", 0)
                }
            }
        edge_key = f"{source}|{destination}|{protocol}"
        if edge_key not in edges:
            edges[edge_key] = {
                "data": {
                    "id": f"edge-{source}-{destination}-{protocol}",
                    "source": source,
                    "target": destination,
                    "Protocol": protocol,
                    "EdgeWeight": 0,
                    "processCount": 0,
                    "csvIndices": []
                }
            }
        try:
            length = float(row.get("Length", 0))
        except:
            length = 0
        edges[edge_key]["data"]["EdgeWeight"] += length
        edges[edge_key]["data"]["processCount"] += 1

    network_data = {"nodes": list(nodes.values()), "edges": list(edges.values())}
    return jsonify(convert_nan_to_none(network_data))

# Endpoint to return rows of a cluster in JSON format (for pagination)
@app.route('/get_cluster_rows', methods=['GET'])
def get_cluster_rows():
    global global_df
    if global_df is None:
        return jsonify({"rows": [], "total": 0})
    cluster_id = request.args.get("cluster_id")
    try:
        page = int(request.args.get("page", 1))
    except Exception as e:
        logging.error(f"Error parsing page: {e}")
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except Exception as e:
        logging.error(f"Error parsing page_size: {e}")
        page_size = 50
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    rows = df_cluster.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")
    return jsonify({"rows": rows, "total": total})

# Endpoint to return an HTML table for a given cluster (for use in the web UI)
@app.route('/get_cluster_table', methods=['GET'])
def get_cluster_table():
    global global_df
    if global_df is None:
        return "<p>No data available.</p>"
    cluster_id = request.args.get("cluster_id")
    try:
        page = int(request.args.get("page", 1))
    except Exception as e:
        logging.error(f"Error parsing page: {e}")
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except Exception as e:
        logging.error(f"Error parsing page_size: {e}")
        page_size = 50

    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    rows = df_cluster.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")
    
    if not rows:
        return "<p>No rows found for this cluster.</p>"
    
    columns = list(rows[0].keys())
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>"
    html += "</tr></thead>"
    html += "<tbody>"
    for row in rows:
        html += "<tr>"
        for col in columns:
            cell = row[col] if row[col] is not None else ""
            html += f"<td style='padding:8px; border:1px solid #ddd;'>{cell}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

# GroundTruth.csv is automatically read from the same folder.
# Endpoint to process CSV data: parses, processes, and stores in global_df.
@app.route('/process_csv', methods=['POST'])
def process_csv_endpoint():
    """ Endpoint to process uploaded CSV data. """
    global global_df, global_start_time, global_end_time, global_duration_seconds # Ensure globals are modified

    try:
        data = request.get_json()
        if not data or "csv_text" not in data:
             logging.warning("Process CSV request missing 'csv_text'.")
             return jsonify({"error": "No CSV data provided."}), 400

        csv_text = data.get("csv_text", "")
        if not csv_text.strip():
             logging.warning("Process CSV request received empty 'csv_text'.")
             return jsonify({"error": "CSV data is empty."}), 400

        # Process to DataFrame using the dedicated function
        df = process_csv_to_df(csv_text) # process_csv_to_df does the main work
        global_df = df # Store the processed DataFrame globally
        logging.info(f"CSV processed into DataFrame with shape: {global_df.shape}")

        # --- Calculate Time Information ---
        global_start_time = None # Reset before calculation
        global_end_time = None
        global_duration_seconds = None

        if "Time" in global_df.columns and pd.api.types.is_datetime64_any_dtype(global_df["Time"]):
            valid_times = global_df["Time"].dropna()
            if not valid_times.empty:
                min_time = valid_times.min()
                max_time = valid_times.max()
                global_start_time = min_time.isoformat()
                global_end_time = max_time.isoformat()
                global_duration_seconds = (max_time - min_time).total_seconds()
                logging.info(f"Time info calculated: Start={global_start_time}, End={global_end_time}, Duration={global_duration_seconds}s")
            else:
                logging.warning("Time column contains only NaT values.")
        else:
            logging.warning("Time column missing, not datetime type, or could not be parsed correctly during processing.")
        # --- End Time Calculation ---

        # Return a success confirmation JSON
        return jsonify({"message": f"CSV processed successfully. {len(global_df)} rows loaded."}), 200

    except ValueError as ve: # Catch specific errors like missing columns
        logging.error(f"Value Error during CSV processing: {ve}")
        global_df, global_start_time, global_end_time, global_duration_seconds = None, None, None, None # Reset globals
        return jsonify({"error": str(ve)}), 400 # Return specific error
    except Exception as e:
        logging.exception(f"Unexpected error processing CSV") # Log full traceback
        global_df, global_start_time, global_end_time, global_duration_seconds = None, None, None, None # Reset globals
        return jsonify({"error": "An unexpected server error occurred during CSV processing."}), 500
    
# New endpoint for downloading the processed CSV file
@app.route('/download_csv', methods=['GET'])
def download_csv():
    global global_df
    if global_df is None:
        return jsonify({"error": "No processed data available."}), 400
    csv_io = StringIO()
    global_df.to_csv(csv_io, index=False, quoting=csv.QUOTE_MINIMAL)
    csv_io.seek(0)
    return Response(csv_io.getvalue(), 
                    mimetype='text/csv', 
                    headers={'Content-Disposition': 'attachment;filename=processed.csv'})

# Serve the index.html page from the static folder
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/protocol_percentages', methods=['GET'])
def protocol_percentages():
    global global_df
    if global_df is None:
        return jsonify({})
    df = global_df.copy()
    df['Protocol'] = df['Protocol'].fillna('').str.strip()
    
    if 'processCount' in df.columns:
        df['processCount'] = pd.to_numeric(df['processCount'], errors='coerce').fillna(1)
        protocol_counts = df.groupby('Protocol')['processCount'].sum()
    else:
        protocol_counts = df.groupby('Protocol').size()
        
    total = protocol_counts.sum()
    percentages = {proto: round(count / total * 100, 5)
                   for proto, count in protocol_counts.items() if proto}
    return jsonify(percentages)

@app.route('/time_info', methods=['GET'])
def get_time_info():
    """Returns the calculated start time, end time, and duration."""
    # Check if globals were successfully populated
    if global_df is None or global_start_time is None or global_end_time is None or global_duration_seconds is None:
        if global_df is None:
             return jsonify({"error": "No data has been processed yet."}), 404
        else:
             return jsonify({"error": "Time information could not be determined from the data."}), 404

    return jsonify({
        "start_time": global_start_time,
        "end_time": global_end_time,
        "duration_seconds": global_duration_seconds
    })

@app.route('/get_edge_table', methods=['GET'])
def get_edge_table():
    global global_df
    if global_df is None:
        return "<p>No data available.</p>"

    source = request.args.get("source")
    destination = request.args.get("destination")
    protocol = request.args.get("protocol")

    try:
        page = int(request.args.get("page", 1))
    except:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except:
        page_size = 50

    df_filtered = global_df[
        (global_df["Source"] == source) & 
        (global_df["Destination"] == destination) & 
        (global_df["Protocol"] == protocol)
    ]

    total = len(df_filtered)
    start = (page - 1) * page_size
    end = start + page_size
    rows = df_filtered.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")

    if not rows:
        return "<p>No rows found for this edge.</p>"

    columns = list(rows[0].keys())
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>"
    html += "</tr></thead><tbody>"
    for row in rows:
        html += "<tr>"
        for col in columns:
            val = row[col] if row[col] is not None else ""
            html += f"<td style='padding:8px; border:1px solid #ddd;'>{val}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

@app.route('/get_multi_edge_table', methods=['POST'])
def get_multi_edge_table():
    global global_df
    if global_df is None:
        return "<p>No data available.</p>"

    try:
        data = request.get_json()
        edges = data.get("edges", [])
        page = int(data.get("page", 1))
        page_size = int(data.get("page_size", 50))
    except Exception as e:
        return f"<p>Error parsing request: {str(e)}</p>"

    if not edges:
        return "<p>No edges selected.</p>"

    mask = False
    for edge in edges:
        try:
            source = edge["source"]
            destination = edge["destination"]
            protocol = edge["protocol"]
            condition = (
                (global_df["Source"] == source) &
                (global_df["Destination"] == destination) &
                (global_df["Protocol"] == protocol)
            )
            mask |= condition
        except KeyError:
            continue  # skip malformed edge dict

    filtered_df = global_df[mask]
    total = len(filtered_df)
    start = (page - 1) * page_size
    end = start + page_size
    rows = filtered_df.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")

    if not rows:
        return "<p>No rows found for selected edges.</p>"

    columns = list(rows[0].keys())
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>"
    html += "</tr></thead><tbody>"
    for row in rows:
        html += "<tr>"
        for col in columns:
            val = row[col] if row[col] is not None else ""
            html += f"<td style='padding:8px; border:1px solid #ddd;'>{val}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

def convert_nan_to_none(obj):
    """
    Recursively converts any np.nan found in dicts or lists to None.
    """
    if isinstance(obj, dict):
        return {k: convert_nan_to_none(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_nan_to_none(item) for item in obj]
    elif isinstance(obj, float) and np.isnan(obj):
        return None
    else:
        return obj

# Main CLI function to process a CSV file from the command line and save the output
def main_cli():
    parser = argparse.ArgumentParser(description="Process CSV files for network traffic analysis.")
    parser.add_argument("input_file", help="Path to the input CSV file")
    parser.add_argument("-o", "--output_file", help="Output CSV file name", default="processed.csv")
    args = parser.parse_args()
    try:
        with open(args.input_file, 'r') as f:
            csv_text = f.read()
    except Exception as e:
        logging.error(f"Error reading input file: {e}")
        sys.exit(1)
    try:
        processed_csv = process_csv(csv_text)
    except Exception as e:
        logging.error(f"Error processing CSV: {e}")
        sys.exit(1)
    try:
        with open(args.output_file, 'w') as f:
            f.write(processed_csv)
        logging.error(f"Processed CSV saved to {args.output_file}")
    except Exception as e:
        logging.error(f"Error saving output file: {e}")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] != "runserver":
        main_cli()
    else:
        app.run(debug=True)