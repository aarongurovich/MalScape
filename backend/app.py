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

# Set up logging so that we only see errors (keeps things quiet during normal use)
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Global variable to store our processed dataframe across endpoints
global_df = None

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
    except:
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
    groups = df.groupby(["Source", "Destination"])
    for (src, dst), group in groups:
        if pd.notna(src) and pd.notna(dst):
            weight = group.shape[0]
            G.add_edge(src, dst, weight=weight)
    partition = community_louvain.best_partition(G, weight='weight', resolution=resolution)
    return partition

# Compute the entropy of a given pandas Series using its value distribution
def compute_entropy(series):
    counts = series.value_counts()
    p = counts / counts.sum()
    return -np.sum(p * np.log(p))

# Process the CSV text input into a pandas DataFrame with various enhancements and computed columns
def process_csv_to_df(csv_text):
    df = pd.read_csv(StringIO(csv_text), dtype=str)
    if not all(col in df.columns for col in ["Source", "Destination"]):
        error_msg = "Missing required column: Source or Destination"
        logging.error(error_msg)
        raise ValueError(error_msg)
    
    processed_cols = ["Source", "Destination", "Payload", "SourcePort", "DestinationPort", "Flags", 
                      "Seq", "Ack", "Win", "Len", "TSval", "TSecr", 
                      "SourceClassification", "DestinationClassification", "ClusterID",
                      "ConnectionID", "SeqDelta", "AckDelta", "IsRetransmission", "TCPFlagCount",
                      "InterArrivalTime", "BytesPerSecond", "IsLargePacket", "PayloadLength",
                      "BurstID", "IsSuspiciousAck", "ClusterEntropy"]
    if all(col in df.columns for col in processed_cols):
        return df

    # Rename Info column to Payload if needed
    if "Info" in df.columns:
        df.rename(columns={"Info": "Payload"}, inplace=True)
    
    # Process the Payload column to fix missing values and extract details
    if "Payload" in df.columns:
        df["Payload"] = df["Payload"].fillna("").str.replace(',', '/', regex=False)
        extracted = parse_payload_vectorized(df["Payload"])
        df = pd.concat([df, extracted], axis=1)
        
        # Compute new flag-based columns based on the Flags string
        if "Flags" in df.columns:
            df["IsSYN"] = df["Flags"].apply(lambda x: 1 if "SYN" in x else 0)
            df["IsRST"] = df["Flags"].apply(lambda x: 1 if "RST" in x else 0)
            df["IsACK"] = df["Flags"].apply(lambda x: 1 if "ACK" in x else 0)
            df["IsPSH"] = df["Flags"].apply(lambda x: 1 if "PSH" in x else 0)
    
    # Compute a normalized NodeWeight based on the connection counts
    connection_counts = df.groupby(["Source", "Destination"])["Source"].transform("count")
    if connection_counts.max() != connection_counts.min():
        node_weights = (connection_counts - connection_counts.min()) / (connection_counts.max() - connection_counts.min())
    else:
        node_weights = pd.Series(1.0, index=connection_counts.index)
    df["NodeWeight"] = node_weights
    # Always compute classification for both Source and Destination IPs
    df["SourceClassification"] = df["Source"].apply(classify_ip_vector)
    df["DestinationClassification"] = df["Destination"].apply(classify_ip_vector)
    
    # Create a composite ConnectionID for unique identification
    df["ConnectionID"] = df["Source"] + ":" + df["SourcePort"].fillna("N/A") + "-" + df["Destination"] + ":" + df["DestinationPort"].fillna("N/A")
    
    # Convert the Time column to a datetime format with milliseconds
    try:
        df["Time"] = pd.to_datetime(df["Time"], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')
    except Exception as e:
        logging.error(f"Error converting Time column to datetime: {e}")
    df["Length"] = pd.to_numeric(df["Length"], errors='coerce')
    for col in ["Seq", "Ack", "Win", "Len", "TSval", "TSecr"]:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    # Compute the time difference between packets for each connection
    df["InterArrivalTime"] = df.groupby("ConnectionID")["Time"].diff().dt.total_seconds()
    df["BytesPerSecond"] = df["Length"] / df["InterArrivalTime"]
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf], np.nan)
    df["IsLargePacket"] = df["Length"] > 1000
    df["PayloadLength"] = df["Len"]
    df["BurstID"] = df.groupby("ConnectionID")["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum())
    df["PrevSeq"] = df.groupby("ConnectionID")["Seq"].shift(1)
    df["IsSuspiciousAck"] = df.apply(lambda row: True if pd.notnull(row["PrevSeq"]) and row["Ack"] < row["PrevSeq"] else False, axis=1)
    df.drop(columns=["PrevSeq"], inplace=True)
    
    # Compute clusters using the graph-based clustering method
    node_cluster = compute_clusters(df, resolution=2.5)
    df["ClusterID"] = df["Source"].apply(lambda x: str(node_cluster.get(x, 'N/A')))
    
    # Calculate average entropy per cluster using Protocol, SourcePort, and DestinationPort
    cluster_entropy = {}
    for cluster, group in df.groupby("ClusterID"):
        ent_protocol = compute_entropy(group["Protocol"]) if "Protocol" in group.columns else 0
        ent_srcport = compute_entropy(group["SourcePort"]) if "SourcePort" in group.columns else 0
        ent_dstport = compute_entropy(group["DestinationPort"]) if "DestinationPort" in group.columns else 0
        cluster_entropy[cluster] = (ent_protocol + ent_srcport + ent_dstport) / 3
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy)
    
    return df

# Convert the processed DataFrame back to CSV text for output
def process_csv(csv_text):
    df = process_csv_to_df(csv_text)
    out = StringIO()
    df.to_csv(out, index=False, quoting=csv.QUOTE_MINIMAL)
    return out.getvalue()

app = Flask(__name__)
CORS(app)  # Enable CORS so that requests from our web app can be processed

# Endpoint to filter and aggregate data by different metrics based on user filters
@app.route('/filter_and_aggregate', methods=['POST'])
def filter_and_aggregate():
    global global_df
    if global_df is None:
        return jsonify([])
    data = request.get_json()
    payloadKeyword = data.get("payloadKeyword", "").lower()
    sourceFilter = data.get("sourceFilter", "").lower()
    destinationFilter = data.get("destinationFilter", "").lower()
    protocolFilter = data.get("protocolFilter", "").lower()
    try:
        entropyMin = float(data.get("entropyMin", float('-inf')))
    except Exception as e:
        entropyMin = float('-inf')
    try:
        entropyMax = float(data.get("entropyMax", float('inf')))
    except Exception as e:
        entropyMax = float('inf')
    isLargePacketOnly = data.get("isLargePacketOnly", False)
    isRetransmissionOnly = data.get("isRetransmissionOnly", False)
    isSuspiciousAckOnly = data.get("isSuspiciousAckOnly", False)
    metric = data.get("metric", "count")

    # New numeric filters for unique source/destination counts
    min_source_amt = int(data["minSourceAmt"]) if data.get("minSourceAmt", "").strip() != "" else 0
    max_source_amt = int(data["maxSourceAmt"]) if data.get("maxSourceAmt", "").strip() != "" else float('inf')
    min_dest_amt = int(data["minDestinationAmt"]) if data.get("minDestinationAmt", "").strip() != "" else 0
    max_dest_amt = int(data["maxDestinationAmt"]) if data.get("maxDestinationAmt", "").strip() != "" else float('inf')
    
    df = global_df.copy()
    if payloadKeyword:
        df = df[df["Payload"].str.lower().str.contains(payloadKeyword, na=False)]
    if sourceFilter:
        df = df[df["Source"].str.lower().str.contains(sourceFilter, na=False)]
    if destinationFilter:
        df = df[df["Destination"].str.lower().str.contains(destinationFilter, na=False)]
    if protocolFilter:
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
    else:
        df[metric] = pd.to_numeric(df[metric], errors='coerce').fillna(0)
        agg = df.groupby("ClusterID")[metric].sum()
    
    # Get unique counts for Source and Destination per cluster
    unique_sources = df.groupby("ClusterID")["Source"].nunique()
    unique_destinations = df.groupby("ClusterID")["Destination"].nunique()

    # Only include clusters that meet our min/max unique source/destination criteria
    filtered_pivot = []
    for cluster, value in agg.items():
        src_count = unique_sources.get(cluster, 0)
        dst_count = unique_destinations.get(cluster, 0)
        if src_count < min_source_amt or src_count > max_source_amt:
            continue
        if dst_count < min_dest_amt or dst_count > max_dest_amt:
            continue
        filtered_pivot.append({"cluster": cluster, "value": value})
    
    return jsonify(filtered_pivot)

# Endpoint to return network data for a given cluster
@app.route('/cluster_network', methods=['GET'])
def cluster_network():
    global global_df
    if global_df is None:
        return jsonify({"nodes": [], "edges": []})
    
    cluster_id_param = request.args.get("cluster_id")
    # Filter the global data to only include rows with the matching cluster ID
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id_param)]
    
    nodes = {}
    edges = {}
    # Build nodes and edges for the network graph from the filtered data
    for idx, row in df_cluster.iterrows():
        source = str(row.get("Source", "")).strip()
        destination = str(row.get("Destination", "")).strip()
        protocol = str(row.get("Protocol", "")).strip()
        # Skip if either the source, destination, or protocol are missing
        if not source or not destination or not protocol:
            continue
        # Ensure classification is set; compute if not already in the row
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
    return jsonify({"nodes": list(nodes.values()), "edges": list(edges.values())})

# Endpoint to return rows of a cluster in JSON format (used for pagination)
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
    # Filter by cluster and prepare the subset of rows for the current page
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    # Replace NaN with None so that JSON is valid
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

    # Filter data for the selected cluster
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    # Replace NaN with None so they appear as empty cells in HTML
    rows = df_cluster.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")
    
    if not rows:
        return "<p>No rows found for this cluster.</p>"
    
    # Use the first row's keys to form table headers
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

# Endpoint to process CSV data: parses, processes, and stores in global_df
@app.route('/process_csv', methods=['POST'])
def process_csv_endpoint():
    global global_df
    try:
        data = request.get_json()
        csv_text = data.get("csv_text", "")
        processed_text = process_csv(csv_text)
        global_df = process_csv_to_df(csv_text)
        return Response(processed_text, mimetype='text/plain')
    except Exception as e:
        logging.error(f"Error processing CSV: {e}")
        return jsonify({"error": str(e)}), 400

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

# When this script is executed, either run the CLI or launch the server
if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] != "runserver":
        main_cli()
    else:
        app.run(debug=True)
