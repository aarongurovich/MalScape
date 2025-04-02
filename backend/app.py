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

# Configure logging to only log errors (to reduce overhead)
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Global variable for the processed dataframe
global_df = None

# Precompute internal subnets and their integer ranges for fast IP classification.
internal_subnets = [
    ip_network('172.28.0.0/16'),
    ip_network('192.168.61.0/24')
]
internal_ranges = [(int(net.network_address), int(net.broadcast_address)) for net in internal_subnets]

def classify_ip_vector(ip):
    try:
        ip_int = int(ip_address(ip))
    except:
        return "External"
    for rmin, rmax in internal_ranges:
        if rmin <= ip_int <= rmax:
            return "Internal"
    return "External"

def parse_payload_vectorized(payload_series):
    cols = ["SourcePort", "DestinationPort", "Flags", "Seq", "Ack", "Win", "Len", "TSval", "TSecr"]
    df_extracted = pd.DataFrame(index=payload_series.index, columns=cols)
    
    # Updated regex: Accepts either '>' or '→' as the delimiter.
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

def compute_clusters(df, resolution=2.5):
    G = nx.Graph()
    groups = df.groupby(["Source", "Destination"])
    for (src, dst), group in groups:
        if pd.notna(src) and pd.notna(dst):
            weight = group.shape[0]
            G.add_edge(src, dst, weight=weight)
    partition = community_louvain.best_partition(G, weight='weight', resolution=resolution)
    return partition

def compute_entropy(series):
    counts = series.value_counts()
    p = counts / counts.sum()
    return -np.sum(p * np.log(p))

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

    if "Info" in df.columns:
        df.rename(columns={"Info": "Payload"}, inplace=True)
    
    if "Payload" in df.columns:
        df["Payload"] = df["Payload"].fillna("").str.replace(',', '/', regex=False)
        extracted = parse_payload_vectorized(df["Payload"])
        df = pd.concat([df, extracted], axis=1)
    
    connection_counts = df.groupby(["Source", "Destination"])["Source"].transform("count")
    if connection_counts.max() != connection_counts.min():
        node_weights = (connection_counts - connection_counts.min()) / (connection_counts.max() - connection_counts.min())
    else:
        node_weights = pd.Series(1.0, index=connection_counts.index)
    df["NodeWeight"] = node_weights
    # Always compute classification for Source and Destination
    df["SourceClassification"] = df["Source"].apply(classify_ip_vector)
    df["DestinationClassification"] = df["Destination"].apply(classify_ip_vector)
    
    df["ConnectionID"] = df["Source"] + ":" + df["SourcePort"].fillna("N/A") + "-" + df["Destination"] + ":" + df["DestinationPort"].fillna("N/A")
    
    # Convert Time column using the new format with milliseconds
    try:
        df["Time"] = pd.to_datetime(df["Time"], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')
    except Exception as e:
        logging.error(f"Error converting Time column to datetime: {e}")
    df["Length"] = pd.to_numeric(df["Length"], errors='coerce')
    for col in ["Seq", "Ack", "Win", "Len", "TSval", "TSecr"]:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    # Compute InterArrivalTime in seconds
    df["InterArrivalTime"] = df.groupby("ConnectionID")["Time"].diff().dt.total_seconds()
    df["BytesPerSecond"] = df["Length"] / df["InterArrivalTime"]
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf], np.nan)
    df["IsLargePacket"] = df["Length"] > 1000
    df["PayloadLength"] = df["Len"]
    df["BurstID"] = df.groupby("ConnectionID")["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum())
    df["PrevSeq"] = df.groupby("ConnectionID")["Seq"].shift(1)
    df["IsSuspiciousAck"] = df.apply(lambda row: True if pd.notnull(row["PrevSeq"]) and row["Ack"] < row["PrevSeq"] else False, axis=1)
    df.drop(columns=["PrevSeq"], inplace=True)
    
    # Compute clusters and convert them to strings
    node_cluster = compute_clusters(df, resolution=2.5)
    df["ClusterID"] = df["Source"].apply(lambda x: str(node_cluster.get(x, 'N/A')))
    
    cluster_entropy = {}
    for cluster, group in df.groupby("ClusterID"):
        ent_protocol = compute_entropy(group["Protocol"]) if "Protocol" in group.columns else 0
        ent_srcport = compute_entropy(group["SourcePort"]) if "SourcePort" in group.columns else 0
        ent_dstport = compute_entropy(group["DestinationPort"]) if "DestinationPort" in group.columns else 0
        cluster_entropy[cluster] = (ent_protocol + ent_srcport + ent_dstport) / 3
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy)
    
    return df

def process_csv(csv_text):
    df = process_csv_to_df(csv_text)
    out = StringIO()
    df.to_csv(out, index=False, quoting=csv.QUOTE_MINIMAL)
    return out.getvalue()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

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
        logging.error(f"Error parsing entropyMin: {e}")
        entropyMin = float('-inf')
    try:
        entropyMax = float(data.get("entropyMax", float('inf')))
    except Exception as e:
        logging.error(f"Error parsing entropyMax: {e}")
        entropyMax = float('inf')
    isLargePacketOnly = data.get("isLargePacketOnly", False)
    isRetransmissionOnly = data.get("isRetransmissionOnly", False)
    isSuspiciousAckOnly = data.get("isSuspiciousAckOnly", False)
    metric = data.get("metric", "count")
    
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
    
    if metric == "count":
        agg = df.groupby("ClusterID").size()
    else:
        df[metric] = pd.to_numeric(df[metric], errors='coerce').fillna(0)
        agg = df.groupby("ClusterID")[metric].sum()
    pivot = [{"cluster": cluster, "value": value} for cluster, value in agg.items()]
    return jsonify(pivot)

@app.route('/cluster_network', methods=['GET'])
def cluster_network():
    global global_df
    if global_df is None:
        return jsonify({"nodes": [], "edges": []})
    
    cluster_id_param = request.args.get("cluster_id")
    # Use string comparison to ensure consistency
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id_param)]
    
    nodes = {}
    edges = {}
    for idx, row in df_cluster.iterrows():
        source = str(row.get("Source", "")).strip()
        destination = str(row.get("Destination", "")).strip()
        protocol = str(row.get("Protocol", "")).strip()
        # Skip if any endpoint is missing or empty
        if not source or not destination or not protocol:
            continue
        # Always ensure a classification is present
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
    # Ensure cluster_id comparison is done as strings
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    # Replace NaN values with None so that JSON is valid
    rows = df_cluster.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")
    return jsonify({"rows": rows, "total": total})

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

    # Filter for the selected cluster (ensure string comparison)
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    # Replace NaN with None so that they become empty strings in HTML
    rows = df_cluster.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")
    
    if not rows:
        return "<p>No rows found for this cluster.</p>"
    
    # Use the keys of the first row as the table columns
    columns = list(rows[0].keys())
    # Start building the HTML table string
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    # Create table header
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>"
    html += "</tr></thead>"
    # Create table body rows
    html += "<tbody>"
    for row in rows:
        html += "<tr>"
        for col in columns:
            cell = row[col] if row[col] is not None else ""
            html += f"<td style='padding:8px; border:1px solid #ddd;'>{cell}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    # Add a simple summary with a hidden element carrying the total row count for pagination
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

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

# New endpoint to download the processed CSV file
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

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

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
