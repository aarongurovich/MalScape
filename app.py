from flask import Flask, request, Response, jsonify, send_from_directory
import csv
import pandas as pd
from ipaddress import ip_address, ip_network
from io import StringIO
import re
import networkx as nx
import community as community_louvain 
import numpy as np
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Precompute internal subnets and their integer ranges for fast IP classification.
internal_subnets = [
    ip_network('172.28.0.0/16'),
    ip_network('192.168.61.0/24')
]
internal_ranges = [(int(net.network_address), int(net.broadcast_address)) for net in internal_subnets]

def classify_ip_vector(ip):
    try:
        ip_int = int(ip_address(ip))
    except ValueError:
        return "Invalid IP"
    for rmin, rmax in internal_ranges:
        if rmin <= ip_int <= rmax:
            return "Internal"
    return "External"

def parse_payload_vectorized(payload_series):
    """
    Extract columns from the payload:
      - SourcePort, DestinationPort, Flags, Seq, Ack, Win, Len, TSval, TSecr.
    """
    cols = ["SourcePort", "DestinationPort", "Flags", "Seq", "Ack", "Win", "Len", "TSval", "TSecr"]
    df_extracted = pd.DataFrame(index=payload_series.index, columns=cols)
    sp_dp_flags = payload_series.str.extract(r'^\s*:?\s*(\d+)\s*>\s*(\d+)\s*\[([^\]]+)\]', expand=True)
    df_extracted["SourcePort"]      = sp_dp_flags[0]
    df_extracted["DestinationPort"] = sp_dp_flags[1]
    df_extracted["Flags"]           = sp_dp_flags[2]
    df_extracted["Seq"]   = payload_series.str.extract(r'Seq=(\d+)',   expand=False)
    df_extracted["Ack"]   = payload_series.str.extract(r'Ack=(\d+)',   expand=False)
    df_extracted["Win"]   = payload_series.str.extract(r'Win=(\d+)',   expand=False)
    df_extracted["Len"]   = payload_series.str.extract(r'Len=(\d+)',   expand=False)
    df_extracted["TSval"] = payload_series.str.extract(r'TSval=(\d+)', expand=False)
    df_extracted["TSecr"] = payload_series.str.extract(r'TSecr=(\d+)', expand=False)
    df_extracted.fillna("N/A", inplace=True)
    return df_extracted

def compute_clusters(df):
    """
    Compute clusters using the Louvain method.
    """
    G = nx.Graph()
    for src, dst in zip(df['Source'], df['Destination']):
        if pd.notna(src) and pd.notna(dst):
            G.add_edge(src, dst)
    partition = community_louvain.best_partition(G)
    return partition

def compute_entropy(series):
    counts = series.value_counts()
    p = counts / counts.sum()
    return -np.sum(p * np.log(p))

def process_csv(csv_text, start_source=None, start_destination=None):
    """
    Reads CSV input, processes payload fields, classifies IP addresses, computes additional
    behavioral, traffic, and temporal features, and finally computes clusters and cluster entropy.
    
    Derived columns include:
      - ConnectionID, SeqDelta, AckDelta, IsRetransmission, TCPFlagCount,
        InterArrivalTime, BytesPerSecond, IsLargePacket, PayloadLength, BurstID,
        IsSuspiciousAck, and ClusterEntropy.
    """
    df = pd.read_csv(StringIO(csv_text), dtype=str)
    
    # Verify minimal required columns.
    if not all(col in df.columns for col in ["Source", "Destination"]):
        raise ValueError("Missing required column: Source or Destination")
    
    processed_cols = ["Source", "Destination", "Payload", "SourcePort", "DestinationPort", "Flags", 
                      "Seq", "Ack", "Win", "Len", "TSval", "TSecr", 
                      "SourceClassification", "DestinationClassification", "ClusterID",
                      "ConnectionID", "SeqDelta", "AckDelta", "IsRetransmission", "TCPFlagCount",
                      "InterArrivalTime", "BytesPerSecond", "IsLargePacket", "PayloadLength",
                      "BurstID", "IsSuspiciousAck", "ClusterEntropy"]
    if all(col in df.columns for col in processed_cols):
        out = StringIO()
        df.to_csv(out, index=False, quoting=csv.QUOTE_MINIMAL)
        return out.getvalue()

    # Rename 'Info' to 'Payload' if needed.
    if "Info" in df.columns:
        df.rename(columns={"Info": "Payload"}, inplace=True)
    
    # Process Payload if it exists.
    if "Payload" in df.columns:
        df["Payload"] = df["Payload"].fillna("").str.replace(',', '/', regex=False)
        extracted = parse_payload_vectorized(df["Payload"])
        df = pd.concat([df, extracted], axis=1)
    
    # Compute connection counts.
    connection_counts = df.groupby(["Source", "Destination"])["Source"].transform("count")
    node_weights = connection_counts.copy()
    edge_weights = connection_counts.copy()
    if node_weights.max() != node_weights.min():
        node_weights = (node_weights - node_weights.min()) / (node_weights.max() - node_weights.min())
    else:
        node_weights = pd.Series(1.0, index=node_weights.index)
    if edge_weights.max() != edge_weights.min():
        edge_weights = (edge_weights - edge_weights.min()) / (edge_weights.max() - edge_weights.min())
    else:
        edge_weights = pd.Series(1.0, index=edge_weights.index)
    
    # Classify IPs.
    df["SourceClassification"] = df["Source"].apply(classify_ip_vector)
    df["DestinationClassification"] = df["Destination"].apply(classify_ip_vector)
    
    # --- Derived Columns ---
    df["ConnectionID"] = df["Source"] + ":" + df["SourcePort"].fillna("N/A") + "-" + df["Destination"] + ":" + df["DestinationPort"].fillna("N/A")
    for col in ["Time", "Length"]:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    for col in ["Seq", "Ack", "Win", "Len", "TSval", "TSecr"]:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df["SeqDelta"] = df.groupby("ConnectionID")["Seq"].diff()
    df["AckDelta"] = df.groupby("ConnectionID")["Ack"].diff()
    df["IsRetransmission"] = df["SeqDelta"] == 0
    df["TCPFlagCount"] = df["Flags"].apply(lambda x: len(str(x).split()) if pd.notnull(x) and x != "N/A" else 0)
    df["InterArrivalTime"] = df.groupby("ConnectionID")["Time"].diff()
    df["BytesPerSecond"] = df["Length"] / df["InterArrivalTime"]
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf], np.nan)
    df["IsLargePacket"] = df["Length"] > 1000
    df["PayloadLength"] = df["Len"]
    df["BurstID"] = df.groupby("ConnectionID")["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum())
    df["PrevSeq"] = df.groupby("ConnectionID")["Seq"].shift(1)
    df["IsSuspiciousAck"] = df.apply(lambda row: True if pd.notnull(row["PrevSeq"]) and row["Ack"] < row["PrevSeq"] else False, axis=1)
    df.drop(columns=["PrevSeq"], inplace=True)
    # --- End Derived Columns ---

    # Compute clusters using Louvain.
    node_cluster = compute_clusters(df)
    df["ClusterID"] = df["Source"].apply(lambda x: node_cluster.get(x, 'N/A'))
    
    # Compute ClusterEntropy.
    cluster_entropy = {}
    for cluster, group in df.groupby("ClusterID"):
        ent_protocol = compute_entropy(group["Protocol"]) if "Protocol" in group.columns else 0
        ent_srcport = compute_entropy(group["SourcePort"]) if "SourcePort" in group.columns else 0
        ent_dstport = compute_entropy(group["DestinationPort"]) if "DestinationPort" in group.columns else 0
        cluster_entropy[cluster] = (ent_protocol + ent_srcport + ent_dstport) / 3
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy)
    
    if start_source:
        matching_rows = df[df["Source"] == start_source]
        if not matching_rows.empty:
            target_cluster = matching_rows.iloc[0]["ClusterID"]
            df = df[df["ClusterID"] == target_cluster]
        else:
            df = df[0:0]
    
    out = StringIO()
    df.to_csv(out, index=False, quoting=csv.QUOTE_MINIMAL)
    return out.getvalue()

@app.route('/process_csv', methods=['POST'])
def process_csv_endpoint():
    try:
        data = request.get_json()
        csv_text = data.get("csv_text", "")
        start_source = data.get("start_source")
        start_destination = data.get("start_destination")
        processed = process_csv(csv_text, start_source, start_destination)
        return Response(processed, mimetype='text/plain')
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

if __name__ == '__main__':
    app.run(debug=True)
