from flask import Flask, request, Response, jsonify, send_from_directory
import csv
import pandas as pd
from ipaddress import ip_address, ip_network
from io import StringIO
import re
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
    Use vectorized string extraction to get initial payload fields:
    SourcePort, DestinationPort, and Flags.
    """
    pattern = r'^\s*(\d+)\s*>\s*(\d+)\s*\[([^\]]+)\]'
    extracted = payload_series.str.extract(pattern, expand=True)
    return extracted  # columns: 0=SourcePort, 1=DestinationPort, 2=Flags

def compute_clusters(df):
    """
    Compute clusters (connected components) using union-find with union-by-rank.
    """
    nodes = set(df['Source'].dropna()).union(set(df['Destination'].dropna()))
    parent = {node: node for node in nodes}
    rank = {node: 0 for node in nodes}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rootX = find(x)
        rootY = find(y)
        if rootX != rootY:
            if rank[rootX] > rank[rootY]:
                parent[rootY] = rootX
            elif rank[rootX] < rank[rootY]:
                parent[rootX] = rootY
            else:
                parent[rootY] = rootX
                rank[rootX] += 1

    for src, dst in zip(df['Source'], df['Destination']):
        if pd.notna(src) and pd.notna(dst):
            union(src, dst)
    
    cluster_map = {}
    cluster_id = 1
    for node in nodes:
        root = find(node)
        if root not in cluster_map:
            cluster_map[root] = cluster_id
            cluster_id += 1

    node_cluster = {node: cluster_map[find(node)] for node in nodes}
    return node_cluster

def process_csv(csv_text, start_source=None, start_destination=None):
    df = pd.read_csv(StringIO(csv_text), dtype=str)
    if not all(col in df.columns for col in ["Source", "Destination"]):
        raise ValueError("Missing required column: Source or Destination")
    
    if "Info" in df.columns:
        df.rename(columns={"Info": "Payload"}, inplace=True)
    
    if "Payload" in df.columns:
        mask = df["Payload"].notna()
        df.loc[mask, "Payload"] = df.loc[mask, "Payload"].str.replace(',', '/', regex=False)
        extracted = parse_payload_vectorized(df.loc[mask, "Payload"])
        df.loc[mask, "SourcePort"] = extracted[0]
        df.loc[mask, "DestinationPort"] = extracted[1]
        df.loc[mask, "Flags"] = extracted[2]
    
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
    
    df["SourceClassification"] = df["Source"].apply(classify_ip_vector)
    df["DestinationClassification"] = df["Destination"].apply(classify_ip_vector)
    
    # Compute clusters and assign ClusterID to each row based on the Source.
    node_cluster = compute_clusters(df)
    df["ClusterID"] = df["Source"].apply(lambda x: node_cluster.get(x, 'N/A'))
    
    # If a start_source is provided, filter the dataframe to only include rows with the same ClusterID.
    if start_source:
        matching_rows = df[df['Source'] == start_source]
        if not matching_rows.empty:
            target_cluster = matching_rows.iloc[0]['ClusterID']
            df = df[df['ClusterID'] == target_cluster]
        else:
            # If the start_source is not found, return an empty dataframe
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
