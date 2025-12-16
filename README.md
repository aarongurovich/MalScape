# MalScape

MalScape is a network traffic analysis and visualization tool designed to identify patterns, clusters, and anomalies within network communication data. It leverages the Louvain method for community detection to group communicating nodes and highlights potential security threats based on ground truth data.

## Getting Started

Follow these steps to set up the project locally.

### Prerequisites

* **Python** (v3.11 or higher recommended)
* **pip** (Python package installer)

### Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/aarongurovich/malscape.git](https://github.com/aarongurovich/malscape.git)
    cd malscape
    ```

2.  **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application**
    
    *For development:*
    ```bash
    python backend/app.py
    ```
    
    *For production (using Gunicorn):*
    ```bash
    gunicorn backend.app:app
    ```

4.  Open your browser and navigate to `http://localhost:5000` to view the interface.

## Usage

1.  **Upload Data**: Use the web interface to upload a network traffic CSV file. The tool expects columns such as `Source`, `Destination`, `Protocol`, `Length`, and `Time`.
2.  **Analyze Clusters**: The application automatically groups IP addresses into clusters using the Louvain algorithm. You can view these relationships in the network graph.
3.  **Detect Anomalies**: MalScape cross-references connections with a `GroundTruth.csv` file (located in `backend/`) to flag known malicious activity.
4.  **Visualize**: Explore the data using hierarchical clustering views, network graphs, and heatmaps.

## Features

* **Community Detection**: Uses the Louvain algorithm to cluster nodes based on communication frequency and weight.
* **Anomaly Detection**: Identifies and flags specific "attack" connections based on pre-defined ground truth data.
* **Hierarchical Clustering**: View data at different resolutions to find macro and micro patterns.
* **Network Visualization**: Interactive node-link diagrams showing relationships between internal and external IP addresses.
* **Traffic Parsing**: Automatically parses TCP payloads to extract flags (SYN, ACK, PSH, RST), sequence numbers, and window sizes.

## Project Structure

* **`backend/`**: Contains the Flask application logic (`app.py`) and ground truth data.
* **`frontend/`**: Contains the web interface files (`MalscapeDev.html`, `MalscapeProd.html`).
* **`tools/`**: Helper scripts for data conversion and downloading.
* **`requirements.txt`**: List of Python dependencies.

## Author

**Aaron Gurovich**
