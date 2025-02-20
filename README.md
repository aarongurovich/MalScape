# MalScape

MalScape is a web-based tool for visualizing network connections using CSV data. It utilizes Cytoscape.js for network graph rendering and Pyodide for client-side CSV processing. This tool is designed to facilitate network data analysis and visualization.

---

## Features

- **Interactive Network Graphs:** Visualize network connections as nodes and edges.
- **Edge Filtering:** Filter edges based on source and destination IPs.
- **Protocol-Based Coloring:** Edges are color-coded by protocol type.
- **Dynamic Table Display:** Displays top 50 rows of the CSV file, with options to load more.
- **Tooltips and Hover Information:** Detailed information on nodes and edges is displayed on hover.
- **Legend Panel:** Color legend for protocol mapping.

---

## Requirements

- A modern web browser:
  - Google Chrome
  - Mozilla Firefox
  - Microsoft Edge
  - Safari
- A CSV file with at least the following columns:
  - `Source` - Source IP address
  - `Destination` - Destination IP address
  - `Protocol` - Network protocol (e.g., HTTP, DNS, FTP)

---

## Usage

### 1. Opening the Tool
- Open the `index.html` file in a compatible web browser.
- No installations are required as all processing is performed within the browser environment.

---

### 2. Uploading CSV Data
- Click on the **"Choose File"** button.
- Select a `.csv` file from local storage.
- The tool will process the file and:
  - Visualize the network graph.
  - Display the first 50 rows of the CSV file in a table format.

---

## Network Graph

- **Nodes** represent IP addresses:
  - Internal IPs are displayed as rectangles.
  - External IPs are displayed as ellipses.
- **Edges** represent network connections:
  - Color-coded by protocol type.
  - Weighted by the frequency of the connection.
- **Tooltip Information:**
  - Hovering over a node displays:
    - Node ID (IP address)
    - Classification (Internal or External)
  - Hovering over an edge displays:
    - Source and Destination IPs
    - Protocol type
    - Number of matching rows in the CSV

---

## Filtering and Selecting Edges

### Filtering by Source and Destination IP
- Enter **Source IP** and **Destination IP** in the input fields.
- The tool automatically selects the corresponding edge if found.
- If no matching edge is found, no action is taken.

### Edge Selection on Graph
- **Click on an Edge:** 
  - Highlights the edge in red.
  - Displays corresponding rows in the CSV table.
- **Click Again:** 
  - Unselects the edge.
  - The associated rows are hidden from the table.

### Unselecting All Edges
- Click on the **"Unselect All Edges"** button to:
  - Clear all selections.
  - Display all rows in the table.

---

## CSV Table Display

- Displays the first **50 rows** of the CSV file by default.
- Click **"Load More"** to display additional rows, 50 at a time.
- If an edge is selected, only the corresponding rows are shown.

---

## Legend

- A legend panel is displayed on the right side of the interface.
- It maps colors to protocol types for easy identification:
  - DNS, FTP, HTTP, SMB, SMTP, SSH, STP, TCP, TLSv1, etc.
- The legend updates dynamically as new protocols are detected in the CSV.

---

## Troubleshooting

- **No Graph Displayed:** Ensure that the CSV file includes the `Source`, `Destination`, and `Protocol` columns.
- **Edge Not Found:** Verify the accuracy of the Source and Destination IPs entered.
- **Large CSV Files:** The tool paginates the table to enhance performance. Click **"Load More"** to view additional rows.

---

## Notes

- This tool is designed for network analysis and visualization.
- It is optimized for medium-sized CSV files.
- All processing is performed client-side using Pyodide and Cytoscape.js.

---
