# MalScape

MalScape is a web-based tool that visualizes network connections from a CSV file. It uses Cytoscape.js for network graphs and Pyodide to process the CSV data right in the browser. Here's how to use it:

---

## Getting Started

1. **Open the Tool:**  
   Just open the `index.html` file in any modern browser (Chrome, Firefox, Edge, Safari). You don’t need to install anything else.

2. **Upload Your CSV File:**  
   - Click on the **"Choose File"** button.
   - Select a `.csv` file from your computer. Make sure the file has at least these columns:
     - `Source` - Source IP address
     - `Destination` - Destination IP address
     - `Protocol` - The protocol used (e.g., HTTP, DNS, FTP)
   - The tool will process the file and display the network graph along with a table of the data.

---

## Network Graph

- The graph shows IPs as nodes and connections as edges.
- **Nodes** are shaped based on whether they’re Internal or External and colored based on cluster group.
- **Edges** are colored based on the protocol (e.g., HTTP, DNS, FTP).

### Hovering for Info:
- **Hover over a Node:**  
  - Shows the IP address and whether it’s Internal or External.
- **Hover over an Edge:**  
  - Shows the source and destination IPs, protocol, and the number of rows that match this connection in the CSV.

---

## Filtering and Selecting

### Filter by Source and Destination IP:
1. Type the **Source IP** and **Destination IP** in the input fields at the top.
2. Click **"Select Edge"** to highlight the connection between those two IPs. If no edge is found, a popup will let you know.

### Selecting Edges on the Graph:
- **Click on an Edge:** It turns **red** and the related rows are displayed in the table.
- **Click Again:** It gets unselected and the rows disappear from the table.

### Unselect All Edges:
- Click on **"Unselect All Edges"** to clear all selections and show all rows in the table.

---

## Viewing CSV Data

- The table shows the CSV content with the top **50 rows** displayed by default.
- Click **"Load More"** to view the next 50 rows.
- If you select an edge, only rows related to that edge will be shown.

---

## Legend

- On the right, there’s a legend showing which colors correspond to which protocols


## Tips & Tricks

- **No Graph Appearing?** Make sure your CSV has `Source`, `Destination`, and `Protocol` columns.
- **Edge Not Found?** Double-check the Source and Destination IPs you typed in.
- **Large CSV Files?** The tool loads 50 rows at a time to keep things fast. Use **"Load More"** as needed.

---

That’s it! Just open, upload, and explore your network data with MalScape.
