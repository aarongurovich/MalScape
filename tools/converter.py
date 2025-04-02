#!/usr/bin/env python3
import os
import re
import lzma
import argparse
import subprocess
import pandas as pd
from datetime import datetime, timedelta

def extract_timestamp_from_filename(filename):
    """
    Extract a timestamp string from the filename.
    The expected format is YYYYMMDDHHMMSS.
    For example: mypcap_20091103082335.pcap.xz
    """
    pattern = r'(\d{14})'
    match = re.search(pattern, filename)
    if not match:
        raise ValueError("No valid timestamp in 'YYYYMMDDHHMMSS' format was found in the filename.")
    timestamp_str = match.group(1)
    try:
        base_time = datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")
    except ValueError as e:
        raise ValueError(f"Error parsing timestamp: {e}")
    return base_time

def decompress_file(compressed_file):
    """Decompress a .xz file and write the uncompressed content to a new file."""
    if not compressed_file.endswith('.xz'):
        raise ValueError("The file does not have a .xz extension.")
    
    uncompressed_file = compressed_file[:-3]
    print(f"Decompressing {compressed_file} to {uncompressed_file} ...")
    
    try:
        with lzma.open(compressed_file, 'rb') as fin, open(uncompressed_file, 'wb') as fout:
            chunk_size = 1024 * 1024  # 1 MB
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                fout.write(chunk)
    except Exception as e:
        raise RuntimeError(f"Error decompressing file: {e}")
    
    print("Decompression complete.")
    return uncompressed_file

def convert_pcap_to_csv(pcap_file, csv_file):
    """
    Use tshark to convert the pcap file to CSV.
    The command extracts the following fields:
      - frame.number
      - frame.time_epoch
      - ip.src
      - ip.dst
      - _ws.col.protocol
      - frame.len
      - _ws.col.Info   # This field preserves the original Info column.
    The added option -E quote=d ensures that fields are enclosed in quotes.
    """
    print(f"Converting {pcap_file} to CSV {csv_file} using tshark ...")
    
    tshark_cmd = [
        "tshark",
        "-r", pcap_file,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",            # Enclose fields in double quotes.
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.protocol",
        "-e", "frame.len",
        "-e", "_ws.col.Info"         # Added Info field extraction.
    ]
    
    try:
        with open(csv_file, "w") as fout:
            subprocess.run(tshark_cmd, check=True, stdout=fout)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"tshark command failed: {e}")
    except Exception as e:
        raise RuntimeError(f"Error during tshark execution: {e}")
    
    print("Conversion to CSV complete.")

def convert_time_and_rename_columns(csv_file, output_csv, base_time):
    """
    Reads the CSV file, renames the columns as specified,
    converts the 'frame.time_epoch' column (renamed to 'Time')
    from an absolute epoch time to a relative time offset (by subtracting the capture's start time)
    and then adds that offset to the base_time (extracted from the filename).
    The resulting timestamp includes milliseconds.
    Also renames the Info column to Payload.
    """
    print(f"Reading CSV file {csv_file} ...")
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        raise RuntimeError(f"Error reading CSV file: {e}")

    print(f"Using base timestamp: {base_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Rename columns including the Info field to Payload.
    df.rename(columns={
        "frame.number": "No.",
        "frame.time_epoch": "Time",
        "ip.src": "Source",
        "ip.dst": "Destination",
        "_ws.col.protocol": "Protocol",
        "frame.len": "Length",
        "_ws.col.info": "Payload"  # Rename Info to Payload.
    }, inplace=True)
    
    # Convert the Time column to numeric (absolute epoch seconds).
    try:
        df["Time"] = pd.to_numeric(df["Time"], errors='coerce')
    except Exception as e:
        raise RuntimeError(f"Error converting Time column to numeric: {e}")
    
    capture_start = df["Time"].min()
    print(f"Capture start epoch: {capture_start}")

    print("Converting 'Time' column to absolute timestamps with milliseconds ...")
    try:
        df["Time"] = df["Time"].apply(
            lambda x: (base_time + timedelta(seconds=(x - capture_start))).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        )
    except Exception as e:
        raise RuntimeError(f"Error converting 'Time' column: {e}")
    
    try:
        df.to_csv(output_csv, index=False)
    except Exception as e:
        raise RuntimeError(f"Error writing the output CSV file: {e}")
    
    print(f"Final CSV saved as {output_csv}")

def main():
    parser = argparse.ArgumentParser(
        description="Uncompress a .pcap.xz file, convert it to CSV via tshark, "
                    "rename columns and convert the 'Time' column into absolute timestamps (with milliseconds) "
                    "using the timestamp from the filename as the capture start. The final CSV will have the same base filename."
    )
    parser.add_argument("compressed_file", help="Path to the compressed .pcap.xz file")
    args = parser.parse_args()

    try:
        base_time = extract_timestamp_from_filename(os.path.basename(args.compressed_file))
    except Exception as e:
        print(e)
        return

    try:
        pcap_file = decompress_file(args.compressed_file)
    except Exception as e:
        print(e)
        return

    base_name = os.path.basename(args.compressed_file)
    if base_name.endswith(".pcap.xz"):
        base_name = base_name[:-len(".pcap.xz")]
    final_csv = base_name + ".csv"

    intermediate_csv = "temp_output.csv"
    try:
        convert_pcap_to_csv(pcap_file, intermediate_csv)
    except Exception as e:
        print(e)
        return

    try:
        convert_time_and_rename_columns(intermediate_csv, final_csv, base_time)
    except Exception as e:
        print(e)
        return

    if os.path.exists(intermediate_csv):
        os.remove(intermediate_csv)

    print("All operations completed successfully.")

if __name__ == "__main__":
    main()
