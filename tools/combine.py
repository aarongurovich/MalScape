import pandas as pd
import glob
import os

def combine_csv_files(input_folder, output_file):
    # Find all CSV files in the folder and sort them.
    csv_files = sorted(glob.glob(os.path.join(input_folder, "*.csv")))
    print(f"Found {len(csv_files)} CSV files.")

    combined_df = pd.DataFrame()

    # Read and concatenate each CSV file.
    for file in csv_files:
        print(f"Reading {file} ...")
        try:
            df = pd.read_csv(file)
            combined_df = pd.concat([combined_df, df], ignore_index=True)
        except Exception as e:
            print(f"Error reading {file}: {e}")

    # Update the "No." column with sequential numbers starting at 1.
    combined_df['No.'] = range(1, len(combined_df) + 1)

    # Save the combined DataFrame to the output CSV file.
    try:
        combined_df.to_csv(output_file, index=False)
        print(f"\n✅ Combined CSV saved as {output_file}")
    except Exception as e:
        print(f"Error saving the final CSV: {e}")

if __name__ == "__main__":
    input_folder = r"C:\Users\Aaron\Malscape\Combine"
    output_file = "combined_day1.csv"
    combine_csv_files(input_folder, output_file)