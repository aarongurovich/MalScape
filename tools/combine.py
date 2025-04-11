import pandas as pd
import glob
import os

def combine_csv_files(input_folder, output_file):
    # Find all CSV files in the folder
    csv_files = sorted(glob.glob(os.path.join(input_folder, "*.csv")))

    print(f"Found {len(csv_files)} CSV files.")

    combined_df = pd.DataFrame()

    for file in csv_files:
        print(f"Reading {file} ...")
        try:
            df = pd.read_csv(file)
            combined_df = pd.concat([combined_df, df], ignore_index=True)
        except Exception as e:
            print(f"Error reading {file}: {e}")

    # Save the combined file
    try:
        combined_df.to_csv(output_file, index=False)
        print(f"\n✅ Combined CSV saved as {output_file}")
    except Exception as e:
        print(f"Error saving the final CSV: {e}")

if __name__ == "__main__":
    input_folder = r"C:\Users\Aaron\MalScape\Combine"
    output_file = "combined_day1.csv"

    combine_csv_files(input_folder, output_file)
