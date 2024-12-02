import subprocess
import os
import zipfile
import sys

def extract_zip_file(zip_path, extract_to):
    """Extracts the contents of a ZIP file to a specified directory."""
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print(f"ZIP file extracted to: {extract_to}")

def run_bandit_analysis(target_directory, json_report_path):
    """Runs Bandit analysis on a target directory and outputs a JSON report."""
    try:
        # JSON Report
        json_command = [
            "bandit", "-r", target_directory, "-f", "json", "-o", json_report_path
        ]
        subprocess.run(json_command, check=True)
        print(f"JSON report generated at: {json_report_path}")

    except subprocess.CalledProcessError as e:
        print("An error occurred while running Bandit:", e)

if __name__ == "__main__":
    # Check if the required argument is provided
    if len(sys.argv) < 2:
        print("Usage: python bandit_analyzer.py <zip_file_path> [<json_report_path>]")
        sys.exit(1)

    zip_file_path = sys.argv[1]
    extract_directory = "analysis_code_extract"

    # Default report path
    json_report_path = sys.argv[2] if len(sys.argv) > 2 else "bandit_report.json"

    # Verify the ZIP file exists
    if not os.path.isfile(zip_file_path):
        print(f"Error: ZIP file '{zip_file_path}' not found.")
        sys.exit(1)

    # Create the extraction directory if it doesn't exist
    os.makedirs(extract_directory, exist_ok=True)

    # Extract ZIP file
    extract_zip_file(zip_file_path, extract_directory)

    # Run Bandit analysis on the extracted files
    run_bandit_analysis(extract_directory, json_report_path)
