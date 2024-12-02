import subprocess
import json
import os
import sys
from datetime import datetime
from pathlib import Path

def run_bandit_analyzer(zip_file_path, json_report_path):
    """Runs the bandit_analyzer.py script to analyze code and generate a JSON report."""
    try:
        subprocess.run(
            ["python", "bandit_analyzer.py", zip_file_path, json_report_path],
            check=True
        )
        print(f"Bandit analysis completed. JSON report generated at: {json_report_path}")
    except subprocess.CalledProcessError as e:
        print("An error occurred while running bandit_analyzer.py:", e)
        sys.exit(1)

def generate_html_report(json_report_path, html_report_path):
    """Converts JSON report to HTML format."""
    try:
        # Load JSON data
        with open(json_report_path, "r") as json_file:
            data = json.load(json_file)

        # Start HTML structure
        html_content = "<html><head><title>Lazy Source Code Analysis Report</title></head><body>"
        html_content += "<h1>Lazy Source Code Security Analysis Report</h1>"

        # Check if there are any results
        if not data.get("results"):
            html_content += "<p>No security issues found.</p>"
        else:
            # Add table of findings
            html_content += "<table border='1'><tr><th>Issue</th><th>Severity</th><th>File</th><th>Line</th></tr>"
            for result in data["results"]:
                html_content += (
                    f"<tr>"
                    f"<td>{result['issue_text']}</td>"
                    f"<td>{result['issue_severity']}</td>"
                    f"<td>{result['filename']}</td>"
                    f"<td>{result['line_number']}</td>"
                    f"</tr>"
                )
            html_content += "</table>"

        # Close HTML structure
        html_content += "</body></html>"

        # Write to HTML file
        with open(html_report_path, "w") as html_file:
            html_file.write(html_content)

        print(f"HTML report generated at: {html_report_path}")

    except (IOError, json.JSONDecodeError) as e:
        print("An error occurred while generating the HTML report:", e)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bandit_master.py <zip_file_path>")
        sys.exit(1)

    zip_file_path = sys.argv[1]

    # Create "Analyzed-Reports" folder if it doesn't exist
    reports_dir = Path("Analyzed-Reports")
    reports_dir.mkdir(exist_ok=True)

    # Generate filenames with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_report_path = reports_dir / f"bandit_report_{timestamp}.json"
    html_report_path = reports_dir / f"bandit_report_{timestamp}.html"

    # Run the Bandit analysis and generate a JSON report
    run_bandit_analyzer(zip_file_path, json_report_path)

    # Generate the HTML report from the JSON report
    generate_html_report(json_report_path, html_report_path)
