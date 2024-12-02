import json
import os
from datetime import datetime
from cwe_mapping import get_cwe_details

# Function to generate the HTML report
def generate_report(json_report_path, output_folder):
    # Load the Bandit JSON report
    with open(json_report_path, 'r') as file:
        bandit_report = json.load(file)
    
    # Prepare the output file name and path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"bandit_report_{timestamp}.html"
    output_path = os.path.join(output_folder, report_filename)
    
    # Start the HTML report
    html_content = '''
    <html>
    <head><title>Bandit Security Analysis Report</title></head>
    <body>
    <h1>Bandit Security Analysis Report</h1>
    <table border="1">
    <tr><th>File</th><th>Line</th><th>Vulnerability Name</th><th>CWE ID</th><th>Severity</th><th>Description</th><th>Remediation</th></tr>
    '''
    
    # Iterate through the Bandit report to fill the table
    for issue in bandit_report.get('results', []):
        file_path = issue.get('filename', 'N/A')
        line_number = issue.get('line_number', 'N/A')
        vulnerability_name = issue.get('test_id', 'N/A')
        
        # Get CWE details for the vulnerability
        cwe_details = get_cwe_details(vulnerability_name)
        
        # Add a row to the HTML table
        html_content += f'''
        <tr>
            <td>{file_path}</td>
            <td>{line_number}</td>
            <td>{vulnerability_name}</td>
            <td>{cwe_details['cwe_id']}</td>
            <td>{cwe_details['severity']}</td>
            <td>{cwe_details['description']}</td>
            <td>{cwe_details['remediation']}</td>
        </tr>
        '''
    
    # Close the HTML content
    html_content += '''
    </table>
    </body>
    </html>
    '''
    
    # Save the generated HTML report
    with open(output_path, 'w') as report_file:
        report_file.write(html_content)
    
    return output_path

# Example usage
if __name__ == "__main__":
    json_report_path = "path/to/your/analysis_report.json"  # Replace with your actual report path
    output_folder = "path/to/save/reports"  # Replace with the folder where you want to save the HTML report
    report_path = generate_report(json_report_path, output_folder)
    print(f"Report generated at: {report_path}")
