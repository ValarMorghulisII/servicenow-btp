import os
import json
import requests
from flask import Flask, request, jsonify, render_template
import pandas as pd
import defusedxml.ElementTree as ET

app = Flask(__name__)

# ServiceNow API Configuration
SERVICENOW_INSTANCE = os.getenv("SN_INSTANCE", "your-instance.service-now.com")
SERVICENOW_USER = os.getenv("SN_USER", "")
SERVICENOW_PASS = os.getenv("SN_PASSWORD", "")
SN_API_URL = f"https://{SERVICENOW_INSTANCE}/api/now/table/incident" # Or 'sn_vul_entry' for Vulnerability Response

def parse_file(file_obj, filename):
    """Normalizes JSON, XML, or Excel content into a list of vulnerability dicts."""
    records = []
    ext = os.path.splitext(filename)[1].lower()

    if ext == '.json':
        data = json.load(file_obj)
        records = data if isinstance(data, list) else data.get('vulnerabilities', [data])

    elif ext in ['.xlsx', '.xls']:
        df = pd.read_excel(file_obj)
        # Convert NaN values to empty strings for API compatibility
        records = df.fillna("").to_dict(orient='records')

    elif ext == '.xml':
        tree = ET.parse(file_obj)
        root = tree.getroot()
        # Expecting repeated item elements (e.g., <vulnerability>...</vulnerability>)
        for elem in root.findall('.//vulnerability') or root.iter():
            if elem.tag != root.tag:
                record = {child.tag: child.text.strip() if child.text else "" for child in elem}
                if record:
                    records.append(record)
    else:
        raise ValueError(f"Unsupported file format: {ext}")

    return records

def create_servicenow_ticket(vuln_data):
    """Sends a single record to ServiceNow API."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # Map input attributes to ServiceNow Table fields
    payload = {
        "short_description": f"Vulnerability: {vuln_data.get('title', vuln_data.get('name', 'Security Vulnerability'))}",
        "description": json.dumps(vuln_data, indent=2),
        "severity": str(vuln_data.get('severity', '3')),
        "assignment_group": "Security Response"
    }

    response = requests.post(
        SN_API_URL,
        auth=(SERVICENOW_USER, SERVICENOW_PASS),
        headers=headers,
        json=payload,
        timeout=10
    )
    return response

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty file name"}), 400

    try:
        records = parse_file(file.stream, file.filename)
    except Exception as e:
        return jsonify({"error": f"Failed to parse file: {str(e)}"}), 400

    # Sequential processing loop
    results = {"total": len(records), "created": 0, "failed": 0, "details": []}

    for index, record in enumerate(records):
        try:
            res = create_servicenow_ticket(record)
            if res.status_code in [200, 201]:
                ticket_info = res.json().get('result', {})
                results["created"] += 1
                results["details"].append({
                    "record_index": index,
                    "status": "success",
                    "ticket_number": ticket_info.get("number")
                })
            else:
                results["failed"] += 1
                results["details"].append({
                    "record_index": index,
                    "status": "failed",
                    "error": res.text
                })
        except Exception as err:
            results["failed"] += 1
            results["details"].append({
                "record_index": index,
                "status": "error",
                "error": str(err)
            })

    return jsonify(results), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))