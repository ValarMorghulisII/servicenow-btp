import os
import json
import requests
from flask import Flask, request, jsonify, render_template
import pandas as pd
import defusedxml.ElementTree as ET

app = Flask(__name__)

# Environment Configuration
SN_INSTANCE = os.getenv("SN_INSTANCE", "your-instance.service-now.com")
VAULT_URL = os.getenv("VAULT_URL", "https://vault.yourdomain.com/v1/secret/data/servicenow")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")

def get_servicenow_credentials():
    """Retrieves ServiceNow API credentials dynamically from Password Vault."""
    if not VAULT_TOKEN:
        raise ValueError("VAULT_TOKEN environment variable is not configured.")
        
    headers = {"X-Vault-Token": VAULT_TOKEN}
    response = requests.get(VAULT_URL, headers=headers, timeout=10)
    response.raise_for_status()
    
    # Extract credentials from Vault JSON response
    vault_data = response.json().get("data", {}).get("data", {})
    username = vault_data.get("username")
    password = vault_data.get("password")
    
    if not username or not password:
        raise KeyError("Password Vault response missing 'username' or 'password'.")
        
    return username, password


def parse_file(file_obj, filename):
    """Normalizes JSON, XML, or Excel scan data into a list of dictionaries."""
    records = []
    ext = os.path.splitext(filename)[1].lower()

    if ext == '.json':
        data = json.load(file_obj)
        records = data if isinstance(data, list) else data.get('vulnerabilities', [data])

    elif ext in ['.xlsx', '.xls']:
        df = pd.read_excel(file_obj)
        records = df.fillna("").to_dict(orient='records')

    elif ext == '.xml':
        tree = ET.parse(file_obj)
        root = tree.getroot()
        # Look for vulnerability elements or parse child tags
        for elem in root.findall('.//vulnerability') or root.iter():
            if elem.tag != root.tag:
                record = {child.tag: child.text.strip() if child.text else "" for child in elem}
                if record:
                    records.append(record)
    else:
        raise ValueError(f"Unsupported file format: {ext}")

    return records


def create_servicenow_ticket(vuln_data, sn_user, sn_pass):
    """Posts a single vulnerability record to ServiceNow Incident/Vulnerability table."""
    sn_api_url = f"https://{SN_INSTANCE}/api/now/table/incident"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "short_description": f"Vulnerability: {vuln_data.get('title', vuln_data.get('name', 'Security Scan Item'))}",
        "description": json.dumps(vuln_data, indent=2),
        "severity": str(vuln_data.get('severity', '3')),
        "assignment_group": "Security Response"
    }

    response = requests.post(
        sn_api_url,
        auth=(sn_user, sn_pass),
        headers=headers,
        json=payload,
        timeout=10
    )
    return response


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file included in request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Parse uploaded file
    try:
        records = parse_file(file.stream, file.filename)
    except Exception as e:
        return jsonify({"error": f"Failed to parse file: {str(e)}"}), 400

    # Retrieve ServiceNow Credentials from Vault once per batch request
    try:
        sn_user, sn_pass = get_servicenow_credentials()
    except Exception as e:
        return jsonify({"error": f"Vault authentication failed: {str(e)}"}), 500

    results = {"total_records": len(records), "created": 0, "failed": 0, "details": []}

    # Sequential Loop: Processing 1 record at a time
    for index, record in enumerate(records):
        try:
            res = create_servicenow_ticket(record, sn_user, sn_pass)
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
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)