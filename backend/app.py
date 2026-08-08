import os
import json
import re
import requests
import yaml
import pandas as pd
import defusedxml.ElementTree as ET
from flask import Flask, request, jsonify, render_template
from celery import Celery

app = Flask(__name__)

# Environment Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SN_INSTANCE = os.getenv("SN_INSTANCE", "your-instance.service-now.com")
VAULT_URL = os.getenv("VAULT_URL", "https://vault.yourdomain.com/v1/secret/data/servicenow")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")

# Celery Initialization
celery_app = Celery(app.name, broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    task_track_started=True,
    result_extended=True
)


def load_validation_rules():
    """Loads validation constraints from validation_rules.yml (or validation.yml)."""
    for config_path in ["validation_rules.yml", "validation.yml"]:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return yaml.safe_load(f).get("rules", {})
    return {}


VALIDATION_RULES = load_validation_rules()


def validate_record_dynamic(record, rules):
    """Evaluates a record against dynamic YAML rules. Returns a list of error messages."""
    errors = []

    for field_name, constraints in rules.items():
        aliases = constraints.get("aliases", [])
        possible_keys = [field_name] + aliases

        val = None
        found_key = None
        for key in possible_keys:
            if key in record and record[key] not in [None, ""]:
                val = str(record[key]).strip()
                found_key = key
                break

        # Rule 1: Mandatory Check
        if constraints.get("mandatory", False) and val is None:
            field_display = f"'{field_name}'" if not aliases else f"'{field_name}' (or {aliases})"
            errors.append(f"Missing mandatory field {field_display}")
            continue

        if val is None:
            continue

        # Rule 2: Minimum Length Check
        min_len = constraints.get("min_length")
        if min_len is not None and len(val) < min_len:
            errors.append(f"Field '{found_key}' length ({len(val)}) is under minimum ({min_len})")

        # Rule 3: Maximum Length Check
        max_len = constraints.get("max_length")
        if max_len is not None and len(val) > max_len:
            errors.append(f"Field '{found_key}' length ({len(val)}) exceeds maximum ({max_len})")

        # Rule 4: Allowed Values Check
        allowed = constraints.get("allowed_values")
        if allowed:
            allowed_strs = [str(x).lower() for x in allowed]
            if val.lower() not in allowed_strs:
                errors.append(f"Field '{found_key}' value '{val}' is not in allowed list {allowed}")

        # Rule 5: Regex Pattern Check
        pattern = constraints.get("regex_pattern")
        if pattern and not re.match(pattern, val):
            errors.append(f"Field '{found_key}' value '{val}' does not match pattern '{pattern}'")

    return errors


def get_servicenow_credentials():
    """Retrieves ServiceNow credentials dynamically from Password Vault."""
    if not VAULT_TOKEN:
        raise ValueError("VAULT_TOKEN environment variable is not set.")

    headers = {"X-Vault-Token": VAULT_TOKEN}
    response = requests.get(VAULT_URL, headers=headers, timeout=10)
    response.raise_for_status()

    vault_data = response.json().get("data", {}).get("data", {})
    username = vault_data.get("username")
    password = vault_data.get("password")

    if not username or not password:
        raise KeyError("Password Vault response missing 'username' or 'password'.")

    return username, password


def parse_file(file_obj, filename):
    """Normalizes JSON, XML, or Excel scan data into a list of dictionaries."""
    ext = os.path.splitext(filename)[1].lower()

    if ext == '.json':
        data = json.load(file_obj)
        return data if isinstance(data, list) else data.get('vulnerabilities', [data])

    elif ext in ['.xlsx', '.xls']:
        df = pd.read_excel(file_obj)
        return df.fillna("").to_dict(orient='records')

    elif ext == '.xml':
        tree = ET.parse(file_obj)
        root = tree.getroot()
        records = []
        for elem in root.findall('.//vulnerability') or root.iter():
            if elem.tag != root.tag:
                rec = {child.tag: child.text.strip() if child.text else "" for child in elem}
                if rec:
                    records.append(rec)
        return records

    else:
        raise ValueError(f"Unsupported file format: {ext}")


def create_servicenow_ticket(vuln_data, sn_user, sn_pass):
    """Posts a record to the ServiceNow Incident API with all requested fields."""
    sn_api_url = f"https://{SN_INSTANCE}/api/now/table/incident"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    title = (vuln_data.get('short_description') or vuln_data.get('title') or 
             vuln_data.get('name') or vuln_data.get('summary') or 'Security Alert')
    
    base_desc = vuln_data.get('description', '')
    cvss = vuln_data.get('cvss_score', '')
    lob = vuln_data.get('lob') or vuln_data.get('line_of_business', '')
    reportee = vuln_data.get('reportee') or vuln_data.get('reporter', '')

    # Format extended fields into description body
    description_body = (
        f"{base_desc}\n\n"
        f"--- Metadata ---\n"
        f"CVSS Score: {cvss}\n"
        f"LOB: {lob}\n"
        f"Reportee: {reportee}"
    ).strip()

    payload = {
        "short_description": f"Vulnerability: {title}",
        "description": description_body,
        "severity": str(vuln_data.get('severity', '3')),
        "priority": str(vuln_data.get('priority', '3')),
        "u_cvss_score": str(cvss),
        "u_lob": str(lob),
        "u_reportee": str(reportee),
        "assignment_group": "Security Response"
    }

    return requests.post(
        sn_api_url,
        auth=(sn_user, sn_pass),
        headers=headers,
        json=payload,
        timeout=10
    )


@celery_app.task(bind=True)
def process_vulnerabilities_task(self, records):
    """Background task processing vulnerability records sequentially."""
    try:
        sn_user, sn_pass = get_servicenow_credentials()
    except Exception as e:
        return {"status": "Error", "message": f"Vault authentication failed: {str(e)}"}

    total = len(records)
    created, failed = 0, 0
    successful_tickets = []
    failed_records = []

    for index, record in enumerate(records):
        validation_errors = validate_record_dynamic(record, VALIDATION_RULES)

        if validation_errors:
            failed += 1
            bad_record = dict(record)
            bad_record["_failure_reason"] = "Validation Error: " + "; ".join(validation_errors)
            failed_records.append(bad_record)
        else:
            try:
                res = create_servicenow_ticket(record, sn_user, sn_pass)
                if res.status_code in [200, 201]:
                    ticket_number = res.json().get('result', {}).get('number')
                    created += 1
                    successful_tickets.append({"record_index": index, "ticket_number": ticket_number})
                else:
                    failed += 1
                    bad_record = dict(record)
                    bad_record["_failure_reason"] = f"ServiceNow API Error ({res.status_code}): {res.text}"
                    failed_records.append(bad_record)
            except Exception as err:
                failed += 1
                bad_record = dict(record)
                bad_record["_failure_reason"] = f"Execution Exception: {str(err)}"
                failed_records.append(bad_record)

        self.update_state(
            state='PROGRESS',
            meta={
                'current': index + 1,
                'total': total,
                'created': created,
                'failed': failed
            }
        )

    return {
        'status': 'Completed',
        'total': total,
        'created': created,
        'failed': failed,
        'successful_tickets': successful_tickets,
        'failed_records': failed_records
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/rules', methods=['GET'])
def get_rules():
    """Returns dynamic validation rules to the frontend UI."""
    return jsonify(VALIDATION_RULES)


@app.route('/create-ticket', methods=['POST'])
def create_single_ticket():
    """Handles single ticket generation from the UI form."""
    record = request.get_json() if request.is_json else request.form.to_dict()

    if not record:
        return jsonify({"error": "No payload submitted"}), 400

    # Validate against dynamic rules
    validation_errors = validate_record_dynamic(record, VALIDATION_RULES)
    if validation_errors:
        return jsonify({"error": "Validation Error", "details": validation_errors}), 400

    try:
        sn_user, sn_pass = get_servicenow_credentials()
        res = create_servicenow_ticket(record, sn_user, sn_pass)
        if res.status_code in [200, 201]:
            ticket_info = res.json().get('result', {})
            return jsonify({
                "message": "Ticket created successfully",
                "ticket_number": ticket_info.get("number"),
                "sys_id": ticket_info.get("sys_id")
            }), 201
        else:
            return jsonify({"error": f"ServiceNow API Error ({res.status_code})", "details": res.text}), 500
    except Exception as err:
        return jsonify({"error": f"Execution Exception: {str(err)}"}), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({"error": "No valid file uploaded"}), 400

    file = request.files['file']
    try:
        records = parse_file(file.stream, file.filename)
    except Exception as e:
        return jsonify({"error": f"Parse error: {str(e)}"}), 400

    task = process_vulnerabilities_task.apply_async(args=[records])
    return jsonify({"task_id": task.id, "total_records": len(records)}), 202


@app.route('/status/<task_id>')
def task_status(task_id):
    task = process_vulnerabilities_task.AsyncResult(task_id)
    if task.state == 'PENDING':
        return jsonify({"state": task.state, "status": "Task Queued"})
    elif task.state == 'PROGRESS':
        return jsonify({"state": task.state, "meta": task.info})
    elif task.state == 'SUCCESS':
        return jsonify({"state": task.state, "result": task.info})
    else:
        return jsonify({"state": task.state, "status": str(task.info)})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)