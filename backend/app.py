import os
import json
import requests
import pandas as pd
import xmltodict
from flask import Flask, render_template, request, jsonify
from cfenv import AppEnv

app = Flask(__name__)
env = AppEnv()

# Detect environment (Defaults to True for local testing)
IS_LOCAL = os.getenv("LOCAL_DEV", "true").lower() == "true"

# Parse SAP BTP Bound Services (when deployed on Cloud Foundry)
xsuaa_service = env.get_service(name="xsuaa-ticket-portal")
xsuaa_credentials = xsuaa_service.credentials if xsuaa_service else {}

credstore_service = env.get_service(name="credstore-ticket-portal")
credstore_credentials = credstore_service.credentials if credstore_service else {}

# Configuration Variables
SN_INSTANCE_URL = os.getenv("SN_INSTANCE_URL", "https://devinstance.service-now.com")
SN_USER = os.getenv("SN_USER", "admin")
SN_PASSWORD = os.getenv("SN_PASSWORD", "your_password_here")
SN_CREDENTIAL_KEY = os.getenv("SN_CREDENTIAL_KEY", "servicenow_api_account")


def check_jwt_authorization(req):
    """Validates SAP BTP SSO JWT token on BTP; automatically bypassed during local development."""
    if IS_LOCAL:
        return True, None

    auth_header = req.headers.get("Authorization", None)
    if not auth_header or not auth_header.startswith("Bearer "):
        return False, "Missing or invalid authorization header."

    access_token = auth_header.split(" ")[1]
    try:
        from sap import xssec
        security_context = xssec.create_security_context(access_token, xsuaa_credentials)
        if not security_context.check_scope("$XSAPPNAME.TicketAdmin"):
            return False, "Forbidden: Insufficient privileges."
        return True, None
    except Exception as e:
        return False, f"Token validation failed: {str(e)}"


def get_servicenow_password():
    """Retrieves ServiceNow API password from SAP Password Vault on Cloud Foundry, or environment variable locally."""
    if IS_LOCAL or not credstore_credentials:
        return SN_PASSWORD

    try:
        url = f"{credstore_credentials.get('url')}/password?name={SN_CREDENTIAL_KEY}"
        response = requests.get(
            url,
            auth=(credstore_credentials.get("username"), credstore_credentials.get("password")),
            headers={"headers": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json().get("value")
        raise RuntimeError(f"Vault error: HTTP {response.status_code}")
    except Exception as e:
        raise RuntimeError(f"Failed to fetch credentials from Password Vault: {str(e)}")


def parse_uploaded_file(file):
    """Parses uploaded JSON, Excel (.xlsx/.xls), or XML files into a list of dictionaries."""
    filename = file.filename.lower()

    if filename.endswith(".json"):
        content = json.load(file)
        return content if isinstance(content, list) else [content]

    elif filename.endswith((".xlsx", ".xls")):
        df = pd.read_excel(file)
        # Convert NaN values to None for clean JSON serialization
        return df.where(pd.notnull(df), None).to_dict(orient="records")

    elif filename.endswith(".xml"):
        parsed = xmltodict.parse(file.read())
        root = list(parsed.values())[0]
        # Expecting structure like <tickets><ticket>...</ticket></tickets> or <items><item>...</item></items>
        tickets = root.get("ticket", root.get("item", []))
        return tickets if isinstance(tickets, list) else [tickets]

    else:
        raise ValueError("Unsupported file format. Please upload a .json, .xlsx, .xls, or .xml file.")


def validate_tickets(tickets):
    """Validates input payload to ensure mandatory fields are present."""
    errors = []
    if not isinstance(tickets, list) or len(tickets) == 0:
        return False, ["Payload must contain at least one valid record."]

    for idx, ticket in enumerate(tickets, start=1):
        if not isinstance(ticket, dict):
            errors.append(f"Row {idx}: Record is not a valid key-value object.")
            continue
        if not str(ticket.get("short_description", "")).strip():
            errors.append(f"Row {idx}: Missing mandatory 'short_description' field.")

    return len(errors) == 0, errors


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tickets", methods=["POST"])
def process_tickets():
    # 1. Check Authorization (SSO JWT in BTP, Bypassed Locally)
    is_authorized, auth_error = check_jwt_authorization(request)
    if not is_authorized:
        return jsonify({"success": False, "errors": [auth_error]}), 401

    # 2. Retrieve Credentials (Vault in BTP, ENV Locally)
    try:
        sn_password = get_servicenow_password()
    except Exception as err:
        return jsonify({"success": False, "errors": [str(err)]}), 500

    # 3. Parse Request Payload
    mode = request.form.get("mode")
    tickets = []

    if mode == "single":
        tickets.append({
            "short_description": request.form.get("short_description"),
            "description": request.form.get("description", ""),
            "urgency": request.form.get("urgency", "3"),
            "impact": request.form.get("impact", "3"),
            "category": request.form.get("category", "inquiry")
        })

    elif mode == "bulk":
        if "file" not in request.files or not request.files["file"].filename:
            return jsonify({"success": False, "errors": ["No file uploaded."]}), 400
        try:
            tickets = parse_uploaded_file(request.files["file"])
        except Exception as e:
            return jsonify({"success": False, "errors": [str(e)]}), 400

    else:
        return jsonify({"success": False, "errors": ["Invalid submission mode."]}), 400

    # 4. Input Schema Validation
    is_valid, validation_errors = validate_tickets(tickets)
    if not is_valid:
        return jsonify({"success": False, "errors": validation_errors}), 422

    # 5. Automated Sequential API Execution to ServiceNow
    sn_api_url = f"{SN_INSTANCE_URL.rstrip('/')}/api/now/table/incident"
    results = []

    for idx, ticket in enumerate(tickets, start=1):
        try:
            res = requests.post(
                sn_api_url,
                auth=(SN_USER, sn_password),
                json=ticket,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=15
            )
            if res.status_code == 201:
                data = res.json().get("result", {})
                results.append({
                    "row": idx,
                    "short_description": ticket.get("short_description"),
                    "status": "SUCCESS",
                    "ticket_number": data.get("number"),
                    "sys_id": data.get("sys_id")
                })
            else:
                results.append({
                    "row": idx,
                    "short_description": ticket.get("short_description"),
                    "status": "FAILED",
                    "error": f"HTTP {res.status_code}: {res.text}"
                })
        except Exception as ex:
            results.append({
                "row": idx,
                "short_description": ticket.get("short_description"),
                "status": "FAILED",
                "error": str(ex)
            })

    return jsonify({
        "success": True,
        "total": len(tickets),
        "results": results
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)