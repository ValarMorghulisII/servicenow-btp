# Vulnerability Ingestion & ServiceNow Ticket Generator

An enterprise-ready microservice solution deployed on **SAP Business Technology Platform (SAP BTP) Cloud Foundry**. This application enables users to upload repository vulnerability scan reports in **JSON, XML, or Excel (.xlsx/.xls)** formats, dynamically validates records against customizable YAML constraints, asynchronously processes the items via Celery and Redis, retrieves ServiceNow credentials at runtime from a **Password Vault**, and sequentially creates ServiceNow tickets.

---

## 📋 Required Customization Checklist

Before deploying this codebase to your own SAP BTP space or environment, **you must update the following placeholders and configuration settings** across the repository:

### 1. Cloud Foundry Deployment Configuration (`manifest.yml`)
* **`destinations.url`**: Replace `<region>` with your SAP BTP region host (e.g., `us10`, `eu10`, `ap11`).
  * *Example:* `https://servicenow-backend.cfapps.eu10.hana.ondemand.com`
* **`docker.image`**: Replace `<your-docker-registry>` with your organization's container registry path for both `servicenow-backend` and `servicenow-worker`.
  * *Example:* `myregistry.azurecr.io/secops/servicenow-backend:latest`
* **`SN_INSTANCE`**: Set your ServiceNow instance domain.
  * *Example:* `dev12345.service-now.com` or `company.service-now.com`
* **`VAULT_URL`**: Set the API endpoint of your Password Vault.
  * *Example:* `https://vault.company.com/v1/secret/data/servicenow`
* **`VAULT_TOKEN`**: Provide a valid token or authentication secret to access the Vault path (or replace with SAP BTP Credential Store bindings).

### 2. Approuter Authentication Configuration (`xs-security.json` & `approuter/xs-app.json`)
* **`xsappname`** (`xs-security.json`): Update if you require tenant-isolated or distinct authorization scopes across environments (e.g., `servicenow-btp-prod`).

### 3. Dynamic Validation Configuration (`backend/validation_rules.yml`)
* Customize the fields, length limits, allowed severity levels, and regex patterns to match the vulnerability scan format used by your security tools.

---

## 🏗 System Architecture & Workflow   

[ User Browser ]
│
▼ (SSO Auth via XSUAA)
[ SAP BTP Approuter ]
│
▼
[ Flask Backend API ] ──(Async Upload)──► [ Redis Broker ] ◄──► [ Celery Worker ]
│                                                              │
├─► GET /rules (YAML Validation)                               ├─► GET Credentials (Password Vault)
└─► GET /status/<task_id> (Live Polling)                       └─► POST Tickets 1-by-1 (ServiceNow REST API)

1. **Authentication**: Users access the portal via SAP BTP Approuter enforced with Single Sign-On (SSO) through XSUAA and SAP IAS / Corporate IdP.
2. **Ingestion & Validation**: File uploads (JSON, XML, XLSX) are parsed and validated record-by-record against `validation_rules.yml`.
3. **Asynchronous Queuing**: Parsed records are passed to Celery via Redis to prevent HTTP timeout issues during bulk processing (e.g., 500+ records).
4. **Credential Retrieval**: The background worker calls the Password Vault API dynamically at runtime to retrieve ServiceNow credentials.
5. **Sequential Creation**: Tickets are posted sequentially to ServiceNow.
6. **Progress Tracking & Error Reporting**: The frontend polls progress live and displays a progress bar. Invalid or failed records are compiled with an explicit `_failure_reason` and can be downloaded directly as a JSON file.

---

## 📁 Repository Structure

├── approuter/
│   ├── package.json
│   └── xs-app.json               # Route definitions and SSO authentication settings
├── backend/
│   ├── app.py                    # Flask application and Celery background task logic
│   ├── Dockerfile                 # Container runtime definition for Web & Worker
│   ├── requirements.txt          # Python dependencies
│   ├── validation_rules.yml      # Configurable validation constraints
│   └── templates/
│       └── index.html            # Web UI with live progress bar and export features
├── manifest.yml                  # Cloud Foundry deployment manifest
├── xs-security.json              # XSUAA security scopes and roles
├── .cfignore                     # Cloud Foundry upload exclusions
└── .dockerignore                 # Docker build exclusions

---

## 🛠 Configuration Reference

### Dynamic Rules (`backend/validation_rules.yml`)

Modify this file to update validation logic without redeploying application code:

yaml
rules:
  title:
    mandatory: true
    min_length: 3
    max_length: 100
    aliases: ["name", "vulnerability_name", "summary"]

  severity:
    mandatory: true
    allowed_values: ["1", "2", "3", "4", "5", "Low", "Medium", "High", "Critical"]

  description:
    mandatory: false
    max_length: 2000

  cve_id:
    mandatory: false
    max_length: 20
    regex_pattern: "^CVE-\\d{4}-\\d{4,}$"
****************************************************************************************************************
Deployment Guide (SAP Cloud Foundry) --Prerequisites
Cloud Foundry CLI (cf) installed.

Docker runtime environment and access to a Container Registry.

Provisioned SAP BTP Cloud Foundry space with entitlement for Redis and XSUAA services.

Step 1: Create BTP Services
Run the following commands to provision the required backing services in your Cloud Foundry space:
