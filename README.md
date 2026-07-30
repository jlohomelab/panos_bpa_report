# PAN-OS Best Practice Assessment (BPA) Report Generator

A standalone Python utility that leverages the Palo Alto Networks Strata Cloud Manager (SCM) Posture Management API to analyze a firewall's `running-config.xml` and generate a beautifully formatted, interactive HTML Best Practice Assessment (BPA) report.

## ✨ Features

* **Zero Dependencies:** Built entirely using Python's native `http.client` and `json` libraries. No `pip install requests` or third-party packages required. Runs flawlessly out-of-the-box on macOS, Linux, and Windows.
* **Automated API Workflow:** Automatically handles the complex SCM API upload process (requesting a secure Google Cloud Storage pre-signed URL, uploading the raw XML with gzip headers, and polling the task URI for completion).
* **Pure CSS/HTML Reporting:** The generated HTML report uses 100% custom CSS for its dynamic Doughnut and Bar charts. It does not rely on external CDNs or JavaScript libraries (like Chart.js), making it highly secure and instantly loadable in offline or air-gapped environments.
* **Interactive UI:** Features collapsible configuration sections (Device, Network, Policies, Objects) and quick-toggle buttons to hide/show "Passed" and "Note" items, allowing administrators to focus strictly on failed checks.
* **Granular Remediation Data:** Intelligently parses the API's JSON response to extract exact `failed_fields`, explicitly highlighting which configuration parameters triggered a failure.
* **Offline Testing Utility:** Includes a secondary script (`test_html_report.py`) to rapidly generate and preview the HTML report from a locally saved JSON payload without needing to query the API.

## 📋 Prerequisites

1. **Python 3.6+** installed on your system.
2. A locally exported **PAN-OS XML configuration file** (e.g., `running-config.xml`). 
   * *Export via Firewall Web UI: Device > Setup > Operations > Export named configuration snapshot.*
3. **Strata Cloud Manager (SCM) API Credentials:**
   * `CLIENT_ID`
   * `CLIENT_SECRET`
   * `TSG_ID` (Tenant Service Group ID)

## 🚀 Setup & Configuration

1. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/panos-bpa-report.git](https://github.com/yourusername/pan-os-bpa-generator.git)
   cd panos-bpa-report

2. Open panos_bpa_report.py in a text editor.
Update the Configuration block at the top of the script with your API credentials:
   * `CLIENT_ID`
   * `CLIENT_SECRET`
   * `TSG_ID` (Tenant Service Group ID)


## 💻 Usage
Generate a Live Report (API Mode)
Run the main script and pass the path to your exported firewall configuration file.
python panos_bpa_report.py /path/to/running-config.xml

Example: 
```bash
python panos_bpa_report.py /path/to/running-config.xml
[*] Authenticating with Palo Alto Networks...
[*] Step 1: Requesting upload session for pa440-20260728.xml...
[*] Step 2: Uploading XML to Google Cloud Storage...
    [+] Upload successful.
[*] Step 3: Waiting for Posture Analysis to complete...
    -> Polling status... (Attempt 1/30)
    -> Polling status... (Attempt 2/30)
    -> Polling status... (Attempt 3/30)
    [+] Analysis marked as COMPLETE by backend.
[*] Step 3b: Downloading Posture Result JSON from Google Cloud Storage...
[+] Report successfully generated: /Users/username/panos_bpa_report.html
```

## 📊 Report Overview
The generated HTML report features a golden-yellow theme and includes:

* Device Information: Automatically extracted Platform, PAN-OS version, Hostname, and Management IP.
* Overall Score: Pure CSS Doughnut chart (Status Overview) and Bar chart (Failures by Severity), alongside overall pass rates and check totals.
* Category Breakdown: High-level pass/fail statistics separated by Device, Network, Policies, and Objects.
* Detailed Configuration Check: A comprehensive, categorized table of every evaluated rule. Failed rules are highlighted with red borders/backgrounds and include specific remediation * context and exact failing parameters.


## 📝 Disclaimer
This script is provided as-is for educational and administrative convenience. It is not officially supported or endorsed by Palo Alto Networks. Ensure you comply with your organization's security and API usage policies before uploading configuration files to cloud services.
