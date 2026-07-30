import http.client
import urllib.parse
import json
import os
import datetime
import webbrowser
import argparse
import sys
import time

# ==========================================
# CONFIGURATION & CREDENTIALS
# ==========================================
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
TSG_ID = "YOUR_TSG_ID"

# API Endpoints
BASE_URL = "https://api.sase.paloaltonetworks.com"
AUTH_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
INIT_UPLOAD_URL = f"{BASE_URL}/posture/checks/v1/reports/config-file-upload"

# ==========================================
# HTTP HELPER FUNCTION
# ==========================================
def make_http_request(method, url, headers=None, body=None):
    parsed_url = urllib.parse.urlparse(url)
    conn = http.client.HTTPSConnection(parsed_url.netloc)
    
    target = parsed_url.path
    if parsed_url.query:
        target += f"?{parsed_url.query}"
        
    conn.request(method, target, body=body, headers=headers or {})
    response = conn.getresponse()
    
    resp_body = response.read()
    resp_headers = {k.lower(): v for k, v in response.getheaders()}
    status = response.status
    conn.close()
    
    try:
        parsed_body = json.loads(resp_body)
    except Exception:
        parsed_body = resp_body.decode('utf-8', errors='ignore') if resp_body else None
        
    return status, resp_headers, parsed_body

# ==========================================
# API FUNCTIONS
# ==========================================
def get_access_token():
    print("[*] Authenticating with Palo Alto Networks...")
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': f'tsg_id:{TSG_ID}',
        'tsg_id': TSG_ID
    })

    status, _, data = make_http_request("POST", AUTH_URL, headers=headers, body=payload)
    if status >= 400:
        print(f"[-] Authentication failed (Status {status}): {data}")
        sys.exit(1)
    return data.get('access_token')

def analyze_config_file(token, file_path):
    auth_headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    with open(file_path, 'rb') as f_in:
        raw_xml_data = f_in.read()

    print(f"[*] Step 1: Requesting upload session for {os.path.basename(file_path)}...")
    init_url = f"{INIT_UPLOAD_URL}?tsg_id={TSG_ID}"
    init_payload = json.dumps({"file_name": os.path.basename(file_path)})
    
    status, init_headers, init_data = make_http_request("POST", init_url, headers=auth_headers, body=init_payload)
    
    if status == 429:
        print("[-] Error 429: Maximum limit of active config uploads reached.")
        print("    -> Please wait 10-15 minutes for previous jobs to timeout, then try again.")
        sys.exit(1)
    elif status >= 400:
        print(f"[-] API Error during initialization (Status {status}): {init_data}")
        sys.exit(1)

    upload_url = init_data.get('upload_url')
    task_uri = init_headers.get('location')
    
    if not upload_url:
        print("[-] Error: API did not return an upload_url.")
        sys.exit(1)

    print("[*] Step 2: Uploading XML to Google Cloud Storage...")
    gcs_headers = {"Content-Type": "text/plain", "Content-Encoding": "gzip"}
    gcs_status, _, gcs_response = make_http_request("PUT", upload_url, headers=gcs_headers, body=raw_xml_data)
    
    if gcs_status in [200, 201]:
        print("    [+] Upload successful.")
    else:
        print(f"[-] Error: Upload rejected by Google Cloud Storage (Status {gcs_status}).")
        sys.exit(1)
        
    print("[*] Step 3: Waiting for Posture Analysis to complete...")
    if task_uri.startswith("http"):
        poll_url = task_uri
    else:
        poll_url = f"{BASE_URL}{task_uri if task_uri.startswith('/') else '/' + task_uri}"
        
    if "/posture/checks/reports/" in poll_url:
        poll_url = poll_url.replace("/posture/checks/reports/", "/posture/checks/v1/reports/")
    poll_url += f"?tsg_id={TSG_ID}" if "?" not in poll_url else f"&tsg_id={TSG_ID}"
    
    max_retries = 30
    for attempt in range(max_retries):
        time.sleep(10) 
        print(f"    -> Polling status... (Attempt {attempt + 1}/{max_retries})")
        
        status, _, status_data = make_http_request("GET", poll_url, headers=auth_headers)
        if status >= 400:
            print(f"[-] API Error during polling (Status {status}): {status_data}")
            sys.exit(1)
            
        process_status = status_data.get('status', '').lower()
        
        if process_status in ['completed', 'success']:
            print("    [+] Analysis marked as COMPLETE by backend.")
            result_obj = status_data.get("result", {})
            custom_check_url = result_obj.get("custom_check_url") or status_data.get("custom_check_url")
            
            if custom_check_url:
                print("[*] Step 3b: Downloading Posture Result JSON from Google Cloud Storage...")
                dl_status, _, dl_data = make_http_request("GET", custom_check_url)
                if dl_status >= 400:
                    print(f"[-] Error downloading final report: {dl_data}")
                    sys.exit(1)
                return dl_data
            return status_data
                
        elif process_status in ['failed', 'error']:
            print("[-] Analysis failed on Palo Alto's end.")
            sys.exit(1)
            
    print("[-] Error: Timed out waiting for analysis to complete.")
    sys.exit(1)

# ==========================================
# PARSER
# ==========================================
def parse_bpa_json(api_data):
    found_rules = []
    
    device_info = {
        "platform": api_data.get('information', {}).get('platform', "Unknown"),
        "panos_version": api_data.get('information', {}).get('PanOS_version', "Unknown"),
        "device_ip_address": api_data.get('information', {}).get('device_ip_address', "Unknown"),
        "device_hostname": api_data.get('information', {}).get('device_hostname', "Unknown")
    }
    
    bp_device = api_data.get("best_practices", {}).get("device", {})
    if isinstance(bp_device, dict):
        if device_info["device_hostname"] == "Unknown":
            try:
                gen_cfg = bp_device.get("device_setup_general", [{}])[0].get("configuration", {})
                if "system" in gen_cfg:
                    device_info["device_hostname"] = gen_cfg["system"].get("hostname", "Unknown")
            except Exception: pass
            
        if device_info["device_ip_address"] == "Unknown":
            try:
                mgmt_cfg = bp_device.get("device_setup_management_interface", [{}])[0].get("configuration", {})
                device_info["device_ip_address"] = mgmt_cfg.get("ip_address", "Unknown")
            except Exception: pass

    def extract_warnings(obj, top_category, sub_category, current_location="Global", current_name="None"):
        if isinstance(obj, dict):
            if "configuration" in obj and isinstance(obj["configuration"], dict):
                cfg = obj["configuration"]
                current_location = cfg.get("location", current_location) or "Global"
                current_name = cfg.get("name", cfg.get("rule_name", current_name)) or "None"

            if "warnings" in obj and isinstance(obj["warnings"], list):
                for warning in obj["warnings"]:
                    rule_id = str(warning.get("check_id", ""))
                    check_name = warning.get("check_name", "Unknown Check")
                    check_message = warning.get("check_message", "")
                    passed = warning.get("check_passed", False)
                    check_type = warning.get("check_type", "Informational").capitalize()
                    
                    if passed:
                        verdict = "Pass"
                    elif check_type.lower() == "informational":
                        verdict = "Note"
                    else:
                        verdict = "Fail"
                    
                    failed_fields = warning.get("failed_fields")
                    ff_str = ""
                    if failed_fields and isinstance(failed_fields, dict) and not passed:
                        ff_str = ", ".join([f"{k}: {v}" for k, v in failed_fields.items()])
                        
                    found_rules.append({
                        "id": rule_id,
                        "top_category": top_category.capitalize(),
                        "sub_category": sub_category.replace('_', ' ').title(),
                        "location": current_location,
                        "name": current_name,
                        "check_name": check_name,
                        "check_message": check_message,
                        "failed_fields": ff_str,
                        "type": check_type,
                        "verdict": verdict
                    })
            
            for key, value in obj.items():
                if key not in ["warnings", "configuration", "notes", "summary_remediation", "best_practices"]:
                    extract_warnings(value, top_category, sub_category, current_location, current_name)
                else:
                    extract_warnings(value, top_category, sub_category, current_location, current_name)
                    
        elif isinstance(obj, list):
            for item in obj:
                extract_warnings(item, top_category, sub_category, current_location, current_name)

    bp_root = api_data.get("best_practices", {})
    if bp_root and isinstance(bp_root, dict):
        for top_cat, top_val in bp_root.items():
            if isinstance(top_val, dict):
                for sub_cat, sub_val in top_val.items():
                    extract_warnings(sub_val, top_cat, sub_cat)
    else:
        extract_warnings(api_data, "General", "General")
            
    return found_rules, device_info

# ==========================================
# UI HELPERS & TEMPLATE
# ==========================================
def get_type_badge(check_type):
    ct = check_type.lower()
    if "critical" in ct:
        return f'<span style="background:#f8d7da;color:#842029;border:1px solid #dc3545;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;white-space:nowrap">Critical</span>'
    elif "warning" in ct:
        return f'<span style="background:#fff3cd;color:#664d03;border:1px solid #ffc107;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;white-space:nowrap">Warning</span>'
    else:
        return f'<span style="background:#cfe2ff;color:#084298;border:1px solid #0d6efd;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;white-space:nowrap">Informational</span>'

def get_verdict_badge(verdict):
    v = verdict.lower()
    if v == "fail":
        return f'<span style="background:#f8d7da;color:#842029;border:1px solid #dc3545;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">Fail</span>'
    elif v == "pass":
        return f'<span style="background:#d1e7dd;color:#0f5132;border:1px solid #198754;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">Pass</span>'
    else:
        return f'<span style="background:#e2e3e5;color:#41464b;border:1px solid #6c757d;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">Note</span>'

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>BPA Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#f4f6f9;color:#212529}
.header{position:relative;background:linear-gradient(135deg,#ffc800 0%,#ffd84d 100%);color:black;padding:32px 40px}
.header h1{font-size:26px;font-weight:700;margin-bottom:4px;color:black;}
.header p{opacity:0.85;font-size:14px;color:black;}
.toggle-wrapper { position: absolute; right: 40px; top: 32px; display: flex; gap: 10px; }
.toggle-btn { background: #212529; color: #ffc800; border: none; padding: 10px 16px; border-radius: 6px; font-size: 13px; font-weight: 700; cursor: pointer; transition: all 0.2s; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
.toggle-btn:hover { background: #000; transform: translateY(-1px); }
.container{max-width:none;margin:0 auto;padding:32px 3vw}
.card{background:white;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,0.08);margin-bottom:24px;overflow:hidden}
.card-header{padding:16px 24px;border-bottom:1px solid #e9ecef;font-weight:700;font-size:15px;color:black;display:flex;justify-content:space-between;align-items:center}
.card-body{padding:24px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.meta-item label{font-size:11px;font-weight:700;color:#6c757d;text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px}
.meta-item span{font-size:15px;font-weight:600;color:#212529}

/* Pure CSS Custom Charts Layout */
.overall-stats-wrapper { display: flex; flex-wrap: wrap; gap: 30px; align-items: center; }
.css-charts-container { display: flex; gap: 40px; border-right: 1px solid #e9ecef; padding-right: 30px; }
.donut-wrapper { display: flex; flex-direction: column; align-items: center; gap: 10px; }
.donut-chart { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
.donut-inner { width: 85px; height: 85px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 20px; font-weight: 800; color:#198754; flex-direction: column; }
.donut-inner span { font-size: 11px; font-weight: normal; color: #6c757d; }
.bar-chart-wrapper { display: flex; flex-direction: column; align-items: center; gap: 10px; width: 180px;}
.bar-chart { display: flex; align-items: flex-end; justify-content: space-around; height: 100px; width: 100%; border-bottom: 2px solid #e9ecef; padding-bottom: 5px; margin-top:10px;}
.bar-col { display: flex; flex-direction: column; align-items: center; width: 40px; }
.bar { width: 100%; border-radius: 3px 3px 0 0; display: flex; justify-content: center; align-items: flex-start; color: white; font-size: 11px; padding-top: 4px; font-weight: bold; }
.bar-label { font-size: 11px; font-weight: 600; color: #495057; margin-top: 5px; }
.chart-title { font-size: 13px; font-weight: 700; color: black; }

.score-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(120px, 1fr));gap:16px; flex: 1;}
.score-box{text-align:center;padding:20px;border-radius:8px}
.score-box .num{font-size:36px;font-weight:800;line-height:1}
.score-box .lbl{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;margin-top:6px;opacity:0.8}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#ffc800;color:black;padding:10px 16px;text-align:left;font-size:12px;font-weight:700;letter-spacing:0.3px}
tr:hover:not(.failed-row){background:#f8f9fa}
table.bpa-section-table{table-layout:fixed;width:100%;word-wrap:break-word}
table.bpa-section-table th, table.bpa-section-table td{min-width:38px}

.failed-row { background-color: #fff5f5; border-left: 4px solid #ef4444; }
.failed-row:hover { background-color: #fee2e2 !important; }

/* Filter Toggling */
body.hide-passed .pass-row { display: none !important; }
body.hide-notes .note-row { display: none !important; }

.bpa-section-wrapper { margin-bottom: 24px; background:white; border-radius:8px; box-shadow:0 1px 4px rgba(0,0,0,0.08); overflow:hidden;}
.bpa-section-header { background: linear-gradient(135deg, #ffc800 0%, #ffd84d 100%); color: black; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
.bpa-section-title { font-weight: 700; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; color:black; }
.bpa-section-toggle { background: rgba(0,0,0,0.1); border: 1px solid rgba(0,0,0,0.3); color: black; padding: 3px 10px; border-radius: 4px; font-size: 14px; cursor: pointer; line-height: 1; }
.bpa-section--collapsed .bpa-section-table-wrap { display: none; }
.section-header { color: black; margin-top: 40px; border-bottom: 2px solid #ffc800; padding-bottom: 8px; font-size: 1.5em;}

/* Legend */
.legend-item { display:flex; align-items:center; gap:6px; font-size:11px; font-weight:600; color:#495057;}
.legend-color { width:12px; height:12px; border-radius:3px; }
</style>
</head>
<body>
<div class="header">
  <h1>Best Practice Assessment Report</h1>
  <p>Strata Cloud Manager Posture API &nbsp;|&nbsp; Generated {{ TIMESTAMP }}</p>
  <div class="toggle-wrapper">
    <button id="togglePassedBtn" class="toggle-btn">Hide Passed Items</button>
    <button id="toggleNotesBtn" class="toggle-btn">Hide Note Items</button>
  </div>
</div>
<div class="container">
  
  <div class="card">
    <div class="card-header">Device Information</div>
    <div class="card-body">
      <div class="meta-grid">
        <div class="meta-item"><label>Platform</label><span>{{ PLATFORM }}</span></div>
        <div class="meta-item"><label>PAN-OS Version</label><span>{{ PANOS_VERSION }}</span></div>
        <div class="meta-item"><label>Device IP Address</label><span>{{ DEVICE_IP }}</span></div>
        <div class="meta-item"><label>Device Hostname</label><span>{{ HOSTNAME }}</span></div>
        <div class="meta-item"><label>Analysis Time</label><span>{{ TIMESTAMP }}</span></div>
        <div class="meta-item"><label>Source File</label><span>{{ FILENAME }}</span></div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Overall Score</div>
    <div class="card-body">
      <div class="overall-stats-wrapper">
        <div class="css-charts-container">
            <div class="donut-wrapper">
                <div class="chart-title">Status Overview</div>
                <div class="donut-chart" style="background: conic-gradient(#198754 0%, #198754 {{ PASS_PCT }}%, #dc3545 {{ PASS_PCT }}%, #dc3545 {{ PASS_FAIL_PCT }}%, #e6b400 {{ PASS_FAIL_PCT }}%, #e6b400 100%);">
                    <div class="donut-inner">{{ PASS_RATE }}%<br><span>Passed</span></div>
                </div>
                <div style="display:flex; gap:12px; margin-top:5px;">
                    <div class="legend-item"><div class="legend-color" style="background:#198754"></div> Pass</div>
                    <div class="legend-item"><div class="legend-color" style="background:#dc3545"></div> Fail</div>
                    <div class="legend-item"><div class="legend-color" style="background:#e6b400"></div> Note</div>
                </div>
            </div>
            <div class="bar-chart-wrapper">
                <div class="chart-title">Issues by Check Type</div>
                <div class="bar-chart">
                    <div class="bar-col"><div class="bar" style="height: {{ CRITICAL_H }}%; background: #dc3545;">{{ CRITICAL_VAL }}</div><div class="bar-label">Critical</div></div>
                    <div class="bar-col"><div class="bar" style="height: {{ WARNING_H }}%; background: #f59e0b;">{{ WARNING_VAL }}</div><div class="bar-label">Warning</div></div>
                    <div class="bar-col"><div class="bar" style="height: {{ INFO_H }}%; background: #3b82f6;">{{ INFO_VAL }}</div><div class="bar-label">Info</div></div>
                </div>
            </div>
        </div>
        
        <div class="score-grid">
          <div class="score-box" style="background:#fffbeb;color:#e6b400"><div class="num">{{ PASS_RATE }}%</div><div class="lbl">Pass Rate</div></div>
          <div class="score-box" style="background:#f0f7f0;color:#198754"><div class="num">{{ TOTAL_PASS }}</div><div class="lbl">Checks Passed</div></div>
          <div class="score-box" style="background:#fdf0f0;color:#dc3545"><div class="num">{{ TOTAL_FAIL }}</div><div class="lbl">Checks Failed</div></div>
          <div class="score-box" style="background:#fefbf0;color:#856404"><div class="num">{{ TOTAL_NOTE }}</div><div class="lbl">Notes</div></div>
          <div class="score-box" style="background:#f4f6f9;color:#495057"><div class="num">{{ TOTAL_CHECKS }}</div><div class="lbl">Total Checks</div></div>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Results by Category</div>
    <table>
      <tr><th style="color:black">Category</th><th style="text-align:center; color:black">Total</th><th style="text-align:center; color:black">Passed</th><th style="text-align:center; color:black">Failed</th><th style="color:black">Pass Rate</th></tr>
      {{ CATEGORY_ROWS }}
    </table>
  </div>

  <div class="card-header" style="background:transparent; padding: 0 0 16px 0; border:none;">
    <h2 style="color:black; font-size:20px;">Detailed Configuration Check</h2>
  </div>

  {{ SECTIONS }}

</div>
<script>
    // Collapsible Sections
    document.querySelectorAll('.bpa-section-header').forEach(header => {
        header.addEventListener('click', () => {
            const wrapper = header.parentElement;
            wrapper.classList.toggle('bpa-section--collapsed');
            const btn = header.querySelector('.bpa-section-toggle');
            btn.innerHTML = wrapper.classList.contains('bpa-section--collapsed') ? '&#9660;' : '&#9650;';
        });
    });

    // Toggle Passed
    const togglePassedBtn = document.getElementById('togglePassedBtn');
    if (togglePassedBtn) {
        togglePassedBtn.addEventListener('click', () => {
            document.body.classList.toggle('hide-passed');
            togglePassedBtn.innerText = document.body.classList.contains('hide-passed') ? 'Show Passed Items' : 'Hide Passed Items';
        });
    }

    // Toggle Notes
    const toggleNotesBtn = document.getElementById('toggleNotesBtn');
    if (toggleNotesBtn) {
        toggleNotesBtn.addEventListener('click', () => {
            document.body.classList.toggle('hide-notes');
            toggleNotesBtn.innerText = document.body.classList.contains('hide-notes') ? 'Show Note Items' : 'Hide Note Items';
        });
    }
</script>
</body>
</html>
"""

def generate_report(rules_list, device_info, filename_analyzed, output_filename="panos_bpa_report.html"):
    metrics = {
        "Total": 0, "Pass": 0, "Fail": 0, "Note": 0,
        "types": {"Critical": 0, "Warning": 0, "Informational": 0},
        "cats": {}
    }
    
    grouped_rules = {}
    for rule in rules_list:
        tc = rule['top_category']
        verdict = rule['verdict']
        check_type = rule.get("type", "Informational")
        
        if tc not in grouped_rules:
            grouped_rules[tc] = []
            metrics["cats"][tc] = {"Total": 0, "Pass": 0, "Fail": 0, "Note": 0}
            
        grouped_rules[tc].append(rule)
        
        metrics["Total"] += 1
        metrics[verdict] += 1
        metrics["cats"][tc]["Total"] += 1
        metrics["cats"][tc][verdict] += 1
        
        # Only count in the Type bar chart if the check did NOT pass
        if verdict in ["Fail", "Note"] and check_type in metrics["types"]:
            metrics["types"][check_type] += 1

    pass_rate_overall = round((metrics["Pass"] / metrics["Total"]) * 100, 1) if metrics["Total"] > 0 else 0
    
    # CSS Donut Chart Data Calculation
    pass_pct = round((metrics["Pass"] / metrics["Total"]) * 100, 1) if metrics["Total"] > 0 else 0
    fail_pct = round((metrics["Fail"] / metrics["Total"]) * 100, 1) if metrics["Total"] > 0 else 0
    pass_fail_pct = min(100.0, pass_pct + fail_pct)

    # CSS Bar Chart Data Calculation
    crit_val = metrics["types"]["Critical"]
    warn_val = metrics["types"]["Warning"]
    info_val = metrics["types"]["Informational"]
    max_type = max(crit_val, warn_val, info_val)
    crit_h = max(15, (crit_val / max_type * 100)) if max_type > 0 and crit_val > 0 else 0
    warn_h = max(15, (warn_val / max_type * 100)) if max_type > 0 and warn_val > 0 else 0
    info_h = max(15, (info_val / max_type * 100)) if max_type > 0 and info_val > 0 else 0

    cat_rows_html = ""
    for tc, m in metrics["cats"].items():
        rate = round((m["Pass"] / m["Total"]) * 100, 1) if m["Total"] > 0 else 0
        cat_rows_html += f"""
        <tr>
            <td style="padding:12px 16px;border-bottom:1px solid #e9ecef;font-weight:600">{tc}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e9ecef;text-align:center">{m['Total']}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e9ecef;text-align:center;color:#198754;font-weight:600">{m['Pass']}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e9ecef;text-align:center;color:#dc3545;font-weight:600">{m['Fail']}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e9ecef;min-width:160px"><div style="display:flex;align-items:center;gap:8px"><div style="flex:1"><div style="background:#e9ecef;border-radius:4px;height:8px;width:100%"><div style="background:{'#198754' if rate >= 75 else '#dc3545'};width:{rate}%;height:8px;border-radius:4px"></div></div></div><span style="color:{'#198754' if rate >= 75 else '#dc3545'};font-weight:700;font-size:13px">{rate}%</span></div></td>
        </tr>
        """

    sections_html = ""
    for tc, rules in grouped_rules.items():
        sections_html += f"""
        <div class="bpa-section-wrapper">
            <div class="bpa-section-header">
                <span class="bpa-section-title">{tc} Configuration ({len(rules)} items)</span>
                <button class="bpa-section-toggle" type="button">&#9650;</button>
            </div>
            <div class="bpa-section-table-wrap" style="overflow-x:auto">
                <table class="bpa-section-table">
                    <thead>
                        <tr>
                            <th style="width:75px">ID</th>
                            <th style="width:140px">Sub Section</th>
                            <th style="width:120px">Location</th>
                            <th style="width:200px">Object/Rule Name</th>
                            <th>Check Description & Remediation</th>
                            <th style="width:100px;text-align:center">Check Type</th>
                            <th style="width:80px;text-align:center">Verdict</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for rule in rules:
            row_classes = f"{rule['verdict'].lower()}-row"
            if rule['verdict'] == "Fail":
                row_classes += " failed-row"

            desc_html = f'<div style="font-size:13px; font-weight:600; color:black; margin-bottom:4px;">{rule["check_name"]}</div>'
            desc_html += f'<div style="font-size:12px; color:#495057;">{rule["check_message"]}</div>'
            if rule["failed_fields"]:
                desc_html += f'<div style="margin-top:6px;font-size:11px;"><b>Failed Fields:</b> <span style="background:#fee2e2; color:#dc3545; padding:2px 6px; border-radius:4px; font-family:monospace;">{rule["failed_fields"]}</span></div>'

            sections_html += f"""
            <tr class="{row_classes}">
                <td style="padding:8px 12px;border-bottom:1px solid #e9ecef;font-size:12px;vertical-align:top;color:#6c757d">#{rule['id']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e9ecef;font-size:12px;vertical-align:top;font-weight:600;">{rule['sub_category']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e9ecef;font-size:12px;vertical-align:top">{rule['location']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e9ecef;font-size:12px;vertical-align:top;word-wrap:break-word;">{rule['name']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e9ecef;vertical-align:top">{desc_html}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e9ecef;vertical-align:top;text-align:center">{get_type_badge(rule['type'])}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #e9ecef;vertical-align:top;text-align:center">{get_verdict_badge(rule['verdict'])}</td>
            </tr>
            """
        sections_html += "</tbody></table></div></div>"

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = HTML_TEMPLATE.replace("{{ TIMESTAMP }}", timestamp)
    html_content = html_content.replace("{{ FILENAME }}", os.path.basename(filename_analyzed))
    html_content = html_content.replace("{{ PLATFORM }}", device_info["platform"])
    html_content = html_content.replace("{{ PANOS_VERSION }}", device_info["panos_version"])
    html_content = html_content.replace("{{ DEVICE_IP }}", device_info["device_ip_address"])
    html_content = html_content.replace("{{ HOSTNAME }}", device_info["device_hostname"])
    
    html_content = html_content.replace("{{ TOTAL_CHECKS }}", str(metrics["Total"]))
    html_content = html_content.replace("{{ TOTAL_PASS }}", str(metrics["Pass"]))
    html_content = html_content.replace("{{ TOTAL_FAIL }}", str(metrics["Fail"]))
    html_content = html_content.replace("{{ TOTAL_NOTE }}", str(metrics["Note"]))
    html_content = html_content.replace("{{ PASS_RATE }}", str(pass_rate_overall))
    
    html_content = html_content.replace("{{ PASS_PCT }}", str(pass_pct))
    html_content = html_content.replace("{{ PASS_FAIL_PCT }}", str(pass_fail_pct))
    
    html_content = html_content.replace("{{ CRITICAL_VAL }}", str(crit_val) if crit_val > 0 else "")
    html_content = html_content.replace("{{ WARNING_VAL }}", str(warn_val) if warn_val > 0 else "")
    html_content = html_content.replace("{{ INFO_VAL }}", str(info_val) if info_val > 0 else "")
    html_content = html_content.replace("{{ CRITICAL_H }}", str(crit_h))
    html_content = html_content.replace("{{ WARNING_H }}", str(warn_h))
    html_content = html_content.replace("{{ INFO_H }}", str(info_h))
    
    html_content = html_content.replace("{{ CATEGORY_ROWS }}", cat_rows_html)
    html_content = html_content.replace("{{ SECTIONS }}", sections_html)
    
    file_path = os.path.abspath(output_filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"[+] Report successfully generated: {file_path}")
    webbrowser.open(f"file://{file_path}")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate PAN-OS Posture HTML Report natively")
    parser.add_argument("config_file", help="Path to the PAN-OS XML configuration file")
    args = parser.parse_args()

    if not os.path.exists(args.config_file):
        print(f"[-] Error: File '{args.config_file}' not found.")
        sys.exit(1)

    try:
        token = get_access_token()
        raw_api_data = analyze_config_file(token, args.config_file)
        
        valid_rules, device_data = parse_bpa_json(raw_api_data)
        if len(valid_rules) > 0:
            generate_report(valid_rules, device_data, args.config_file)
        else:
            print("[-] No rules parsed.")
            
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")