import os
import re
import time
import base64
import ipaddress
import requests
from io import BytesIO
from flask import Flask, request, jsonify, send_file, render_template
from openpyxl import Workbook
from iso3166 import countries
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore, Lock
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")

# =========================
# CONFIGURATION
# =========================
IOC_MAX = 100
IOC_MAX_WORKERS = 6
VT_MAX, APIVOID_MAX, ABUSE_MAX = 8, 8, 6

vt_semaphore, apivoid_semaphore, abuse_semaphore = Semaphore(VT_MAX), Semaphore(APIVOID_MAX), Semaphore(ABUSE_MAX)
vt_lock, apivoid_lock, abuse_lock, services_lock = Lock(), Lock(), Lock(), Lock()

# =========================
# API KEYS
# =========================
VT_API_KEYS = [k.strip() for k in os.getenv("VT_API_KEYS", "").split(",") if k.strip()]
APIVOID_KEYS = [k.strip() for k in os.getenv("APIVOID_API_KEYS", "").split(",") if k.strip()]
ABUSEIPDB_KEYS = [k.strip() for k in os.getenv("ABUSEIPDB_API_KEYS", "").split(",") if k.strip()]

vt_index = apivoid_index = abuse_index = 0
exhausted_messages = ""

# =========================
# SESSION
# =========================
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
session.mount("https://", adapter)

country_cache = {}

# =========================
# VALIDATION
# =========================
def is_ip(entry):
    try: ipaddress.ip_address(entry); return True
    except ValueError: return False

def is_hash(entry): return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", entry))
def is_url(entry):
    try: parsed = urlparse(entry if entry.startswith("http") else f"http://{entry}"); return bool(parsed.hostname and "." in parsed.hostname)
    except: return False

def get_type(entry):
    return "IP" if is_ip(entry) else "HASH" if is_hash(entry) else "URL" if is_url(entry) else None

def mask_key(key): return key[:4] + "..." + key[-4:] if key else "None"
def normalize_url(url): return url if url.startswith("http") else f"http://{url}"
def get_country(code):
    if not code: return None
    if code in country_cache: return country_cache[code]
    try: country_cache[code] = countries.get(code.upper()).name; return country_cache[code]
    except: return code

# =========================
# KEY ROTATION
# =========================
def rotate_key(keys, service):
    global vt_index, apivoid_index, abuse_index
    if not keys: return None
    lock_map, index_map = {"vt": vt_lock, "apivoid": apivoid_lock, "abuse": abuse_lock}, {"vt": vt_index, "apivoid": apivoid_index, "abuse": abuse_index}
    with lock_map[service]:
        key = keys[index_map[service]]
        if service == "vt": vt_index = (vt_index + 1) % len(keys)
        if service == "apivoid": apivoid_index = (apivoid_index + 1) % len(keys)
        if service == "abuse": abuse_index = (abuse_index + 1) % len(keys)
        return key

# =========================
# VIRUSTOTAL LOOKUP
# =========================
def vt_lookup(entry):
    with vt_semaphore:
        key = rotate_key(VT_API_KEYS, "vt")
        if not key: return None
        headers = {"x-apikey": key}
        try:
            if is_hash(entry): url = f"https://www.virustotal.com/api/v3/files/{entry}"
            elif is_ip(entry): url = f"https://www.virustotal.com/api/v3/ip_addresses/{entry}"
            else:
                encoded = base64.urlsafe_b64encode(normalize_url(entry).encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
            r = session.get(url, headers=headers, timeout=15)
            if r.status_code == 429: global exhausted_messages; exhausted_messages+= f"VirusTotal API key {mask_key(key)} exhausted. "; return None
            if r.status_code != 200: print(f"VT lookup failed with status code {r.status_code}"); return None

            attr = r.json().get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            result = {"vt_detections": stats.get("malicious"), "isp": attr.get("as_owner"), "country": get_country(attr.get("country"))}

            if is_hash(entry):
                ptc = attr.get("popular_threat_classification") or {}
                labels = [c.get("value") for c in (ptc.get("popular_threat_category") or []) if isinstance(c, dict) and c.get("value")]
                result.update({"file_name": attr.get("meaningful_name"), "file_size": attr.get("size"), "file_type": attr.get("type_description"), "threat_labels": ", ".join(labels) if labels else None})

            if is_url(entry): result["associated_ip"] = attr.get("last_serving_ip_address")
            return result
        except Exception as e: print(f"Error in VT lookup: {str(e)}"); return None

# =========================
# APIVOID LOOKUP
# =========================
def apivoid_lookup(entry):
    if is_hash(entry): return None
    with apivoid_semaphore:
        key = rotate_key(APIVOID_KEYS, "apivoid")
        if not key: return None
        headers = {"X-API-Key": key, "Content-Type": "application/json"}
        try:
            endpoint, payload = ("https://api.apivoid.com/v2/ip-reputation", {"ip": entry}) if is_ip(entry) else ("https://api.apivoid.com/v2/domain-reputation", {"host": urlparse(normalize_url(entry)).hostname})
            r = session.post(endpoint, headers=headers, json=payload, timeout=15)
            if r.status_code == 429: global exhausted_messages; exhausted_messages+= f"APIVoid API key {mask_key(key)} exhausted. "; return None
            if r.status_code != 200: print(f"APIVoid lookup failed with status code {r.status_code}"); return None
            data = r.json()
            return {"detections": data.get("blacklists", {}).get("detections", -1), "riskscore": data.get("risk_score", {}).get("result"), "country": data.get("information", {}).get("country_name") or data.get("server_details", {}).get("country_name"), "isp": data.get("information", {}).get("isp") or data.get("server_details", {}).get("isp")}
        except Exception as e: print(f"Error in APIVoid lookup: {str(e)}"); return None

# =========================
# ABUSEIPDB
# =========================
def abuse_lookup(ip):
    if not is_ip(ip): return None
    with abuse_semaphore:
        key = rotate_key(ABUSEIPDB_KEYS, "abuse")
        if not key: return None
        try:
            r = session.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": key, "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15)
            if r.status_code == 429: global exhausted_messages; exhausted_messages+= f"AbuseIPDB API key {mask_key(key)} exhausted. "; return None
            if r.status_code != 200: print(f"AbuseIPDB lookup failed with status code {r.status_code}"); return None
            return r.json().get("data")
        except Exception as e: print(f"Error in AbuseIPDB lookup: {str(e)}"); return None

# =========================
# SUMMARY BUILDER
# =========================
def build_summary(entry, etype, isp, country, detections, vt, apv, abv):
    if etype == "IP":
        sentence = (
            f"The IP {entry} belongs to ISP {isp} from country {country} with {detections} malicious detections."
            if detections >= 0
            else f"The IP {entry} was not found in any database."
        )
        sentence += (
            f" ApiVoid shows risk score of {apv.get('riskscore')}."
            if apv and apv.get('riskscore', 0) > 0
            else ""
        )
        sentence += (
            f" AbuseIPDB reports an abuse confidence score of {abv.get('abuseConfidenceScore')}% with {abv.get('totalReports')} total reports."
            if abv and abv.get("abuseConfidenceScore", 0) > 10
            else ""
        )
        return sentence

    if etype == "URL":
        sentence = f"The URL {entry}"
        if country and isp:
            sentence += f" belongs to the ISP {isp} from country {country}"
        sentence += (
            f" and has {detections} malicious detections."
            if detections >= 0
            else " was not found in any database."
        )
        return sentence

    sentence = (
        f"The hash {entry} has {detections} malicious detections."
        if detections >= 0
        else f"The hash {entry} was not found in any database"
    )
    if vt:
        sentence += (
            f" It is identified as {vt.get('file_type')} with name {vt.get('file_name')} "
            f"and size {vt.get('file_size')} bytes"
        )
        if vt.get('threat_labels'):
            sentence += f" and associated with threat labels: {vt.get('threat_labels')}"
    return sentence + "."

# =========================
# ROUTES
# =========================
@app.route("/")
def index(): return render_template("index.html")
@app.route("/ping")
def ping(): return "OK"

@app.route("/get_ip_info", methods=["POST"])
def get_ip_info():
    start = time.time()
    data = request.get_json(silent=True)
    no_data_ips=[]
    if not data or "ips" not in data: return jsonify({"error": "Invalid JSON"}), 400

    entries = list(set(data.get("ips", [])))[:IOC_MAX]
    raw_table, summaries, services_used = [], [], set()

    def process(entry):
        etype = get_type(entry)
        if not etype: return None
        vt, apv, abv = vt_lookup(entry), apivoid_lookup(entry), abuse_lookup(entry)
        for s, val in [("VirusTotal", vt), ("APIVoid", apv), ("AbuseIPDB", abv)]:
            if val and s not in services_used: services_used.add(s)
        vt_det, apv_det = (vt.get("vt_detections") if vt else -1), (apv.get("detections") if apv else -1)
        detections = max(vt_det, apv_det)
        if detections < 0: no_data_ips.append(entry)
        isp = (apv.get("isp") if apv else None) or (vt.get("isp") if vt else "-")
        country = (apv.get("country") if apv else None) or (vt.get("country") if vt else "-")
        row = [entry, isp, country, vt_det, apv.get("riskscore") if apv else "-", apv_det, abv.get("abuseConfidenceScore") if abv else "-", abv.get("totalReports") if abv else "-", "-", "-", "-", "-", "-", "-"]
        return build_summary(entry, etype, isp, country, detections, vt, apv, abv), row

    with ThreadPoolExecutor(max_workers=IOC_MAX_WORKERS) as executor:
        futures = [executor.submit(process, e) for e in entries]
        for f in as_completed(futures):
            result = f.result()
            if result:
                summary, row = result
                summaries.append(summary)
                raw_table.append(row)

    return jsonify({"raw_table": raw_table, "summary": "<br><br>".join(summaries), "elapsed": round(time.time()-start,2), "services_used": list(services_used), "no_data_ips": no_data_ips, "exhausted_messages": exhausted_messages})

# @app.route("/download_excel", methods=["POST"])
# def download_excel():
#     table = request.json.get("table_data", [])
#     wb = Workbook(); ws = wb.active; ws.title="Results"
#     ws.append(["IOC","ISP","Country","Detections","APIVoid Risk","APIVoid Blacklist","Abuse Confidence","Abuse Reports","","","","","",""])
#     for row in table: ws.append(row)
#     stream = BytesIO(); wb.save(stream); stream.seek(0)
#     return send_file(stream, as_attachment=True, download_name="IOC_Report.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

@app.route("/download_excel", methods=["POST"])
def download_excel():
    data = request.get_json()
    table_data = data.get("table_data", [])
    summary_text = data.get("summary", "")
    column_label = data.get("column_label", "IP")

    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    import io
    from flask import send_file

    wb = Workbook()
    ws = wb.active
    ws.title = "Lookup Data"

    headers = [
        column_label, "ISP", "Country", "Detections",
        "APIVoid Risk Score", "APIVoid Blacklist Detections",
        "AbuseIPDB Confidence Score", "AbuseIPDB Report Count",
        "Threat Actor", "Country Of Origin", "Target Sector",
        "Threat Category", "Campaign Name", "Malware Families"
    ]
    ws.append(headers)

    for row in table_data:
        ws.append(row[:14])  # Direct append (removes redundant assignments)

    bold = Font(bold=True)
    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    border = Border(*(Side(style="thin"),) * 4)

    for r in ws.iter_rows():
        for c in r:
            c.alignment = center
            c.border = border
            if c.row == 1:
                c.font = bold

    for col in ws.columns:
        length = max(len(str(c.value)) if c.value else 0 for c in col)
        ws.column_dimensions[get_column_letter(col[0].column)].width = max(12, min(length + 4, 50))

    ws_summary = wb.create_sheet("Summary")
    ws_summary["A1"] = "Scan Summary"
    ws_summary["A1"].font = Font(size=14, bold=True)
    ws_summary["A2"] = summary_text.strip()
    ws_summary["A2"].alignment = Alignment(wrap_text=True, vertical="top")
    ws_summary.column_dimensions["A"].width = 100

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="IP_Info.xlsx"
    )

# =========================
# RUN
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
