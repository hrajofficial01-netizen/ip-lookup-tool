import os
import time
import re
import requests
import base64
from io import BytesIO
from flask import Flask, request, jsonify, send_file, render_template
from openpyxl import Workbook
from iso3166 import countries
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore

app = Flask(__name__, static_folder="static", template_folder="templates")

# =========================
# CONFIGURATION
# =========================
IOC_MAX_WORKERS = 10
VT_MAX_CONCURRENT = 10
APIVOID_MAX_CONCURRENT = 10
ABUSE_MAX_CONCURRENT = 10
REQUEST_DELAY = 0.2

vt_semaphore = Semaphore(VT_MAX_CONCURRENT)
apivoid_semaphore = Semaphore(APIVOID_MAX_CONCURRENT)
abuse_semaphore = Semaphore(ABUSE_MAX_CONCURRENT)

# =========================
# ROUTES
# =========================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/ping")
def ping():
    return "OK"

# =========================
# API KEYS
# =========================
VT_API_KEYS = [k.strip() for k in os.getenv("VT_API_KEYS", "").split(",") if k.strip()]
APIVOID_KEYS = [k.strip() for k in os.getenv("APIVOID_API_KEYS", "").split(",") if k.strip()]
ABUSEIPDB_KEYS = [k.strip() for k in os.getenv("ABUSEIPDB_API_KEYS", "").split(",") if k.strip()]

vt_key_index = 0
apivoid_key_index = 0
abuse_key_index = 0

def rotate_key(keys, index_name):
    global vt_key_index, apivoid_key_index, abuse_key_index
    if not keys:
        return None
    if index_name == "vt":
        key = keys[vt_key_index]
        vt_key_index = (vt_key_index + 1) % len(keys)
    elif index_name == "apivoid":
        key = keys[apivoid_key_index]
        apivoid_key_index = (apivoid_key_index + 1) % len(keys)
    else:
        key = keys[abuse_key_index]
        abuse_key_index = (abuse_key_index + 1) % len(keys)
    return key

# =========================
# TYPE CHECKS
# =========================
def is_ip(entry):
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", entry))

def is_hash(entry):
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", entry))

def is_url(entry):
    return not is_ip(entry) and not is_hash(entry)

def get_entry_type(entry):
    if is_ip(entry):
        return "IP"
    if is_hash(entry):
        return "HASH"
    return "URL"

# =========================
# HELPERS
# =========================
country_cache = {}

def get_country_name(code):
    if not code:
        return None
    if code in country_cache:
        return country_cache[code]
    try:
        name = countries.get(code.upper()).name
        country_cache[code] = name
        return name
    except:
        return code

def safe_int(v):
    return v if isinstance(v, int) else None

# =========================
# LOOKUPS (PARALLEL + SAFE)
# =========================
def vt_lookup(entry):
    with vt_semaphore:
        time.sleep(REQUEST_DELAY)
        key = rotate_key(VT_API_KEYS, "vt")
        if not key:
            return None
        try:
            headers = {"x-apikey": key}

            if is_hash(entry):
                url = f"https://www.virustotal.com/api/v3/files/{entry}"
            elif is_ip(entry):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{entry}"
            else:
                url_id = base64.urlsafe_b64encode(entry.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code != 200:
                print(f"VirusTotal error for {entry}: {r.status_code} - {r.text}")
                return None

            attr = r.json().get("data", {}).get("attributes", {})

            result = {
                "vt_detections": safe_int(attr.get("last_analysis_stats", {}).get("malicious")),
                "isp": attr.get("as_owner"),
                "country": get_country_name(attr.get("country")),
            }

            if is_hash(entry):
                ptc = attr.get("popular_threat_classification", {})
                categories = ptc.get("popular_threat_category", [])
                threat_labels = [c.get("value") for c in categories if isinstance(c, dict)]
                result.update({
                    "file_name": attr.get("meaningful_name"),
                    "file_size": attr.get("size"),
                    "file_type": attr.get("type_description"),
                    "threat_labels": threat_labels
                })

            if is_url(entry):
                result["associated_ip"] = attr.get("last_serving_ip_address")

            return result

        except:
            print(f"VirusTotal error for {entry}: {r.status_code} - {r.text}")
            return None


def apivoid_lookup(entry):
    with apivoid_semaphore:
        time.sleep(REQUEST_DELAY)
        key = rotate_key(APIVOID_KEYS, "apivoid")
        if not key:
            return None
        try:
            headers = {"X-API-Key": key, "Content-Type": "application/json"}

            if is_ip(entry):
                endpoint = "https://api.apivoid.com/v2/ip-reputation"
                payload = {"ip": entry}
            else:
                endpoint = "https://api.apivoid.com/v2/domain-reputation"
                payload = {"host": entry}

            r = requests.post(endpoint, headers=headers, json=payload, timeout=15)
            if r.status_code != 200:
                print(f"APIVoid error for {entry}: {r.status_code} - {r.text}")
                return None

            data = r.json()

            result = {
                "detections": safe_int(data.get("blacklists", {}).get("detections")),
                "riskscore": safe_int(data.get("risk_score", {}).get("result")),
                "country": data.get("information", {}).get("country_name") if is_ip(entry)
                           else data.get("server_details", {}).get("country_name"),
                "isp": data.get("information", {}).get("isp") if is_ip(entry)
                       else data.get("server_details", {}).get("isp"),
            }

            return result

        except:
            print(f"APIVoid error for {entry}: {r.status_code} - {r.text}")
            return None


def abuseipdb_lookup(ip):
    with abuse_semaphore:
        time.sleep(REQUEST_DELAY)
        key = rotate_key(ABUSEIPDB_KEYS, "abuse")
        if not key:
            return None
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=15
            )
            if r.status_code != 200:
                print(f"AbuseIPDB error for {ip}: {r.status_code} - {r.text}")
                return None
            return r.json().get("data")
        except:
            print(f"AbuseIPDB error for {ip}: {r.status_code} - {r.text}")
            return None

# =========================
# PARALLEL SERVICE CALLS
# =========================
def parallel_services_lookup(entry):
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            "vt": executor.submit(vt_lookup, entry),
            "apv": executor.submit(apivoid_lookup, entry),
        }
        if is_ip(entry):
            futures["abv"] = executor.submit(abuseipdb_lookup, entry)
        else:
            futures["abv"] = None

        results = {}
        for name, future in futures.items():
            if future:
                results[name] = future.result()
            else:
                results[name] = None

        return results

# =========================
# MAIN ROUTE
# =========================
@app.route("/get_ip_info", methods=["POST"])
def get_ip_info():
    start = time.time()
    data = request.get_json(silent=True)
    if not data or "ips" not in data:
        return jsonify({"error": "Invalid JSON data received"}), 400

    entries = data.get("ips", [])[:100]

    raw_table = []
    ioc_summaries = []
    services_used = set()
    no_data = []

    def process(entry):
        etype = get_entry_type(entry)
        services = parallel_services_lookup(entry)

        vt = services["vt"]
        apv = services["apv"]
        abv = services["abv"]

        if vt: services_used.add("VirusTotal")
        if apv: services_used.add("APIVoid")
        if abv: services_used.add("AbuseIPDB")

        vt_det = vt.get("vt_detections") if vt else "-"
        isp = vt.get("isp") if vt else "-"
        country = vt.get("country") if vt else "-"

        apv_blacklist = apv.get("detections") if apv else "-"
        apv_riskscore = apv.get("riskscore") if apv else "-"

        if etype == "URL" and apv:
            isp = apv.get("isp") or isp
            country = apv.get("country") or country

        abuse_conf = abv.get("abuseConfidenceScore") if abv else "-"
        abuse_reports = abv.get("totalReports") if abv else "-"

        if vt_det == "-" and apv_blacklist == "-" and abuse_conf == "-":
            no_data.append(entry)

        summary_obj = {
            "entry": entry,
            "type": etype,
            "isp": isp,
            "country": country,
            "vt_detections": vt_det,
            "apivoid_blacklist": apv_blacklist,
            "apivoid_riskscore": apv_riskscore,
            "abuse_confidence": abuse_conf,
            "abuse_reports": abuse_reports,
            "file_name": vt.get("file_name") if vt else None,
            "file_size": vt.get("file_size") if vt else None,
            "file_type": vt.get("file_type") if vt else None,
            "threat_labels": vt.get("threat_labels") if vt else None,
        }

        row = [
            entry, isp, country, vt_det,
            apv_riskscore, apv_blacklist,
            abuse_conf, abuse_reports,
            "-", "-", "-", "-", "-", "-"
        ]

        return summary_obj, row

    with ThreadPoolExecutor(max_workers=IOC_MAX_WORKERS) as executor:
        futures = [executor.submit(process, e) for e in entries]
        for f in as_completed(futures):
            summary_obj, row = f.result()
            ioc_summaries.append(summary_obj)
            raw_table.append(row)

    return jsonify({
        "raw_table": raw_table,
        "summary": build_summary_for_iocs(ioc_summaries),
        "elapsed": round(time.time() - start, 2),
        "services_used": list(services_used),
        "no_data_ips": no_data,
        "exhausted_messages": []
    })

# =========================
# SUMMARY BUILDER (UNCHANGED LOGIC)
# =========================
def build_summary_for_iocs(iocs):
    lines = []
    for ioc in iocs:
        entry = ioc["entry"]
        etype = ioc["type"]
        vt_det = safe_int(ioc.get("vt_detections"))
        apv_det = safe_int(ioc.get("apivoid_blacklist"))
        detections = max([v for v in [vt_det, apv_det] if v is not None], default="-")

        if etype == "IP":
            sentence = (
                f"The IP <b>{entry}</b> belongs to ISP <b>{ioc.get('isp','Unknown')}</b> "
                f"from country  <b>{ioc.get('country','Unknown')}</b> with "
                f"<b>{detections}</b> malicious detections."
            )
            if ioc.get("apivoid_riskscore") and ioc.get("apivoid_riskscore") != "-":
                sentence += f" APIVoid shows Risk Score: <b>{ioc.get('apivoid_riskscore')}</b>. "
            if ioc.get("abuse_confidence") and ioc.get("abuse_confidence") != "-":
                sentence += f" AbuseIPDB shows Confidence of abuse score of : <b>{ioc.get('abuse_confidence')} %</b> "
            if ioc.get("abuse_reports") and ioc.get("abuse_reports") != "-":
                sentence += f" and <b>{ioc.get('abuse_reports')}</b> reports in the last 90 days."
                
        elif etype == "URL":
            sentence = f"The URL <b>{entry}</b>"
            if ioc.get("isp"):
                sentence += f" is hosted by ISP <b>{ioc.get('isp','Unknown')}</b>"
            if ioc.get("country"):
                sentence += f" from country <b>{ioc.get('country','Unknown')}</b>"    
            sentence+=f" has <b>{detections}</b> malicious detections."
            if ioc.get("apivoid_riskscore") and ioc.get("apivoid_riskscore") != "-":
                sentence += f" APIVoid shows Risk Score: <b>{ioc.get('apivoid_riskscore')}</b>. "
        else:
            sentence = f"The hash <b>{entry}</b> has <b>{detections}</b> malicious detections."
            if ioc.get("file_name") and ioc.get("file_name") != "-":
                sentence += f" Commonly known file name is <b>{ioc.get('file_name')}</b> "
            if ioc.get("file_type") and ioc.get("file_type") != "-":
                sentence += f" with file type is <b>{ioc.get('file_type')}</b>."
            if ioc.get("file_size") and ioc.get("file_size") != "-":
                sentence += f" File size is <b>{ioc.get('file_size')} bytes</b>"
            if ioc.get("threat_labels"):
                sentence += f" and it is associated with threat labels like <b>{', '.join(ioc.get('threat_labels'))}</b>"
            sentence += "."

        lines.append(sentence)

    return "<br><br>".join(lines)

# =========================
# EXCEL EXPORT
# =========================
@app.route("/download_excel", methods=["POST"])
def download_excel():
    table = request.json.get("table_data", [])
    wb = Workbook()
    ws = wb.active
    ws.title = "Results"

    ws.append([
        "IP/URL/HASH", "ISP", "Country", "VT Detections",
        "APIVoid Risk", "APIVoid Blacklist",
        "AbuseIPDB Confidence", "AbuseIPDB Reports",
        "Threat Actor", "Country Origin",
        "Target Sector", "Threat Category",
        "Campaign", "Malware"
    ])

    for row in table:
        ws.append(row)

    stream = BytesIO()
    wb.save(stream)
    stream.seek(0)

    return send_file(
        stream,
        as_attachment=True,
        download_name="IOC_Report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
