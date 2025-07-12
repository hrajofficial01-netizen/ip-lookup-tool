from flask import Flask, request, jsonify, send_file, render_template
import os
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Side, Font
from iso3166 import countries
import ipaddress
import tempfile
import socket
from urllib.parse import urlparse
import time
import io
import io
from flask import Flask, request, jsonify, send_file, render_template
from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter

load_dotenv()

app = Flask(__name__)

VT_KEYS = [key.strip() for key in os.getenv("VT_API_KEYS", "").split(",") if key.strip()]
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
DBIP_KEY = os.getenv("DBIP_API_KEY")
IPINFO_KEY = os.getenv("IPINFO_API_KEY")
APIVOID_KEY = os.getenv("APIVOID_API_KEY")

vt_key_index = 0
vt_key_lock = threading.Lock()
exhausted_vt_keys = set()
exhausted_other_keys = set()
vt_keys_used = set()
vt_keys_success = set()

MAX_WORKERS = 100
used_services = set()
unused_services = set()
country_cache = {}

def get_country_name(code):
    if not code:
        return "Unknown"
    if code in country_cache:
        return country_cache[code]
    try:
        name = countries.get(code.upper()).name
        country_cache[code] = name
        return name
    except:
        return code

def mask_key(key):
    return key[:4] + "..." + key[-4:] if key else "None"

def get_next_vt_key():
    global vt_key_index
    with vt_key_lock:
        for _ in range(len(VT_KEYS)):
            key = VT_KEYS[vt_key_index % len(VT_KEYS)]
            vt_key_index += 1
            if key and key not in exhausted_vt_keys:
                return key
        return None

def fetch_virustotal_url_data(url):
    result = {"detections": None, "services_used": []}
    key = get_next_vt_key()
    if not key:
        return result
    headers = {"x-apikey": key}
    try:
        scan_url = "https://www.virustotal.com/api/v3/urls"
        resp = requests.post(scan_url, headers=headers, data={"url": url})
        if resp.status_code != 200:
            exhausted_vt_keys.add(key)
            return result
        scan_id = resp.json()['data']['id']
        report_url = f"https://www.virustotal.com/api/v3/urls/{scan_id}"
        resp = requests.get(report_url, headers=headers)
        if resp.status_code != 200:
            exhausted_vt_keys.add(key)
            return result
        data = resp.json().get('data', {}).get('attributes', {})
        detections = data.get('last_analysis_stats', {}).get('malicious', 0)
        result['detections'] = detections
        result['services_used'].append("VirusTotal URL")
    except Exception as e:
        print(f"[ERROR] VT URL scan failed: {e}")
    return result

def query_virustotal(ip):
    used_services.add("VT")
    tried = set()
    while True:
        key = get_next_vt_key()
        if not key or key in tried:
            break
        tried.add(key)
        headers = {"x-apikey": key}
        vt_keys_used.add(key)
        try:
            resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
            if resp.status_code == 401:
                exhausted_vt_keys.add(key)
                continue
            elif resp.status_code != 200:
                return {}, "VTError", key
            data = resp.json()
            vt_keys_success.add(key)
            attr = data.get("data", {}).get("attributes", {})
            return {
                "isp": attr.get("as_owner"),
                "country": get_country_name(attr.get("country")),
                "detections": attr.get("last_analysis_stats", {}).get("malicious", 0)
            }, "VT", key
        except Exception as e:
            return {}, f"VT ERROR: {str(e)}", key
    return {}, "NoVTKeyAvailable", None

def query_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return {}, "NoKey"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    try:
        resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers=headers, timeout=10)
        if resp.status_code == 429:
            exhausted_other_keys.add("AbuseIPDB")
            return {}, "RateLimit"
        data = resp.json().get("data", {})
        used_services.add("AbuseIPDB")
        return {
            "isp": data.get("isp"),
            "country": get_country_name(data.get("countryCode")),
            "detections": data.get("totalReports", 0)
        }, "AbuseIPDB"
    except Exception as e:
        return {}, f"ABUSEIPDB ERROR: {str(e)}"

def query_dbip(ip):
    if not DBIP_KEY:
        return {}, "NoKey"
    try:
        resp = requests.get(f"https://api.db-ip.com/v2/{DBIP_KEY}/{ip}/json", timeout=10)
        if resp.status_code != 200:
            return {}, "DBIP Error"
        data = resp.json()
        used_services.add("DBIP")
        return {
            "isp": data.get("organization"),
            "country": get_country_name(data.get("countryCode")),
            "detections": 0
        }, "DBIP"
    except Exception as e:
        return {}, f"DBIP ERROR: {str(e)}"

def query_ipinfo(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"Authorization": f"Bearer {IPINFO_KEY}"} if IPINFO_KEY else {}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return {}, "IPINFO Error"
        data = resp.json()
        used_services.add("IPINFO")
        return {
            "isp": data.get("org"),
            "country": get_country_name(data.get("country")),
            "detections": 0
        }, "IPINFO"
    except Exception as e:
        return {}, f"IPINFO ERROR: {str(e)}"

def query_apivoid(ip):
    if not APIVOID_KEY:
        return {}, "NoKey"
    try:
        resp = requests.get(f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={APIVOID_KEY}&ip={ip}", timeout=10)
        if resp.status_code == 429:
            exhausted_other_keys.add("APIVoid")
            return {}, "RateLimit"
        if resp.status_code != 200:
            return {}, "APIVoid Error"
        data = resp.json().get("data", {}).get("report", {})
        used_services.add("APIVoid")
        return {
            "isp": data.get("network", {}).get("organization"),
            "country": get_country_name(data.get("information", {}).get("country_code")),
            "detections": data.get("blacklists", {}).get("detections", 0)
        }, "APIVoid"
    except Exception as e:
        return {}, f"APIVOID ERROR: {str(e)}"

def resolve_url_to_ip(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        hostname = urlparse(url).hostname
        if hostname:
            resolved_ip = socket.gethostbyname(hostname)
            return hostname, resolved_ip
    except Exception as e:
        print(f"[ERROR] Could not resolve {url} - {e}")
    return None, None

def is_valid_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_unspecified)
    except:
        return False

def is_valid_url(url):
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return bool(parsed.hostname)
    except:
        return False

def get_ip_info(ip):
    final = {}
    sources = {"isp": "None", "country": "None", "detections": "None"}
    vt_key = None

    vt_result, vt_source, vt_key_used = query_virustotal(ip)
    if vt_result:
        final.update(vt_result)
        vt_key = vt_key_used
        sources.update({k: vt_source for k in vt_result})
    else:
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(func, ip): name for func, name in [
                    (query_abuseipdb, "AbuseIPDB"),
                    (query_dbip, "DBIP"),
                    (query_ipinfo, "IPINFO")
                ]
            }
            for f in as_completed(futures):
                data, src = f.result()
                if data:
                    for k in ["isp", "country", "detections"]:
                        if not final.get(k):
                            final[k] = data.get(k)
                            sources[k] = src
                    break

    for k in ["isp", "country", "detections"]:
        if not final.get(k):
            data, src = query_apivoid(ip)
            if data and data.get(k):
                final[k] = data.get(k)
                sources[k] = src

    print(f"[{ip}] Final Sources - ISP: {sources['isp']}, Country: {sources['country']}, Detections: {sources['detections']}")
    return {
        "ip": ip,
        "isp": final.get("isp", "N/A"),
        "country": final.get("country", "N/A"),
        "detections": final.get("detections", 0),
        "vt_key_used": mask_key(vt_key) if vt_key else None,
        "summary": f"The IP: {ip} belongs to the ISP: {final.get('isp', 'N/A')} from the country: {final.get('country', 'N/A')} with detection count: {final.get('detections', 0)}."
    }

def lookup_url(url):
    hostname, resolved_ip = resolve_url_to_ip(url)
    if not resolved_ip:
        return {
            "type": "URL",
            "query": url,
            "error": "Could not resolve domain to IP.",
            "ip": url,
            "isp": "N/A",
            "country": "N/A",
            "detections": 0,
            "vt_key_used": None,
            "summary": f"The URL: {url} could not be resolved to an IP address.",
        }

    vt_data = fetch_virustotal_url_data(url)
    ip_info = get_ip_info(resolved_ip)

    # ✅ Ensure detection count is 0 if None or missing
    detections = vt_data.get("detections") or 0

    return {
        "type": "URL",
        "query": url,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "ip": url,
        "isp": ip_info.get("isp"),
        "country": ip_info.get("country"),
        "detections": detections,
        "vt_key_used": ip_info.get("vt_key_used"),
        "summary": f"The URL:  {url}  resolves to IP:  {resolved_ip}  and has  {detections}  detections belonging to ISP:  {ip_info.get('isp')}  with Country:  {ip_info.get('country')} ."
    }


# ✅ `handle_ip_lookup()` and `/download_excel` + `/` route are included in [next message] due to length...
@app.route("/get_ip_info", methods=["POST"])
def handle_ip_lookup():
    start = time.time()
    data = request.json
    entries = data.get("ips", [])

    global used_services, unused_services, vt_keys_used, vt_keys_success
    used_services.clear()
    unused_services.clear()
    vt_keys_used.clear()
    vt_keys_success.clear()
    exhausted_other_keys.clear()

    seen = set()
    valid_entries = []
    skipped_invalid = []

    for entry in entries:
        entry = entry.strip()
        if entry in seen:
            continue
        seen.add(entry)

        if is_valid_public_ip(entry) or is_valid_url(entry):
            valid_entries.append(entry)
        else:
            skipped_invalid.append(entry)

        if len(valid_entries) >= 100:
            break

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(
            lambda e: get_ip_info(e) if is_valid_public_ip(e) else lookup_url(e),
            valid_entries
        ))

    has_url = any(r.get("type") == "URL" for r in results)

    no_data_ips = [r["ip"] for r in results if (
        (not r.get("isp") or r.get("isp") == "N/A") and
        (not r.get("country") or r.get("country") == "N/A")
    )]

    table_rows = ""
    raw_table = []

    for r in results:
        ip_or_url = r.get("query", r["ip"])
        resolved_ip = r.get("resolved_ip") if r.get("type") == "URL" else "-"
        row_html = f"<tr><td>{ip_or_url}</td><td>{resolved_ip}</td><td>{r['isp']}</td><td>{r['country']}</td><td>{r['detections']}</td></tr>"
        table_rows += row_html
        raw_table.append([ip_or_url, resolved_ip, r["isp"], r["country"], r["detections"], r.get("vt_key_used")])

    summary_lines = []
    for i, r in enumerate(results):
        if i != 0:
            summary_lines.append("")
        summary_lines.append(r["summary"])
    summary_text = "\n".join(summary_lines)

    elapsed = round(time.time() - start, 2)
    unused_services.update({"VT", "AbuseIPDB", "DBIP", "IPINFO", "APIVoid"} - used_services)

    vt_keys_success_current = vt_keys_used & vt_keys_success
    vt_keys_exhausted_current = exhausted_vt_keys.copy()

    print("\n📊 API USAGE SUMMARY")
    print(f"✅ Data found for {len(valid_entries)} entries in {elapsed} seconds.")
    print(f"🔧 Services Used     : {', '.join(sorted(used_services)) or 'None'}")
    print(f"⚪ Services Unused   : {', '.join(sorted(unused_services)) or 'None'}")

    print(f"✅ Successfully Used VT Keys: {len(vt_keys_success_current)}")
    for key in vt_keys_success_current:
        print(f"    {mask_key(key)}")

    print(f"❌ Exhausted VT Keys: {len(vt_keys_exhausted_current)}")
    for key in vt_keys_exhausted_current:
        print(f"    {mask_key(key)}")

    if exhausted_other_keys:
        print("❌ Exhausted Other Services:", ", ".join(exhausted_other_keys))

    if len(vt_keys_exhausted_current) > 10:
        print("⚠️ Warning: More than 10 VT keys are exhausted. Consider rotating or refreshing your keys.")

    vt_keys_unused_current = set(VT_KEYS) - (vt_keys_success | exhausted_vt_keys)
    print(f"🟡 Unused VT Keys: {len(vt_keys_unused_current)}")
    for key in vt_keys_unused_current:
        print(f"    {mask_key(key)}")

    print("Used API Keys:")
    if vt_keys_success_current:
        print("  VT Keys:", ", ".join(mask_key(k) for k in vt_keys_success_current))
    if "AbuseIPDB" in used_services:
        print("  AbuseIPDB Key:", mask_key(ABUSEIPDB_KEY))
    if "DBIP" in used_services:
        print("  DBIP Key:", mask_key(DBIP_KEY))
    if "IPINFO" in used_services:
        print("  IPInfo Key:", mask_key(IPINFO_KEY))
    if "APIVoid" in used_services:
        print("  APIVoid Key:", mask_key(APIVOID_KEY))
    print("----------------------------\n")

    column_label = "IP/URL" if has_url else "IP"

    return jsonify({
        "summary": summary_text,
        "table": table_rows,
        "raw_table": raw_table,
        "no_data_ips": no_data_ips,
        "per_ip_vt_keys": {r["ip"]: r.get("vt_key_used") for r in results},
        "has_url": has_url,
        "column_label": column_label
    })

from flask import request, send_file
from io import BytesIO
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side

@app.route("/download_excel", methods=["POST"])
def download_excel():
    import io
    from flask import send_file
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    data = request.get_json()
    table_data = data.get("table_data", [])
    summary = data.get("summary", "")
    column_label = data.get("column_label", "IP")

    print("Incoming /download_excel payload:")
    print("Summary:", summary)
    print("Column label:", column_label)
    if table_data:
        print("First row of table_data:", table_data[0])

    wb = Workbook()

    # ====== IP Data Sheet ======
    ws_data = wb.active
    ws_data.title = "IP Data"

    # Determine if resolved IP column is needed
    has_resolved_ip = any(len(row) > 5 and row[1] != "-" for row in table_data)

    # Define headers
    if has_resolved_ip:
        headers = [column_label, "Resolved IP", "ISP", "Country", "Detection Count"]
    else:
        headers = [column_label, "ISP", "Country", "Detection Count"]

    # Add header row
    ws_data.append(headers)

    # Set style for headers
    for cell in ws_data[1]:
        cell.font = Font(bold=True)
        cell.alignment = Alignment(horizontal="center", vertical="center")

    # Border style
    border_style = Border(
        left=Side(border_style="thin", color="000000"),
        right=Side(border_style="thin", color="000000"),
        top=Side(border_style="thin", color="000000"),
        bottom=Side(border_style="thin", color="000000"),
    )

    # Add data rows
    for row in table_data:
        if has_resolved_ip:
            row_data = row[:5]  # [IP/URL, Resolved IP, ISP, Country, Detections]
        else:
            row_data = [row[0], row[2], row[3], row[4]]
        ws_data.append(row_data)

    # Apply formatting and borders to all cells
    for row in ws_data.iter_rows(min_row=1, max_row=ws_data.max_row, max_col=ws_data.max_column):
        for cell in row:
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.border = border_style

    # Auto-fit columns
    for col in ws_data.columns:
        max_len = max(len(str(cell.value or "")) for cell in col)
        ws_data.column_dimensions[get_column_letter(col[0].column)].width = max_len + 5

    # ====== Summary Sheet ======
    ws_summary = wb.create_sheet("Summary")
    ws_summary["A1"] = "Summary"
    ws_summary["A1"].font = Font(bold=True)

    for i, line in enumerate(summary.split("\n"), start=2):
        ws_summary[f"A{i}"] = line

    max_len = max((len(str(cell.value or "")) for cell in ws_summary["A"] if cell.value), default=10)
    ws_summary.column_dimensions["A"].width = max_len + 5

    # ====== Return Excel file ======
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="IP_Info.xlsx"
    )


@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
