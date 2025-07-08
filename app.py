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
import time

load_dotenv()

app = Flask(__name__)

# Load API keys from environment variables
VT_KEYS = [key.strip() for key in os.getenv("VT_API_KEYS", "").split(",") if key.strip()]
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
DBIP_KEY = os.getenv("DBIP_API_KEY")
IPINFO_KEY = os.getenv("IPINFO_API_KEY")
APIVOID_KEY = os.getenv("APIVOID_API_KEY")

vt_key_index = 0
vt_key_lock = threading.Lock()
exhausted_vt_keys = set()
exhausted_other_keys = set()

MAX_WORKERS = 100

# Track services usage per request
used_services = set()
unused_services = set()

# Cache for country names to avoid repeated lookups
country_cache = {}

def get_country_name(code):
    if not code:
        return "Unknown"
    if code in country_cache:
        return country_cache[code]
    try:
        country_name = countries.get(code.upper()).name
        country_cache[code] = country_name
        return country_name
    except:
        return code

def get_next_vt_key():
    global vt_key_index
    with vt_key_lock:
        for _ in range(len(VT_KEYS)):
            key = VT_KEYS[vt_key_index % len(VT_KEYS)]
            vt_key_index += 1
            if key and key not in exhausted_vt_keys:
                return key
        return None

def query_virustotal(ip):
    key = get_next_vt_key()
    if not key:
        return {}, "NoVTKey"
    headers = {"x-apikey": key}
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
        if resp.status_code == 401:
            exhausted_vt_keys.add(key)
            return query_virustotal(ip)  # Retry with next key
        if resp.status_code != 200:
            return {}, "VTError"
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        isp = attrs.get("as_owner")
        country = attrs.get("country")
        detections = attrs.get("last_analysis_stats", {}).get("malicious", 0)
        used_services.add("VT")
        return {
            "isp": isp,
            "country": get_country_name(country),
            "detections": detections
        }, "VT"
    except Exception as e:
        return {}, f"VT ERROR: {str(e)}"

def query_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return {}, "NoKey"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    try:
        resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers=headers, timeout=10)
        if resp.status_code == 429:
            exhausted_other_keys.add("AbuseIPDB")
            return {}, "RateLimit"
        data = resp.json().get("data", {})
        isp = data.get("isp")
        country = data.get("countryCode")
        detections = data.get("totalReports", 0)
        used_services.add("AbuseIPDB")
        return {
            "isp": isp,
            "country": get_country_name(country),
            "detections": detections
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
        resp = requests.get(
            f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={APIVOID_KEY}&ip={ip}",
            timeout=10
        )
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

def get_ip_info(ip):
    final_result = {}
    source_map = {"isp": "None", "country": "None", "detections": "None"}

    # Try VirusTotal first
    result, source = query_virustotal(ip)
    if result:
        final_result.update(result)
        source_map.update({k: source for k in result})
    else:
        # Query AbuseIPDB, DBIP, IPInfo in parallel, take first successful data
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
                        # Only fallback if value is None or "N/A", but NOT 0 (0 is valid)
                        if k not in final_result or final_result.get(k) in (None, "N/A"):
                            final_result[k] = data.get(k)
                            source_map[k] = src
                    break

    # If any info missing, try APIVoid
    for k in ["isp", "country", "detections"]:
        if final_result.get(k) in (None, "N/A"):
            result, src = query_apivoid(ip)
            if result and result.get(k) not in (None, "N/A"):
                final_result[k] = result.get(k)
                source_map[k] = src

    # Normalize final result values
    final_result = {
        "isp": final_result.get("isp") or "N/A",
        "country": final_result.get("country") or "N/A",
        "detections": final_result.get("detections") if final_result.get("detections") is not None else 0
    }

    print(f"[{ip}] Final Sources - ISP: {source_map['isp']}, Country: {source_map['country']}, Detections: {source_map['detections']}")

    return {
        "ip": ip,
        "isp": final_result["isp"],
        "country": final_result["country"],
        "detections": final_result["detections"],
        "summary": f"The IP: {ip} belongs to the ISP: {final_result['isp']} from the country: {final_result['country']} with detection count: {final_result['detections']}."
    }

def is_valid_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Accept public IPs, including reserved TEST-NET ranges
        # So only exclude private, loopback and unspecified
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_unspecified)
    except:
        return False

@app.route("/get_ip_info", methods=["POST"])
def handle_ip_lookup():
    start = time.time()
    data = request.json
    raw_ips = data.get("ips", [])

    # Reset global tracking per request
    global used_services, unused_services
    used_services = set()
    unused_services = set()

    # Validate and deduplicate public IPs, limit to 100
    filtered_ips = []
    seen = set()
    skipped_private_or_invalid = []

    for ip in raw_ips:
        if ip in seen:
            continue
        seen.add(ip)
        if is_valid_public_ip(ip):
            filtered_ips.append(ip)
        else:
            skipped_private_or_invalid.append(ip)
        if len(filtered_ips) == 100:
            break


    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(get_ip_info, filtered_ips))
    # Track IPs with no useful data
    no_data_ips = [r["ip"] for r in results if (
        (not r["isp"] or r["isp"] == "N/A") and
        (not r["country"] or r["country"] == "N/A")
        )]
    table_rows = "".join(
        f"<tr><td>{r['ip']}</td><td>{r['isp']}</td><td>{r['country']}</td><td>{r['detections']}</td></tr>"
        for r in results
    )

    # Add blank line before each summary except first, to create spacing on web
    summary_lines = []
    for i, r in enumerate(results):
        if i != 0:
            summary_lines.append("")  # blank line for spacing
        summary_lines.append(r["summary"])
    summary_text = "\n".join(summary_lines)

    elapsed = round(time.time() - start, 2)
    unused_services.update({"VT", "AbuseIPDB", "DBIP", "IPINFO", "APIVoid"} - used_services)

    print("\n----- API USAGE SUMMARY -----")
    print(f"IPs searched: {len(filtered_ips)}")
    print("Used Services:", ", ".join(sorted(used_services)))
    print("Unused Services:", ", ".join(sorted(unused_services)))
    print("Exhausted VT Keys:", len(exhausted_vt_keys))
    print("Exhausted Other Keys:", ", ".join(exhausted_other_keys))
    print("Total Time:", elapsed, "seconds")
    print("----------------------------\n")

    return jsonify({
    "summary": summary_text,
    "table": table_rows,
    "raw_table": [[r['ip'], r['isp'], r['country'], r['detections']] for r in results],
    "no_data_ips": no_data_ips
})

@app.route("/download_excel", methods=["POST"])
def download_excel():
    data = request.json
    table_data = data.get("table_data", [])
    summary = data.get("summary", "")

    wb = Workbook()
    ws = wb.active
    ws.title = "IP Info"

    headers = ["IP", "ISP", "Country", "Detections"]
    ws.append(headers)

    # Bold headers
    header_font = Font(bold=True)
    for cell in ws[1]:
        cell.font = header_font

    for row in table_data:
        ws.append(row)

    # Apply border + alignment + autofit for IP Info sheet
    thin_border = Border(left=Side(style="thin"), right=Side(style="thin"),
                         top=Side(style="thin"), bottom=Side(style="thin"))
    for row in ws.iter_rows():
        for cell in row:
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.border = thin_border

    for col in ws.columns:
        max_length = max(len(str(cell.value or "")) for cell in col)
        ws.column_dimensions[col[0].column_letter].width = max_length + 4

    # Summary sheet
    ws_summary = wb.create_sheet("Summary")
    ws_summary.append(["Summary"])

    # Bold header on summary sheet
    for cell in ws_summary[1]:
        cell.font = header_font

    # Add summary lines with spacing (blank lines)
    summary_lines = summary.split("\n")
    for line in summary_lines:
        ws_summary.append([line])

    # Apply alignment + autofit for Summary sheet
    for row in ws_summary.iter_rows():
        for cell in row:
            cell.alignment = Alignment(horizontal="center", vertical="center")

    for col in ws_summary.columns:
        max_length = max(len(str(cell.value or "")) for cell in col)
        ws_summary.column_dimensions[col[0].column_letter].width = max_length + 4

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
    wb.save(tmp.name)
    tmp.seek(0)

    return send_file(tmp.name, as_attachment=True, download_name="IP_Info.xlsx")

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)