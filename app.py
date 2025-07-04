from flask import Flask, request, jsonify, send_file, render_template
import os
import requests
import time
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter
import tempfile
from iso3166 import countries
import ipaddress

load_dotenv()
app = Flask(__name__)

VT_API_KEYS = [k.strip() for k in os.getenv("VT_API_KEYS", "").split(",") if k.strip()]
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
MAX_IPS = 50
exhausted_vt_keys = set()

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/get_ip_info', methods=['POST'])
def get_ip_info():
    data = request.get_json()
    ip_list = data.get('ips', [])[:MAX_IPS]
    
    summary_lines, table_data, table_rows = [], [], []

    for ip in ip_list:
        if is_private_or_reserved(ip):
            print(f"[SKIP] {ip} is a private or reserved IP")
            continue

        print(f"[LOOKUP] Processing IP: {ip}")
        isp, country, detections = "N/A", "N/A", 0

        # Try VirusTotal
        for key in VT_API_KEYS:
            if key in exhausted_vt_keys:
                continue
            vt_resp = query_virustotal(ip, key)
            if vt_resp == 'exhausted':
                exhausted_vt_keys.add(key)
                print(f"[VT] Key exhausted: {key}")
                continue
            elif vt_resp:
                vt_data = vt_resp
                isp = vt_data.get("as_owner", isp)
                country = get_country_name(vt_data.get("country", country))
                detections = max(detections, vt_data.get("last_analysis_stats", {}).get("malicious", 0))
                print(f"[VT] Data for {ip} found with key {key}")
                break

        # Try AbuseIPDB
        abuse_data = query_abuseipdb(ip)
        if abuse_data:
            if not isp or isp == "N/A":
                isp = abuse_data.get("isp", isp)
            if not country or country == "N/A":
                country = abuse_data.get("countryCode", country)
            detections = max(detections, abuse_data.get("abuseConfidenceScore", 0))
            print(f"[ABUSEIPDB] Data for {ip} found")

        # Try IPAPI
        if isp == "N/A" or country == "N/A":
            ipapi_data = query_ipapi(ip)
            if ipapi_data:
                isp = ipapi_data.get("org", isp)
                country = ipapi_data.get("country", country)
                print(f"[IPAPI] Data for {ip} found")

        # Try ipwho.is
        if isp == "N/A" or country == "N/A":
            ipwho = query_ipwhois(ip)
            if ipwho:
                isp = ipwho.get("isp", isp)
                country = ipwho.get("country", country)
                print(f"[IPWHO] Data for {ip} found")

        if isp == "N/A" and country == "N/A":
            summary_lines.append(f"The IP {ip} could not be retrieved from any source.")
            continue

        summary_lines.append(
            f"The IP {ip} belongs to the ISP: {isp} from the country: {country} with detection count: {detections}."
        )
        table_data.append([ip, isp, country, str(detections)])
        table_rows.append(f"<tr><td>{ip}</td><td>{isp}</td><td>{country}</td><td>{detections}</td></tr>")

    return jsonify({
        "summary": "\n\n".join(summary_lines),
        "table": "".join(table_rows),
        "raw_table": table_data
    })

def query_virustotal(ip, api_key):
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key}
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {})
        elif resp.status_code == 429:
            return 'exhausted'
    except Exception as e:
        print(f"[VT] Error: {e}")
    return None

def query_abuseipdb(ip):
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {})
    except Exception as e:
        print(f"[ABUSEIPDB] Error: {e}")
    return None

def query_ipapi(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception as e:
        print(f"[IPAPI] Error: {e}")
    return None

def query_ipwhois(ip):
    try:
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success", False):
                return data
    except Exception as e:
        print(f"[IPWHO] Error: {e}")
    return None

def get_country_name(code):
    try:
        return countries.get(code).name
    except:
        return code or "N/A"

def is_private_or_reserved(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local or addr.is_multicast
    except:
        return True

@app.route('/download_excel', methods=['POST'])
def download_excel():
    data = request.get_json()
    table_data = data.get("table_data", [])
    summary_text = data.get("summary", "")
    return send_file(generate_excel_file(table_data, summary_text.strip().split("\n")), as_attachment=True, download_name="IP_Info.xlsx")

def generate_excel_file(table_data, summary_lines):
    wb = Workbook()
    ws_table = wb.active
    ws_table.title = "Table"
    headers = ["IP", "ISP", "Country", "Detection Count"]

    bold_font = Font(bold=True)
    align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    border = Border(left=Side(style='thin'), right=Side(style='thin'),
                    top=Side(style='thin'), bottom=Side(style='thin'))

    for col_num, header in enumerate(headers, 1):
        cell = ws_table.cell(row=1, column=col_num, value=header)
        cell.font = bold_font
        cell.alignment = align
        cell.border = border

    for row_num, row in enumerate(table_data, 2):
        for col_num, val in enumerate(row, 1):
            cell = ws_table.cell(row=row_num, column=col_num, value=val)
            cell.alignment = align
            cell.border = border

    for col in ws_table.columns:
        max_len = max(len(str(cell.value or "")) for cell in col)
        ws_table.column_dimensions[get_column_letter(col[0].column)].width = max_len + 2

    ws_summary = wb.create_sheet("Summary")
    ws_summary["A1"] = "Summary"
    ws_summary["A1"].font = Font(bold=True, size=14)
    for idx, line in enumerate(summary_lines, start=2):
        ws_summary.cell(row=idx, column=1, value=line).alignment = align

    ws_summary.column_dimensions["A"].width = max(len(line) for line in summary_lines + ["Summary"]) + 5
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
    wb.save(temp.name)
    return temp.name

if __name__ == '__main__':
    app.run(debug=True)
