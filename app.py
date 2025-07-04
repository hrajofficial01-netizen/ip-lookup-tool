from flask import Flask, render_template, request, jsonify, send_file
import os
import requests
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter
import tempfile
from iso3166 import countries
import time
import ipaddress

load_dotenv()
app = Flask(__name__)

# Load VirusTotal API keys from .env (comma-separated)
VT_API_KEYS = [k.strip() for k in os.getenv("VT_API_KEYS", "").split(",") if k.strip()]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_ip_info', methods=['POST'])
def get_ip_info():
    data = request.get_json()
    ip_list = data.get('ips', [])

    summary_lines = []
    table_data = []
    table_rows = []

    BATCH_SIZE = 50
    SLEEP_BETWEEN_BATCHES = 1  # seconds
    exhausted_keys = set()

    for batch_start in range(0, len(ip_list), BATCH_SIZE):
        batch = ip_list[batch_start:batch_start + BATCH_SIZE]
        print(f"Processing batch {batch_start // BATCH_SIZE + 1}: {len(batch)} IPs")

        for ip in batch:
            if is_private_ip(ip):
                summary_lines.append(f"The IP {ip} is a private IP address and was skipped.")
                continue

            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            success = False

            for key in VT_API_KEYS:
                if key in exhausted_keys:
                    continue

                headers = {"x-apikey": key}
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    try:
                        ip_data = response.json()
                        attributes = ip_data.get("data", {}).get("attributes", {})
                        isp = attributes.get("as_owner", "N/A")
                        country_code = attributes.get("country", "N/A")
                        detections = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                        country_name = get_full_country_name(country_code)

                        summary_lines.append(
                            f"The IP {ip} belongs to the ISP: {isp} from the country: {country_name} with detection count: {detections}."
                        )
                        table_data.append([ip, isp, country_name, str(detections)])
                        table_rows.append(f"<tr><td>{ip}</td><td>{isp}</td><td>{country_name}</td><td>{detections}</td></tr>")
                        success = True
                    except Exception as e:
                        summary_lines.append(f"The IP {ip} caused an error during parsing: {str(e)}")
                    break  # Stop trying other keys for this IP

                elif response.status_code == 429:
                    print(f"Rate limit hit for key: {key}. Marking as exhausted.")
                    exhausted_keys.add(key)
                    continue  # Try next key

                else:
                    summary_lines.append(f"The IP {ip} could not be retrieved (Error {response.status_code}).")
                    break

            if not success:
                summary_lines.append(f"The IP {ip} could not be retrieved (All working keys exhausted or failed).")
                summary_lines.append(f"The IP {ip} could not be retrieved (Error {response.status_code}).")

        time.sleep(SLEEP_BETWEEN_BATCHES)

    return jsonify({
        "summary": "\n\n".join(summary_lines),
        "table": "".join(table_rows),
        "raw_table": table_data
    })

@app.route('/download_excel', methods=['POST'])
def download_excel():
    data = request.get_json()
    table_data = data.get("table_data", [])
    summary_text = data.get("summary", "")
    summary_lines = summary_text.strip().split("\n")

    file_path = generate_excel_file(table_data, summary_lines)
    return send_file(file_path, as_attachment=True, download_name="IP_Lookup_Result.xlsx")

def generate_excel_file(table_data, summary_lines):
    wb = Workbook()
    ws_table = wb.active
    ws_table.title = "Table"

    headers = ["IP", "ISP", "Country", "Detection Count"]
    bold_font = Font(bold=True)
    title_font = Font(bold=True, size=14)
    align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    border = Border(
        left=Side(style='thin', color='000000'),
        right=Side(style='thin', color='000000'),
        top=Side(style='thin', color='000000'),
        bottom=Side(style='thin', color='000000')
    )

    for col_num, header in enumerate(headers, 1):
        cell = ws_table.cell(row=1, column=col_num, value=header)
        cell.font = bold_font
        cell.alignment = align
        cell.border = border

    for row_num, row in enumerate(table_data, start=2):
        for col_num, val in enumerate(row, start=1):
            cell = ws_table.cell(row=row_num, column=col_num, value=val)
            cell.alignment = align
            cell.border = border

    for col in ws_table.columns:
        max_len = max(len(str(cell.value or "")) for cell in col)
        ws_table.column_dimensions[get_column_letter(col[0].column)].width = max_len + 2

    ws_summary = wb.create_sheet("Summary")
    summary_title = ws_summary.cell(row=1, column=1, value="Summary")
    summary_title.font = title_font
    summary_title.alignment = align
    summary_title.border = border

    for idx, line in enumerate(summary_lines, start=2):
        cell = ws_summary.cell(row=idx, column=1, value=line)
        cell.alignment = align
        cell.border = border

    ws_summary.column_dimensions["A"].width = max(len(line) for line in summary_lines + ["Summary"]) + 4

    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
    wb.save(temp.name)
    return temp.name

def get_full_country_name(code):
    try:
        return countries.get(code).name
    except:
        return code

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

if __name__ == '__main__':
    app.run(debug=True)
