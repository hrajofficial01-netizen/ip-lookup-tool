import os
import re
import time
import base64
import ipaddress
import requests
from io import BytesIO
from datetime import datetime
import pytz
import traceback
from flask import Flask, request, jsonify, send_file, render_template
from openpyxl import Workbook
from iso3166 import countries
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore, Lock
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError

# 🔹 DB IMPORTS
from db import SessionLocal
from models import LookupData, SearchLog, SearchLogNew

# =========================
# LOAD ENV
# =========================
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")

# =========================
# CONFIGURATION
# =========================
IOC_MAX = 100
IOC_MAX_WORKERS = 6
VT_MAX, APIVOID_MAX, ABUSE_MAX = 8, 8, 6

vt_semaphore = Semaphore(VT_MAX)
apivoid_semaphore = Semaphore(APIVOID_MAX)
abuse_semaphore = Semaphore(ABUSE_MAX)

vt_lock, apivoid_lock, abuse_lock = Lock(), Lock(), Lock()

VT_API_KEYS = [k.strip() for k in os.getenv("VT_API_KEYS", "").split(",") if k.strip()]
APIVOID_KEYS = [k.strip() for k in os.getenv("APIVOID_API_KEYS", "").split(",") if k.strip()]
ABUSEIPDB_KEYS = [k.strip() for k in os.getenv("ABUSEIPDB_API_KEYS", "").split(",") if k.strip()]

vt_index = 0
apivoid_index = 0
abuse_index = 0
exhausted_messages = ""

session_http = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
session_http.mount("https://", adapter)

country_cache = {}

# =========================
# DATABASE HELPERS
# =========================

def get_from_db(entry):
    db = SessionLocal()
    try:
        return db.get(LookupData, entry)
    finally:
        db.close()


def upsert_lookup_data(result):
    db = SessionLocal()
    try:
        entry = result.get("entry")
        if not entry:
            return

        entry_type = (result.get("entry_type") or "ip").lower()
        if entry_type == "url":
            entry = entry.lower()

        existing = db.get(LookupData, entry)
        if existing:
            return  # do NOT overwrite existing enrichment

        new = LookupData(
            entry=entry,
            entry_type=entry_type,
            isp=result.get("isp"),
            asn=result.get("asn"),
            country=result.get("country"),
            detection_count=result.get("detections", 0),
            abuseipdb_confidence_score=result.get("abuseipdb_confidence_score"),
            abuseipdb_report_count=result.get("abuseipdb_report_count"),
            apivoid_risk_score=result.get("apivoid_risk_score"),
            apivoid_blacklist_detections=result.get("apivoid_blacklist_detections"),
            details_json=result.get("details_json"),
            threat_actor=result.get("threat_actor"),
            campaign_name=result.get("campaign_name"),
            malware_families=result.get("malware_families"),
            country_origin=result.get("country_origin"),
            target_sector=result.get("target_sector"),
            threat_category=result.get("threat_category")
        )
        db.add(new)
        db.commit()

    except Exception as e:
        print(f"Error during DB upsert for {entry}: {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()


def insert_search_event(entry, client_name, timestamp, entry_type=None):
    db = SessionLocal()
    try:
        if entry_type and entry_type.lower() == "url":
            entry = entry.lower()

        event = SearchLogNew(
            entry=entry,
            entry_type=entry_type,
            client_name=client_name,
            searched_at=timestamp
        )
        db.add(event)
        db.commit()
    except Exception as e:
        print(f"Error inserting search event for {entry}: {str(e)}")    
        db.rollback()
    finally:
        db.close()


def upsert_search_log(entry, client_name, timestamp, entry_type=None):
    db = SessionLocal()
    try:
        if entry_type and entry_type.lower() == "url":
            entry = entry.lower()

        existing = db.get(SearchLog, (entry, client_name))
        if existing:
            existing.lookup_count += 1
            existing.last_searched = timestamp
        else:
            new = SearchLog(
                entry=entry,
                entry_type=entry_type,
                client_name=client_name,
                first_searched=timestamp,
                last_searched=timestamp,
                lookup_count=1
            )
            db.add(new)

        db.commit()

    except IntegrityError as e:
        db.rollback()
        print(f"IntegrityError during upsert_search_log for {entry}: {str(e)}") 
    finally:
        db.close()

# =========================
# VALIDATION
# =========================

def is_ip(entry):
    try:
        ipaddress.ip_address(entry)
        return True
    except ValueError:
        return False

def is_hash(entry):
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", entry))

def is_url(entry):
    try:
        parsed = urlparse(entry if entry.startswith("http") else f"http://{entry}")
        return bool(parsed.hostname and "." in parsed.hostname)
    except:
        return False

def get_type(entry):
    return "IP" if is_ip(entry) else "HASH" if is_hash(entry) else "URL" if is_url(entry) else None

def normalize_url(url):
    return url if url.startswith("http") else f"http://{url}"

def get_country(code):
    if not code:
        return None
    if code in country_cache:
        return country_cache[code]
    try:
        country_cache[code] = countries.get(code.upper()).name
        return country_cache[code]
    except:
        return code

# =========================
# KEY ROTATION
# =========================

def rotate_key(keys, service):
    global vt_index, apivoid_index, abuse_index

    if not keys:
        return None

    if service == "vt":
        with vt_lock:
            key = keys[vt_index]
            vt_index = (vt_index + 1) % len(keys)
            return key

    if service == "apivoid":
        with apivoid_lock:
            key = keys[apivoid_index]
            apivoid_index = (apivoid_index + 1) % len(keys)
            return key

    if service == "abuse":
        with abuse_lock:
            key = keys[abuse_index]
            abuse_index = (abuse_index + 1) % len(keys)
            return key

def parse_hash_enrichment(source_data):
    def safe_get(d, *keys, default=None):
        for key in keys:
            d = d.get(key, {})
            if not isinstance(d, dict):
                return d if d else default
        return default

    # Extract malicious detections
    detections = safe_get(source_data, "last_analysis_stats", "malicious", default=-1)

    # Extract popular threat label from "popularthreatname" or "suggestedthreatlabel"
  # Compose popular_threat_label from suggested_threat_label and popular_threat_category
    pop_threat_classification = source_data.get("popular_threat_classification", {})

    suggested_label = pop_threat_classification.get("suggested_threat_label")
    popular_categories = pop_threat_classification.get("popular_threat_category", [])

    categories_str = ", ".join([cat.get("value", "") for cat in popular_categories if cat.get("value")])

    if suggested_label and categories_str:
        popular_threat_label = f"{suggested_label} ({categories_str})"
    elif suggested_label:
        popular_threat_label = suggested_label
    elif categories_str:
        popular_threat_label = categories_str
    else:
        popular_threat_label = None

        
    # Other important fields
    size = source_data.get("size")
    file_type= source_data.get("type_description")
    file_name = source_data.get("meaningful_name") or (source_data.get("names")[0] if source_data.get("names") else None)
    malicious_engines = [k for k, v in source_data.get("last_analysis_results", {}).items() if v.get("category") == "malicious"]
    first_seen = source_data.get("first_submission_date")
    last_seen = source_data.get("last_submission_date")
    reputation = source_data.get("reputation")

    return {
        "detections": detections,
        "popular_threat_label": popular_threat_label,
        "file_size": size,
        "file_name": file_name,
        "file_type": file_type,
        "malicious_engines": malicious_engines,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "reputation": reputation
    }

# =========================
# VIRUSTOTAL
# =========================

def vt_lookup(entry):
    with vt_semaphore:
        key = rotate_key(VT_API_KEYS, "vt")
        if not key:
            return None

        headers = {"x-apikey": key}

        try:
            if is_hash(entry):
                url = f"https://www.virustotal.com/api/v3/files/{entry}"
            elif is_ip(entry):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{entry}"
            else:
                encoded = base64.urlsafe_b64encode(normalize_url(entry).encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code != 200:
                print(f"VT lookup failed for {entry} with status {r.status_code}")
                return None

            attr = r.json().get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})

            result = {
                "vt_detections": stats.get("malicious", 0),
                "isp": attr.get("as_owner"),
                "country": get_country(attr.get("country"))
            }

            
            if is_hash(entry):
                    ptc = attr.get("popular_threat_classification") or {}
                    labels = [c.get("value") for c in (ptc.get("popular_threat_category") or []) if isinstance(c, dict) and c.get("value")]
                    result.update({"file_name": attr.get("meaningful_name"), "file_size": attr.get("size"), "file_type": attr.get("type_description"), "threat_labels": ", ".join(labels) if labels else None,"json_response": attr})

            if is_url(entry): result["associated_ip"] = attr.get("last_serving_ip_address")
            
            return result
        
        except Exception as e:
                print(f"Error during VT lookup for {entry}")
                traceback.print_exc()
                return None

# =========================
# APIVOID
# =========================

def apivoid_lookup(entry):
    if is_hash(entry):
        return None

    with apivoid_semaphore:
        key = rotate_key(APIVOID_KEYS, "apivoid")
        if not key:
            return None

        headers = {"X-API-Key": key, "Content-Type": "application/json"}

        try:
            if is_ip(entry):
                endpoint = "https://api.apivoid.com/v2/ip-reputation"
                payload = {"ip": entry}
            else:
                endpoint = "https://api.apivoid.com/v2/domain-reputation"
                payload = {"host": urlparse(normalize_url(entry)).hostname}

            r = requests.post(endpoint, headers=headers, json=payload, timeout=15)
            if r.status_code != 200:
                print(f"APIVoid lookup failed for {entry} with status {r.status_code}")
                return None

            data = r.json()

            return {
                "detections": data.get("blacklists", {}).get("detections", 0),
                "riskscore": data.get("risk_score", {}).get("result"),
                "country": data.get("information", {}).get("country_name"),
                "isp": data.get("information", {}).get("isp")
            }
        except Exception as e:
                print(f"Error during APIVoid lookup for {entry}")
                traceback.print_exc()
                return None

# =========================
# ABUSEIPDB
# =========================

def abuse_lookup(ip):
    if not is_ip(ip):
        return None

    with abuse_semaphore:
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
                print(f"AbuseIPDB lookup failed for {ip} with status {r.status_code}")
                return None

            return r.json().get("data")
        except Exception as e:
                print(f"Error during AbuseIPDB lookup for {ip}")
                traceback.print_exc()
                return None

# =========================
# SUMMARY
# =========================

def build_summary(entry, etype, isp, country, detections, vt=None, apv=None, abv=None, record=None):
    hash_details = {}
    if record:
        isp = record.isp or isp
        country = record.country or country
        detections = record.detection_count or detections
        hash_details= parse_hash_enrichment(record.details_json) if record.details_json else None
        apv = {"riskscore": record.apivoid_risk_score, "detections": record.apivoid_blacklist_detections} if record.apivoid_risk_score is not None else vt
        abv = {"abuseConfidenceScore": record.abuseipdb_confidence_score, "totalReports": record.abuseipdb_report_count} if record.abuseipdb_confidence_score is not None else abv
    if etype == "IP":
        sentence = f"The IP <b>{entry}</b> belongs to ISP <b>{isp}</b> from country <b>{country}</b> with "
        sentence += f"<b>{detections}</b> malicious detections." if detections>1 else f"<b>{detections}</b> malicious detection."
        sentence += f" ApiVoid shows risk score of {int(apv.get('riskscore'))}." if apv and apv.get('riskscore',0)>20 else ""
        sentence += f" AbuseIPDB reports an abuse confidence score of {abv.get('abuseConfidenceScore')}% with {abv.get('totalReports')} total reports." if abv and abv.get("abuseConfidenceScore",0)>10 else ""
        return sentence
    if etype == "URL":
        sentence = f"The URL <b>{entry}</b>"
        if country and isp: sentence += f" belongs to the ISP <b>{isp}</b> from country <b>{country}</b> and "
        sentence += f" has <b>{detections}</b> malicious detections." if detections>1 else f" and has <b>{detections}</b> malicious detection."
        sentence += f" ApiVoid shows risk score of {int(apv.get('riskscore'))}." if apv and apv.get('riskscore',0)>20 else ""
        return sentence
    if etype == "HASH":
        hash_details = hash_details or (vt if vt else {})
        sentence = f"The hash <b>{entry}</b> has <b>{detections}</b> malicious detections." if detections>=0 else f"The hash <b>{entry}</b> was not found in any database."
        if hash_details:
            sentence += f" It is identified as <b>{hash_details.get('file_type') }</b> with name <b>{hash_details.get('file_name')}</b> and size {hash_details.get('file_size')} bytes"
            if hash_details.get('popular_threat_label') or hash_details.get('threat_labels'): sentence += f" and associated with threat label: {hash_details.get('popular_threat_label') or hash_details.get('threat_labels')}"
        return sentence + "."
# =========================
# ROUTES
# =========================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/ping")
def ping():
    return "OK"

@app.route("/get_ip_info", methods=["POST"])
def get_ip_info():
    start = time.time()
    data = request.get_json(silent=True)

    if not data or "ips" not in data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    no_data_ips = []
    client_name = data.get("client_name", "Unknown")
    entries = list(set(data.get("ips", [])))[:IOC_MAX]

    raw_table, summaries, services_used = [], [], set()

    def process(entry):
        etype = get_type(entry)
        if not etype:
            return None

        # 🔹 CHECK DB FIRST
        record = get_from_db(entry)
        if record:
            services_used.add("Database")
            row = [
                entry,
                record.isp ,
                record.country ,
                record.detection_count,
                record.apivoid_risk_score,
                record.apivoid_blacklist_detections ,
                record.abuseipdb_confidence_score,
                record.abuseipdb_report_count ,
                "-", "-", "-", "-", "-", "-"
            ]
            summary = build_summary(entry, etype, isp=None, country=None, detections=record.detection_count, vt=None, apv=None, abv=None, record=record)
            return summary, row


        # 🔹 API LOOKUPS
        vt = vt_lookup(entry)
        apv = apivoid_lookup(entry)
        abv = abuse_lookup(entry)
        
        if not any([vt, apv, abv]):
            no_data_ips.append(entry)

        for s, val in [("VirusTotal", vt), ("APIVoid", apv), ("AbuseIPDB", abv)]:
            if val and s not in services_used: services_used.add(s)
            
        vt_det = vt.get("vt_detections") if vt else -1
        apv_det = apv.get("detections") if apv else -1
        detections = max(vt_det, apv_det)

        isp = (apv.get("isp") if apv else None) or (vt.get("isp") if vt else "-")
        country = (apv.get("country") if apv else None) or (vt.get("country") if vt else "-")

        if vt_det != -1:
            upsert_lookup_data({
                "entry": entry,
                "entry_type": etype,
                "isp": isp,
                "country": country,
                "detections": detections,
                "apivoid_risk_score": apv.get("riskscore") if apv else None,
                "apivoid_blacklist_detections": apv_det,
                "abuseipdb_confidence_score": abv.get("abuseConfidenceScore") if abv else None,
                "abuseipdb_report_count": abv.get("totalReports") if abv else None,
                "details_json": vt.get("json_response") if vt else None
            })

        summary = build_summary(entry, etype, isp, country, detections, vt, apv, abv,record=None)

        row = [
            entry, isp, country, detections,
            apv.get("riskscore") if apv else "-",
            apv_det,
            abv.get("abuseConfidenceScore") if abv else "-",
            abv.get("totalReports") if abv else "-",
            "-", "-", "-", "-", "-", "-"
        ]

        return summary, row

    with ThreadPoolExecutor(max_workers=IOC_MAX_WORKERS) as executor:
        futures = [executor.submit(process, e) for e in entries]
        for f in as_completed(futures):
            result = f.result()
            if result:
                summary, row = result
                summaries.append(summary)
                raw_table.append(row)

    timestamp = datetime.now(pytz.UTC)
    for entry in entries:
        etype = get_type(entry)
        insert_search_event(entry, client_name, timestamp, etype)
        upsert_search_log(entry, client_name, timestamp, etype)

    return jsonify({
        "raw_table": raw_table,
        "summary": "<br><br>".join(summaries),
        "elapsed": round(time.time() - start, 2),
        "services_used": list(services_used),
        "no_data_ips": no_data_ips
    })

@app.route("/test_ssl")
def test_ssl():
    import ssl
    import sys

    return f"""
    ssl module file: {ssl.__file__}
    <br>
    python version: {sys.version}
    """


@app.route("/download_excel", methods=["POST"])
def download_excel():
    table = request.json.get("table_data", [])
    wb = Workbook()
    ws = wb.active
    ws.title = "Results"

    ws.append([
        "IOC","ISP","Country","Detections",
        "APIVoid Risk","APIVoid Blacklist",
        "Abuse Confidence","Abuse Reports",
        "","","","","",""
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

# =========================
# RUN
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
