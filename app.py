import os
import time
import threading
import base64
import io
import ipaddress
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import requests
import pytz
from flask import Flask, request, jsonify, send_file, render_template
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from tie_service import get_ip_tie_data, get_domain_tie_data, extract_enrichment_fields, get_actor_info_from_entry
import atexit
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from iso3166 import countries
from tie_service import get_ip_tie_data, get_domain_tie_data, extract_enrichment_fields
from concurrent.futures import ThreadPoolExecutor
from db import SessionLocal
from models import LookupData, SearchLog
from models import SearchLogNew

def keep_alive():
    while True:
        try:
            response = requests.get("https://ipandurl-lookup-tool.onrender.com/")
            if response.status_code == 200:
                print("Keep alive ping successful")
            else:
                print(f"Keep alive ping returned status code: {response.status_code}")
        except Exception as e:
            print("Keep alive ping failed:", e)
        time.sleep(120)  # Sleep for 2 minutes

# Start the keep_alive function in a daemon thread so it won't block app shutdown
threading.Thread(target=keep_alive, daemon=True).start()

# Load environment variables
load_dotenv()

app = Flask(__name__)

import threading

is_shutting_down = False

def safe_print(*args, **kwargs):
    if not is_shutting_down:
        print(*args, **kwargs)




# API keys from environment
VT_KEYS = [key.strip() for key in os.getenv("VT_API_KEYS", "").split(",") if key.strip()]
ABUSEIPDB_KEYS = [key.strip() for key in os.getenv("ABUSEIPDB_API_KEYS", "").split(",") if key.strip()]
DBIP_KEY = os.getenv("DBIP_API_KEY")
IPINFO_KEY = os.getenv("IPINFO_API_KEY")
APIVOID_KEY = os.getenv("APIVOID_API_KEY")

# Globals
vt_key_index = 0
vt_key_lock = threading.Lock()
exhausted_vt_keys = set()
vt_keys_used = set()
vt_keys_success = set()
# Add AbuseIPDB keys variables (similar structure)
abuseipdb_key_index = 0
abuseipdb_key_lock = threading.Lock()
exhausted_abuseipdb_keys = set()
abuseipdb_keys_used = set()
abuseipdb_keys_success = set()

exhausted_other_keys = set()
used_services = set()
unused_services = set()
country_cache = {}
MAX_WORKERS = 100
# Define a global executor reused across requests

executor_main = ThreadPoolExecutor(max_workers=MAX_WORKERS)
atexit.register(lambda: executor_main.shutdown(wait=True))


from concurrent.futures import ThreadPoolExecutor

THREAT_FIELDS = [
    "threat_actor",
    "campaign_name",
    "malware_families",
    "country_origin",
    "target_sector",
    "threat_category",
]

def entryabuseipdburl(url):
    # AbuseIPDB doesn't support URL lookups
    # Return empty dict to keep interface consistent
    return {}

def upsert_lookup_data(result):
    """
    Inserts into lookup_data if missing.
    Does *not* touch this row again on repeat searches.
    """
    session = SessionLocal()
    try:
        entry_type = result.get("entry_type", result.get("type", "IP")).lower()

        # Use correct source field
        if entry_type == "url":
            entry = (result.get("entry") or result.get("entry") or "").strip().lower()
            if not entry:
                return  # don't insert when we have no valid URL/domain
        else:
            entry = result.get("entry", "").strip()
            if not entry:
                return  # don't insert when we have no valid IP

        # these fields come from get_ip_info or lookup_url
        isp             = result.get("isp", "")
        asn             = result.get("asn", "")
        country         = result.get("country", "")
        detection_count = result.get("detections", 0)
        
        # New enrichment fields
        threat_actor     = result.get("threat_actor")
        campaign_name    = result.get("campaign_name")
        malware_families = result.get("malware_families")

        # New enrichment fields from second api call
        country_origin = result.get("country_origin")
        target_sector = result.get("target_sector")
        threat_category = result.get("threat_category")

        # Newly added AbuseIPDB fields
        abuseipdb_confidence_score = result.get("abuseipdb_confidence_score")
        abuseipdb_report_count = result.get("abuseipdb_report_count")
        
        existing = session.get(LookupData, entry)
        if not existing:
            new = LookupData(
                entry=entry,
                entry_type=entry_type,
                isp=isp,
                asn=asn,
                country=country,
                detection_count=detection_count,
                abuseipdb_confidence_score=abuseipdb_confidence_score,
                abuseipdb_report_count=abuseipdb_report_count,
                threat_actor=threat_actor,
                campaign_name=campaign_name,
                malware_families=malware_families,
                country_origin=country_origin,
                target_sector=target_sector,
                threat_category=threat_category
            )
            session.add(new)
            session.commit()
    except Exception:
        session.rollback()
        raise  # Optionally raise to track errors
    finally:
        session.close()

def insert_search_event(entry, client_name, timestamp, entry_type=None):
    session = SessionLocal()
    try:
        # Normalize URLs/domains
        if entry_type and entry_type.lower() == "url" and entry:
            entry = entry.lower()
        elif not entry_type and entry and "." in entry and not entry.replace(".", "").isdigit():
            entry = entry.lower()

        new_event = SearchLogNew(
            entry=entry,
            entry_type=entry_type,
            client_name=client_name,
            searched_at=timestamp
        )
        session.add(new_event)
        session.commit()
    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()

def upsert_search_log(entry, client_name, timestamp, entry_type=None):
    """
    For each search: increment lookup_count & update last_searched;
    if first time, create row with first_searched=last_searched=timestamp.
    Always stores normalized lowercase URLs/domains.
    """
    session = SessionLocal()
    try:
        # 🔹 If we know the type and it's a URL, normalize
        if entry_type and entry_type.lower() == "url" and entry:
            entry = entry.lower()
        # If no type provided, do a quick heuristic check for domain/URL
        elif not entry_type and entry and "." in entry and not entry.replace(".", "").isdigit():
            entry = entry.lower()
        existing = session.get(SearchLog, (entry, client_name))
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
            session.add(new)
        session.commit()
    except IntegrityError:
        session.rollback()
    finally:
        session.close()
       
        
    
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


def get_next_abuseipdb_key():
    global abuseipdb_key_index
    with abuseipdb_key_lock:
        for _ in range(len(ABUSEIPDB_KEYS)):
            key = ABUSEIPDB_KEYS[abuseipdb_key_index % len(ABUSEIPDB_KEYS)]
            abuseipdb_key_index += 1
            if key and key not in exhausted_abuseipdb_keys:
                return key
        return None


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
    result = {
        "detections": None,
        "categories": [],
        "vt_key_used": None,
        "status_codes": {},       # ← new
        "services_used": []
    }

    key = get_next_vt_key()
    if not key:
        return result

    headers = {"x-apikey": key}
    try:
        # submit URL
        post_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        result["status_codes"]["VT_URL_submit"] = post_resp.status_code

        if post_resp.status_code != 200:
            exhausted_vt_keys.add(key)
            return result

        # lookup report
        encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        get_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded}",
            headers=headers,
            timeout=10
        )
        result["status_codes"]["VT_URL_report"] = get_resp.status_code

        if get_resp.status_code != 200:
            exhausted_vt_keys.add(key)
            return result

        data = get_resp.json().get("data", {}).get("attributes", {})
        result["detections"] = data.get("last_analysis_stats", {}).get("malicious", 0)
        result["categories"] = list(data.get("categories", {}).values())
        result["vt_key_used"] = key
        result["services_used"].append("VirusTotal URL")

        vt_keys_used.add(key)
        vt_keys_success.add(key)

    except Exception as e:
        safe_print(f"[ERROR] VT URL scan failed: {e}")
        # you may also set result["status_codes"]["VT_URL_error"] = str(e)

    return result


# -------------------------------
# VirusTotal IP entry with Key Rotation
# -------------------------------
def entry_virustotal(ip):
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
            if resp.status_code in (401,429, 403):
                exhausted_vt_keys.add(key)
                continue
            if resp.status_code != 200:
                return {}, f"VTError {resp.status_code}", key
            data = resp.json().get("data", {}).get("attributes", {})
            vt_keys_success.add(key)
            return {
                "isp": data.get("as_owner"),
                "country": get_country_name(data.get("country")),
                "detections": data.get("last_analysis_stats", {}).get("malicious", 0)
            }, "VT", key
        except Exception as e:
            exhausted_vt_keys.add(key)
            return {}, f"VT Exception: {str(e)}", key
    return {}, "NoVTKeyAvailable", None


# -------------------------------
# AbuseIPDB entry with Rate-Limit Handling
# -------------------------------
def entry_abuseipdb(ip):
    tried = set()
    while True:
        key = get_next_abuseipdb_key()
        if not key or key in tried:
            break
        tried.add(key)
        headers = {"Key": key, "Accept": "application/json"}
        try:
            resp = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                headers=headers, timeout=10
            )
            if resp.status_code == 429:  # Rate limit
                exhausted_abuseipdb_keys.add(key)
                continue
            if resp.status_code in (401, 403):  # Auth error also consider exhausted
                exhausted_abuseipdb_keys.add(key)
                continue
            if resp.status_code != 200:
                return {}, f"AbuseIPDB Error {resp.status_code}", key
            data = resp.json().get("data", {})
            used_services.add("AbuseIPDB")
            abuseipdb_keys_used.add(key)
            abuseipdb_keys_success.add(key)
            return {
                "isp": data.get("isp"),
                "country": get_country_name(data.get("countryCode")),
                "detections": data.get("totalReports", 0)
            }, "AbuseIPDB", key
        except Exception as e:
            exhausted_abuseipdb_keys.add(key)
            return {}, f"AbuseIPDB Exception: {str(e)}", key
    return {}, "NoAbuseIPDBKeyAvailable", None

def is_valid_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_unspecified)
    except:
        return False

import re
from urllib.parse import urlparse

def is_valid_hash(s):
    s = s.lower()
    return (
        re.fullmatch(r"[a-f0-9]{32}", s) or   # MD5
        re.fullmatch(r"[a-f0-9]{40}", s) or   # SHA1
        re.fullmatch(r"[a-f0-9]{64}", s)      # SHA256
    ) is not None

def is_valid_url(url):
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        hostname = parsed.hostname

        if not hostname or '.' not in hostname:
            return False

        # Reject short numeric-like hostnames (e.g., "12.23.4")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){1,2}", hostname):
            return False

        # Check TLD
        if not re.search(r"\.[a-zA-Z]{2,}$", hostname):
            return False
        
     # ✅ Return lowercased version
        return url.lower()
    except:
        return False

import re

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

from concurrent.futures import ThreadPoolExecutor

def get_ip_info(ip, vt_keys_exhausted=False):
    ip_info = {
        "entry": ip,
        "asn": "",
        "isp": "",
        "country": "",
        "detections": 0,
        "used_service": "",
        "used_key": "",
        "status_codes": {},
        "service_sources": {
            "asn": None,
            "isp": None,
            "country": None,
            "detections": None
        }
    }

    def call_virustotal():
        for _ in range(len(VT_KEYS)):
            vt_key = get_next_vt_key()
            if not vt_key:
                return None, None
            used_services.add("VirusTotal")
            headers = {"x-apikey": vt_key}
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers=headers,
                    timeout=10
                )
                ip_info["status_codes"]["VirusTotal"] = resp.status_code
                vt_keys_used.add(vt_key)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    return data, vt_key
                elif resp.status_code in (401, 429, 403):
                    exhausted_vt_keys.add(vt_key)
                    continue
            except Exception:
                ip_info["status_codes"]["VirusTotal"] = "Error"
                exhausted_vt_keys.add(vt_key)
                return None, vt_key
        return None, None

    def call_abuseipdb():
        tried = set()
        while True:
            key = get_next_abuseipdb_key()
            if not key or key in tried:
                break
            tried.add(key)
            headers = {"Key": key, "Accept": "application/json"}
            try:
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    timeout=10
                )
                ip_info["status_codes"]["AbuseIPDB"] = resp.status_code
                if resp.status_code == 429:
                    exhausted_abuseipdb_keys.add(key)
                    continue
                if resp.status_code in (401, 403):
                    exhausted_abuseipdb_keys.add(key)
                    continue
                if resp.status_code != 200:
                    return {}, None
                abuseipdb_keys_used.add(key)
                abuseipdb_keys_success.add(key)
                used_services.add("AbuseIPDB")
                return resp.json().get("data", {}), key
            except Exception:
                ip_info["status_codes"]["AbuseIPDB"] = "Error"
                exhausted_abuseipdb_keys.add(key)
                return {}, None
        return None, None

    with ThreadPoolExecutor(max_workers=2) as executor:
        vt_future = executor.submit(call_virustotal)
        abuseipdb_future = executor.submit(call_abuseipdb)

        vt_result, vt_key = vt_future.result()
        abuseipdb_result, abuseipdb_key = abuseipdb_future.result()
    if vt_result:
        if vt_keys_exhausted:
            print(f"DEBUG [get_ip_info]: VT keys exhausted, suppressing detection count for IP {ip}")
            det_vt = 0
        else:
            det_vt = vt_result.get("last_analysis_stats", {}).get("malicious", 0) or 0
        print(f"DEBUG [get_ip_info]: IP {ip}, detection count set to {det_vt}")
        ip_info["detections"] = det_vt

    if vt_result:
        asn_vt = vt_result.get("asn", "")
        isp_vt = vt_result.get("as_owner", "")
        ctr_vt = vt_result.get("country", "")

        if not vt_keys_exhausted:
            det_vt = vt_result.get("last_analysis_stats", {}).get("malicious", 0) or 0
        else:
            det_vt = 0

        ip_info["detections"] = det_vt
        ip_info["service_sources"]["detections"] = "VirusTotal" if not vt_keys_exhausted else None

        if asn_vt:
            ip_info["asn"] = asn_vt
            ip_info["service_sources"]["asn"] = "VirusTotal"
        if isp_vt:
            ip_info["isp"] = isp_vt
            ip_info["service_sources"]["isp"] = "VirusTotal"
        if ctr_vt:
            ip_info["country"] = get_country_name(ctr_vt)
            ip_info["service_sources"]["country"] = "VirusTotal"

        ip_info["used_service"] = "VirusTotal"
        ip_info["used_key"] = vt_key
        vt_keys_success.add(vt_key)

    if abuseipdb_result:
        if abuseipdb_result.get("asn") and not ip_info["asn"]:
            ip_info["asn"] = abuseipdb_result["asn"]
            ip_info["service_sources"]["asn"] = "AbuseIPDB"
        if abuseipdb_result.get("isp") and not ip_info["isp"]:
            ip_info["isp"] = abuseipdb_result["isp"]
            ip_info["service_sources"]["isp"] = "AbuseIPDB"
        if abuseipdb_result.get("countryCode") and not ip_info["country"]:
            ip_info["country"] = get_country_name(abuseipdb_result.get("countryCode", ""))
            ip_info["service_sources"]["country"] = "AbuseIPDB"
        ip_info["abuseipdb_confidence_score"] = abuseipdb_result.get("abuseConfidenceScore")
        ip_info["abuseipdb_report_count"] = abuseipdb_result.get("totalReports")

        if ip_info["used_service"] != "VirusTotal":
            ip_info["used_service"] = "AbuseIPDB"
            ip_info["used_key"] = abuseipdb_key

    return ip_info

def get_hash_info(hash_value, vt_keys_exhausted=False):
    hash_info = {
        "entry": hash_value,
        "detections": 0,
        "used_service": "",
        "used_key": "",
        "status_codes": {},
        "service_sources": {
            "detections": None
        }
    }

    def call_virustotal():
        for _ in range(len(VT_KEYS)):
            vt_key = get_next_vt_key()  # Implement this rotating key fetcher as per your app
            if not vt_key:
                return None, None
            used_services.add("VirusTotal")
            headers = {"x-apikey": vt_key, "Accept": "application/json"}
            try:
                url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
                resp = requests.get(url, headers=headers, timeout=10)
                hash_info["status_codes"]["VirusTotal"] = resp.status_code
                vt_keys_used.add(vt_key)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    vt_keys_success.add(vt_key)
                    vt_keys_used.add(vt_key)
                    return data, vt_key
                elif resp.status_code in (401, 429, 403):
                    exhausted_vt_keys.add(vt_key)
                    continue
            except Exception:
                hash_info["status_codes"]["VirusTotal"] = "Error"
                exhausted_vt_keys.add(vt_key)
                return None, vt_key
        return None, None

    vt_result, vt_key = call_virustotal()

    if vt_result:
        detections = vt_result.get("last_analysis_stats", {}).get("malicious", 0) or 0
        hash_info["detections"] = detections
        hash_info["service_sources"]["detections"] = "VirusTotal"
        hash_info["used_service"] = "VirusTotal"
        hash_info["used_key"] = vt_key

    return hash_info

def get_hash_tie_data(hash_value):
    # Placeholder that returns all expected fields with "-" values
    return {
        "threat_actor": "-",
        "campaign_name": "-",
        "malware_families": "-",
        "country_origin": "-",
        "target_sector": "-",
        "threat_category": "-",
        "data": {},  # keep empty data object for compatibility
    }

def lookup_url(url):
    with ThreadPoolExecutor(max_workers=2) as executor:
        vt_future = executor.submit(fetch_virustotal_url_data, url)
        abuseipdb_future = executor.submit(entryabuseipdburl, url)

        vt_data = vt_future.result() or {}
        abuseipdb_data = abuseipdb_future.result() or {}

    used_services.add("VirusTotal")
    # AbuseIPDB will not add any data here for URLs

    # Always take detections from VT (0 if missing)
    detections = vt_data.get("detections") or 0

    # Combine data - AbuseIPDB fields if any - will be None or missing here for URLs
    # You can add AbuseIPDB fields here if relevant for UI or storage
    abuseipdb_confidence_score = abuseipdb_data.get("abuse_confidence_score")
    abuseipdb_report_count = abuseipdb_data.get("reports")

    return {
        "type": "url",
        "entry": url,
        "hostname": urlparse(url if url.startswith("http") else f"http://{url}").hostname,
        "ip": url,
        "asn": "",
        "isp": "N/A",
        "country": "N/A",
        "detections": detections,
        "abuseipdb_confidence_score": abuseipdb_confidence_score,
        "abuseipdb_report_count": abuseipdb_report_count,
        "vt_key_used": mask_key(vt_data.get("vt_key_used")) if vt_data.get("vt_key_used") else None,

        "service_sources": {
            "asn": None,
            "isp": None,
            "country": None,
            "detections": "VirusTotal URL"
        },
        "status_codes": vt_data.get("status_codes", {}),
    }


# ✅ `handle_ip_lookup()` and `/download_excel` + `/` route are included in [next message] due to length...
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/get_ip_info", methods=["POST"])
def handle_ip_lookup():
    start = time.time()
    data = request.json
    entries = data.get("ips", [])
    client_name = data.get("client_name", "").strip()
    global used_services, unused_services, vt_keys_used, vt_keys_success, exhausted_other_keys
    global abuseipdb_keys_used, abuseipdb_keys_success, exhausted_abuseipdb_keys

    used_services.clear()
    unused_services.clear()
    vt_keys_used.clear()
    vt_keys_success.clear()
    exhausted_other_keys.clear()
    abuseipdb_keys_used.clear()
    abuseipdb_keys_success.clear()
    exhausted_abuseipdb_keys.clear()

    seen = set()
    valid_entries = []
    for entry in entries:
            e = entry.strip()
            if e in seen:
                continue
            seen.add(e)
            if is_valid_public_ip(e):
                valid_entries.append(e)
            elif normalized := is_valid_url(e):
                valid_entries.append(normalized)
            elif is_valid_hash(e):
                valid_entries.append(e)
            else:
                # Optionally log skipped invalid entries here
                continue

            if len(valid_entries) >= 100:
                break

    types = set()
    for e in valid_entries:
        if is_valid_public_ip(e):
            types.add("IP")
        else:
            types.add("URL")
    if types == {"IP"}:
        column_label = "IP"
    elif types == {"URL"}:
        column_label = "URL"
    else:
        column_label = "IP/URL"

    from tie_service import get_ip_tie_data, get_domain_tie_data, extract_enrichment_fields, get_actor_info_from_entry
    from concurrent.futures import ThreadPoolExecutor

    def serialize_field(value):
        if value is None:
            return None
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        if isinstance(value, dict):
            return ", ".join(f"{k}: {v}" for k, v in value.items())
        return str(value)

    def build_summary(data, entry_type, vt_keys_exhausted=False):
        print(f"DEBUG [build_summary]: {data.get('entry')}, vt_keys_exhausted={vt_keys_exhausted}")

        def is_meaningful(value):
            if value is None:
                return False
            if isinstance(value, str):
                return value.strip().lower() not in ("", "n/a", "-")
            return True

        ioc_parts = []
        for field, label in [
            ("threat_actor", "threat actor"),
            ("campaign_name", "campaign name"),
            ("malware_families", "malware family"),
            ("country_origin", "country origin"),
            ("target_sector", "target sector"),
            ("threat_category", "threat category"),
        ]:
            val = data.get(field)
            if is_meaningful(val):
                ioc_parts.append(f"{label}: {val}")
        ioc_summary = ""
        if ioc_parts:
            ioc_summary = f" IOC Details: The {'URL' if entry_type == 'url' else 'IP' if entry_type == 'ip' else 'Hash'} is associated with " + ", ".join(ioc_parts) + "."

        if entry_type == "url":
            categories = data.get("categories", [])
            category_str = f" Categories: {', '.join(categories)}." if categories else ""
            summary = (
                f"The URL: {data.get('entry')} has {data.get('detections', 0)} malicious detections."
                + category_str + ioc_summary
            )
        elif entry_type == "hash":
            summary = (
                f"The Hash: {data.get('entry')} has {data.get('detections', 0)} malicious detections."
                + ioc_summary
            )
        else:  # Default to IP
            abuse_score = data.get('abuseipdb_confidence_score')
            abuse_report_count = data.get('abuseipdb_report_count') or '0'
            abuseipdb_info = ""
            try:
                if abuse_score is not None and float(abuse_score) > 10:
                    abuseipdb_info = (f"  AbuseIPDB shows confidence of Abuse Score: {abuse_score}% "
                                    f"and it has been reported {abuse_report_count} times.")
            except (ValueError, TypeError):
                abuseipdb_info = ""

            detection_info = (
                f" with VirusTotal detection count of {data.get('detections', 0)}/95."
            ) if not vt_keys_exhausted else ""

            summary = (
                f"The IP: {data.get('entry')} belongs to ISP: {data.get('isp') or 'N/A'}, "
                f"from Country: {data.get('country') or 'N/A'}"
                + detection_info
                + abuseipdb_info
                + ioc_summary
            )
        return summary

    def resolve_entry(e, vt_keys_exhausted, client_name=client_name, timestamp_ist=None):
        session = SessionLocal()
        try:
            record = session.query(LookupData).filter_by(entry=e).first()
            now = timestamp_ist or datetime.now()
            if record:
                used_services.add("Database")
                data = {
                    "entry": record.entry,
                    "entry_type": record.entry_type,  # Add this line here
                    "isp": record.isp or "",
                    "asn": record.asn or "",
                    "country": record.country or "",
                    "detections": record.detection_count or 0,
                    "abuseipdb_confidence_score": getattr(record, "abuseipdb_confidence_score", None),
                    "abuseipdb_report_count": getattr(record, "abuseipdb_report_count", None),
                    "threat_actor": record.threat_actor or "-",
                    "campaign_name": record.campaign_name or "-",
                    "malware_families": record.malware_families or "-",
                    "country_origin": record.country_origin or "-",
                    "target_sector": record.target_sector or "-",
                    "threat_category": record.threat_category or "-",
                }
                print(f"DEBUG [resolve_entry]: {e}, vt_keys_exhausted={vt_keys_exhausted}")
                data["summary"] = build_summary(data, record.entry_type, vt_keys_exhausted=False)
                if data.get("entry_type") == "url" and data.get("entry"):
                    data["entry"] = data["entry"].lower()
                if not data.get("entry"):
                    data["entry"] = e
                if not data.get("entry"):
                    data["entry"] = e
                return data
            else:
                if is_valid_public_ip(e):
                    with ThreadPoolExecutor(max_workers=3) as executor:
                        vt_future = executor.submit(get_ip_info, e, vt_keys_exhausted=vt_keys_exhausted)
                        tie_future = executor.submit(get_ip_tie_data, e)
                        actor_info_future = executor.submit(get_actor_info_from_entry, e, "ip")
                        vt_result = vt_future.result() or {}
                        tie_result = tie_future.result()
                        actor_details = actor_info_future.result()
                    if tie_result and tie_result.get("data"):
                        enrichment = extract_enrichment_fields(tie_result)
                        used_services.add("ThreatIntel")
                    else:
                        enrichment = {k: None for k in
                                      ("threat_actor", "campaign_name", "malware_families", "country_origin",
                                       "target_sector", "threat_category")}
                    if actor_details:
                        enrichment.update({
                            "country_origin": actor_details.get("country_origin", enrichment.get("country_origin")),
                            "target_sector": actor_details.get("target_sector", enrichment.get("target_sector")),
                            "threat_category": actor_details.get("threat_category", enrichment.get("threat_category")),
                        })
                    if vt_result is None:
                        vt_result = {}
                    for key in [
                        "threat_actor",
                        "campaign_name",
                        "malware_families",
                        "country_origin",
                        "target_sector",
                        "threat_category"
                    ]:
                        enrichment_value = enrichment.get(key)
                        vt_result[key] = serialize_field(enrichment_value)
                    vt_result["entry_type"] = "ip"
                    if not vt_result.get("ip"):
                        vt_result["ip"] = e
                    if not vt_result.get("entry"):
                        vt_result["entry"] = e
                    print(f"DEBUG [resolve_entry]: {e}, vt_keys_exhausted={vt_keys_exhausted}")
                    vt_result["summary"] = build_summary(vt_result, "ip", vt_keys_exhausted=vt_keys_exhausted)
                    if vt_keys_exhausted:
                        vt_result["detections"] = None
                    return vt_result
                elif is_valid_url(e):
                    with ThreadPoolExecutor(max_workers=3) as executor:
                        vt_future = executor.submit(lookup_url, e)
                        tie_future = executor.submit(get_domain_tie_data, e)
                        actor_info_future = executor.submit(get_actor_info_from_entry, e, "url")
                        vt_result = vt_future.result() or {}
                        tie_result = tie_future.result()
                        actor_details = actor_info_future.result()
                    if tie_result and tie_result.get("data"):
                        used_services.add("ThreatIntel")
                        enrichment = extract_enrichment_fields(tie_result)
                    else:
                        enrichment = {k: None for k in
                                      ("threat_actor", "campaign_name", "malware_families", "country_origin",
                                       "target_sector", "threat_category")}
                    if actor_details:
                        enrichment.update({
                            "country_origin": actor_details.get("country_origin", enrichment.get("country_origin")),
                            "target_sector": actor_details.get("target_sector", enrichment.get("target_sector")),
                            "threat_category": actor_details.get("threat_category", enrichment.get("threat_category")),
                        })
                    if vt_result is None:
                        vt_result = {}
                    for key in [
                        "threat_actor",
                        "campaign_name",
                        "malware_families",
                        "country_origin",
                        "target_sector",
                        "threat_category"
                    ]:
                        enrichment_value = enrichment.get(key)
                        vt_result[key] = serialize_field(enrichment_value)
                    vt_result["entry_type"] = "url"
                    vt_result["summary"] = build_summary(vt_result, "url", vt_keys_exhausted=vt_keys_exhausted)
                    if vt_result.get("entry"):
                        vt_result["entry"] = vt_result["entry"].lower()
                    if not vt_result.get("ip"):
                        vt_result["ip"] = e
                    if not vt_result.get("entry"):
                        vt_result["entry"] = e
                    if vt_keys_exhausted:
                        vt_result["detections"] = None
                    return vt_result
                elif is_valid_hash(e):
                    with ThreadPoolExecutor(max_workers=3) as executor:
                        vt_future = executor.submit(get_hash_info, e)   # You must implement get_hash_info similar to others
                        tie_future = executor.submit(get_hash_tie_data, e)  # Similar for hash specific TIE data
                        actor_info_future = executor.submit(get_actor_info_from_entry, e, "hash")
                        vt_result = vt_future.result() or {}
                        tie_result = tie_future.result()
                        actor_details = actor_info_future.result()
                    
                    enrichment = extract_enrichment_fields(tie_result) if tie_result.get("data") else {k: None for k in THREAT_FIELDS}
                    if actor_details:
                        enrichment.update({k: actor_details.get(k, enrichment.get(k)) for k in THREAT_FIELDS})
                    for key in THREAT_FIELDS:
                        vt_result[key] = serialize_field(enrichment.get(key))
                    vt_result["entry_type"] = "hash"
                    vt_result.setdefault("entry", e)
                    vt_result["summary"] = build_summary(vt_result, "hash", vt_keys_exhausted=vt_keys_exhausted)
                    if vt_keys_exhausted:
                        vt_result["detections"] = None
                    return vt_result
                else:
                    return None
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=10) as executor_main:
        # First run with vt_keys_exhausted = False to perform all lookups and allow VT keys exhaustion updates
        futures = [executor_main.submit(resolve_entry, e, False) for e in valid_entries]
        results = [f.result() for f in futures]

    # Compute exhaustion status after all lookups complete
    vt_keys_exhausted = (len(exhausted_vt_keys) == len(VT_KEYS) and len(VT_KEYS) > 0)

    # Rebuild summaries with correct exhaustion flag in place
    for r in results:
        r["summary"] = build_summary(r, r.get("entry_type", "ip"), vt_keys_exhausted=vt_keys_exhausted)
        if vt_keys_exhausted:
            r["detections"] = None

    timestamp_ist = datetime.now(pytz.timezone("Asia/Kolkata"))

    raw_table = []
    for r in results:
        ip_or_url = r.get("entry") or r.get("ip") or "N/A"
        isp = r.get("isp", "")
        country = r.get("country", "")
        detections = r.get("detections")
        if detections is None:
            detections = "-"
        abuseipdb_confidence = str(r.get("abuseipdb_confidence_score", "-"))
        abuseipdb_report_count = str(r.get("abuseipdb_report_count", "-"))
        threat_actor = r.get("threat_actor", "-")
        country_origin = r.get("country_origin", "-")
        target_sector = r.get("target_sector", "-")
        threat_category = r.get("threat_category", "-")
        campaign_name = r.get("campaign_name", "-")
        malware_families = r.get("malware_families", "-")

        raw_table.append([
            ip_or_url,
            isp,
            country,
            detections,
            abuseipdb_confidence,
            abuseipdb_report_count,
            threat_actor,
            country_origin,
            target_sector,
            threat_category,
            campaign_name,
            malware_families
        ])

    for r in results:
        if r.get("used_service") != "Database":
            if vt_keys_exhausted:
                continue  # Skip updating DB for new entries if all VT keys exhausted
            upsert_lookup_data(r)

    for r in results:
        entry_type = r.get("entry_type", r.get("type", "IP"))
        if entry_type.lower() == "url":
            entry = r.get("entry") or r.get("ip")
        else:
            entry = r.get("ip")

        if not entry:
            safe_print(f"Skipping insert_search_event and upsert_search_log for missing entry in result: {r}")
            continue

        insert_search_event(entry, client_name, timestamp_ist, entry_type=entry_type)
        upsert_search_log(entry, client_name, timestamp_ist, entry_type=entry_type)

    has_url = any(r.get("entry_type") == "url" for r in results)
    no_data_ips = []
    for r in results:
        entry_type = r.get("entry_type")
        det = r.get("detections")
        isp_val, ctr_val = r.get("isp", ""), r.get("country", "")
        if entry_type == "url":
            if (det is None or det == 0) and not isp_val and not ctr_val:
                no_data_ips.append(r.get("ip") or r.get("entry"))
        elif entry_type == "hash":
            # For hashes, consider them no-data if detections missing or 0
            if (det is None or det == 0):
                no_data_ips.append(r.get("entry"))
        else:  # IP and fallback
            if not isp_val and not ctr_val:
                no_data_ips.append(r.get("ip") or r.get("entry"))


    summary_lines = []
    for i, r in enumerate(results):
        if i:
            summary_lines.append("")
        summary_lines.append(r.get("summary", ""))

    summary_text = "\n".join(summary_lines)
    elapsed = round(time.time() - start, 2)
    unused_services.update({"VirusTotal", "AbuseIPDB", "DBIP", "IPINFO", "APIVoid", "Database", "ThreatIntel"} - used_services)

    vt_ok = vt_keys_used & vt_keys_success
    vt_bad = exhausted_vt_keys.copy()

    safe_print("\n📊 API USAGE SUMMARY")
    safe_print(f"⏰ Search Timestamp (IST): {timestamp_ist}")
    safe_print(f"✅ Data found for {len(valid_entries)} entr{'y' if len(valid_entries) == 1 else 'ies'} in {elapsed} seconds.")
    safe_print(f"🔧 Services Used     : {', '.join(sorted(s for s in used_services if s)) or 'None'}")
    safe_print(f"🔧 Services Unused     : {', '.join(sorted(s for s in unused_services if s)) or 'None'}")
    safe_print(f"✅ Successfully Used VT Keys: {len(vt_ok)}")
    for k in vt_ok:
        safe_print(f"    {mask_key(k)}")
    safe_print(f"❌ Exhausted VT Keys: {len(vt_bad)}")
    for k in vt_bad:
        safe_print(f"    {mask_key(k)}")
    if exhausted_other_keys:
        safe_print("❌ Exhausted Other Services:", ", ".join(exhausted_other_keys))

    if len(vt_bad) > 10:
        safe_print("⚠️ Warning: More than 10 VT keys are exhausted. Consider rotating or refreshing your keys.")
    vt_unused = set(VT_KEYS) - (vt_keys_success | exhausted_vt_keys)
    safe_print(f"\n🟡 Unused VT Keys: {len(vt_unused)}")
    for k in vt_unused:
        safe_print(f"    {mask_key(k)}")

    abuseipdb_ok = abuseipdb_keys_used & abuseipdb_keys_success
    abuseipdb_bad = exhausted_abuseipdb_keys.copy()

    safe_print(f"\n✅ Successfully Used AbuseIPDB Keys: {len(abuseipdb_ok)}")
    for k in abuseipdb_ok:
        safe_print(f"    {mask_key(k)}")

    safe_print(f"\n❌ Exhausted AbuseIPDB Keys: {len(abuseipdb_bad)}")
    for k in abuseipdb_bad:
        safe_print(f"    {mask_key(k)}")

    abuseipdb_unused = set(ABUSEIPDB_KEYS) - (abuseipdb_keys_success | exhausted_abuseipdb_keys)
    safe_print(f"\n🟡 Unused AbuseIPDB Keys: {len(abuseipdb_unused)}")
    for k in abuseipdb_unused:
        safe_print(f"    {mask_key(k)}")

    safe_print("\nUsed API Keys:")
    if vt_ok:
        safe_print("  VT Keys:", ", ".join(mask_key(k) for k in vt_ok))
    if "AbuseIPDB" in used_services:
        safe_print("  AbuseIPDB Key:", ", ".join(mask_key(k) for k in abuseipdb_keys_used))
    if "DBIP" in used_services:
        safe_print("  DBIP Key:", mask_key(DBIP_KEY))
    if "IPINFO" in used_services:
        safe_print("  IPInfo Key:", mask_key(IPINFO_KEY))
    if "APIVoid" in used_services:
        safe_print("  APIVoid Key:", mask_key(APIVOID_KEY))

    safe_print("\n📋 Per Entry Summary:\n")
    for r in results:
        entry_value = r.get("entry") or r.get("entry")
        if not entry_value:
            continue


        service_sources = r.get("service_sources", {})
        main_parts = [
            f"ASN: {r.get('asn','N/A')} (from {service_sources.get('asn') or '—'})",
            f"ISP: {r.get('isp','N/A')} (from {service_sources.get('isp') or '—'})",
            f"Country: {r.get('country','N/A')} (from {service_sources.get('country') or '—'})",
            f"Detections: {r.get('detections',0)} (from {service_sources.get('detections') or '—'})",
            f"AbuseIPDB Confidence Score: {r.get('abuseipdb_confidence_score', '-')} (from AbuseIPDB)",
            f"AbuseIPDB Report Count: {r.get('abuseipdb_report_count', '-')} (from AbuseIPDB)\n"
        ]

        status_parts = [f"{svc}={code}" for svc, code in r.get("status_codes", {}).items()]

        safe_print()
        safe_print(
            f"[{entry_value}]  "
            + ";   ".join(main_parts)
            + "\n|  StatusCodes: " + ", ".join(status_parts)
        )
        safe_print()

    safe_print("----------------------------\n")
    
    exhausted_messages = []
    if len(exhausted_vt_keys) == len(VT_KEYS) and len(VT_KEYS) > 0:
        exhausted_messages.append("❌ All VirusTotal API keys are exhausted for the day.")

    if len(exhausted_abuseipdb_keys) == len(ABUSEIPDB_KEYS) and len(ABUSEIPDB_KEYS) > 0:
        exhausted_messages.append("❌ All AbuseIPDB API keys are exhausted for the day.")

    return jsonify({
        "summary": summary_text,
        "table": "",  # Generate HTML table outside if needed
        "raw_table": raw_table,
        "no_data_ips": no_data_ips,
        "services_used": sorted(used_services),
        "elapsed": elapsed,
        "per_ip_vt_keys": {r["entry"]: {
            "used_service": r.get("used_service"),
            "used_key": r.get("used_key"),
            "status_codes": r.get("status_codes", {})
            } for r in results if "entry" in r},
        "has_url": has_url,
        "column_label": column_label,
        "exhausted_messages": exhausted_messages
    })

@app.route("/download_excel", methods=["POST"])
def download_excel():
    data = request.get_json()
    table_data = data.get("table_data", [])
    summary_text = data.get("summary", "")
    column_label = data.get("column_label", "IP")

    wb = Workbook()
    ws_table = wb.active
    ws_table.title = "Lookup Data"

    headers = [
        column_label, "ISP", "Country", "Detections",
        "AbuseIPDB Confidence Score", "AbuseIPDB Report Count",
        "Threat Actor", "Country Of Origin", "Target Sector",
        "Threat Category", "Campaign Name", "Malware Families"
    ]
    ws_table.append(headers)

    for row in table_data:
        ip_or_url = row[0]
        isp = row[1]
        country = row[2]
        detections = row[3]
        abuseipdb_confidence = row[4]
        abuseipdb_report_count = row[5]
        threat_actor = row[6]
        country_origin = row[7]
        target_sector = row[8]
        threat_category = row[9]
        campaign_name = row[10]
        malware_families = row[11]

        ws_table.append([
            ip_or_url, isp, country, detections,
            abuseipdb_confidence, abuseipdb_report_count,
            threat_actor, country_origin, target_sector,
            threat_category, campaign_name, malware_families
        ])

    # Formatting: bold headers, center-align, border, and autosize columns
    from openpyxl.styles import Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    bold_font = Font(bold=True)
    center_align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    thin_border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin"),
    )

    for row_cells in ws_table.iter_rows():
        for cell in row_cells:
            cell.alignment = center_align
            cell.border = thin_border
            if cell.row == 1:
                cell.font = bold_font

    for col_cells in ws_table.columns:
        max_length = max(len(str(cell.value)) if cell.value else 0 for cell in col_cells)
        col_letter = get_column_letter(col_cells[0].column)
        ws_table.column_dimensions[col_letter].width = max(12, min(max_length + 4, 50))

    # Add summary sheet
    ws_summary = wb.create_sheet("Summary")
    ws_summary["A1"] = "Scan Summary"
    ws_summary["A1"].font = Font(size=14, bold=True)
    ws_summary["A2"] = summary_text.strip()
    ws_summary["A2"].alignment = Alignment(wrap_text=True, vertical="top")
    ws_summary.column_dimensions["A"].width = 100

    import io
    from flask import send_file

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
    app.run(host="0.0.0.0", port=5000, debug=False)  # Adjust port and debug as needed