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
APIVOID_KEYS = [key.strip() for key in os.getenv("APIVOID_API_KEYS", "").split(",") if key.strip()]

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

# Add ApiVoid keys variables (similar structure)
apivoid_key_index = 0
apivoid_key_lock = threading.Lock()
exhausted_apivoid_keys = set()
apivoid_keys_used = set()
apivoid_keys_success = set()

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
        entry_type = result.get("entry_type", result.get("type", "IP"))
        if entry_type:
            entry_type = entry_type.lower()
        else:
            entry_type = "ip"  # Default fallback

        # Use correct source field
        if entry_type == "url":
            entry = (result.get("entry") or "").strip().lower()
            if not entry:
                return  # don't insert when we have no valid URL/domain
        else:
            entry = (result.get("entry") or "").strip()
            if not entry:
                return  # don't insert when we have no valid IP/hash

        # Extract standard enrichment fields
        isp = result.get("isp", "")
        asn = result.get("asn", "")
        country = result.get("country", "")
        detection_count = result.get("detections", 0)

        # New enrichment fields
        threat_actor = result.get("threat_actor")
        campaign_name = result.get("campaign_name")
        malware_families = result.get("malware_families")

        country_origin = result.get("country_origin")
        target_sector = result.get("target_sector")
        threat_category = result.get("threat_category")

        abuseipdb_confidence_score = result.get("abuseipdb_confidence_score")
        abuseipdb_report_count = result.get("abuseipdb_report_count")
        apivoid_risk_score = result.get("apivoid_risk_score")
        apivoid_blacklist_detections = result.get("apivoid_blacklist_detections")

        details_json = result.get("details_json")  # New JSONB enrichment data container

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
                threat_category=threat_category,
                details_json=details_json,  # Store JSONB data here
                apivoid_risk_score=apivoid_risk_score,
                apivoid_blacklist_detections=apivoid_blacklist_detections
            )
            session.add(new)
            session.commit()
    except Exception:
        session.rollback()
        raise
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

def get_next_apivoid_key():
    global apivoid_key_index
    with apivoid_key_lock:
        for _ in range(len(APIVOID_KEYS)):
            key = APIVOID_KEYS[apivoid_key_index % len(APIVOID_KEYS)]
            apivoid_key_index += 1
            if key and key not in exhausted_apivoid_keys:
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
# AbuseIPDB entry with Rate-Limit Handling
# -------------------------------
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
            "detections": None,
            "abuseipdb_confidence_score": None,
            "abuseipdb_report_count": None,
            "apivoid_risk_score": None,
            "apivoid_blacklist_detections": None
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
                abuseipdb_keys_used.add(key)
                if resp.status_code == 429:
                    exhausted_abuseipdb_keys.add(key)
                    continue
                if resp.status_code in (401, 403):
                    exhausted_abuseipdb_keys.add(key)
                    continue
                if resp.status_code != 200:
                    return {}, None
        
                abuseipdb_keys_success.add(key)
                used_services.add("AbuseIPDB")
                return resp.json().get("data", {}), key
            except Exception:
                ip_info["status_codes"]["AbuseIPDB"] = "Error"
                exhausted_abuseipdb_keys.add(key)
                return {}, None
        return None, None

    def call_apivoid():
        for _ in range(len(APIVOID_KEYS)):
            apivoid_key = get_next_apivoid_key()
            if not apivoid_key:
                return None, None, None
            headers = {"Content-Type": "application/json", "X-API-Key": apivoid_key}
            try:
                resp = requests.post(
                    "https://api.apivoid.com/v2/ip-reputation",
                    json={"ip": ip},
                    headers=headers,
                    timeout=10
                )
                ip_info["status_codes"]["APIVoid"] = resp.status_code
                apivoid_keys_used.add(apivoid_key)
                print(apivoid_key)
                if resp.status_code == 200:
                    data = resp.json()
                    
                    apivoid_keys_success.add(apivoid_key)
                    used_services.add("APIVoid")
                    return data, apivoid_key, resp.status_code
                elif resp.status_code in (401, 403, 429):
                    exhausted_apivoid_keys.add(apivoid_key)
                    continue
            except Exception:
                ip_info["status_codes"]["APIVoid"] = "Error"
                exhausted_apivoid_keys.add(apivoid_key)
                return None, apivoid_key, "Error"
        return None, None, None

    with ThreadPoolExecutor(max_workers=3) as executor:
        vt_future = executor.submit(call_virustotal)
        abuseipdb_future = executor.submit(call_abuseipdb)
        apivoid_future = executor.submit(call_apivoid)

        vt_result, vt_key = vt_future.result()
        abuseipdb_result, abuseipdb_key = abuseipdb_future.result()
        apivoid_result, apivoid_key, apivoid_status = apivoid_future.result()

    # VirusTotal results processing
    if vt_result:
        det_vt = 0 if vt_keys_exhausted else vt_result.get("last_analysis_stats", {}).get("malicious", 0) or 0
        ip_info["detections"] = det_vt
        asn_vt = vt_result.get("asn", "")
        isp_vt = vt_result.get("as_owner", "")
        ctr_vt = vt_result.get("country", "")
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

    # AbuseIPDB results processing
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
        if abuseipdb_result.get("abuseConfidenceScore") is not None:
            ip_info["service_sources"]["abuseipdb_confidence_score"] = "AbuseIPDB"
        if abuseipdb_result.get("totalReports") is not None:
            ip_info["service_sources"]["abuseipdb_report_count"] = "AbuseIPDB"
        if ip_info["used_service"] != "VirusTotal":
            ip_info["used_service"] = "AbuseIPDB"
            ip_info["used_key"] = abuseipdb_key

    # APIVoid results processing
    if apivoid_result:
        
        risk_score = apivoid_result.get("risk_score", {}).get("result")
        blacklist_detections = apivoid_result.get("blacklists", {}).get("detections", 0)
        country = apivoid_result.get("information", {}).get("country_name", "")

        ip_info["apivoid_risk_score"] = risk_score
        ip_info["apivoid_blacklist_detections"] = blacklist_detections

        if country and not ip_info["country"]:
            ip_info["country"] = country
            ip_info["service_sources"]["country"] = "APIVoid"

        if ip_info["used_service"] not in ("VirusTotal", "AbuseIPDB"):
            ip_info["used_service"] = "APIVoid"
            ip_info["used_key"] = apivoid_key
        
        if risk_score is not None:
            ip_info["service_sources"]["apivoid_risk_score"] = "APIVoid"
        if blacklist_detections is not None:
            ip_info["service_sources"]["apivoid_blacklist_detections"] = "APIVoid"

    return ip_info

def parse_hash_enrichment(source_data):
    def safe_get(d, *keys, default=None):
        for key in keys:
            d = d.get(key, {})
            if not isinstance(d, dict):
                return d if d else default
        return default

    # Extract malicious detections
    detections = safe_get(source_data, "last_analysis_stats", "malicious", default=0)

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
    file_name = source_data.get("meaningful_name") or (source_data.get("names")[0] if source_data.get("names") else None)
    malicious_engines = [k for k, v in source_data.get("last_analysis_results", {}).items() if v.get("category") == "malicious"]
    first_seen = source_data.get("first_submission_date")
    last_seen = source_data.get("last_submission_date")
    reputation = source_data.get("reputation")

    return {
        "detections": detections,
        "popular_threat_label": popular_threat_label,
        "size": size,
        "file_name": file_name,
        "malicious_engines": malicious_engines,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "reputation": reputation
    }


def get_hash_info(hash_value, vt_keys_exhausted=False):
    hash_info = {
        "entry": hash_value,
        "detections": 0,
        "used_service": "",
        "used_key": "",
        "status_codes": {},
        "service_sources": {"detections": None},
        "details_json": None
    }

    def call_virustotal():
        for _ in range(len(VT_KEYS)):
            vt_key = get_next_vt_key()
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
        parsed = parse_hash_enrichment(vt_result)
        
        hash_info.update({
            "detections": parsed["detections"],
            "service_sources": {"detections": "VirusTotal"},
            "used_service": "VirusTotal",
            "used_key": vt_key,
            "details_json": vt_result,
            "popular_threat_label": parsed.get("popular_threat_label"),
            "size": parsed.get("size"),
            "file_name": parsed.get("file_name"),
            "malicious_engines": parsed.get("malicious_engines"),
            "first_seen": parsed.get("first_seen"),
            "last_seen": parsed.get("last_seen"),
            "reputation": parsed.get("reputation"),
        })
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

def call_apivoid_url(url):
    for _ in range(len(APIVOID_KEYS)):
        apivoid_key = get_next_apivoid_key()
        if not apivoid_key:
            return None, None
        headers = {"Content-Type": "application/json", "X-API-Key": apivoid_key}
        try:
            resp = requests.post(
                "https://api.apivoid.com/v2/domain-reputation",
                json={"host": url},
                headers=headers,
                timeout=10
            )
            apivoid_keys_used.add(apivoid_key)
            if resp.status_code == 200:
                apivoid_keys_success.add(apivoid_key)
                used_services.add("APIVoid")
                return resp.json(), apivoid_key

            elif resp.status_code in (401, 429, 403):
                exhausted_apivoid_keys.add(apivoid_key)
                continue
        except Exception:
            exhausted_apivoid_keys.add(apivoid_key)
            return None, apivoid_key
    return None, None


def lookup_url(url):
    """Perform parallel URL reputation queries using VirusTotal, AbuseIPDB, and APIVoid."""
    with ThreadPoolExecutor(max_workers=3) as executor:
        vt_future = executor.submit(fetch_virustotal_url_data, url)
        abuseipdb_future = executor.submit(entryabuseipdburl, url)
        apivoid_future = executor.submit(call_apivoid_url, url)

        vt_data = vt_future.result() or {}
        abuseipdb_data = abuseipdb_future.result() or {}
        apivoid_data, apivoid_key = apivoid_future.result() or ({}, None)

    used_services.update(["VirusTotal", "AbuseIPDB", "APIVoid"])

    detections = vt_data.get("detections") or 0
    abuseipdb_confidence_score = abuseipdb_data.get("abuse_confidence_score")
    abuseipdb_report_count = abuseipdb_data.get("reports")

    # Parse APIVoid-specific details, adjusting keys as per confirmed JSON structure
    risk_score = apivoid_data.get("risk_score", {}).get("result")
    blacklist_detections = apivoid_data.get("domain_blacklist", {}).get("detections", 0)
    engine_count = apivoid_data.get("domain_blacklist", {}).get("engines_count", 0)
    asn = apivoid_data.get("server_details", {}).get("asn", "")
    isp = apivoid_data.get("server_details", {}).get("isp", "")
    country = apivoid_data.get("server_details", {}).get("country_name", "")
    server_ip = apivoid_data.get("server_details", {}).get("ip", "")

    return {
        "type": "url",
        "entry": url,
        "hostname": urlparse(url if url.startswith("http") else f"http://{url}").hostname,
        "ip": server_ip or url,
        "asn": asn,
        "isp": isp or "N/A",
        "country": country or "N/A",
        "detections": detections,
        "abuseipdb_confidence_score": abuseipdb_confidence_score,
        "abuseipdb_report_count": abuseipdb_report_count,
        "apivoid_risk_score": risk_score,
        "apivoid_blacklist_detections": blacklist_detections,
        "apivoid_blacklist_engines": engine_count,
        "vt_key_used": mask_key(vt_data.get("vt_key_used")) if vt_data.get("vt_key_used") else None,
        "apivoid_key_used": mask_key(apivoid_key) if apivoid_key else None,
        "service_sources": {
            "asn": "APIVoid" if asn else None,
            "isp": "APIVoid" if isp else None,
            "country": "APIVoid" if country else None,
            "detections": "VirusTotal URL"
        },
        "status_codes": {
            "VirusTotal": vt_data.get("status_codes", {}).get("VirusTotal"),
            "AbuseIPDB": abuseipdb_data.get("status_codes", {}).get("AbuseIPDB"),
            "APIVoid": apivoid_data.get("status_code", 200)
        },
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
    global apivoid_keys_used, apivoid_keys_success, exhausted_apivoid_keys
    apivoid_keys_used.clear()
    apivoid_keys_success.clear()
    exhausted_apivoid_keys.clear()

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
        elif is_valid_url(e):
            types.add("URL")
        elif is_valid_hash(e):
            types.add("HASH")
        else:
            # Optionally handle invalid entries if needed
            pass

    if types == {"IP"}:
        column_label = "IP"
    elif types == {"URL"}:
        column_label = "URL"
    elif types == {"HASH"}:
        column_label = "HASH"
    elif types == {"IP", "URL"}:
        column_label = "IP/URL"
    elif types == {"IP", "HASH"}:
        column_label = "IP/HASH"
    elif types == {"URL", "HASH"}:
        column_label = "URL/HASH"
    else:
        # Mixed of all three or other combinations
        column_label = "IP/URL/HASH"


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
        def is_meaningful(value):
            if value is None:
                return False
            if isinstance(value, str):
                return value.strip().lower() not in ("", "n/a", "-")
            return True

        # Merge details_json fields into main dict if present
        details = data.get("details_json") or {}
        if details:
            for key in ["popular_threat_label", "size", "malicious_engines", "file_name", "first_seen", "last_seen", "reputation"]:
                if key not in data or not is_meaningful(data.get(key)):
                    data[key] = details.get(key)

        ioc_parts = []
        apivoid_parts = []
        if data.get("apivoid_risk_score") is not None and apivoid_risk_score> 0:
            apivoid_parts.append(f"APIVoid shows risk score of : {data['apivoid_risk_score']} .")
        #if data.get("apivoid_blacklist_detections") is not None and data.get("apivoid_blacklist_detections") > 0:
            #apivoid_parts.append(f" and detection count of : {data['apivoid_blacklist_detections']}.")

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
        apivoid_summary = ""
        if apivoid_parts:
            apivoid_summary = f" " + ", ".join(apivoid_parts) 

        vt_detections = data.get('detections', 0) if not vt_keys_exhausted else 0
        apivoid_detections = data.get('apivoid_blacklist_detections', 0) or 0

        max_detections = max(vt_detections, apivoid_detections)
            
        if entry_type == "url":
            categories = data.get("categories", [])
            category_str = f" Categories: {', '.join(categories)}." if categories else ""
            summary = (
                f"The URL: {data.get('entry')} has {max_detections} malicious detections."
                + apivoid_summary
                + category_str + ioc_summary
            )
        elif entry_type == "hash":
            threat_label_str = f" with threat labels: '{data.get('popular_threat_label')}'." if is_meaningful(data.get('popular_threat_label')) else ""
            size_str = f" The file size is {data.get('size', 'N/A')} bytes" if data.get('size') else ""
            file_name_str = f" with commonly known file name as '{data.get('file_name')}'." if is_meaningful(data.get('file_name')) else ""

            # malicious_engines = data.get('malicious_engines') or []
            # if isinstance(malicious_engines, list) and malicious_engines:
            #     engines_str = " Detected as malicious by antivirus engines: " + ", ".join(malicious_engines) + "."
            # else:
            #     engines_str = ""

            # first_seen_str = ""
            # if data.get("first_seen"):
            #     first_seen_str = f" First seen: {datetime.fromtimestamp(data['first_seen']).strftime('%Y-%m-%d')}."
            # last_seen_str = ""
            # if data.get("last_seen"):
            #     last_seen_str = f" Last seen: {datetime.fromtimestamp(data['last_seen']).strftime('%Y-%m-%d')}."
            # reputation_str = ""
            # if is_meaningful(data.get("reputation")):
            #     reputation_str = f" Reputation score: {data.get('reputation')}."

            summary = (
                f"The Hash: {data.get('entry')} has {max_detections} malicious detections"
                + threat_label_str + size_str + file_name_str + ioc_summary#+ engines_str 
                #+ first_seen_str + last_seen_str + reputation_str
            )
        else:  # Default to IP
            abuse_score = data.get('abuseipdb_confidence_score')
            abuse_report_count = data.get('abuseipdb_report_count') or '0'
            abuseipdb_info = ""
            try:
                if abuse_score is not None and float(abuse_score) > 10:
                    abuseipdb_info = (f" AbuseIPDB shows confidence of Abuse Score: {abuse_score}% "
                                    f"and it has been reported {abuse_report_count} times.")
            except (ValueError, TypeError):
                abuseipdb_info = ""

            vt_detections = data.get('detections', 0) if not vt_keys_exhausted else 0
            apivoid_detections = data.get('apivoid_blacklist_detections', 0) or 0

            max_detections = max(vt_detections, apivoid_detections)

            detection_info = (
                f" with detection count of {max_detections}/95."
            ) if not vt_keys_exhausted else ""

            summary = (
                f"The IP: {data.get('entry')} belongs to ISP: {data.get('isp') or 'N/A'}, "
                f"from Country: {data.get('country') or 'N/A'}"
                + detection_info
                + apivoid_summary
                + abuseipdb_info
                + ioc_summary
            )
        return summary

    def resolve_entry(e, vt_keys_exhausted, client_name=client_name, timestamp_ist=None):
        session = SessionLocal()
        data = {}
        try:
            record = session.query(LookupData).filter_by(entry=e).first()
            now = timestamp_ist or datetime.now()
            if record:
                used_services.add("Database")
                data = {
                    "entry": record.entry,
                    "entry_type": record.entry_type or "unknown",
                    "isp": record.isp or "",
                    "asn": record.asn or "",
                    "country": record.country or "",
                    "detections": record.detection_count or 0,
                    "apivoid_risk_score": getattr(record, "apivoid_risk_score", None),
                    "apivoid_blacklist_detections": getattr(record, "apivoid_blacklist_detections", None),
                    "abuseipdb_confidence_score": getattr(record, "abuseipdb_confidence_score", None),
                    "abuseipdb_report_count": getattr(record, "abuseipdb_report_count", None),
                    "threat_actor": record.threat_actor or "-",
                    "campaign_name": record.campaign_name or "-",
                    "malware_families": record.malware_families or "-",
                    "country_origin": record.country_origin or "-",
                    "target_sector": record.target_sector or "-",
                    "threat_category": record.threat_category or "-",
                    "details_json": record.details_json or None,
                }
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
                        enrichment = extract_enrichment_fields(tie_result,"ip")
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
                    data = vt_result
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
                        enrichment = extract_enrichment_fields(tie_result,"url")
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
                    data = vt_result
                elif is_valid_hash(e):
                    with ThreadPoolExecutor(max_workers=3) as executor:
                        vt_future = executor.submit(get_hash_info, e)
                        tie_future = executor.submit(get_hash_tie_data, e)
                        actor_info_future = executor.submit(get_actor_info_from_entry, e, "hash")
                        vt_result = vt_future.result() or {}
                        tie_result = tie_future.result()
                        actor_details = actor_info_future.result()
                    enrichment = extract_enrichment_fields(tie_result,"hash") if tie_result.get("data") else {k: None for k in THREAT_FIELDS}
                    if actor_details:
                        enrichment.update({k: actor_details.get(k, enrichment.get(k)) for k in THREAT_FIELDS})
                    for key in THREAT_FIELDS:
                        vt_result[key] = serialize_field(enrichment.get(key))
                    vt_result["entry_type"] = "hash"
                    vt_result.setdefault("entry", e)
                    vt_result["summary"] = build_summary(vt_result, "hash", vt_keys_exhausted=vt_keys_exhausted)
                    if vt_keys_exhausted:
                        vt_result["detections"] = None
                    data = vt_result
                else:
                    data = {}
        finally:
            session.close()

        if data.get("entry_type") == "hash" and data.get("details_json"):
            parsed = parse_hash_enrichment(data["details_json"])
            data["detections"] = parsed.get("detections", data.get("detections", 0))
            data.update(parsed)

        data["summary"] = build_summary(data, data.get("entry_type", "unknown"), vt_keys_exhausted=vt_keys_exhausted)
        if data.get("entry_type") == "url" and data.get("entry"):
            data["entry"] = data["entry"].lower()
        if not data.get("entry"):
            data["entry"] = e

        return data

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
        apivoid_risk_score = str(r.get("apivoid_risk_score", "-"))
        apivoid_blacklist_detections = str(r.get("apivoid_blacklist_detections", "-"))
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
            apivoid_risk_score,
            apivoid_blacklist_detections,
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
        entry_type = r.get("entry_type") or r.get("type")
        if not entry_type:
            entry_type = "unknown"
        entry_type = entry_type.lower()
        
        if entry_type == "url":
            entry = r.get("entry") or r.get("ip")
        else:
            entry = r.get("entry") or r.get("ip")  # Use r.get("entry") as primary for hash and IP
        
        if not entry:
            safe_print(f"Skipping insert_search_event and upsert_search_log for missing entry in result: {r}")
            continue

        # Only skip entirely unknown types if you want
        if entry_type not in {"ip", "url", "hash"}:
            safe_print(f"Skipping unrecognized entry_type '{entry_type}' for entry: {entry}")
            continue

        insert_search_event(entry, client_name, timestamp_ist, entry_type=entry_type)
        upsert_search_log(entry, client_name, timestamp_ist, entry_type=entry_type)


    has_url = any(r.get("entry_type") == "url" for r in results)
    no_data_ips = []
    for r in results:
        entry_type = r.get("entry_type")
        det = r.get("detections")
        
        # For IPs, get ISP and country to decide no-data
        isp_val, ctr_val = r.get("isp", ""), r.get("country", "")
        print(f" {r.get('entry_type')}, detections={det}")
        if entry_type == "url":
            # For URL: no detailed info other than detection, so only check if detection is missing or None
            if det is None:
                no_data_ips.append(r.get("ip") or r.get("entry"))
        elif entry_type == "hash":
            # For hash: detection missing or None means no data
            
            if det is None:
                no_data_ips.append(r.get("entry"))
        else:
            # For IP: no other detail fields, so check if isp and country missing to capture no data condition
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
    vt_unused = set(VT_KEYS) - (vt_keys_used)
    safe_print(f"\n🟡 Unused VT Keys: {len(vt_unused)}")
    for k in vt_unused:
        safe_print(f"    {mask_key(k)}")

    apivoid_ok = apivoid_keys_used & apivoid_keys_success if 'apivoid_keys_used' in globals() and 'apivoid_keys_success' in globals() else set()
    apivoid_bad = exhausted_apivoid_keys.copy() if 'exhausted_apivoid_keys' in globals() else set()

    safe_print(f"\n✅ Successfully Used APIVoid Keys: {len(apivoid_ok)}")
    for k in sorted(apivoid_ok):
        safe_print(f"    {mask_key(k)}")

    safe_print(f"\n❌ Exhausted APIVoid Keys: {len(apivoid_bad)}")
    for k in sorted(apivoid_bad):
        safe_print(f"    {mask_key(k)}")
    
    safe_print(f"\n✅  APIVoid Keys tried: {len(apivoid_keys_used)}")
    for k in sorted(apivoid_keys_used):
        safe_print(f"    {mask_key(k)}")

    apivoid_unused = set(APIVOID_KEYS) - (apivoid_keys_used) 
    safe_print(f"\n🟡 Unused APIVoid Keys: {len(apivoid_unused)}")
    for k in sorted(apivoid_unused):
        safe_print(f"    {mask_key(k)}")

    abuseipdb_ok = abuseipdb_keys_used & abuseipdb_keys_success
    abuseipdb_bad = exhausted_abuseipdb_keys.copy()

    safe_print(f"\n✅ Successfully Used AbuseIPDB Keys: {len(abuseipdb_ok)}")
    for k in abuseipdb_ok:
        safe_print(f"    {mask_key(k)}")

    safe_print(f"\n❌ Exhausted AbuseIPDB Keys: {len(abuseipdb_bad)}")
    for k in abuseipdb_bad:
        safe_print(f"    {mask_key(k)}")

    abuseipdb_unused = set(ABUSEIPDB_KEYS) - (abuseipdb_keys_used)
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
        safe_print("  APIVoid Key:", ", ".join(mask_key(k) for k in apivoid_ok))

    safe_print("\n📋 Per Entry Summary:\n")
    for r in results:
        entry_value = r.get("entry") or r.get("entry")
        if not entry_value:
            continue

        service_sources = r.get("service_sources", {})
        
        # Helper function to get source label
        def get_source(field_name):
            """Returns service source or 'database' as fallback"""
            return service_sources.get(field_name) or 'database'
        
        main_parts = [
            f"ASN: {r.get('asn','N/A')} (from {get_source('asn')})",
            f"ISP: {r.get('isp','N/A')} (from {get_source('isp')})",
            f"Country: {r.get('country','N/A')} (from {get_source('country')})",
            f"Detections: {r.get('detections',0)} (from {get_source('detections')})",
            f"APIVoid Risk Score: {r.get('apivoid_risk_score', '-')} (from {get_source('apivoid_risk_score')})",
            f"APIVoid Blacklist Detections: {r.get('apivoid_blacklist_detections', '-')} (from {get_source('apivoid_blacklist_detections')})",
            f"AbuseIPDB Confidence Score: {r.get('abuseipdb_confidence_score', '-')} (from {get_source('abuseipdb_confidence_score')})",
            f"AbuseIPDB Report Count: {r.get('abuseipdb_report_count', '-')} (from {get_source('abuseipdb_report_count')})\n"
        ]

        status_codes = r.get("status_codes", {}).copy()
    
        # Check if any data came from database
        if any(get_source(field) == 'database' for field in ['asn', 'isp', 'country', 'detections', 
                                                            'apivoid_risk_score', 'apivoid_blacklist_detections',
                                                            'abuseipdb_confidence_score', 'abuseipdb_report_count']):
            status_codes['database'] = 200
        
        status_parts = [f"{svc}={code}" for svc, code in status_codes.items()]

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
        
    if len(exhausted_apivoid_keys) == len(APIVOID_KEYS) and len(APIVOID_KEYS) > 0:
        exhausted_messages.append("❌ All APIVOID API keys are exhausted for the day.")

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
        "APIVoid Risk Score",
        "APIVoid Blacklist Detections",
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
        apivoid_risk_score = row[4]               # New APIVoid field index
        apivoid_blacklist_detections = row[5]    # New APIVoid field index
        abuseipdb_confidence = row[6]
        abuseipdb_report_count = row[7]
        threat_actor = row[8]
        country_origin = row[9]
        target_sector = row[10]
        threat_category = row[11]
        campaign_name = row[12]
        malware_families = row[13]

        ws_table.append([
            ip_or_url, isp, country, detections,
            apivoid_risk_score, apivoid_blacklist_detections, # Include APIVoid fields here
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