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

# Number of IOCs processed simultaneously
IOC_MAX_WORKERS = 6

# Service workers.
# VT, APIVoid and AbuseIPDB can now run in parallel for the same IOC.
SERVICE_MAX_WORKERS = 18

VT_MAX, APIVOID_MAX, ABUSE_MAX = 8, 8, 6

# Maximum number of attempts when a key returns 429.
# The first key + one additional key only.
RATE_LIMIT_MAX_ATTEMPTS = 2

vt_semaphore = Semaphore(VT_MAX)
apivoid_semaphore = Semaphore(APIVOID_MAX)
abuse_semaphore = Semaphore(ABUSE_MAX)

vt_lock = Lock()
apivoid_lock = Lock()
abuse_lock = Lock()
services_lock = Lock()

# =========================
# API KEYS
# =========================
VT_API_KEYS = [
    k.strip()
    for k in os.getenv("VT_API_KEYS", "").split(",")
    if k.strip()
]

APIVOID_KEYS = [
    k.strip()
    for k in os.getenv("APIVOID_API_KEYS", "").split(",")
    if k.strip()
]

ABUSEIPDB_KEYS = [
    k.strip()
    for k in os.getenv("ABUSEIPDB_API_KEYS", "").split(",")
    if k.strip()
]

vt_index = 0
apivoid_index = 0
abuse_index = 0

# exhausted_messages = ""

# =========================
# SESSION
# =========================
session = requests.Session()

adapter = requests.adapters.HTTPAdapter(
    pool_connections=50,
    pool_maxsize=50
)

session.mount("https://", adapter)

country_cache = {}
country_cache_lock = Lock()

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
    return bool(
        re.fullmatch(
            r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}",
            entry
        )
    )


def is_url(entry):
    try:
        parsed = urlparse(
            entry if entry.startswith("http") else f"http://{entry}"
        )
        return bool(
            parsed.hostname and "." in parsed.hostname
        )
    except Exception:
        return False


def get_type(entry):
    return (
        "IP" if is_ip(entry)
        else "HASH" if is_hash(entry)
        else "URL" if is_url(entry)
        else None
    )


def mask_key(key):
    if not key:
        return "None"

    if len(key) <= 8:
        return "*" * len(key)

    return key[:4] + "..." + key[-4:]


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
    except Exception:
        return code


# =========================
# VALUE HELPERS
# =========================
def has_value(value):
    """
    Determines whether a field contains useful data.

    Values such as None, "", "-", "null" and "unknown"
    are treated as missing.
    """
    if value is None:
        return False

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return False

        if value.lower() in {
            "-",
            "null",
            "none",
            "n/a",
            "na",
            "unknown"
        }:
            return False

    return True


def first_valid_value(*values):
    """
    Returns the first usable value.

    Priority:
    VT -> APIVoid -> AbuseIPDB
    """
    for value in values:
        if has_value(value):
            return value

    return "-"


# =========================
# KEY ROTATION
# =========================
def rotate_key(keys, service):
    global vt_index, apivoid_index, abuse_index

    if not keys:
        return None

    lock_map = {
        "vt": vt_lock,
        "apivoid": apivoid_lock,
        "abuse": abuse_lock
    }

    index_map = {
        "vt": vt_index,
        "apivoid": apivoid_index,
        "abuse": abuse_index
    }

    with lock_map[service]:

        current_index = index_map[service]

        key = keys[current_index]

        if service == "vt":
            vt_index = (current_index + 1) % len(keys)

        elif service == "apivoid":
            apivoid_index = (current_index + 1) % len(keys)

        elif service == "abuse":
            abuse_index = (current_index + 1) % len(keys)

        return key


def build_key_list(system_keys, user_key):
    """
    User supplied key gets priority.

    If no user key was supplied, only system keys are used.

    Duplicate keys are removed.
    """
    keys = []

    if user_key and user_key.strip():
        keys.append(user_key.strip())

    for key in system_keys:
        if key and key not in keys:
            keys.append(key)

    return keys


# =========================
# API KEY ERROR HANDLING
# =========================
def record_key_error(
    key_errors,
    service,
    key,
    status_code
):
    key_errors.append({
        "service": service,
        "key": mask_key(key),
        "status_code": status_code
    })


# =========================
# VIRUSTOTAL LOOKUP
# =========================
def vt_lookup(
    entry,
    exhausted_messages,
    user_key=None,
    key_errors=None
):
    with vt_semaphore:

        keys = build_key_list(
            VT_API_KEYS,
            user_key
        )

        if not keys:
            return None

        # User key + system keys are attempted in order.
        #
        # 40x errors other than 429:
        # try another key.
        #
        # 429:
        # try only one additional key.
        #
        # This prevents endless retries.
        max_attempts = len(keys)

        attempted = 0

        for key in keys:

            attempted += 1

            if attempted > max_attempts:
                break

            headers = {
                "x-apikey": key
            }

            try:

                if is_hash(entry):

                    url = (
                        f"https://www.virustotal.com/"
                        f"api/v3/files/{entry}"
                    )

                elif is_ip(entry):

                    url = (
                        f"https://www.virustotal.com/"
                        f"api/v3/ip_addresses/{entry}"
                    )

                else:

                    encoded = (
                        base64.urlsafe_b64encode(
                            normalize_url(entry).encode()
                        )
                        .decode()
                        .strip("=")
                    )

                    url = (
                        f"https://www.virustotal.com/"
                        f"api/v3/urls/{encoded}"
                    )

                r = session.get(
                    url,
                    headers=headers,
                    timeout=15
                )

                # =========================
                # RATE LIMIT
                # =========================
                if r.status_code == 429:

                    exhausted_messages.append(
                        f"VirusTotal API key "
                        f"{mask_key(key)} exhausted."
                    )

                    # Only one additional key after a 429.
                    if attempted < min(
                        len(keys),
                        RATE_LIMIT_MAX_ATTEMPTS
                    ):
                        continue

                    return None

                # =========================
                # OTHER 4xx / API ERRORS
                # =========================
                if r.status_code != 200:

                    print(
                        f"VT lookup failed for {entry}: "
                        f"HTTP {r.status_code} "
                        f"using key {mask_key(key)}"
                    )

                    if key_errors is not None:
                        record_key_error(
                            key_errors,
                            "VirusTotal",
                            key,
                            r.status_code
                        )

                    # Try the next available key.
                    continue

                attr = (
                    r.json()
                    .get("data", {})
                    .get("attributes", {})
                )

                stats = attr.get(
                    "last_analysis_stats",
                    {}
                )

                result = {
                    "vt_detections": stats.get("malicious"),
                    "isp": attr.get("as_owner"),
                    "country": get_country(
                        attr.get("country")
                    )
                }

                if is_hash(entry):

                    ptc = (
                        attr.get(
                            "popular_threat_classification"
                        )
                        or {}
                    )

                    labels = [
                        c.get("value")
                        for c in (
                            ptc.get(
                                "popular_threat_category"
                            )
                            or []
                        )
                        if isinstance(c, dict)
                        and c.get("value")
                    ]

                    result.update({
                        "file_name": attr.get(
                            "meaningful_name"
                        ),

                        "file_size": attr.get(
                            "size"
                        ),

                        "file_type": attr.get(
                            "type_description"
                        ),

                        "threat_labels": (
                            ", ".join(labels)
                            if labels
                            else None
                        )
                    })

                if is_url(entry):

                    result["associated_ip"] = (
                        attr.get(
                            "last_serving_ip_address"
                        )
                    )

                return result

            except requests.RequestException as e:

                print(
                    f"VT request error for {entry}: {e} "
                    f"using key {mask_key(key)}"
                )

                if key_errors is not None:
                    record_key_error(
                        key_errors,
                        "VirusTotal",
                        key,
                        "REQUEST_ERROR"
                    )

                # Try next key.
                continue

            except Exception as e:

                print(
                    f"VT processing error for {entry}: {e}"
                )

                return None

        return None


# =========================
# APIVOID LOOKUP
# =========================
def apivoid_lookup(
    entry,
    exhausted_messages,
    user_key=None,
    key_errors=None
):

    if is_hash(entry):
        return None

    with apivoid_semaphore:

        keys = build_key_list(
            APIVOID_KEYS,
            user_key
        )

        if not keys:
            return None

        max_attempts = len(keys)

        attempted = 0

        for key in keys:

            attempted += 1

            if attempted > max_attempts:
                break

            headers = {
                "X-API-Key": key,
                "Content-Type": "application/json"
            }

            try:

                if is_ip(entry):

                    endpoint = (
                        "https://api.apivoid.com/"
                        "v2/ip-reputation"
                    )

                    payload = {
                        "ip": entry
                    }

                else:

                    endpoint = (
                        "https://api.apivoid.com/"
                        "v2/domain-reputation"
                    )

                    payload = {
                        "host": urlparse(
                            normalize_url(entry)
                        ).hostname
                    }

                r = session.post(
                    endpoint,
                    headers=headers,
                    json=payload,
                    timeout=15
                )

                # =========================
                # RATE LIMIT
                # =========================
                if r.status_code == 429:

                    exhausted_messages.append(
                        f"APIVoid API key "
                        f"{mask_key(key)} exhausted."
                    )

                    if attempted < min(
                        len(keys),
                        RATE_LIMIT_MAX_ATTEMPTS
                    ):
                        continue

                    return None

                # =========================
                # OTHER API ERRORS
                # =========================
                if r.status_code != 200:

                    print(
                        f"APIVoid lookup failed for {entry}: "
                        f"HTTP {r.status_code} "
                        f"using key {mask_key(key)}"
                    )

                    if key_errors is not None:
                        record_key_error(
                            key_errors,
                            "APIVoid",
                            key,
                            r.status_code
                        )

                    # Try next API key.
                    continue

                data = r.json()

                return {
                    "detections": (
                        data.get(
                            "blacklists",
                            {}
                        ).get(
                            "detections",
                            -1
                        )
                    ),

                    "riskscore": (
                        data.get(
                            "risk_score",
                            {}
                        ).get(
                            "result"
                        )
                    ),

                    "country": (
                        data.get(
                            "information",
                            {}
                        ).get(
                            "country_name"
                        )
                        or
                        data.get(
                            "server_details",
                            {}
                        ).get(
                            "country_name"
                        )
                    ),

                    "isp": (
                        data.get(
                            "information",
                            {}
                        ).get(
                            "isp"
                        )
                        or
                        data.get(
                            "server_details",
                            {}
                        ).get(
                            "isp"
                        )
                    )
                }

            except requests.RequestException as e:

                print(
                    f"APIVoid request error for {entry}: "
                    f"{e} using key {mask_key(key)}"
                )

                if key_errors is not None:
                    record_key_error(
                        key_errors,
                        "APIVoid",
                        key,
                        "REQUEST_ERROR"
                    )

                continue

            except Exception as e:

                print(
                    f"APIVoid processing error for {entry}: "
                    f"{e}"
                )

                return None

        return None


# =========================
# ABUSEIPDB
# =========================
def abuse_lookup(
    ip,
    exhausted_messages,
    user_key=None,
    key_errors=None
):

    if not is_ip(ip):
        return None

    with abuse_semaphore:

        keys = build_key_list(
            ABUSEIPDB_KEYS,
            user_key
        )

        if not keys:
            return None

        max_attempts = len(keys)

        attempted = 0

        for key in keys:

            attempted += 1

            if attempted > max_attempts:
                break

            try:

                r = session.get(
                    "https://api.abuseipdb.com/api/v2/check",

                    headers={
                        "Key": key,
                        "Accept": "application/json"
                    },

                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90
                    },

                    timeout=15
                )

                # =========================
                # RATE LIMIT
                # =========================
                if r.status_code == 429:

                    exhausted_messages.append(
                        f"AbuseIPDB API key "
                        f"{mask_key(key)} exhausted."
                    )

                    if attempted < min(
                        len(keys),
                        RATE_LIMIT_MAX_ATTEMPTS
                    ):
                        continue

                    return None

                # =========================
                # OTHER API ERRORS
                # =========================
                if r.status_code != 200:

                    print(
                        f"AbuseIPDB lookup failed for {ip}: "
                        f"HTTP {r.status_code} "
                        f"using key {mask_key(key)}"
                    )

                    if key_errors is not None:
                        record_key_error(
                            key_errors,
                            "AbuseIPDB",
                            key,
                            r.status_code
                        )

                    # Try next key.
                    continue

                result = r.json().get(
                    "data"
                )

                if not result:
                    return None

                # AbuseIPDB provides country information
                # through countryCode / countryName.
                #
                # countryName is preferred.
                # countryCode is used as a fallback.
                country_name = (
                    result.get("countryName")
                    or get_country(
                        result.get("countryCode")
                    )
                )

                return {
                    "abuseConfidenceScore": (
                        result.get(
                            "abuseConfidenceScore"
                        )
                    ),

                    "totalReports": (
                        result.get(
                            "totalReports"
                        )
                    ),

                    "isp": result.get("isp"),

                    "country": country_name,

                    "countryCode": (
                        result.get(
                            "countryCode"
                        )
                    )
                }

            except requests.RequestException as e:

                print(
                    f"AbuseIPDB request error for {ip}: "
                    f"{e} using key {mask_key(key)}"
                )

                if key_errors is not None:
                    record_key_error(
                        key_errors,
                        "AbuseIPDB",
                        key,
                        "REQUEST_ERROR"
                    )

                continue

            except Exception as e:

                print(
                    f"AbuseIPDB processing error for {ip}: "
                    f"{e}"
                )

                return None

        return None


# =========================
# SUMMARY BUILDER
# =========================
def build_summary(
    entry,
    etype,
    isp,
    country,
    detections,
    vt,
    apv,
    abv
):

    if etype == "IP":

        sentence = (
            f"The IP {entry} belongs to ISP {isp} "
            f"from country {country} with "
            f"{detections} malicious detections."
            if detections >= 0
            else
            f"The IP {entry} was not found "
            f"in any database."
        )

        sentence += (
            f" ApiVoid shows risk score of "
            f"{apv.get('riskscore')}."
            if apv
            and has_value(
                apv.get("riskscore")
            )
            and apv.get("riskscore", 0) > 0
            else ""
        )

        sentence += (
            f" AbuseIPDB reports an abuse "
            f"confidence score of "
            f"{abv.get('abuseConfidenceScore')}% "
            f"with {abv.get('totalReports')} "
            f"total reports."
            if abv
            and abv.get(
                "abuseConfidenceScore",
                0
            ) > 10
            else ""
        )

        return sentence

    if etype == "URL":

        sentence = f"The URL {entry}"

        if has_value(country) and has_value(isp):

            sentence += (
                f" belongs to the ISP {isp} "
                f"from country {country}"
            )

        sentence += (
            f" and has {detections} "
            f"malicious detections."
            if detections >= 0
            else
            " was not found in any database."
        )

        return sentence

    sentence = (
        f"The hash {entry} has "
        f"{detections} malicious detections."
        if detections >= 0
        else
        f"The hash {entry} was not found "
        f"in any database"
    )

    if vt:

        sentence += (
            f" It is identified as "
            f"{vt.get('file_type')} "
            f"with name {vt.get('file_name')} "
            f"and size {vt.get('file_size')} bytes"
        )

        if vt.get("threat_labels"):

            sentence += (
                f" and associated with threat "
                f"labels: {vt.get('threat_labels')}"
            )

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


# =========================
# MAIN LOOKUP ROUTE
# =========================
@app.route("/get_ip_info", methods=["POST"])
def get_ip_info():

    start = time.time()

    data = request.get_json(
        silent=True
    )

    no_data_ips = []

    if not data or "ips" not in data:
        return jsonify({
            "error": "Invalid JSON"
        }), 400

    # =========================
    # USER API KEYS
    # =========================
    #
    # These are optional.
    #
    # If the user does not provide a key,
    # existing system keys continue to be used.
    #
    user_api_keys = data.get(
        "api_keys",
        {}
    ) or {}

    user_vt_key = (
        user_api_keys.get("vt")
        or user_api_keys.get("virustotal")
    )

    user_apivoid_key = (
        user_api_keys.get("apivoid")
    )

    user_abuse_key = (
        user_api_keys.get("abuseipdb")
        or user_api_keys.get("abuse")
    )

    # =========================
    # INPUT ORDER
    # =========================
    #
    # Do NOT use set() here because it destroys
    # the user's original order.
    #
    # Duplicate removal is handled while
    # preserving order.
    entries = []

    seen_entries = set()

    for entry in data.get("ips", []):

        if not isinstance(entry, str):
            continue

        entry = entry.strip()

        if not entry:
            continue

        if entry not in seen_entries:

            seen_entries.add(entry)
            entries.append(entry)

        if len(entries) >= IOC_MAX:
            break

    raw_table = [None] * len(entries)
    summaries = [None] * len(entries)

    services_used = set()

    exhausted_messages = []
    key_errors = []

    services_lock_local = Lock()
    messages_lock = Lock()

    # =========================
    # PROCESS ONE IOC
    # =========================
    def process(index, entry):

        etype = get_type(entry)

        if not etype:
            return index, None

        # =========================
        # API CALLS ARE PARALLEL
        # =========================
        #
        # Previously these were:
        #
        # vt = vt_lookup(...)
        # apv = apivoid_lookup(...)
        # abv = abuse_lookup(...)
        #
        # which meant:
        #
        # VT -> APIVoid -> AbuseIPDB
        #
        # Now all three are started together.
        #
        with ThreadPoolExecutor(
            max_workers=3
        ) as service_executor:

            vt_future = service_executor.submit(
                vt_lookup,
                entry,
                exhausted_messages,
                user_vt_key,
                key_errors
            )

            apv_future = service_executor.submit(
                apivoid_lookup,
                entry,
                exhausted_messages,
                user_apivoid_key,
                key_errors
            )

            abv_future = service_executor.submit(
                abuse_lookup,
                entry,
                exhausted_messages,
                user_abuse_key,
                key_errors
            )

            # =========================
            # WAIT FOR ALL SERVICES
            # =========================
            #
            # The row is not constructed until
            # all three service calls have finished.
            #
            vt = vt_future.result()
            apv = apv_future.result()
            abv = abv_future.result()

        # =========================
        # SERVICES USED
        # =========================
        for service, value in [
            ("VirusTotal", vt),
            ("APIVoid", apv),
            ("AbuseIPDB", abv)
        ]:

            if value:

                with services_lock_local:

                    services_used.add(
                        service
                    )

        # =========================
        # DETECTIONS
        # =========================
        #
        # Detection is independent from ISP/Country.
        #
        # Only VT and APIVoid participate.
        #
        # AbuseIPDB detection is NOT used.
        #
        vt_det = (
            vt.get(
                "vt_detections"
            )
            if vt
            and has_value(
                vt.get("vt_detections")
            )
            else -1
        )

        apv_det = (
            apv.get(
                "detections"
            )
            if apv
            and has_value(
                apv.get("detections")
            )
            else -1
        )

        try:
            vt_det_numeric = int(vt_det)
        except (ValueError, TypeError):
            vt_det_numeric = -1

        try:
            apv_det_numeric = int(apv_det)
        except (ValueError, TypeError):
            apv_det_numeric = -1

        # Detection = maximum of VT and APIVoid.
        #
        # AbuseIPDB is intentionally excluded.
        detections = max(
            vt_det_numeric,
            apv_det_numeric
        )

        if detections < 0:

            with messages_lock:
                no_data_ips.append(entry)

        # =========================
        # ISP FALLBACK
        # =========================
        #
        # Priority:
        #
        # 1. VT
        # 2. APIVoid
        # 3. AbuseIPDB
        # 4. "-"
        #
        isp = first_valid_value(
            vt.get("isp") if vt else None,
            apv.get("isp") if apv else None,
            abv.get("isp") if abv else None
        )

        # =========================
        # COUNTRY FALLBACK
        # =========================
        #
        # Priority:
        #
        # 1. VT
        # 2. APIVoid
        # 3. AbuseIPDB
        # 4. "-"
        #
        country = first_valid_value(
            vt.get("country") if vt else None,
            apv.get("country") if apv else None,
            abv.get("country") if abv else None
        )

        # =========================
        # TABLE ROW
        # =========================
        #
        # Threat hunting fields remain removed.
        #
        # row = [
        #     entry,
        #     isp,
        #     country,
        #     vt_det,
        #     apv.get("riskscore") if apv else "-",
        #     apv_det,
        #     abv.get("abuseConfidenceScore") if abv else "-",
        #     abv.get("totalReports") if abv else "-",
        #     "-",
        #     "-",
        #     "-",
        #     "-",
        #     "-",
        #     "-"
        # ]

        row = [
            entry,
            isp,
            country,
            vt_det,
            apv.get("riskscore")
            if apv
            and has_value(
                apv.get("riskscore")
            )
            else "-",

            apv_det,

            abv.get(
                "abuseConfidenceScore"
            )
            if abv
            and has_value(
                abv.get(
                    "abuseConfidenceScore"
                )
            )
            else "-",

            abv.get(
                "totalReports"
            )
            if abv
            and has_value(
                abv.get("totalReports")
            )
            else "-"
        ]

        summary = build_summary(
            entry,
            etype,
            isp,
            country,
            detections,
            vt,
            apv,
            abv
        )

        return index, (
            summary,
            row
        )

    # =========================
    # PROCESS IOCs
    # =========================
    #
    # IOC order is preserved because each result
    # is written to its original index.
    #
    with ThreadPoolExecutor(
        max_workers=IOC_MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(
                process,
                index,
                entry
            )
            for index, entry in enumerate(entries)
        ]

        for future in as_completed(futures):

            try:

                index, result = future.result()

                if result:

                    summary, row = result

                    summaries[index] = summary
                    raw_table[index] = row

            except Exception as e:

                print(
                    f"IOC processing error: {e}"
                )

    # Remove any failed/None entries while
    # preserving original order.
    final_table = []
    final_summaries = []

    for index, row in enumerate(raw_table):

        if row is not None:

            final_table.append(row)

            if summaries[index] is not None:
                final_summaries.append(
                    summaries[index]
                )

    # =========================
    # REQUEST SUMMARY MESSAGES
    # =========================

    messages = []

    # =========================
    # USER API KEY INFORMATION
    # =========================
    #
    # Show masked key only when the user actually
    # supplied one.
    #
    if user_vt_key:

        messages.append(
            f"🔑 VirusTotal user API key used: "
            f"<span class=\"text-purple-400 font-bold\">"
            f"{mask_key(user_vt_key)}</span>"
        )

    if user_apivoid_key:

        messages.append(
            f"🔑 APIVoid user API key used: "
            f"<span class=\"text-purple-400 font-bold\">"
            f"{mask_key(user_apivoid_key)}</span>"
        )

    if user_abuse_key:

        messages.append(
            f"🔑 AbuseIPDB user API key used: "
            f"<span class=\"text-purple-400 font-bold\">"
            f"{mask_key(user_abuse_key)}</span>"
        )

    # =========================
    # KEY ERROR SUMMARY
    # =========================
    #
    # This tells the frontend that a user/system
    # key failed while another key was attempted.
    #
    unique_key_errors = []
    seen_key_errors = set()

    for error in key_errors:

        error_key = (
            error["service"],
            error["key"],
            str(error["status_code"])
        )

        if error_key not in seen_key_errors:

            seen_key_errors.add(
                error_key
            )

            unique_key_errors.append(
                error
            )

    for error in unique_key_errors:

        messages.append(
            f"⚠️ {error['service']} API key "
            f"{error['key']} returned "
            f"HTTP {error['status_code']}; "
            f"another available key was attempted."
        )

    # =========================
    # INVALID / FAILED USER KEYS
    # =========================
    #
    # These are returned separately so the frontend
    # can display its popup if the user supplied a key.
    #
    user_key_errors = []

    user_key_map = {
        "VirusTotal": user_vt_key,
        "APIVoid": user_apivoid_key,
        "AbuseIPDB": user_abuse_key
    }

    for error in unique_key_errors:

        service = error["service"]

        user_key = user_key_map.get(
            service
        )

        if (
            user_key
            and error["key"] == mask_key(user_key)
        ):

            user_key_errors.append({
                "service": service,
                "key": mask_key(user_key),
                "status_code": error[
                    "status_code"
                ]
            })

    # =========================
    # EXHAUSTED MESSAGES
    # =========================
    if exhausted_messages:

        unique_exhausted = list(
            dict.fromkeys(
                exhausted_messages
            )
        )

        for msg in unique_exhausted:

            messages.append(
                f"<div class=\"font-medium "
                f"mb-3 text-red-600\">"
                f"{msg}</div>"
            )

    # =========================
    # NO DATA
    # =========================
    unique_no_data = list(
        dict.fromkeys(
            no_data_ips
        )
    )

    if unique_no_data:

        display_list = unique_no_data[
            :5
        ]

        more = (
            f" and "
            f"{len(unique_no_data) - 5}"
            f" more..."
            if len(unique_no_data) > 5
            else ""
        )

        messages.append(
            f"⚠️ {len(unique_no_data)} "
            f"entr{'y' if len(unique_no_data) == 1 else 'ies'} "
            f"returned no detection data: "
            f"{', '.join(display_list)}"
            f"{more}"
        )

    # =========================
    # SERVICES MESSAGE
    # =========================
    service_list = sorted(
        services_used
    )

    # =========================
    # FINAL RESPONSE
    # =========================
    elapsed = round(
        time.time() - start,
        2
    )

    processed_count = len(
        final_table
    )

    entry_msg = (
        f"✅ Data found for "
        f"<span class=\"text-green-400 "
        f"font-bold\">"
        f"{processed_count} "
        f"entr{'y' if processed_count == 1 else 'ies'}"
        f"</span> in "
        f"<span class=\"text-blue-400 "
        f"font-bold\">"
        f"{elapsed} seconds"
        f"</span>."
    )

    service_msg = (
        f"🔧 Service"
        f"{'s' if len(service_list) != 1 else ''} "
        f"used: "
        f"<span class=\"text-purple-400 "
        f"font-bold\">"
        f"{', '.join(service_list) or 'None'}"
        f"</span>"
    )

    # These are intentionally added at the front
    # so the request summary starts with:
    #
    # Data found...
    # Services used...
    #
    messages.insert(
        0,
        service_msg
    )

    messages.insert(
        0,
        entry_msg
    )

    return jsonify({

        # =========================
        # TABLE
        # =========================
        #
        # Maintains exact input order.
        "raw_table": final_table,

        # =========================
        # SUMMARY
        # =========================
        "summary": "<br><br>".join(
            final_summaries
        ),

        # =========================
        # TIMING
        # =========================
        "elapsed": elapsed,

        # =========================
        # SERVICES
        # =========================
        "services_used": service_list,

        # =========================
        # NO DATA
        # =========================
        "no_data_ips": unique_no_data,

        # =========================
        # API KEY INFORMATION
        # =========================
        "exhausted_messages": (
            list(
                dict.fromkeys(
                    exhausted_messages
                )
            )
        ),

        "key_errors": unique_key_errors,

        "user_key_errors": user_key_errors,

        # =========================
        # REQUEST SUMMARY
        # =========================
        "messages": messages
    })


# @app.route("/download_excel", methods=["POST"])
# def download_excel():
#     table = request.json.get("table_data", [])
#     wb = Workbook(); ws = wb.active; ws.title="Results"
#     ws.append(["IOC","ISP","Country","Detections","APIVoid Risk","APIVoid Blacklist","Abuse Confidence","Abuse Reports","","","","","",""])
#     for row in table: ws.append(row)
#     stream = BytesIO(); wb.save(stream); stream.seek(0)
#     return send_file(stream, as_attachment=True, download_name="IOC_Report.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# =========================
# DOWNLOAD EXCEL
# =========================
@app.route("/download_excel", methods=["POST"])
def download_excel():

    data = request.get_json()

    table_data = data.get(
        "table_data",
        []
    )

    summary_text = data.get(
        "summary",
        ""
    )

    column_label = data.get(
        "column_label",
        "IP"
    )

    from openpyxl import Workbook
    from openpyxl.styles import (
        Font,
        Alignment,
        Border,
        Side
    )
    from openpyxl.utils import (
        get_column_letter
    )
    import io
    from flask import send_file

    wb = Workbook()

    ws = wb.active

    ws.title = "Lookup Data"

    headers = [
        column_label,
        "ISP",
        "Country",
        "Detections",
        "APIVoid Risk Score",
        "APIVoid Blacklist Detections",
        "AbuseIPDB Confidence Score",
        "AbuseIPDB Report Count",

        # "Threat Actor",
        # "Country Of Origin",
        # "Target Sector",
        # "Threat Category",
        # "Campaign Name",
        # "Malware Families"
    ]

    ws.append(headers)

    # for row in table_data:
    #     ws.append(row[:14])  # Direct append (removes redundant assignments)

    for row in table_data:

        ws.append(
            row[:8]
        )  # removed the threat hunting fields

    bold = Font(
        bold=True
    )

    center = Alignment(
        horizontal="center",
        vertical="center",
        wrap_text=True
    )

    border = Border(
        *(Side(style="thin"),) * 4
    )

    for r in ws.iter_rows():

        for c in r:

            c.alignment = center
            c.border = border

            if c.row == 1:
                c.font = bold

    for col in ws.columns:

        length = max(
            len(str(c.value))
            if c.value
            else 0
            for c in col
        )

        ws.column_dimensions[
            get_column_letter(
                col[0].column
            )
        ].width = max(
            12,
            min(
                length + 4,
                50
            )
        )

    ws_summary = wb.create_sheet(
        "Summary"
    )

    ws_summary["A1"] = (
        "Scan Summary"
    )

    ws_summary["A1"].font = Font(
        size=14,
        bold=True
    )

    ws_summary["A2"] = (
        summary_text.strip()
    )

    ws_summary["A2"].alignment = Alignment(
        wrap_text=True,
        vertical="top"
    )

    ws_summary.column_dimensions[
        "A"
    ].width = 100

    output = io.BytesIO()

    wb.save(output)

    output.seek(0)

    return send_file(
        output,
        mimetype=(
            "application/vnd."
            "openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
        as_attachment=True,
        download_name="IP_Info.xlsx"
    )


# =========================
# RUN
# =========================
if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )