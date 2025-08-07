from concurrent.futures import ThreadPoolExecutor
from api_service import api_request

BASE_URL = "https://api.threatintel.io/v1"

def get_ip_tie_data(ip):
    url = f"{BASE_URL}/ip/tie/{ip}"
    return api_request(url)

def get_ip_other_data(ip):
    # Example: another Threat Intel endpoint
    url = f"{BASE_URL}/ip/other/{ip}"
    return api_request(url)

def get_domain_tie_data(domain):
    url = f"{BASE_URL}/domains/tie/{domain}"
    return api_request(url)

def run_parallel_tie_calls(entry, entry_type):
    with ThreadPoolExecutor(max_workers=2) as executor:
        if entry_type == "url":
            futures = [executor.submit(get_domain_tie_data, entry)]
        else:
            # For IPs, run multiple threatintel calls in parallel if desired
            futures = [executor.submit(get_ip_tie_data, entry)]
            # Add more futures if you have more endpoints:
            # futures.append(executor.submit(get_ip_other_data, entry))
        
        results = [f.result() for f in futures]
    
    # Merge/aggregate results here if multiple, or return single
    # For example, if only one:
    return results[0]

def extract_enrichment_fields(tie_result):
    data = tie_result.get("data") or {}  # use empty dict if data is None or missing
    return {
        "threat_actor": data.get("threat_actor"),
        "campaign_name": data.get("campaign_name"),
        "malware_families": data.get("malware_families"),
    }

