from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from api_service import api_request


BASE_URL = "https://api.threatintel.io/v1"


def get_ip_tie_data(ip):
    url = f"{BASE_URL}/ip/tie/{ip}"
    try:
        return api_request(url)
    except Exception as e:
        print(f"Error fetching IP TIE data: {e}")
        return None


def get_domain_tie_data(domain):
    url = f"{BASE_URL}/domains/tie/{domain}"
    try:
        return api_request(url)
    except Exception as e:
        print(f"Error fetching Domain TIE data: {e}")
        return None


def run_parallel_tie_calls(entry, entry_type):
    """
    Run parallel threat intel API calls based on entry type (ip or url/domain).
    Returns first successfully retrieved result or None.
    """
    with ThreadPoolExecutor(max_workers=2) as executor:
        if entry_type == "url":
            futures = [executor.submit(get_domain_tie_data, entry)]
        else:  # for ip and others
            futures = [executor.submit(get_ip_tie_data, entry)]
            # Additional futures (e.g., get_ip_other_data) can be added here if needed

        for future in futures:
            result = future.result()
            if result:
                return result
    return None


def extract_enrichment_fields(tie_result):
    """
    Extract basic enrichment fields from the first API call response.
    """
    if not tie_result:
        return {}

    data = tie_result.get("data") or {}
    return {
        "threat_actor": data.get("threat_actor"),
        "campaign_name": data.get("campaign_name"),
        "malware_families": data.get("malware_families"),
    }


def get_actor_details(actor_name):
    """
    Call the second API to get detailed actor info.
    """
    if not actor_name:
        return None

    encoded_name = quote(str(actor_name))
    url = f"{BASE_URL}/actors/target/tie/{encoded_name}"
    try:
        response = api_request(url)
        return response
    except Exception as e:
        print(f"Error fetching actor details: {e}")
        return None


def parse_actor_details_response(actor_details_response):
    """
    Parse detailed actor info response and extract needed fields.
    """
    if not actor_details_response:
        return None

    data = actor_details_response.get("data") or {}
    return {
        "actor_name": data.get("name"),
        "country_origin": data.get("country_origin"),
        "target_sector": data.get("sector_targets"),
        "threat_category": data.get("threat_category"),
    }


def get_actor_info_from_entry(entry, entry_type):
    """
    Main function to get threat actor info for an entry (IP or URL).
    """
    main_data = run_parallel_tie_calls(entry, entry_type)
    enrichment = extract_enrichment_fields(main_data)

    if not enrichment:
        return None

    actor_name_or_id = enrichment.get("threat_actor")

    if actor_name_or_id:
        # If actor is a list, take first element
        if isinstance(actor_name_or_id, list):
            actor_name_or_id = actor_name_or_id[0]

        actor_details = get_actor_details(actor_name_or_id)
        parsed = parse_actor_details_response(actor_details)

        if parsed:
            return parsed

    # No actor info found
    return None


# Optional: For manual quick test
if __name__ == "__main__":
    test_ip = "8.8.8.8"
    test_url = "report-telegram.me"

    print("Testing IP entry:")
    ip_actor_info = get_actor_info_from_entry(test_ip, "ip")
    print(ip_actor_info if ip_actor_info else "No actor info found.")

    print("\nTesting URL entry:")
    url_actor_info = get_actor_info_from_entry(test_url, "url")
    print(url_actor_info if url_actor_info else "No actor info found.")
