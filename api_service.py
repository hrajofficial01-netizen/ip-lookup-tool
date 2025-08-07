from token_manager import get_access_token
import requests


def api_request(url, method="GET", headers=None, params=None, data=None, json=None):
    if headers is None:
        headers = {}

    # Set default accept header required by ThreatIntel API
    headers.setdefault("accept", "application/cloudevents+json")

    access_token = get_access_token()
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        response = requests.request(method, url, headers=headers, params=params, data=data, json=json, timeout=10)

        if response.status_code == 401:
            # Refresh token and retry once on Unauthorized
            access_token = get_access_token()
            headers["Authorization"] = f"Bearer {access_token}"
            response = requests.request(method, url, headers=headers, params=params, data=data, json=json, timeout=10)

        if response.status_code == 400:
            # Handle bad request gracefully — log and return None
            print(f"Bad Request (400) for {url}: {response.text}")
            return None

        response.raise_for_status()
        return response.json()

    except requests.HTTPError as e:
        # For other HTTP errors, log and raise
        print(f"API request failed for {url} with status {getattr(e.response, 'status_code', 'Unknown')}: {getattr(e.response, 'text', '')}")
        raise

    except Exception as e:
        print(f"Error during API request to {url}: {e}")
        raise
