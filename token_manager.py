import os
import json
import time
import requests
from dotenv import load_dotenv

load_dotenv()  # This loads variables from a .env file into the environment
TOKENS_FILE = "tokens.json"   # File to persist tokens securely

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
TOKEN_ENDPOINT = "https://api.threatintel.io/v1/user/token"  # Your token URL

def save_tokens(tokens):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f)

def load_tokens():
    try:
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def is_token_expired(tokens):
    # exp is timestamp in milliseconds, refresh 1 min before expiry
    return time.time() >= (tokens["exp"] / 1000) - 60

def authenticate():
    """Get new access token using client credentials"""
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(TOKEN_ENDPOINT, json=payload, headers=headers)
    response.raise_for_status()
    tokens = response.json()
    save_tokens(tokens)
    return tokens

def refresh_access_token(tokens):
    """Use refresh token to get a new access token"""
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": tokens.get("refresh_token"),
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(TOKEN_ENDPOINT, json=payload, headers=headers)
    if response.status_code == 200:
        new_tokens = response.json()
        save_tokens(new_tokens)
        return new_tokens
    # Refresh token expired or invalid
    return None

def get_valid_tokens():
    """Return valid tokens, refresh or authenticate as needed"""
    tokens = load_tokens()
    if not tokens:
        tokens = authenticate()
    elif is_token_expired(tokens):
        new_tokens = refresh_access_token(tokens)
        if new_tokens:
            tokens = new_tokens
        else:
            tokens = authenticate()
    return tokens

def get_access_token():
    tokens = get_valid_tokens()
    return tokens["access_token"]
