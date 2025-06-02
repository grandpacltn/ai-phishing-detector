import json
import requests
from msal import ConfidentialClientApplication

with open("credentials.json") as f:
    config = json.load(f)

AUTHORITY = f"https://login.microsoftonline.com/{config['tenant_id']}"
SCOPE = config["scopes"]
REDIRECT_URI = config["redirect_uri"]

app = ConfidentialClientApplication(
    config["client_id"],
    authority=AUTHORITY,
    client_credential=config["client_secret"]
)

def get_access_token():
    result = app.acquire_token_for_client(scopes=SCOPE)
    return result.get("access_token")