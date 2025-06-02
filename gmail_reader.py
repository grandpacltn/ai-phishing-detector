import os.path
import base64
import re
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# If modifying these scopes, delete the token.json file
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_latest_email():
    """Logs into Gmail and fetches the latest email body."""
    creds = None

    # Load credentials from token file if it exists
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If there are no valid credentials, do the login flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # This opens a browser to log in with Gmail
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)
        # Save the access token
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # Connect to Gmail API
    service = build('gmail', 'v1', credentials=creds)

    # Get the latest email from inbox
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=1).execute()
    messages = results.get('messages', [])

    if not messages:
        return "No email found."

    msg = service.users().messages().get(userId='me', id=messages[0]['id'], format='full').execute()
    parts = msg['payload'].get('parts', [])

    # Try to find plain text
    for part in parts:
        if part['mimeType'] == 'text/plain':
            data = part['body'].get('data', '')
            decoded = base64.urlsafe_b64decode(data).decode('utf-8')
            return clean_text(decoded)

    return "Could not extract plain text email."

def clean_text(text):
    text = re.sub(r"http\S+", "", text)
    return text.strip()
print(get_latest_email())