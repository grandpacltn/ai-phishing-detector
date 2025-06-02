from flask import Flask, render_template, request, session, redirect, url_for
import joblib
import re
import string
import spf
import base64
import requests
from bs4 import BeautifulSoup
from msal import PublicClientApplication
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from spf_dkim_dmarc_validator import validate_email_headers, validate_email_headers_from_graph

app = Flask(__name__)
app.secret_key = "your_secret_key_here"
model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

HOTMAIL_CLIENT_ID = "1152bae5-7ea1-4c30-abd8-a3c9e7a8aebd"
HOTMAIL_AUTHORITY = "https://login.microsoftonline.com/common"
HOTMAIL_SCOPE = ["Mail.Read"]
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def clean_email(text):
    if not isinstance(text, str): return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", "", text)
    text = text.translate(str.maketrans("", "", string.punctuation))
    text = re.sub(r"\d+", "", text)
    return text.strip()

def extract_domain(email):
    try: return email.split('@')[1]
    except: return None

def check_spf(domain, sender_ip="1.2.3.4", sender_email="test@example.com"):
    try:
        result, _, _ = spf.check2(i=sender_ip, s=sender_email, h=domain)
        return result
    except: return "error"

@app.route('/')
def home():
    return render_template("index.html", prediction=None, history=session.get('history', []), validation={})

@app.route('/predict', methods=['POST'])
def predict():
    email = request.form['email_text']
    cleaned = clean_email(email)
    vec = vectorizer.transform([cleaned])
    result = "phishing" if model.predict(vec)[0] == 1 else "legit"

    # ✅ Run header validation even on pasted emails
    validation = validate_email_headers(email)

    history = session.get('history', [])
    history.append({
        'email': email[:50],
        'result': result,
        'spf': validation.get('spf', 'unknown'),
        'dkim': validation.get('dkim', 'unknown'),
        'dmarc': validation.get('dmarc', 'unknown'),
        'reply_spoof': validation.get('reply_spoof', 'unknown')
    })
    session['history'] = history[-10:]

    return render_template(
        "index.html",
        prediction=result,
        history=session['history'],
        validation=validation
    )
def scan_hotmail():
    try:
        app_msal = PublicClientApplication(HOTMAIL_CLIENT_ID, authority=HOTMAIL_AUTHORITY)
        flow = app_msal.initiate_device_flow(scopes=HOTMAIL_SCOPE)
        if "user_code" not in flow: return "❌ Error: Device flow failed."
        session['device_flow'] = flow
        return render_template("authenticate.html", user_code=flow['user_code'], verify_url=flow['verification_uri'])
    except Exception as e:
        return f"❌ Error: {str(e)}"


@app.route('/scan_hotmail_login')
def scan_hotmail_login():
    try:
        app_msal = PublicClientApplication(HOTMAIL_CLIENT_ID, authority=HOTMAIL_AUTHORITY)
        flow = app_msal.initiate_device_flow(scopes=HOTMAIL_SCOPE)
        if "user_code" not in flow:
            return "❌ Error: Microsoft device flow failed."

        session["device_flow"] = flow
        return render_template("authenticate.html", user_code=flow["user_code"], verify_url=flow["verification_uri"])
    except Exception as e:
        return f"❌ Error: {str(e)}"


@app.route('/scan_hotmail_fetch')
def scan_hotmail_fetch():
    try:
        if 'device_flow' not in session:
            return redirect(url_for('scan_hotmail_login'))

        app_msal = PublicClientApplication(HOTMAIL_CLIENT_ID, authority=HOTMAIL_AUTHORITY)
        token = app_msal.acquire_token_by_device_flow(session['device_flow'])

        if "access_token" not in token:
            return "❌ Error: Microsoft login failed."

        headers = {
            "Authorization": f"Bearer {token['access_token']}"
        }
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me/messages?$top=10&$select=subject,body,internetMessageHeaders",
            headers=headers
        )

        messages = response.json().get("value", [])
        results = []

        for msg in messages:
            try:
                html = msg.get('body', {}).get('content', '')
                plain = BeautifulSoup(html, 'html.parser').get_text()
                cleaned = clean_email(plain)
                vec = vectorizer.transform([cleaned])
                label = "phishing" if model.predict(vec)[0] == 1 else "legit"

                validation = validate_email_headers_from_graph(msg)

                results.append({
                    'text': plain[:500],
                    'result': label,
                    'spf': validation.get('spf', 'none'),
                    'dkim': validation.get('dkim', 'none'),
                    'dmarc': validation.get('dmarc', 'none'),
                    'reply_spoof': validation.get('reply_spoof', 'none')
                })
            except Exception as inner_e:
                print("⚠️ Email parsing error:", inner_e)
                continue

        return render_template("index.html", hotmail_results=results, prediction=None, history=session.get('history', []), validation={})

    except Exception as e:
        print("❌ MAIN ERROR:", e)
        return f"❌ Error fetching emails: {str(e)}"

def authenticate_gmail():
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', GOOGLE_SCOPES)
    creds = flow.run_local_server(port=5222)
    return build('gmail', 'v1', credentials=creds)

def fetch_gmail_emails(service, max_results=10):
    emails, messages = [], service.users().messages().list(userId='me', maxResults=max_results).execute().get('messages', [])
    for msg in messages:
        data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
        content, parts = '', data['payload'].get('parts', [])
        if 'data' in data['payload'].get('body', {}):
            content = data['payload']['body']['data']
        elif parts:
            for p in parts:
                if p['mimeType'] == 'text/plain':
                    content = p['body'].get('data', '')
                    break
        if content:
            decoded = base64.urlsafe_b64decode(content).decode('utf-8', errors='ignore')
            emails.append(BeautifulSoup(decoded, 'html.parser').get_text())
    return emails

@app.route('/scan_gmail')
def scan_gmail():
    try:
        service = authenticate_gmail()
        emails = fetch_gmail_emails(service)
        results = []
        for e in emails:
            cleaned = clean_email(e)
            vec = vectorizer.transform([cleaned])
            label = "phishing" if model.predict(vec)[0] == 1 else "legit"
            results.append({'text': e[:100], 'result': label})
        return render_template("index.html", gmail_results=results, prediction=None, history=session.get('history', []))
    except Exception as e:
        return f"❌ Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True, port=5222)