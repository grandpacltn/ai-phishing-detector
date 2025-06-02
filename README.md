🧠 AI Phishing Detector

An intelligent web-based application that detects phishing emails using Natural Language Processing (NLP), machine learning, and real-time SPF, DKIM, DMARC header validation. Supports email scanning from Gmail and Hotmail/Outlook using their respective APIs.

✨ Features
	•	🔍 Detect Phishing vs Legit Emails (via ML model)
	•	📧 Scan Gmail and Hotmail/Outlook inboxes
	•	🔐 SPF, DKIM, DMARC & Reply Spoofing Validation
	•	🧠 Natural Language Processing (NLP)
	•	🎤 Speech Output (AI reads result aloud)
	•	📊 Detection History Chart
	•	🌙 Dark Mode + Typing Indicator + Reset Button
	•	📱 Mobile-Responsive Design

 🚀 Demo

🧪 Visit locally at: http://127.0.0.1:5222
🔑 Authenticate with Google or Microsoft, then scan inbox for phishing analysis.

🔒 Email Validation (SPF, DKIM, DMARC)
	•	SPF: Verifies sender IP against domain policy
	•	DKIM: Checks signature against DNS records
	•	DMARC: Ensures alignment between SPF/DKIM and domain policy
	•	Reply Spoofing: Flags if Reply-To differs from From

 📂 Project Structure
 ai_phishing_detector/
├── app.py
├── templates/
│   ├── index.html
│   └── authenticate.html
├── phishing_model.pkl
├── vectorizer.pkl
├── credentials.json
├── spf_dkim_dmarc_validator.py
└── static/ (optional)

🔐 How to Use
	1.	Clone the project
 git clone https://github.com/grandpacltn/ai-phishing-detector.git
cd ai-phishing-detector

 Install dependencies
 pip install -r requirements.txt

 Run the app
 python app.py

 Visit
•	http://127.0.0.1:5222
•	Paste an email or scan your inbox.

🧪 Gmail & Hotmail Setup

Gmail:
	•	Enable Gmail API in Google Cloud
	•	Create OAuth 2.0 credentials
	•	Save as credentials.json

Hotmail/Outlook:
	•	Register App in Microsoft Azure Portal
	•	Use MSAL for device code login


🛡️ Security Notes
	•	Your tokens are stored in session only
	•	No email data is saved or shared
	•	For educational/ethical testing purposes only


👨‍💻 Author

Cybergrandpaa


📄 License

MIT License – Use it ethically, don’t scam with it. This tool is made for education and protection.
