import re
import dkim
import dns.resolver
import spf

# ----------- HEADER EXTRACTORS -----------

def extract_headers(raw_email_text):
    headers = {}
    lines = raw_email_text.split("\n")
    for line in lines:
        if line.lower().startswith("from:"):
            headers["From"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("reply-to:"):
            headers["Reply-To"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("received-spf:"):
            headers["SPF"] = line.strip()
        elif line.lower().startswith("authentication-results:"):
            headers["Auth"] = line.strip()
    return headers

def get_domain_from_email(email):
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email)
    return match.group(1) if match else None

# ----------- CHECK FUNCTIONS -----------

def check_dmarc(domain):
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for txt in txt_records:
            if "v=DMARC1" in txt.to_text():
                return "pass"
        return "fail"
    except:
        return "none"

def check_dkim(domain):
    try:
        selector = "default"
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, "TXT")
        for rdata in answers:
            if "v=DKIM1" in rdata.to_text():
                return "pass"
        return "fail"
    except:
        return "none"

def check_spf(domain, sender_ip="1.2.3.4", sender_email="test@example.com"):
    try:
        result, code, explanation = spf.check2(i=sender_ip, s=sender_email, h=domain)
        return result
    except:
        return "none"

def detect_reply_spoof(headers):
    from_email = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return "yes" if reply_to and reply_to != from_email else "no"

# ----------- VALIDATORS -----------

def validate_email_headers(raw_email_text):
    raw_email_text = raw_email_text.lower()  # normalize text

    # ✅ Use regex to extract pass/fail
    spf_match = re.search(r"spf\s*=\s*(pass|fail)", raw_email_text)
    dkim_match = re.search(r"dkim\s*=\s*(pass|fail)", raw_email_text)
    dmarc_match = re.search(r"dmarc\s*=\s*(pass|fail)", raw_email_text)

    # ✅ Extract reply-to and from
    from_match = re.search(r"from:\s*(\S+)", raw_email_text)
    reply_to_match = re.search(r"reply-to:\s*(\S+)", raw_email_text)

    from_email = from_match.group(1) if from_match else ""
    reply_to_email = reply_to_match.group(1) if reply_to_match else ""

    spoof_result = "yes" if reply_to_email and reply_to_email != from_email else "no"

    return {
        "spf": spf_match.group(1) if spf_match else "none",
        "dkim": dkim_match.group(1) if dkim_match else "none",
        "dmarc": dmarc_match.group(1) if dmarc_match else "none",
        "reply_spoof": spoof_result
    }

import re

def validate_email_headers_from_graph(msg):
    headers = msg.get("internetMessageHeaders", [])
    body = msg.get("body", {}).get("content", "")
    full_text = body

    def get_header(name):
        for h in headers:
            if h.get("name", "").lower() == name.lower():
                return h.get("value", "")
        return ""

    # Merge headers + body to detect spoofed/missing failures
    auth_results = get_header("Authentication-Results") + "\n" + full_text
    auth_results = auth_results.lower()

    # Regex matching for SPF/DKIM/DMARC
    spf_match = re.search(r"spf\s*=\s*(pass|fail|none)", auth_results)
    dkim_match = re.search(r"dkim\s*=\s*(pass|fail|none)", auth_results)
    dmarc_match = re.search(r"dmarc\s*=\s*(pass|fail|none)", auth_results)

    # Get From & Reply-To for spoof detection
    from_header = get_header("From")
    reply_to_header = get_header("Reply-To")
    spoof_result = "yes" if reply_to_header and reply_to_header != from_header else "no"

    return {
        "spf": spf_match.group(1) if spf_match else "none",
        "dkim": dkim_match.group(1) if dkim_match else "none",
        "dmarc": dmarc_match.group(1) if dmarc_match else "none",
        "reply_spoof": spoof_result
    }