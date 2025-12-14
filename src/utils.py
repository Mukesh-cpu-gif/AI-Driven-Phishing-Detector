# src/utils.py
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

def parse_email(file_buffer):
    """
    Parses a raw .eml file buffer and returns a dictionary of data.
    """
    try:
        msg = BytesParser(policy=policy.default).parse(file_buffer)
        
        # Extract Body
        body_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                # Prefer plain text, fallback to html
                if part.get_content_type() == "text/plain":
                    body_content += part.get_content()
        else:
            body_content = msg.get_content()
            
        return {
            "subject": msg.get("Subject", "No Subject"),
            "from": msg.get("From", "Unknown Sender"),
            "auth_results": msg.get("Authentication-Results", ""),
            "body": body_content,
            "raw_msg": msg # Keep original object just in case
        }
    except Exception as e:
        return {"error": str(e)}

def get_heuristic_score(email_data):
    """
    Analyzes email metadata for technical red flags.
    Returns: (score, list_of_reasons)
    """
    score = 0
    reasons = []
    
    # 1. Authentication Check
    auth_results = email_data.get("auth_results", "").lower()
    if "spf=fail" in auth_results or "dkim=fail" in auth_results or "dmarc=fail" in auth_results:
        score += 30
        reasons.append("Authentication checks (SPF/DKIM/DMARC) failed.")

    # 2. Urgency Check
    text = email_data.get("body", "").lower()
    urgency_words = ["urgent", "immediately", "account suspended", "expire", "action required"]
    if any(word in text for word in urgency_words):
        score += 20
        reasons.append("Contains high-urgency language typical of scams.")

    # 3. Link Analysis (Basic)
    urls = re.findall(r'https?://[^\s"\'>]+', text)
    if len(urls) > 0:
        # Check for mismatch (Simplified for now)
        sender_domain = email_data["from"].split("@")[-1].strip(">")
        for url in urls:
            link_domain = urlparse(url).netloc
            if link_domain and sender_domain not in link_domain:
                score += 20
                reasons.append(f"Suspicious link to external domain: {link_domain}")
                break # Only penalize once for links

    # 4. HTML Heavy
    if "<html" in text:
        score += 10
        reasons.append("Email is heavily HTML formatted (common in mass phishing).")
        
    return score, reasons