from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse
import re

# Get absolute path of this script
BASE_DIR = Path(__file__).resolve().parent

# Build path to email file
EMAIL_PATH = BASE_DIR.parent / "sample_emails" / "phishing" / "phish1.eml"

with open(EMAIL_PATH, "rb") as f:
    msg = BytesParser(policy=policy.default).parse(f)

print("===== HEADERS =====")
for key, value in msg.items():
    print(f"{key}: {value}")

print("\n===== BODY =====")
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            print(part.get_content())
else:
    print(msg.get_content())

# --- BASIC FEATURES ---
print("\n===== BASIC FEATURES =====")
print("From:", msg.get("From"))
print("Subject:", msg.get("Subject"))

# --- AUTH RESULTS ---
auth_results = msg.get("Authentication-Results")
print("\nAuthentication Results:")
print(auth_results)

# --- EXTRACT URLs FROM BODY ---
body = msg.get_body(preferencelist=('html', 'plain'))
text = body.get_content() if body else ""

urls = re.findall(r'https?://[^\s"\'>]+', text)

print("\nExtracted URLs:")
for url in set(urls):
    print("-", url)

print("\n===== PHISHING HEURISTICS =====")

score = 0

# 1️⃣ Authentication failure
if auth_results:
    auth_lower = auth_results.lower()
    if "spf=fail" in auth_lower or "dkim=fail" in auth_lower or "dmarc=fail" in auth_lower:
        print("❌ Auth failure detected")
        score += 1

# 2️⃣ Urgency indicators (language-agnostic)
urgency_words = ["urgent", "now", "today", "expire", "expiram", "agora", "hoje"]
if any(word in text.lower() for word in urgency_words):
    print("⚠️ Urgency language detected")
    score += 1

# 3️⃣ Suspicious URL (domain mismatch)
from_email = msg.get("From", "")
for url in urls:
    domain = urlparse(url).netloc
    if domain not in from_email:
        print(f"⚠️ Suspicious link domain: {domain}")
        score += 1

# 4️⃣ HTML heavy email (common phishing trait)
if "<html" in text.lower():
    print("⚠️ HTML-heavy email")
    score += 1

print("\nPhishing Risk Score:", score)
