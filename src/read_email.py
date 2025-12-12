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
