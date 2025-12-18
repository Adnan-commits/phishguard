import re

PHISHING_KEYWORDS = [
    "verify", "update", "login", "password", "account",
    "bank", "secure", "confirm", "suspended"
]

URGENCY_WORDS = [
    "urgent", "immediately", "action required", "within 24 hours"
]

def rule_based_email_detection(sender, subject, body):
    risk_score = 0

    content = f"{subject} {body}".lower()

    # 1. Phishing keywords
    if any(word in content for word in PHISHING_KEYWORDS):
        risk_score += 1

    # 2. Urgency language
    if any(word in content for word in URGENCY_WORDS):
        risk_score += 1

    # 3. Credential request
    if re.search(r"(password|otp|credit card|ssn)", content):
        risk_score += 1

    # 4. Excessive links
    link_count = len(re.findall(r"http[s]?://", body))
    if link_count > 2:
        risk_score += 1

    # 5. Suspicious sender domain
    if "@" in sender:
        domain = sender.split("@")[-1]
        if domain.count('.') > 2:
            risk_score += 1

    # 6. ALL CAPS subject
    if subject.isupper() and len(subject) > 10:
        risk_score += 1

    return risk_score >= 2
