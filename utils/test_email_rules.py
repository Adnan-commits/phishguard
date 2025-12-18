from rules.email_rules import rule_based_email_detection

emails = [
    {
        "sender": "security@google.com",
        "subject": "New login detected",
        "body": "We noticed a new login from Chrome browser."
    },
    {
        "sender": "secure-update@paypal.verify-user.com",
        "subject": "URGENT: VERIFY YOUR ACCOUNT",
        "body": "Click immediately to verify your account http://fake-link.com/login"
    }
]

for email in emails:
    verdict = rule_based_email_detection(
        email["sender"], email["subject"], email["body"]
    )
    print(email["subject"], "→", "PHISHING" if verdict else "LEGITIMATE")
