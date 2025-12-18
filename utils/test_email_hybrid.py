from utils.email_hybrid_detector import detect_phishing_email

emails = [
    {
        "sender": "security@google.com",
        "subject": "New login detected",
        "body": "We noticed a login from a new device."
    },
    {
        "sender": "secure-update@paypal.verify-user.com",
        "subject": "URGENT: VERIFY YOUR ACCOUNT",
        "body": "Click immediately to verify your account http://fake-link.com/login"
    }
]

for e in emails:
    print(
        e["subject"],
        "→",
        detect_phishing_email(e["sender"], e["subject"], e["body"])
    )
