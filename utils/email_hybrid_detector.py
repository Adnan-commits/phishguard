from model.load_email_model import load_email_model
from rules.email_rules import rule_based_email_detection
from features.email_features import clean_email_text, extract_email_structural_features
from scipy.sparse import hstack

email_model, tfidf = load_email_model()

def detect_phishing_email(sender, subject, body):
    reasons = []

    # Rule-based signals
    if "urgent" in subject.lower():
        reasons.append("Urgency language detected")
    if "verify" in subject.lower() or "password" in body.lower():
        reasons.append("Credential-related keywords detected")
    if body.lower().count("http") > 2:
        reasons.append("Multiple links detected in email")

    rule_flag = rule_based_email_detection(sender, subject, body)

    # ML confidence
    email_text = clean_email_text(subject + " " + body)
    text_features = tfidf.transform([email_text])

    struct_features = extract_email_structural_features(sender, body)
    combined_features = hstack([text_features, [struct_features]])

    proba = email_model.predict_proba(combined_features)[0]
    phishing_confidence = round(proba[1] * 100, 2)

    # Hybrid verdict
    # Final verdict logic (fixed)
    if phishing_confidence >= 80:
        verdict = "PHISHING"
    elif rule_flag and phishing_confidence >= 60:
        verdict = "PHISHING"
    elif rule_flag or phishing_confidence >= 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    return {
        "verdict": verdict,
        "confidence": phishing_confidence,
        "reasons": reasons
    }
