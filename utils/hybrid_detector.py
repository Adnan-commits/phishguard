from features.url_features import extract_url_features
from rules.url_rules import rule_based_url_detection
from model.load_model import load_phishing_model
import tldextract

# Load trained ML model once
model = load_phishing_model()

# Known legitimate brand domains (for explanation only)
KNOWN_BRANDS = {
    "facebook": ["facebook.com", "fb.com"],
    "google": ["google.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"]
}


def detect_phishing_url(url):
    features = extract_url_features(url)

    # -------------------------------
    # Rule-based explanations
    # -------------------------------
    rule_reasons = []

    if features[0] > 75:
        rule_reasons.append("Unusually long URL")

    if features[1] == 1:
        rule_reasons.append("IP address used instead of domain")

    if features[3] == 1:
        rule_reasons.append("Contains '@' symbol")

    if features[6] > 2:
        rule_reasons.append("Excessive subdomains")

    if features[4] == 0:
        rule_reasons.append("Does not use HTTPS")

    # Inputs for rule engine (risk scoring)
    rule_inputs = {
        "url_length": features[0],
        "has_ip": features[1],
        "has_at": features[3],
        "subdomain_count": features[6],
        "has_https": features[4]
    }

    # Strong rule confirmation (>= 2 risk indicators)
    rule_flag = rule_based_url_detection(rule_inputs)

    # -------------------------------
    # ML prediction
    # -------------------------------
    proba = model.predict_proba([features])[0]
    phishing_confidence = round(proba[1] * 100, 2)

    # -------------------------------
    # Explanation enrichment
    # (Brand impersonation – SAFE)
    # -------------------------------
    ext = tldextract.extract(url.lower())
    registered_domain = f"{ext.domain}.{ext.suffix}"

    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in url.lower():
            if registered_domain not in legit_domains:
                rule_reasons.append(
                    f"Possible impersonation of {brand.capitalize()} domain"
                )
            break

    # ML-based explanation (only at high confidence)
    if phishing_confidence >= 80:
        rule_reasons.append(
            "URL structure closely matches known phishing patterns"
        )

    # -------------------------------
    # Final verdict logic
    # -------------------------------
    any_rule_signal = len(rule_reasons) > 0

    if phishing_confidence >= 80:
        verdict = "PHISHING"
    elif phishing_confidence >= 60 and rule_flag:
        verdict = "PHISHING"
    elif phishing_confidence >= 50 and any_rule_signal:
        verdict = "SUSPICIOUS"
    elif rule_flag:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    return {
        "verdict": verdict,
        "confidence": phishing_confidence,
        "reasons": rule_reasons
    }
