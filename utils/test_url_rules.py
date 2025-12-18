from features.url_features import extract_url_features
from rules.url_rules import rule_based_url_detection

test_urls = [
    "https://www.google.com",
    "http://secure-login.paypal.verify-user.com/login",
    "http://192.168.1.10/login"
]

for url in test_urls:
    features = extract_url_features(url)
    verdict = rule_based_url_detection(features)
    print(url, "→", "PHISHING" if verdict else "LEGITIMATE")
