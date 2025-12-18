import re

LEAKAGE_WORDS = ['phishing', 'spam', 'ham']

def clean_email_text(text):
    text = text.lower()
    for word in LEAKAGE_WORDS:
        text = text.replace(word, '')
    return text

def extract_email_structural_features(sender, body):
    features = []

    # 1. Email length
    features.append(len(body))

    # 2. Number of URLs
    features.append(len(re.findall(r"http[s]?://", body)))

    # 3. Suspicious sender domain
    if "@" in sender:
        domain = sender.split("@")[-1]
        features.append(1 if domain.count('.') > 2 else 0)
    else:
        features.append(0)

    # 4. IP-based URL
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', body) else 0)

    return features
