import re
import tldextract
from urllib.parse import urlparse

SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
PHISHING_KEYWORDS = ["login", "verify", "update", "secure", "account", "bank"]

def extract_url_features(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = extracted.domain + "." + extracted.suffix
    path = parsed.path

    features = []

    # 1–7 (original)
    features.append(len(url))                                        # url_length
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)  # has_ip
    features.append(url.count('.'))                                  # dot_count
    features.append(1 if '@' in url else 0)                          # has_at
    features.append(1 if parsed.scheme == "https" else 0)            # has_https
    features.append(url.count('-'))                                  # dash_count

    subdomain = extracted.subdomain
    features.append(0 if subdomain == "" else subdomain.count('.') + 1)  # subdomain_count

    # 8–13 (enhanced)
    features.append(len(domain))                                     # domain_length
    features.append(len(path))                                       # path_length
    features.append(sum(char.isdigit() for char in url))             # digit_count
    features.append(1 if any(s in url for s in SHORTENERS) else 0)    # uses_shortener
    features.append(sum(k in url.lower() for k in PHISHING_KEYWORDS)) # keyword_count
    features.append(parsed.query.count('='))                          # query_param_count

    return features
