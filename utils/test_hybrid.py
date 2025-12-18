from utils.hybrid_detector import detect_phishing_url

test_urls = [
    "https://www.google.com",
    "http://secure-login.paypal.verify-user.com/login",
    "http://192.168.1.10/login",
    "https://accounts.google.com/signin",
    "https://bit.ly/3xYzAbC"
]

for url in test_urls:
    print(url, "→", detect_phishing_url(url))
