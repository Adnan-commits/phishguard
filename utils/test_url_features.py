from features.url_features import extract_url_features

test_url = "http://secure-login.paypal.verify-user.com/login"

features = extract_url_features(test_url)

for key, value in features.items():
    print(f"{key}: {value}")
