import joblib

MODEL_PATH = "model/phishing_url_model.pkl"

def load_phishing_model():
    return joblib.load(MODEL_PATH)
