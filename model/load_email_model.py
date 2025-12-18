import joblib

EMAIL_MODEL_PATH = "model/phishing_email_model.pkl"
TFIDF_PATH = "model/email_tfidf_vectorizer.pkl"

def load_email_model():
    model = joblib.load(EMAIL_MODEL_PATH)
    tfidf = joblib.load(TFIDF_PATH)
    return model, tfidf
