# 🛡️ PhishGuard — Hybrid Phishing Detection Platform

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20App-black?logo=flask)
![ML](https://img.shields.io/badge/ML-scikit--learn-orange?logo=scikit-learn)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

PhishGuard is a hybrid phishing detection platform that combines **rule-based heuristics** and **machine learning** to detect malicious URLs and phishing emails — with explainable risk scoring so users understand *why* something was flagged.

---

## 📊 Results

| Target | Accuracy |
|---|---|
| Malicious URL Detection | **87.8%** |
| Phishing Email Detection | **99.2%** |

---

## 🏗️ Architecture

PhishGuard runs two independent detection pipelines — one for URLs, one for emails — each combining a rule engine with a trained ML model.

```
         ┌────────────────────────────────────────┐
         │              Flask Web App              │
         │          app/app.py + templates/        │
         └───────────────┬────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
   ┌──────▼──────┐               ┌──────▼──────┐
   │  URL Input  │               │ Email Input │
   └──────┬──────┘               └──────┬──────┘
          │                             │
   ┌──────▼──────┐               ┌──────▼──────┐
   │  url_rules  │               │ email_rules │   ← Rule-based heuristics
   └──────┬──────┘               └──────┬──────┘     (rules/)
          │                             │
   ┌──────▼──────┐               ┌──────▼──────┐
   │url_features │               │email_features│  ← Feature extraction
   └──────┬──────┘               └──────┬──────┘     (features/)
          │                             │
   ┌──────▼────────────┐    ┌───────────▼─────────────┐
   │phishing_url_model │    │ phishing_email_model    │  ← Trained ML models
   │      .pkl         │    │ + email_tfidf_vectorizer│    (model/)
   └──────┬────────────┘    └───────────┬─────────────┘
          │                             │
          └──────────────┬──────────────┘
                         │
                  ┌──────▼──────┐
                  │ Risk Score  │
                  │  + Verdict  │
                  └─────────────┘
```

### How Each Pipeline Works

**URL Detection**
1. `url_rules.py` applies rule-based heuristic checks on the URL structure
2. `url_features.py` extracts numerical features from the URL
3. `phishing_url_model.pkl` (trained ML model) classifies based on those features
4. A combined risk score and verdict is returned

**Email Detection**
1. `email_rules.py` applies heuristic checks on email headers and content
2. `email_features.py` extracts features from the email body and metadata
3. `email_tfidf_vectorizer.pkl` vectorizes the text content
4. `phishing_email_model.pkl` classifies the vectorized input
5. A combined risk score and verdict is returned

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Web Framework | Python, Flask |
| Frontend | HTML, CSS (served via Flask templates) |
| ML Models | scikit-learn (`.pkl` — separate models for URL and email) |
| Text Vectorization | TF-IDF (`email_tfidf_vectorizer.pkl`) |
| Feature Engineering | Custom Python modules (`url_features.py`, `email_features.py`) |
| Rule Engine | Custom Python modules (`url_rules.py`, `email_rules.py`) |

---

## 📁 Project Structure

```
phishguard/
├── app/
│   ├── app.py               # Flask application — routes & detection logic
│   ├── static/              # CSS, JS, and static assets
│   └── templates/           # HTML templates
├── features/
│   ├── url_features.py      # Feature extraction for URLs
│   ├── email_features.py    # Feature extraction for emails
│   └── feature_order.txt    # Defines feature vector ordering
├── model/
│   ├── phishing_url_model.pkl        # Trained URL classifier
│   ├── phishing_email_model.pkl      # Trained email classifier
│   ├── email_tfidf_vectorizer.pkl    # TF-IDF vectorizer for email text
│   ├── load_model.py                 # URL model loader
│   └── load_email_model.py           # Email model loader
├── rules/
│   ├── url_rules.py         # Heuristic rules for URL detection
│   └── email_rules.py       # Heuristic rules for email detection
├── utils/                   # Shared utility functions
├── requirements.txt
└── runtime.txt
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.x
- pip

### Installation

```bash
git clone https://github.com/Adnan-commits/phishguard.git
cd phishguard
pip install -r requirements.txt
```

### Running the App

```bash
cd app
python app.py
```

Then open `http://localhost:5000` in your browser.

---

## 👤 Author

**Adnan Bardgujar**
[LinkedIn](https://www.linkedin.com/in/adnan-bardgujar-b43b7a25b) · [GitHub](https://github.com/Adnan-commits)

---

> ⚠️ PhishGuard is an academic project. It is not intended as a production-grade security tool without further dataset validation and hardening.
