from flask import Flask, render_template, request
from utils.hybrid_detector import detect_phishing_url
from utils.email_hybrid_detector import detect_phishing_email
from datetime import datetime

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan-url", methods=["POST"])
def scan_url():
    url = request.form.get("url")
    result = detect_phishing_url(url)
    return render_template(
        "result.html",
        item=url,
        verdict=result["verdict"],
        confidence=result["confidence"],
        reasons=result["reasons"],
        mode="URL",
        scanned_at=datetime.now().strftime("%d %b %Y, %I:%M %p")
    )


@app.route("/scan-email", methods=["POST"])
def scan_email():
    sender = request.form.get("sender")
    subject = request.form.get("subject")
    body = request.form.get("body")

    result = detect_phishing_email(sender, subject, body)
    return render_template(
        "result.html",
        item=subject,
        verdict=result["verdict"],
        confidence=result["confidence"],
        reasons=result["reasons"],
        mode="EMAIL",
        scanned_at=datetime.now().strftime("%d %b %Y, %I:%M %p")
    )


if __name__ == "__main__":
     app.run(host="0.0.0.0", port=10000)
