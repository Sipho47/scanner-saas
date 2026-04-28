
from fastapi import FastAPI, Query
import requests

app = FastAPI()

@app.get("/")
def home():
    return {"message": "API running"}

@app.get("/scan")
def scan(url: str = Query(...)):
    result = {}

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Basic info
        result["status_code"] = response.status_code
        result["server"] = headers.get("server", "Unknown")

        # Security checks
        result["security_headers"] = {
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
        }

        # Simple vulnerabilities
        issues = []

        if not headers.get("X-Frame-Options"):
            issues.append("Missing X-Frame-Options (Clickjacking risk)")

        if not headers.get("Content-Security-Policy"):
            issues.append("Missing Content-Security-Policy")

        if not headers.get("Strict-Transport-Security"):
            issues.append("Missing HSTS (HTTPS not enforced)")

        result["issues"] = issues

    except Exception as e:
        result["error"] = str(e)

    return result