
import requests
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from scanner import (
    check_ssl,
    discover_subdomains,
    get_hostname,
    normalize_url,
    parse_ports,
    resolve_public_ip,
    scan_ports,
)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {"message": "API running"}


@app.get("/scan")
def scan(url: str = Query(...), ports: str | None = Query(default=None)):
    result = {}

    try:
        normalized_url = normalize_url(url)
        hostname = get_hostname(normalized_url)
        selected_ports = parse_ports(ports)
        resolved_ip = resolve_public_ip(hostname)

        response = requests.get(
            normalized_url,
            timeout=5,
            headers={"User-Agent": "ScannerSaaS/1.0"},
        )
        headers = response.headers

        # Basic info
        result["target"] = normalized_url
        result["hostname"] = hostname
        result["resolved_ip"] = resolved_ip
        result["status_code"] = response.status_code
        result["reachable"] = response.ok
        result["final_url"] = response.url
        result["server"] = headers.get("server", "Unknown")

        # Security checks
        result["security_headers"] = {
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
        }

        # Safe, passive-ish scanner checks
        result["ports"] = scan_ports(hostname, selected_ports)
        result["ssl"] = check_ssl(hostname)
        result["subdomains"] = discover_subdomains(hostname)

        # Simple vulnerabilities / warnings
        issues = []

        if not headers.get("X-Frame-Options"):
            issues.append("Missing X-Frame-Options (Clickjacking risk)")

        if not headers.get("Content-Security-Policy"):
            issues.append("Missing Content-Security-Policy")

        if not headers.get("Strict-Transport-Security"):
            issues.append("Missing HSTS (HTTPS not enforced)")

        if result["ssl"]["valid"] and result["ssl"].get("days_until_expiry") is not None:
            if result["ssl"]["days_until_expiry"] < 30:
                issues.append("SSL certificate expires in less than 30 days")

        if 80 in result["ports"]["open"]:
            issues.append("HTTP port 80 is open")

        result["issues"] = issues

    except Exception as e:
        result["error"] = str(e)

    return result
