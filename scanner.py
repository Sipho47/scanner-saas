from datetime import datetime, timezone
import ipaddress
import socket
import ssl
from urllib.parse import urlparse


DEFAULT_PORTS = [80, 443, 8080, 8443]
COMMON_SUBDOMAINS = ["www", "api", "app", "admin", "dev", "staging", "mail"]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL is required")

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported")

    if not parsed.hostname:
        raise ValueError("URL must include a valid hostname")

    return url


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("URL must include a valid hostname")
    return parsed.hostname.lower()


def resolve_public_ip(hostname: str) -> str:
    ip_address = socket.gethostbyname(hostname)
    parsed_ip = ipaddress.ip_address(ip_address)

    if (
        parsed_ip.is_private
        or parsed_ip.is_loopback
        or parsed_ip.is_link_local
        or parsed_ip.is_reserved
        or parsed_ip.is_multicast
    ):
        raise ValueError("Target resolves to a private or restricted IP address")

    return ip_address


def parse_ports(raw_ports: str | None) -> list[int]:
    if not raw_ports:
        return DEFAULT_PORTS

    ports = []
    for value in raw_ports.split(","):
        value = value.strip()
        if not value:
            continue

        try:
            port = int(value)
        except ValueError as exc:
            raise ValueError(f"Invalid port: {value}") from exc

        if port < 1 or port > 65535:
            raise ValueError(f"Port out of range: {port}")

        if port not in ports:
            ports.append(port)

    if len(ports) > 10:
        raise ValueError("Please scan 10 ports or fewer at a time")

    return ports or DEFAULT_PORTS


def check_port(hostname: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(hostname: str, ports: list[int] | None = None) -> dict[str, list[int]]:
    selected_ports = ports or DEFAULT_PORTS
    open_ports = []
    closed_ports = []

    for port in selected_ports:
        if check_port(hostname, port):
            open_ports.append(port)
        else:
            closed_ports.append(port)

    return {
        "checked": selected_ports,
        "open": open_ports,
        "closed_or_filtered": closed_ports,
    }


def check_ssl(hostname: str, port: int = 443) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                certificate = secure_sock.getpeercert()

        not_after = certificate.get("notAfter")
        expires_at = None
        days_until_expiry = None

        if not_after:
            expires_timestamp = ssl.cert_time_to_seconds(not_after)
            expires_at_datetime = datetime.fromtimestamp(expires_timestamp, timezone.utc)
            expires_at = expires_at_datetime.isoformat()
            days_until_expiry = (expires_at_datetime - datetime.now(timezone.utc)).days

        return {
            "valid": True,
            "issuer": _format_certificate_name(certificate.get("issuer", [])),
            "subject": _format_certificate_name(certificate.get("subject", [])),
            "expires_at": expires_at,
            "days_until_expiry": days_until_expiry,
        }
    except Exception as exc:
        return {
            "valid": False,
            "error": str(exc),
        }


def discover_subdomains(hostname: str) -> list[dict[str, str]]:
    root_domain = _guess_root_domain(hostname)
    discovered = []

    for prefix in COMMON_SUBDOMAINS:
        subdomain = f"{prefix}.{root_domain}"

        try:
            ip_address = resolve_public_ip(subdomain)
        except Exception:
            continue

        discovered.append({"host": subdomain, "ip": ip_address})

    return discovered


def _format_certificate_name(parts: tuple) -> dict[str, str]:
    formatted = {}

    for group in parts:
        for key, value in group:
            formatted[key] = value

    return formatted


def _guess_root_domain(hostname: str) -> str:
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    return ".".join(labels[-2:])
