from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import time


STRIPE_CHECKOUT_URL = "https://api.stripe.com/v1/checkout/sessions"


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    price_label: str
    scan_limit: int
    price_env: str | None = None


PLANS = {
    "free": Plan("free", "Free", "$0/mo", 25),
    "pro": Plan("pro", "Pro", "$19/mo", 500, "STRIPE_PRO_PRICE_ID"),
    "business": Plan(
        "business",
        "Business",
        "$79/mo",
        5000,
        "STRIPE_BUSINESS_PRICE_ID",
    ),
}


def get_public_plans() -> list[dict]:
    return [
        {
            "id": plan.id,
            "name": plan.name,
            "price": plan.price_label,
            "scan_limit": plan.scan_limit,
            "paid": plan.price_env is not None,
            "configured": bool(get_price_id(plan.id)) if plan.price_env else True,
        }
        for plan in PLANS.values()
    ]


def create_checkout_session(plan_id: str, base_url: str, user_email: str) -> dict:
    import requests

    plan = PLANS.get(plan_id)
    if not plan:
        raise ValueError("Unknown plan")

    if not plan.price_env:
        raise ValueError("The free plan does not require checkout")

    secret_key = os.getenv("STRIPE_SECRET_KEY")
    price_id = get_price_id(plan_id)

    if not secret_key:
        raise ValueError("Missing STRIPE_SECRET_KEY")

    if not price_id:
        raise ValueError(f"Missing {plan.price_env}")

    base_url = os.getenv("PUBLIC_BASE_URL", base_url).rstrip("/")
    response = requests.post(
        STRIPE_CHECKOUT_URL,
        auth=(secret_key, ""),
        data={
            "mode": "subscription",
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": 1,
            "success_url": f"{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            "cancel_url": f"{base_url}/billing/cancel",
            "customer_email": user_email,
            "metadata[plan]": plan.id,
            "metadata[user_email]": user_email,
        },
        timeout=10,
    )

    if response.status_code >= 400:
        try:
            error = response.json()["error"]["message"]
        except Exception:
            error = response.text
        raise ValueError(error)

    session = response.json()
    return {"checkout_url": session["url"], "session_id": session["id"]}


def verify_stripe_webhook(payload: bytes, signature_header: str | None) -> dict:
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    if not webhook_secret:
        raise ValueError("Missing STRIPE_WEBHOOK_SECRET")

    if not signature_header:
        raise ValueError("Missing Stripe-Signature header")

    timestamp, signatures = _parse_signature_header(signature_header)
    if abs(time.time() - timestamp) > 300:
        raise ValueError("Webhook signature timestamp is too old")

    signed_payload = f"{timestamp}.".encode() + payload
    expected_signature = hmac.new(
        webhook_secret.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    if not any(hmac.compare_digest(expected_signature, signature) for signature in signatures):
        raise ValueError("Invalid webhook signature")

    return json.loads(payload)


def get_price_id(plan_id: str) -> str | None:
    plan = PLANS.get(plan_id)
    if not plan or not plan.price_env:
        return None
    return os.getenv(plan.price_env)


def _parse_signature_header(signature_header: str) -> tuple[int, list[str]]:
    timestamp = None
    signatures = []

    for part in signature_header.split(","):
        key, _, value = part.partition("=")
        if key == "t":
            timestamp = int(value)
        elif key == "v1":
            signatures.append(value)

    if timestamp is None or not signatures:
        raise ValueError("Invalid Stripe-Signature header")

    return timestamp, signatures
