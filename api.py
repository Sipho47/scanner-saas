
import requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.extension import _rate_limit_exceeded_handler

from auth import create_access_token, decode_token, hash_password, verify_password
from database import (
    create_user,
    downgrade_expired_plan,
    get_scan_result,
    get_user_by_email,
    init_db,
    list_scan_results,
    save_payment_event,
    save_scan_result,
    update_user_plan,
)
from payments import (
    create_checkout_session,
    get_public_plans,
    verify_stripe_webhook,
)
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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


PLAN_PORT_LIMITS = {
    "free": 5,
    "pro": 20,
    "business": 50,
}


class RegisterRequest(BaseModel):
    email: str
    password: str


class CheckoutRequest(BaseModel):
    plan_id: str


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "plan": user["plan"],
        "plan_expires_at": user.get("plan_expires_at"),
        "created_at": user["created_at"],
        "port_limit": PLAN_PORT_LIMITS.get(user["plan"], PLAN_PORT_LIMITS["free"]),
    }


def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    if payload.get("error"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return downgrade_expired_plan(user)


def enforce_port_limit(ports: str | None, user: dict) -> None:
    if user["plan"] not in PLAN_PORT_LIMITS:
        raise HTTPException(status_code=403, detail="Invalid plan")

    try:
        selected_ports = parse_ports(ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    max_ports = PLAN_PORT_LIMITS.get(user["plan"], PLAN_PORT_LIMITS["free"])

    if len(selected_ports) > max_ports:
        raise HTTPException(
            status_code=400,
            detail=f"Port limit exceeded for {user['plan']} plan ({max_ports})",
        )


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {"message": "API running"}


@app.post("/register")
def register(data: RegisterRequest):
    email = data.email.strip().lower()
    password = data.password

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    if get_user_by_email(email):
        raise HTTPException(status_code=400, detail="User already exists")

    try:
        user = create_user(email, hash_password(password))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not create user") from exc

    token = create_access_token({"sub": user["email"]})
    return {
        "message": "User created",
        "access_token": token,
        "token_type": "bearer",
        "user": public_user(user),
    }


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)

    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": user["email"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": public_user(user),
    }


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"user": public_user(user)}


@app.get("/scan")
@limiter.limit("10/minute")
def scan(
    request: Request,
    url: str = Query(...),
    ports: str | None = Query(default=None),
    user=Depends(get_current_user),
):
    result = {}
    enforce_port_limit(ports, user)

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

    try:
        saved_scan = save_scan_result(
            result,
            fallback_target=url,
            user_email=user["email"],
        )
        result["scan_id"] = saved_scan["id"]
        result["created_at"] = saved_scan["created_at"]
    except Exception as e:
        result["storage_error"] = str(e)

    return result


@app.get("/scans")
def scans(limit: int = Query(default=20, ge=1, le=100), user=Depends(get_current_user)):
    return {"scans": list_scan_results(limit, user_email=user["email"])}


@app.get("/scans/{scan_id}")
def scan_detail(scan_id: int, user=Depends(get_current_user)):
    saved_scan = get_scan_result(scan_id, user_email=user["email"])
    if not saved_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return saved_scan


@app.get("/billing/plans")
def billing_plans():
    return {"plans": get_public_plans()}


@app.get("/billing/success")
def billing_success():
    return RedirectResponse("/?billing=success")


@app.get("/billing/cancel")
def billing_cancel():
    return RedirectResponse("/?billing=cancel")


@app.post("/billing/create-checkout-session")
def billing_checkout(
    data: CheckoutRequest,
    request: Request,
    user=Depends(get_current_user),
):
    base_url = str(request.base_url)

    try:
        return create_checkout_session(data.plan_id, base_url, user["email"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("stripe-signature")

    try:
        event = verify_stripe_webhook(payload, signature)
        saved_event = save_payment_event(event)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if event["type"] == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        metadata = session.get("metadata") or {}
        user_email = metadata.get("user_email") or session.get("customer_email")
        plan = metadata.get("plan")

        if user_email and plan in PLAN_PORT_LIMITS:
            update_user_plan(user_email, plan, days=30)

    return {
        "received": True,
        "event_id": event["id"],
        "event_type": event["type"],
        "stored_event_id": saved_event["id"],
    }
