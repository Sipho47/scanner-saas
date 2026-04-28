# scanner-saas

FastAPI security scanner with a browser dashboard and saved scan history.

## Run locally

```bash
uvicorn api:app --reload
```

Open `http://127.0.0.1:8000/`.

## Database

The app uses SQLite locally by default and stores data in `scanner.db`.

On Render, add a PostgreSQL database and set the app's `DATABASE_URL`
environment variable. The table is created automatically on startup.

## Stripe

Checkout is prepared but disabled until these environment variables exist:

```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PRO_PRICE_ID=price_...
STRIPE_BUSINESS_PRICE_ID=price_...
STRIPE_WEBHOOK_SECRET=whsec_...
PUBLIC_BASE_URL=https://scanner-saas-1.onrender.com
```

Create recurring Stripe Prices for the Pro and Business plans, then add their
Price IDs to your local environment or Render service.

## Authentication

Set a long random secret in production:

```bash
SECRET_KEY=change_me_to_a_long_random_value
```

Users can register and log in with JWT bearer tokens. Protected endpoints only
return the current user's scans. Plan limits currently allow:

- Free: 5 ports per scan
- Pro: 20 ports per scan
- Business: 50 ports per scan

`GET /scan` is rate-limited to 10 requests per minute per client IP. Paid
plans receive a `plan_expires_at` timestamp when Stripe confirms checkout; if
that timestamp is in the past, the account is downgraded to Free on the next
authenticated request.

## Endpoints

- `POST /register`
- `POST /login`
- `GET /me`
- `GET /scan?url=https://example.com`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /billing/plans`
- `POST /billing/create-checkout-session`
- `POST /webhooks/stripe`
- `GET /health`
