# PostGuard NG 🛡️🇳🇬

> A FastAPI security gateway for validating and protecting signed postcode lookup requests before they reach NIPOST infrastructure.

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

This project is a working API gateway built to protect postcode lookup requests issued to Nigeria's NIPOST postcode infrastructure.

It does not act as a replacement for NIPOST itself. Instead, it sits in front of the upstream service and enforces security controls before forwarding valid requests.

The actual implementation in this repository includes:

- HMAC-SHA256 request signing verification
- timestamp validation and replay protection using nonce tracking
- Redis-backed rate limiting
- region and level policy enforcement per client
- advisory geo-anomaly logging based on postcode/region/location mismatch
- upstream proxying to the NIPOST lookup API

---

## Project Structure

```text
.
├── app.py              # FastAPI application and API routes
├── config.py           # Environment configuration and client policies
├── security.py         # Validation, rate limiting, geo checks, upstream proxy
├── requirements.txt    # Python dependencies
├── .env.example        # Example environment file (if added in your local setup)
├── README.md
├── LICENSE
└── .gitignore
```

The current codebase is a compact, production-style prototype and is centered around these main files:

- `app.py` – defines the API endpoints and request validation flow
- `config.py` – holds settings and the demo client policy map
- `security.py` – performs HMAC verification, nonce tracking, rate limiting and proxy logic

---

## Security Features

### 1. HMAC request validation
Every request must include a valid signature computed from the request body and headers. The canonical payload is built as:

```text
METHOD:PATH:CLIENT_ID:TIMESTAMP:NONCE:RAW_BODY
```

and then hashed with HMAC-SHA256 using a separate per-client secret. For example, `demo-client` uses `POSTGUARD_DEMO_CLIENT_SECRET`, while `partner-x` uses `POSTGUARD_PARTNER_X_SECRET`. Each secret must contain at least 32 bytes.

### 2. Replay protection
A nonce is stored atomically in Redis for a short TTL after the request signature and client policy are verified. Reuse of the same nonce for the same client is rejected.

### 3. Rate limiting
Per-client request quotas use an atomic Redis counter with a fixed 60-second window. Redis errors fail closed with a service-unavailable response.

### 4. Client policy enforcement
The project defines a demo client map in `config.py` with allowed regions and maximum requested levels.

Example policy entries:

```python
"demo-client": {
    "allowed_regions": ["abuja", "fct", "lagos"],
    "max_level": 2,
    "rate_limit_per_minute": 10,
}
```

### 5. Advisory geo mismatch signals
The requester supplies its own coordinates, so they are not trustworthy proof of location. Mismatches are logged for monitoring but do not block the request. Use a trusted location source and authoritative postcode-region data before enforcing geo-based access decisions.

### Request and upstream protections
Request bodies are limited by `MAX_REQUEST_BODY_BYTES` (16 KiB by default), and security headers have strict length/format validation. The upstream HTTP client is reused for the application lifespan, has explicit timeouts, and does not follow redirects. Upstream error bodies are never returned to API clients.

---

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/Ahmadib12/PostGuard-NG.git
cd PostGuard-NG
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows:

```bash
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```envenvenvenvenvenvenvenvenvenvenvenvenvenvenvenv
POSTGUARD_DEMO_CLIENT_SECRET=<unique-random-secret-at-least-32-bytes>
POSTGUARD_PARTNER_X_SECRET=<different-unique-random-secret-at-least-32-bytes>
NIPOST_API_KEY=your-nipost-api-key
MOCK_NIPOST=true
REDIS_URL=redis://localhost:6379/0
HOST=0.0.0.0
PORT=8000
DEBUG=false
MAX_REQUEST_BODY_BYTES=16384
```

Generate each client secret separately (run the command twice):

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

The client ID determines the environment variable name. For example, `demo-client` reads `POSTGUARD_DEMO_CLIENT_SECRET`.

### 5. Start the service

```bash
python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

---

## API Endpoints

### Health check

```http
GET /health
```

Returns service metadata and active protections.

### Secure postcode query

```http
POST /api/v1/secure-query
```

#### Body

```json
{
  "postcode": "FC-03-B06-AG-12",
  "level": 2,
  "client_lat": 9.0765,
  "client_lon": 7.3986,
  "declared_region": "Abuja"
}
```

#### Required headers

```http
X-Client-ID: demo-client
X-Timestamp: 1720000000
X-Nonce: 123e4567-e89b-12d3-a456-426614174000
X-Signature: <sha256-hmac-hex>
```

---

## Generating the HMAC signature

The service expects the raw request body as the signed payload.

Example Python snippet:

```python
import json
import hmac
import hashlib

client_id = "demo-client"
timestamp = "1720000000"
nonce = "123e4567-e89b-12d3-a456-426614174000"
secret = "your-secret-key"

payload = {
    "postcode": "FC-03-B06-AG-12",
    "level": 2,
    "client_lat": 9.0765,
    "client_lon": 7.3986,
    "declared_region": "Abuja",
}

raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
path = "/api/v1/secure-query"
method = "POST"
canonical = f"{method}:{path}:{client_id}:{timestamp}:{nonce}:{raw_body.decode('utf-8')}"
signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

print(signature)
```

Then send the value in `X-Signature`.

---

## Notes

- Redis must be running for nonce and rate limit checks to work.
- Run unit and API-flow tests with `python -m unittest discover -s tests -v`. For an opt-in concurrency test against the configured Redis instance, set `RUN_REDIS_INTEGRATION_TESTS=1` before running the suite; use a dedicated test Redis database.
- The project includes demo client policies in `config.py`; replace them with a real tenant database or auth model before production deployment.
- For production, terminate HTTPS at a trusted reverse proxy/load balancer and restrict direct access to the application. Use authenticated Redis on a private network; configure Redis TLS (`rediss://`) where supported. Do not expose Redis publicly.
- Rotate any credentials that were previously committed or shared, and keep real secrets out of `.env.example` and source control.
- Geo checks are advisory only because the client supplies its own coordinates.

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.
