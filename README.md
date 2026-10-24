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
- basic geo-anomaly detection based on postcode/region/location mismatch
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

and then hashed with HMAC-SHA256 using the configured `POSTGUARD_CLIENT_SECRET`.

### 2. Replay protection
A nonce is stored in Redis for a short TTL. Reuse of the same nonce for the same client is rejected.

### 3. Rate limiting
Per-client request quotas are enforced using a Redis key and sliding-style count validation.

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

### 5. Geo mismatch checks
Requests can be blocked when the postcode, declared region, and client geo coordinates do not align.

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

```env
POSTGUARD_CLIENT_SECRET=your-secret-key
NIPOST_API_KEY=your-nipost-api-key
REDIS_URL=redis://localhost:6379/0
HOST=0.0.0.0
PORT=8000
DEBUG=false
```

### 5. Start the service

```bash
uvicorn app:app --reload --host 0.0.0.0 --port 8000
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
- The project includes demo client policies in `config.py`; replace them with a real tenant database or auth model before production deployment.
- Geo validation is intentionally simple and acts as a prototype guardrail, not a full geospatial intelligence system.

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.
