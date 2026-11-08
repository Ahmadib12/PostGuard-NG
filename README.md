# PostGuard-NG

PostGuard-NG is a FastAPI security gateway for signed postcode lookup requests. The project sits in front of an upstream postcode service and enforces authentication, replay protection, rate limiting, region policy checks, and advisory geo monitoring before a request is passed along.

This repository is intentionally security-focused middleware rather than a full postcode service. The live NIPOST integration is not assumed to be available unless official endpoint details and credentials are provided and tested.

## What it does

- Validates a client’s identity before accepting requests.
- Verifies HMAC-SHA256 signatures over the raw request body.
- Rejects expired timestamps and malformed security headers.
- Keeps a Redis-backed nonce store with atomic registration to prevent replay attacks.
- Enforces per-client rate limits with a fail-closed Redis path.
- Checks client policy restrictions such as allowed regions and maximum lookup levels.
- Logs structured security events in JSON for future monitoring dashboards.
- Uses mock-mode responses for local development and demonstration when no live upstream is configured.

## Architecture overview

- `app.py`: FastAPI routes, request validation, health endpoints, logging, and middleware.
- `security.py`: HMAC verification, replay checks, rate limiting, client policy validation, geo anomaly monitoring, and upstream proxy logic.
- `config.py`: environment validation and client configuration with a demo policy structure that is ready for future database-backed client management.
- `secure_query_client.py`: sample client that signs and sends a request with a consistent canonical format.
- `tests/`: automated unit and API verification for the gateway flow.

## Request authentication flow

Every secure request includes:

- `X-Client-ID`
- `X-Timestamp`
- `X-Nonce`
- `X-Signature`

The gateway checks:

1. Client identity exists in the configured policy map.
2. Request header format is valid.
3. Timestamp is within the configured skew window.
4. HMAC is computed over the exact raw body using the client-specific secret.
5. Client policy allows the region and lookup level.
6. Redis-backed rate limit permits the request.
7. The nonce is atomically registered for that client; duplicates are rejected.

Canonical signing format:

```text
METHOD:PATH:CLIENT_ID:TIMESTAMP:NONCE:RAW_BODY
```

The signature is generated with HMAC-SHA256 using a client-specific secret. Secrets must be at least 32 bytes and stored outside version control.

## Replay protection and rate limiting

The asynchronous request path executes synchronous Redis work in a worker thread and uses one atomic Lua script to increment/check the client rate counter and register the nonce. A request over the limit returns `429` without consuming its nonce; an in-limit duplicate returns `409`. Concurrent requests cannot bypass either check because Redis executes the combined script atomically. A rate-limited request can be retried with the same signed request after the rate window only while its timestamp remains within the configured clock-skew limit. If Redis is unavailable, the application fails closed with a 503 response.

Rate limiting also uses Redis atomic counters. Each client keeps a separate counter and window. A Redis failure prevents request acceptance and emits a structured error event.

## Client access policies

The demo configuration keeps a simple policy structure:

```python
"demo-client": {
    "allowed_regions": ["abuja", "fct", "lagos"],
    "max_level": 2,
    "rate_limit_per_minute": 10,
}
```

This is intentionally structured so a database-backed client registry can be introduced later without rewriting the API contract.

## Geo anomaly monitoring

Geo monitoring is advisory and does not infer a location from postcode prefixes or assume Abuja coordinates represent Nigerian coverage. The prototype has no authoritative postcode-to-region or coordinate dataset, and client-supplied coordinates cannot prove a user’s real location. The request model only validates that coordinates are within global latitude/longitude bounds; reliable geographic anomaly monitoring requires trusted location signals and authoritative postal data.

A trusted location source and authoritative postcode-region data would be required before making geo-based enforcement decisions.

## Upstream proxy protection

The proxy layer uses explicit timeouts, disables redirects, accepts only 2xx responses with valid JSON whose top-level value is an object, and does not expose upstream error bodies or raw exceptions to clients. Because no authoritative NIPOST response schema is available here, it does not assume any specific fields within that object.

Important: the current implementation is mock-first. The app supports mock mode even when a live upstream is not configured. Do not treat this as a verified live NIPOST integration unless the official endpoint and credentials are provided and tested.

## Environment variables

Create a local `.env` from `.env.example` and keep secrets out of source control.

Example variables:

```bash
HOST=0.0.0.0
PORT=8000
DEBUG=false
MOCK_NIPOST=true
REDIS_URL=redis://localhost:6379/0
POSTGUARD_DEMO_CLIENT_SECRET=replace-me-with-a-32-byte-secret
POSTGUARD_PARTNER_X_SECRET=replace-me-with-a-different-32-byte-secret
NIPOST_API_KEY=live-key-only-when-not-using-mock-mode
```

## Local setup

### Python 3.11 virtual environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Redis setup

Redis is needed for nonce and rate-limit enforcement. A local Redis instance or container should be available before running the application.

Example:

```bash
redis-server
```

## Run the application

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

Optional Redis integration tests can be enabled with:

```bash
RUN_REDIS_INTEGRATION_TESTS=1 python -m unittest discover -s tests -v
```

## Sample client

The repository includes a sample CLI client in `secure_query_client.py`.

Example:

```bash
python secure_query_client.py --client-id demo-client --base-url http://127.0.0.1:8000
```

Set the secret in the environment using the same naming convention as the server:

```bash
export POSTGUARD_DEMO_CLIENT_SECRET="replace-with-32-plus-bytes"
```

## API endpoints

### Health

```http
GET /health
```

Returns liveness, readiness, and upstream mode information without exposing secrets or infrastructure details. The synchronous Redis readiness ping is run in a worker thread so it does not block the asynchronous event loop.

### Secure postcode lookup

```http
POST /api/v1/secure-query
```

Example request body:

```json
{
  "postcode": "FC-03-B06-AG-12",
  "level": 1,
  "client_lat": 9.0579,
  "client_lon": 7.4951,
  "declared_region": "Abuja"
}
```

## Current limitations

- The current client registry is configuration-based; it is not yet backed by a database.
- The upstream integration is mock-first and should not be described as a production NIPOST implementation until official documentation and credentials are available.
- Geo checks remain advisory and do not constitute definitive fraud detection.
- The application is hardened for a secure internal deployment model, but it is not a complete production environment by itself.

## Future roadmap

Planned work for later phases includes:

- Security dashboard overview endpoints.
- API metric and audit log collection.
- Client management and policy storage.
- Rate-limit and upstream health monitoring.
- Official NIPOST integration when authoritative documentation and credentials are available.

## License

This project is licensed under the MIT License. See `LICENSE` for details.
