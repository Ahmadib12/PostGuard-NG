import hashlib
import hmac
import json
import logging
import os
import time
from typing import Dict, Optional

import httpx
import redis
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PostGuard-NG")

app = FastAPI(
    title="PostGuard NG Security Gateway",
    description="Production-hardened middleware protecting NIPOST postcode infrastructure.",
    version="2.0.0",
)

# -----------------------------
# Required environment variables
# -----------------------------
CLIENT_SECRET_KEY = os.getenv("POSTGUARD_CLIENT_SECRET")
if not CLIENT_SECRET_KEY:
    raise RuntimeError("POSTGUARD_CLIENT_SECRET is required. Set it in your environment.")

NIPOST_API_KEY = os.getenv("NIPOST_API_KEY")
if not NIPOST_API_KEY:
    raise RuntimeError("NIPOST_API_KEY is required. Set it in your environment.")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# -----------------------------
# Demo client registry
# Replace with DB/identity service in production
# -----------------------------
CLIENT_POLICY: Dict[str, Dict[str, object]] = {
    "demo-client": {
        "allowed_regions": ["abuja", "fct", "lagos"],
        "max_level": 2,
        "rate_limit_per_minute": 10,
    },
    "partner-x": {
        "allowed_regions": ["abuja", "fct"],
        "max_level": 3,
        "rate_limit_per_minute": 20,
    },
}

NIPOST_BASE_URL = "https://api.postcode.gov.ng/v1"
REQUEST_TTL_SECONDS = 120
NONCE_TTL_SECONDS = 300
MAX_REQUESTS_PER_MINUTE = 10
MAX_CLOCK_SKEW_SECONDS = 120

# -----------------------------
# Pydantic request models
# -----------------------------
class PostcodeQuery(BaseModel):
    postcode: str = Field(..., min_length=8, max_length=30, example="FC-03-B06-AG-12")
    level: int = Field(1, ge=1, le=5)
    client_lat: float = Field(..., ge=-90.0, le=90.0)
    client_lon: float = Field(..., ge=-180.0, le=180.0)
    declared_region: str = Field(..., min_length=2, max_length=50)

    @field_validator("postcode")
    @classmethod
    def validate_postcode(cls, v: str) -> str:
        sanitized = v.strip().upper()
        if not sanitized:
            raise ValueError("postcode cannot be empty")
        if len(sanitized) < 8:
            raise ValueError("postcode is too short")
        return sanitized

    @field_validator("declared_region")
    @classmethod
    def validate_region(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("declared_region cannot be empty")
        return v.strip()

# -----------------------------
# Utility functions
# -----------------------------
def current_unix_time() -> int:
    return int(time.time())

def verify_timestamp(ts: str) -> bool:
    try:
        ts_int = int(ts)
    except ValueError:
        return False
    return abs(current_unix_time() - ts_int) <= MAX_CLOCK_SKEW_SECONDS

def register_nonce(client_id: str, nonce: str) -> bool:
    key = f"postguard:nonce:{client_id}:{nonce}"
    if redis_client.exists(key):
        return False
    redis_client.set(key, "1", ex=NONCE_TTL_SECONDS)
    return True

def check_rate_limit(client_id: str) -> bool:
    limit = CLIENT_POLICY.get(client_id, {}).get("rate_limit_per_minute", MAX_REQUESTS_PER_MINUTE)
    key = f"postguard:rate:{client_id}"
    now = current_unix_time()
    window_seconds = 60

    # Simple fixed-window rate limiter backed by Redis
    # Replace with a real sliding-window or token bucket in production if needed
    current_count = redis_client.get(key)
    if current_count is None:
        redis_client.set(key, 1, ex=window_seconds)
        return True

    if int(current_count) >= limit:
        return False

    redis_client.incr(key)
    return True

def verify_hmac_signature(raw_body: bytes, client_id: str, timestamp: str, nonce: str, signature: str, request_method: str, request_path: str) -> bool:
    if not signature:
        return False
    if not verify_timestamp(timestamp):
        return False

    canonical = f"{request_method}:{request_path}:{client_id}:{timestamp}:{nonce}:{raw_body.decode('utf-8', 'replace')}"
    expected = hmac.new(CLIENT_SECRET_KEY.encode(), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

def is_allowed_client(client_id: str) -> bool:
    return client_id in CLIENT_POLICY

def validate_client_policy(client_id: str, query: PostcodeQuery) -> None:
    policy = CLIENT_POLICY.get(client_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client ID.")

    allowed_regions = {str(r).lower() for r in policy.get("allowed_regions", [])}
    requested_region = query.declared_region.lower()

    if requested_region not in allowed_regions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client '{client_id}' is not allowed to query region '{requested_region}'."
        )

    if query.level > int(policy.get("max_level", 1)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client '{client_id}' is not allowed to request level {query.level}."
        )

def detect_geo_anomaly(query: PostcodeQuery, client_ip: str) -> Optional[str]:
    postcode = query.postcode.upper()
    region = query.declared_region.lower()

    # Example: FC/FCT postcode should align with Abuja metadata.
    if postcode.startswith("FC"):
        if region not in {"abuja", "fct"}:
            logger.warning(json.dumps({
                "event": "LOCATION_SPOOFING_BLOCKED",
                "ip": client_ip,
                "postcode": postcode,
                "declared_region": region,
            }))
            return "LOCATION_SPOOFING"

        # stronger heuristic: ensure coordinates are within Abuja / FCT approximate bounds
        lat = query.client_lat
        lon = query.client_lon
        if not (8.9 <= lat <= 9.3 and 6.9 <= lon <= 7.7):
            logger.warning(json.dumps({
                "event": "GEO_FENCE_MISMATCH",
                "ip": client_ip,
                "postcode": postcode,
                "lat": lat,
                "lon": lon,
            }))
            return "GEO_FENCE_MISMATCH"

    return None

# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health_check():
    return {
        "system": "PostGuard NG Security Gateway",
        "status": "Operational",
        "target_infrastructure": "https://api.postcode.gov.ng",
        "protection_active": [
            "Redis-backed rate limiting",
            "HMAC-SHA256 integrity checks",
            "Timestamp + nonce replay protection",
            "Geo anomaly detection",
            "Client policy enforcement",
            "Secure upstream proxying",
        ],
    }

@app.post("/api/v1/secure-query")
async def secure_postcode_query(
    query: PostcodeQuery,
    request: Request,
    x_client_id: str = Header(..., alias="X-Client-ID"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_nonce: str = Header(..., alias="X-Nonce"),
    x_signature: str = Header(..., alias="X-Signature"),
):
    client_ip = request.client.host if request.client else "unknown"

    if not is_allowed_client(x_client_id):
        logger.warning(json.dumps({
            "event": "UNKNOWN_CLIENT",
            "client_id": x_client_id,
            "ip": client_ip,
        }))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client ID.")

    # 1) Check timestamp freshness
    if not verify_timestamp(x_timestamp):
        logger.warning(json.dumps({
            "event": "INVALID_TIMESTAMP",
            "client_id": x_client_id,
            "ip": client_ip,
            "timestamp": x_timestamp,
        }))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired timestamp.")

    # 2) Ensure Neo/nonce cannot be replayed
    if not register_nonce(x_client_id, x_nonce):
        logger.warning(json.dumps({
            "event": "REPLAY_DETECTED",
            "client_id": x_client_id,
            "ip": client_ip,
            "nonce": x_nonce,
        }))
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected. Nonce already used.")

    # 3) Enforce per-client rate limit
    if not check_rate_limit(x_client_id):
        logger.warning(json.dumps({
            "event": "RATE_LIMIT_EXCEEDED",
            "client_id": x_client_id,
            "ip": client_ip
        }))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")

    # 4) Validate request policy for this client
    validate_client_policy(x_client_id, query)

    # 5) Verify HMAC signature over canonical payload
    raw_body = await request.body()
    if not verify_hmac_signature(raw_body, x_client_id, x_timestamp, x_nonce, x_signature, request.method, request.url.path):
        logger.critical(json.dumps({
            "event": "PAYLOAD_TAMPERING_DETECTED",
            "client_id": x_client_id,
            "ip": client_ip,
            "nonce": x_nonce,
        }))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid HMAC signature.")

    # 6) Geo check
    geo_issue = detect_geo_anomaly(query, client_ip)
    if geo_issue:
        return {
            "status": "BLOCKED",
            "threat_detected": geo_issue,
            "message": "Geospatial mismatch detected. Request does not align with postcode telemetry.",
            "client_id": x_client_id
        }

    # 7) Secure proxy to NIPOST
    nipost_url = f"{NIPOST_BASE_URL}/lookup?code={query.postcode}&level={query.level}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                nipost_url,
                headers={"X-API-Key": NIPOST_API_KEY},
                timeout=10.0,
            )
        except httpx.RequestError as exc:
            logger.error(json.dumps({
                "event": "UPSTREAM_CONNECTION_ERROR",
                "client_id": x_client_id,
                "ip": client_ip,
                "error": str(exc),
            }))
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to connect to NIPOST upstream.")

    if response.status_code != 200:
        logger.warning(json.dumps({
            "event": "UPSTREAM_ERROR",
            "client_id": x_client_id,
            "nipost_status_code": response.status_code,
            "ip": client_ip,
        }))
        return {
            "status": "UPSTREAM_ERROR",
            "shield": "PostGuard NG Active",
            "nipost_status_code": response.status_code,
            "error_details": response.json(),
        }

    logger.info(json.dumps({
        "event": "REQUEST_PASSED_AND_PROXIED",
        "client_id": x_client_id,
        "postcode": query.postcode,
        "ip": client_ip
    }))

    return {
        "status": "SUCCESS",
        "security_score": "100%",
        "shield": "PostGuard NG Firewall Active",
        "nipost_data": response.json(),
    }
