import json
import logging

from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from config import settings
from security import (
    check_rate_limit,
    detect_geo_anomaly,
    is_allowed_client,
    proxy_to_nipost,
    register_nonce,
    validate_client_policy,
    verify_hmac_signature,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PostGuard-NG")

app = FastAPI(
    title=settings.app_name,
    description="Production-hardened middleware protecting NIPOST postcode infrastructure.",
    version=settings.app_version,
)

if settings.required:
    missing = ", ".join(settings.required)
    raise RuntimeError(f"Missing required environment variables: {missing}")


class PostcodeQuery(BaseModel):
    postcode: str = Field(..., min_length=8, max_length=30, example="FC-03-B06-AG-12")
    level: int = Field(1, ge=1, le=5)
    client_lat: float = Field(..., ge=-90.0, le=90.0)
    client_lon: float = Field(..., ge=-180.0, le=180.0)
    declared_region: str = Field(..., min_length=2, max_length=50)

    @field_validator("postcode")
    @classmethod
    def validate_postcode(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("declared_region")
    @classmethod
    def validate_region(cls, value: str) -> str:
        return value.strip()


@app.get("/health")
async def health_check():
    return {
        "system": settings.app_name,
        "status": "Operational",
        "target_infrastructure": "https://api.postcode.gov.ng",
        "protection_active": [
            "HMAC-SHA256 request integrity",
            "Redis-backed rate limiting",
            "Timestamp and nonce replay protection",
            "Geo anomaly detection",
            "Client policy enforcement",
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

    # 1. Validate client identity
    if not is_allowed_client(x_client_id):
        logger.warning(json.dumps({"event": "UNKNOWN_CLIENT", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client ID.")

    # 2. Prevent replay
    if not register_nonce(x_client_id, x_nonce):
        logger.warning(json.dumps({"event": "REPLAY_DETECTED", "client_id": x_client_id, "ip": client_ip, "nonce": x_nonce}))
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected. Nonce already used.")

    # 3. Enforce rate limit
    if not check_rate_limit(x_client_id):
        logger.warning(json.dumps({"event": "RATE_LIMIT_EXCEEDED", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")

    # 4. Enforce client policy
    validate_client_policy(x_client_id, query.declared_region, query.level)

    # 5. Verify signature
    raw_body = await request.body()
    if not verify_hmac_signature(
        raw_body,
        x_client_id,
        x_timestamp,
        x_nonce,
        x_signature,
        request.method,
        request.url.path,
    ):
        logger.critical(json.dumps({"event": "PAYLOAD_TAMPERING_DETECTED", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid HMAC signature.")

    # 6. Geo anomaly detection
    geo_issue = detect_geo_anomaly(query.postcode, query.declared_region, query.client_lat, query.client_lon)
    if geo_issue:
        logger.warning(json.dumps({
            "event": geo_issue,
            "client_id": x_client_id,
            "postcode": query.postcode,
            "declared_region": query.declared_region,
            "ip": client_ip,
        }))
        return {
            "status": "BLOCKED",
            "threat_detected": geo_issue,
            "message": "Geospatial mismatch detected. Request does not align with postcode telemetry.",
        }

    # 7. Proxy upstream
    upstream_result = await proxy_to_nipost(query.postcode, query.level)
    if upstream_result["status"] == "UPSTREAM_ERROR":
        return upstream_result

    logger.info(json.dumps({
        "event": "REQUEST_PASSED_AND_PROXIED",
        "client_id": x_client_id,
        "postcode": query.postcode,
        "ip": client_ip,
    }))

    return {
        "status": "SUCCESS",
        "security_score": "100%",
        "shield": "PostGuard NG Firewall Active",
        "nipost_data": upstream_result["nipost_data"],
    }
