import json
import logging
import re
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

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


@asynccontextmanager
async def lifespan(application: FastAPI):
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=3.0),
        follow_redirects=False,
    ) as client:
        application.state.http_client = client
        yield


app = FastAPI(
    title=settings.app_name,
    description="Security gateway for signed postcode lookup requests.",
    version=settings.app_version,
    lifespan=lifespan,
)

if settings.required:
    missing = ", ".join(settings.required)
    raise RuntimeError(f"Missing required environment variables: {missing}")

_CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._~-]+$")
_SIGNATURE_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_body_bytes: int):
        self.application = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.application(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                response = JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)
                await response(scope, receive, send)
                return
            if declared_length < 0:
                response = JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)
                await response(scope, receive, send)
                return
            if declared_length > self.max_body_bytes:
                response = JSONResponse({"detail": "Request body too large."}, status_code=413)
                await response(scope, receive, send)
                return

        body_chunks = []
        body_size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            body_size += len(chunk)
            if body_size > self.max_body_bytes:
                response = JSONResponse({"detail": "Request body too large."}, status_code=413)
                await response(scope, receive, send)
                return
            body_chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(body_chunks)
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.application(scope, replay_receive, send)


app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.max_request_body_bytes)


class PostcodeQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

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


@app.get("/")
async def root():
    return {
        "system": settings.app_name,
        "docs": "/docs",
        "health": "/health",
    }


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
            "Advisory geo anomaly signals",
            "Client policy enforcement",
        ],
    }


@app.post("/api/v1/secure-query")
async def secure_postcode_query(
    query: PostcodeQuery,
    request: Request,
    x_client_id: str = Header(..., alias="X-Client-ID", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$"),
    x_timestamp: str = Header(..., alias="X-Timestamp", min_length=1, max_length=12, pattern=r"^[0-9]+$"),
    x_nonce: str = Header(..., alias="X-Nonce", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$"),
    x_signature: str = Header(..., alias="X-Signature", min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$"),
):
    client_ip = request.client.host if request.client else "unknown"

    # 1. Validate client identity
    if not is_allowed_client(x_client_id):
        logger.warning(json.dumps({"event": "UNKNOWN_CLIENT", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client ID.")

    # 2. Verify signature before consuming nonce or rate-limit capacity.
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

    # 3. Enforce client policy before consuming request quota.
    validate_client_policy(x_client_id, query.declared_region, query.level)

    # 4. Prevent replay.
    if not register_nonce(x_client_id, x_nonce):
        logger.warning(json.dumps({"event": "REPLAY_DETECTED", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected. Nonce already used.")

    # 5. Enforce rate limit.
    if not check_rate_limit(x_client_id):
        logger.warning(json.dumps({"event": "RATE_LIMIT_EXCEEDED", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")

    # Client-provided coordinates are untrusted; use the result for monitoring only.
    geo_issue = detect_geo_anomaly(query.postcode, query.declared_region, query.client_lat, query.client_lon)
    if geo_issue:
        logger.warning(json.dumps({
            "event": geo_issue,
            "client_id": x_client_id,
            "postcode": query.postcode,
            "declared_region": query.declared_region,
            "ip": client_ip,
        }))

    # 7. Proxy upstream
    upstream_result = await proxy_to_nipost(query.postcode, query.level, request.app.state.http_client)
    if upstream_result["status"] == "UPSTREAM_ERROR":
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "message": "NIPOST request failed.",
                "upstream_status_code": upstream_result.get("nipost_status_code"),
            },
        )

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
