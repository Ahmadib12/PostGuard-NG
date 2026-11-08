import asyncio
import json
import logging
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from admin_api import router as admin_router
from config import settings
from dashboard_store import initialize_admin_credentials, initialize_database, record_request, record_security_event
from security import (
    check_rate_limit_and_register_nonce,
    detect_geo_anomaly,
    is_allowed_client,
    normalize_region,
    proxy_to_nipost,
    redis_client,
    validate_client_policy,
    validate_nonce_format,
    verify_hmac_signature,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PostGuard-NG")


async def emit_event(
    level: str,
    event: str,
    request_id: str | None = None,
    http_status: int | None = None,
    **fields,
):
    payload = {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "level": level, "event": event}
    if request_id:
        payload["request_id"] = request_id
    for key, value in fields.items():
        if value is None:
            continue
        payload[key] = value
    logger.log({"INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}.get(level.upper(), 20), json.dumps(payload, separators=(",", ":"), ensure_ascii=True))
    try:
        event_fields = dict(fields)
        client_id = event_fields.pop("client_id", None)
        await asyncio.to_thread(
            record_security_event,
            event,
            request_id,
            client_id,
            http_status,
            **event_fields,
        )
    except Exception:
        logger.exception("Could not persist security telemetry; request security enforcement remains active.")


@asynccontextmanager
async def lifespan(application: FastAPI):
    await asyncio.to_thread(initialize_database)
    generated_admin = await asyncio.to_thread(initialize_admin_credentials)
    if generated_admin:
        logger.warning(
            "Initial administrator credentials (shown once): username=%s password=%s. "
            "Set ADMIN_USERNAME and ADMIN_PASSWORD in the local environment to replace them.",
            generated_admin[0],
            generated_admin[1],
        )
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
app.include_router(admin_router)


_CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
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


class RequestTelemetryMiddleware:
    def __init__(self, app):
        self.application = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/v1/"):
            await self.application(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        started = asyncio.get_running_loop().time()
        status_code = 500

        async def capture_status(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.application(scope, receive, capture_status)
        finally:
            headers = dict(scope.get("headers", []))
            raw_client_id = headers.get(b"x-client-id", b"").decode("ascii", "ignore")
            client_id = raw_client_id if _CLIENT_ID_PATTERN.fullmatch(raw_client_id) else None
            duration_ms = max(0, int((asyncio.get_running_loop().time() - started) * 1000))
            try:
                await asyncio.to_thread(
                    record_request,
                    request_id,
                    client_id,
                    status_code,
                    duration_ms,
                    bool(state.get("authenticated", False)),
                )
            except Exception:
                logger.exception("Could not persist request telemetry; request security enforcement remains active.")


app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.max_request_body_bytes)
app.add_middleware(RequestTelemetryMiddleware)


class PostcodeQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    postcode: str = Field(..., min_length=8, max_length=30, example="FC-03-B06-AG-12")
    level: int = Field(1, ge=1)
    client_lat: float = Field(..., ge=-90.0, le=90.0)
    client_lon: float = Field(..., ge=-180.0, le=180.0)
    declared_region: str = Field(..., min_length=2, max_length=50)

    @field_validator("postcode")
    @classmethod
    def validate_postcode(cls, value: str) -> str:
        postcode = value.strip().upper()
        if not re.fullmatch(r"[A-Z0-9-]+", postcode):
            raise ValueError("postcode contains unsupported characters.")
        return postcode

    @field_validator("declared_region")
    @classmethod
    def validate_region(cls, value: str) -> str:
        region = value.strip()
        if not region:
            raise ValueError("declared_region is required.")
        return region


@app.get("/")
async def root():
    return {
        "system": settings.app_name,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
async def health_check():
    ready = True
    redis_status = "unknown"
    try:
        redis_status = "ok" if await asyncio.to_thread(redis_client.ping) else "unavailable"
        ready = ready and redis_status == "ok"
    except Exception:
        redis_status = "unavailable"
        ready = False

    upstream_status = "mock_mode" if settings.mock_nipost else "not_checked"
    upstream_reachable = settings.mock_nipost
    return {
        "status": "ok" if ready else "degraded",
        "liveness": {"ok": True},
        "readiness": {"ready": ready, "redis": redis_status},
        "upstream": {"mode": upstream_status, "reachable": upstream_reachable},
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
    x_client_id: str = Header(..., alias="X-Client-ID"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_nonce: str = Header(..., alias="X-Nonce"),
    x_signature: str = Header(..., alias="X-Signature"),
):
    request_id = request.state.request_id

    if not re.fullmatch(r"^[A-Za-z0-9._-]+$", x_client_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed client ID.")
    if not x_timestamp or not x_timestamp.isascii() or not x_timestamp.isdigit() or len(x_timestamp) > 12:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed timestamp.")
    if not validate_nonce_format(x_nonce):
        await emit_event("WARNING", "INVALID_NONCE", request_id=request_id, http_status=400, client_id=x_client_id)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed nonce value.")
    if not re.fullmatch(r"^[0-9a-fA-F]{64}$", x_signature):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed signature.")

    if not is_allowed_client(x_client_id):
        await emit_event("WARNING", "UNKNOWN_CLIENT", request_id=request_id, http_status=401, client_id=x_client_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client ID.")

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
        await emit_event("CRITICAL", "INVALID_SIGNATURE", request_id=request_id, http_status=403, client_id=x_client_id, path=request.url.path)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid HMAC signature.")

    request.state.authenticated = True
    try:
        validate_client_policy(x_client_id, query.declared_region, query.level)
    except HTTPException:
        await emit_event(
            "WARNING",
            "CLIENT_POLICY_VIOLATION",
            request_id=request_id,
            http_status=403,
            client_id=x_client_id,
            region=normalize_region(query.declared_region),
            lookup_level=query.level,
        )
        raise

    try:
        request_control_result = await asyncio.to_thread(
            check_rate_limit_and_register_nonce,
            x_client_id,
            x_nonce,
        )
    except HTTPException:
        await emit_event("ERROR", "REDIS_FAILURE", request_id=request_id, http_status=503, client_id=x_client_id, component="request_controls")
        raise

    if request_control_result == "rate_limited":
        await emit_event("WARNING", "RATE_LIMIT_EXCEEDED", request_id=request_id, http_status=429, client_id=x_client_id)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")

    if request_control_result == "replay":
        await emit_event("WARNING", "REPLAY_DETECTED", request_id=request_id, http_status=409, client_id=x_client_id)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected. Nonce already used.")

    if request_control_result != "allowed":
        await emit_event("ERROR", "REDIS_FAILURE", request_id=request_id, http_status=503, client_id=x_client_id, component="request_controls")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request security service is temporarily unavailable.",
        )

    geo_issue = detect_geo_anomaly(query.postcode, query.declared_region, query.client_lat, query.client_lon)
    if geo_issue:
        await emit_event(
            "WARNING",
            geo_issue,
            request_id=request_id,
            client_id=x_client_id,
            region=normalize_region(query.declared_region),
        )

    upstream_result = await proxy_to_nipost(query.postcode, query.level, request.app.state.http_client)
    if upstream_result["status"] == "UPSTREAM_ERROR":
        await emit_event(
            "ERROR",
            "UPSTREAM_FAILURE",
            request_id=request_id,
            http_status=502,
            client_id=x_client_id,
            upstream_status=upstream_result.get("status_code"),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "message": "Upstream lookup failed.",
                "upstream_status_code": upstream_result.get("status_code"),
            },
        )

    return {
        "status": "SUCCESS",
        "security": {
            "authentication": "verified",
            "replay_protection": "enforced",
            "rate_limit": "enforced",
            "geo_checks": "advisory",
            "upstream_source": upstream_result.get("source", "mock"),
        },
        "nipost_data": upstream_result["nipost_data"],
    }
