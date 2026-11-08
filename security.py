import hashlib
import hmac
import json
import logging
import re
import time
from typing import Optional

import httpx
import redis
from fastapi import HTTPException, status

from config import settings


logger = logging.getLogger("PostGuard-NG.security")
redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)

NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{16,128}$")

_RATE_LIMIT_SCRIPT = """
local count = redis.call("INCR", KEYS[1])
if count == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return count
"""

_REQUEST_CONTROLS_SCRIPT = """
local count = redis.call("INCR", KEYS[1])
if count == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
if count > tonumber(ARGV[2]) then
    return 0
end
local nonce_registered = redis.call("SET", KEYS[2], "1", "EX", ARGV[3], "NX")
if not nonce_registered then
    return -1
end
return 1
"""


def current_unix_time() -> int:
    return int(time.time())


def normalize_region(value: str) -> str:
    return value.strip().lower().replace("_", " ").replace("-", " ").replace("/", " ")


def validate_nonce_format(nonce: str) -> bool:
    return bool(nonce) and bool(NONCE_PATTERN.fullmatch(nonce))


def verify_timestamp(timestamp_str: str) -> bool:
    if not timestamp_str or not timestamp_str.isascii() or not timestamp_str.isdigit() or len(timestamp_str) > 12:
        return False
    try:
        ts = int(timestamp_str)
    except ValueError:
        return False
    return abs(current_unix_time() - ts) <= settings.max_clock_skew_seconds


def register_nonce(client_id: str, nonce: str) -> bool:
    key = f"postguard:nonce:{client_id}:{nonce}"
    try:
        return bool(redis_client.set(key, "1", ex=settings.nonce_ttl_seconds, nx=True))
    except redis.RedisError as exc:
        logger.error(json.dumps({"event": "REDIS_FAILURE", "component": "nonce_registration"}))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request security service is temporarily unavailable.",
        ) from exc


def check_rate_limit(client_id: str) -> bool:
    limit = settings.client_policy.get(client_id, {}).get("rate_limit_per_minute", settings.rate_limit_per_minute)
    key = f"postguard:rate:{client_id}"

    try:
        current_count = redis_client.eval(_RATE_LIMIT_SCRIPT, 1, key, settings.rate_limit_window_seconds)
    except redis.RedisError as exc:
        logger.error(json.dumps({"event": "REDIS_FAILURE", "component": "rate_limit"}))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request security service is temporarily unavailable.",
        ) from exc
    return current_count <= limit


def check_rate_limit_and_register_nonce(client_id: str, nonce: str) -> str:
    limit = settings.client_policy.get(client_id, {}).get("rate_limit_per_minute", settings.rate_limit_per_minute)
    rate_key = f"postguard:rate:{client_id}"
    nonce_key = f"postguard:nonce:{client_id}:{nonce}"

    try:
        result = redis_client.eval(
            _REQUEST_CONTROLS_SCRIPT,
            2,
            rate_key,
            nonce_key,
            settings.rate_limit_window_seconds,
            limit,
            settings.nonce_ttl_seconds,
        )
    except redis.RedisError as exc:
        logger.error(json.dumps({"event": "REDIS_FAILURE", "component": "request_controls"}))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request security service is temporarily unavailable.",
        ) from exc

    return {1: "allowed", 0: "rate_limited", -1: "replay"}.get(result, "unavailable")


def verify_hmac_signature(
    raw_body: bytes,
    client_id: str,
    timestamp: str,
    nonce: str,
    signature: str,
    method: str,
    path: str,
) -> bool:
    if not client_id or not isinstance(raw_body, (bytes, bytearray)):
        return False
    if len(signature) != 64 or not validate_nonce_format(nonce):
        return False
    if not verify_timestamp(timestamp):
        return False

    secret = settings.client_secrets.get(client_id)
    if not secret:
        return False

    canonical_prefix = f"{method}:{path}:{client_id}:{timestamp}:{nonce}:".encode("utf-8")
    expected = hmac.new(
        secret.encode("utf-8"),
        canonical_prefix + raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature.lower())


def is_allowed_client(client_id: str) -> bool:
    return bool(client_id) and client_id in settings.client_policy


def validate_client_policy(client_id: str, declared_region: str, requested_level: int) -> None:
    policy = settings.client_policy.get(client_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client ID.")

    allowed_regions = {normalize_region(str(region)) for region in policy.get("allowed_regions", [])}
    requested_region = normalize_region(declared_region)

    if requested_region not in allowed_regions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Client is not permitted to query the requested region.",
        )

    max_level = int(policy.get("max_level", 1))
    if requested_level > max_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requested lookup level exceeds the client policy limit.",
        )


def detect_geo_anomaly(postcode: str, declared_region: str, client_lat: float, client_lon: float) -> Optional[str]:
    if not (-90.0 <= float(client_lat) <= 90.0) or not (-180.0 <= float(client_lon) <= 180.0):
        return "GEO_FENCE_MISMATCH"
    return None


async def proxy_to_nipost(postcode: str, level: int, client: httpx.AsyncClient) -> dict:
    if settings.mock_nipost:
        return {
            "status": "SUCCESS",
            "source": "mock",
            "nipost_data": {
                "postcode": postcode,
                "level": level,
                "source": "mock",
            },
        }

    url = f"{settings.nipost_base_url}/v1/lookup"
    headers = {"Accept": "application/json"}
    if settings.nipost_api_key:
        headers["X-API-Key"] = settings.nipost_api_key

    try:
        response = await client.get(
            url,
            params={"code": postcode, "level": level},
            headers=headers,
            timeout=httpx.Timeout(10.0, connect=3.0),
            follow_redirects=False,
        )
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as exc:
        logger.warning(json.dumps({"event": "UPSTREAM_FAILURE", "error_type": type(exc).__name__, "target": url}))
        return {
            "status": "UPSTREAM_ERROR",
            "message": "Upstream lookup failed.",
            "status_code": 502,
        }

    if not 200 <= response.status_code < 300:
        logger.warning(json.dumps({"event": "UPSTREAM_FAILURE", "status_code": response.status_code, "target": url}))
        return {
            "status": "UPSTREAM_ERROR",
            "message": "Upstream lookup failed.",
            "status_code": response.status_code,
        }

    try:
        nipost_data = response.json()
    except ValueError:
        logger.warning(json.dumps({"event": "UPSTREAM_FAILURE", "status_code": response.status_code, "target": url, "reason": "malformed_json"}))
        return {
            "status": "UPSTREAM_ERROR",
            "message": "Upstream response was not valid JSON.",
            "status_code": response.status_code,
        }

    if not isinstance(nipost_data, dict):
        logger.warning(json.dumps({"event": "UPSTREAM_FAILURE", "status_code": response.status_code, "target": url, "reason": "unexpected_response_shape"}))
        return {
            "status": "UPSTREAM_ERROR",
            "message": "Upstream response format was unexpected.",
            "status_code": response.status_code,
        }

    return {
        "status": "SUCCESS",
        "source": "live",
        "nipost_data": nipost_data,
    }
