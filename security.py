import hashlib
import hmac
import logging
import time
from typing import Optional

import httpx
import redis
from fastapi import HTTPException, status

from config import settings


redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
logger = logging.getLogger(__name__)

_RATE_LIMIT_SCRIPT = """
local count = redis.call("INCR", KEYS[1])
if count == 1 then
    redis.call("EXPIRE", KEYS[1], 60)
end
return count
"""


def current_unix_time() -> int:
    return int(time.time())


def verify_timestamp(timestamp_str: str) -> bool:
    if not timestamp_str.isascii() or not timestamp_str.isdigit() or len(timestamp_str) > 12:
        return False
    ts = int(timestamp_str)

    return abs(current_unix_time() - ts) <= settings.max_clock_skew_seconds


def register_nonce(client_id: str, nonce: str) -> bool:
    key = f"postguard:nonce:{client_id}:{nonce}"
    try:
        return bool(redis_client.set(key, "1", ex=settings.nonce_ttl_seconds, nx=True))
    except redis.RedisError as exc:
        logger.error("Redis unavailable while registering request nonce")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request security service is temporarily unavailable.",
        ) from exc


def check_rate_limit(client_id: str) -> bool:
    limit = settings.client_policy.get(client_id, {}).get("rate_limit_per_minute", settings.rate_limit_per_minute)
    key = f"postguard:rate:{client_id}"

    try:
        current_count = redis_client.eval(_RATE_LIMIT_SCRIPT, 1, key)
    except redis.RedisError as exc:
        logger.error("Redis unavailable while checking client rate limit")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request security service is temporarily unavailable.",
        ) from exc
    return current_count <= limit


def verify_hmac_signature(
    raw_body: bytes,
    client_id: str,
    timestamp: str,
    nonce: str,
    signature: str,
    method: str,
    path: str,
) -> bool:
    if len(signature) != 64:
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

    return hmac.compare_digest(expected, signature)


def is_allowed_client(client_id: str) -> bool:
    return client_id in settings.client_policy


def validate_client_policy(client_id: str, declared_region: str, requested_level: int) -> None:
    policy = settings.client_policy.get(client_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown client ID.")

    allowed_regions = {str(r).lower() for r in policy.get("allowed_regions", [])}
    requested_region = declared_region.lower()

    if requested_region not in allowed_regions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client '{client_id}' is not allowed to query region '{requested_region}'.",
        )

    max_level = int(policy.get("max_level", 1))
    if requested_level > max_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client '{client_id}' is not allowed to request level {requested_level}.",
        )


def detect_geo_anomaly(postcode: str, declared_region: str, client_lat: float, client_lon: float) -> Optional[str]:
    postcode = postcode.upper()
    region = declared_region.lower()

    # Example: FC/FCT postcode should align with Abuja metadata.
    if postcode.startswith("FC"):
        if region not in {"abuja", "fct"}:
            return "LOCATION_SPOOFING"

        # Approximate Abuja/FCT bounding box
        if not (8.9 <= client_lat <= 9.3 and 6.9 <= client_lon <= 7.7):
            return "GEO_FENCE_MISMATCH"

    return None


async def proxy_to_nipost(postcode: str, level: int, client: httpx.AsyncClient) -> dict:
    if settings.mock_nipost:
        return {
            "status": "SUCCESS",
            "nipost_data": {
                "postcode": postcode,
                "level": level,
                "source": "mock",
            },
        }

    url = "https://api.postcode.gov.ng/v1/lookup"

    try:
        response = await client.get(
            url,
            params={"code": postcode, "level": level},
            headers={"X-API-Key": settings.nipost_api_key},
        )
    except httpx.RequestError as exc:
        logger.warning("NIPOST request failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to NIPOST infrastructure.",
        ) from exc

    if response.status_code != 200:
        return {
            "status": "UPSTREAM_ERROR",
            "nipost_status_code": response.status_code,
        }

    try:
        nipost_data = response.json()
    except ValueError:
        return {
            "status": "UPSTREAM_ERROR",
            "nipost_status_code": response.status_code,
        }

    return {
        "status": "SUCCESS",
        "nipost_data": nipost_data,
    }
