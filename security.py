import hashlib
import hmac
import json
import time
from typing import Dict, Optional

import httpx
import redis
from fastapi import HTTPException, status

from config import settings


redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)


def current_unix_time() -> int:
    return int(time.time())


def verify_timestamp(timestamp_str: str) -> bool:
    try:
        ts = int(timestamp_str)
    except (TypeError, ValueError):
        return False

    return abs(current_unix_time() - ts) <= settings.max_clock_skew_seconds


def register_nonce(client_id: str, nonce: str) -> bool:
    key = f"postguard:nonce:{client_id}:{nonce}"
    if redis_client.exists(key):
        return False
    redis_client.set(key, "1", ex=settings.nonce_ttl_seconds)
    return True


def check_rate_limit(client_id: str) -> bool:
    limit = settings.client_policy.get(client_id, {}).get("rate_limit_per_minute", settings.rate_limit_per_minute)
    key = f"postguard:rate:{client_id}"

    current_count = redis_client.get(key)
    if current_count is None:
        redis_client.set(key, 1, ex=60)
        return True

    if int(current_count) >= limit:
        return False

    redis_client.incr(key)
    return True


def verify_hmac_signature(
    raw_body: bytes,
    client_id: str,
    timestamp: str,
    nonce: str,
    signature: str,
    method: str,
    path: str,
) -> bool:
    if not signature:
        return False

    if not verify_timestamp(timestamp):
        return False

    canonical = (
        f"{method}:{path}:{client_id}:{timestamp}:{nonce}:"
        f"{raw_body.decode('utf-8', 'replace')}"
    )
    expected = hmac.new(
        settings.postguard_client_secret.encode("utf-8"),
        canonical.encode("utf-8"),
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


async def proxy_to_nipost(postcode: str, level: int) -> dict:
    url = f"https://api.postcode.gov.ng/v1/lookup?code={postcode}&level={level}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                url,
                headers={"X-API-Key": settings.nipost_api_key},
                timeout=10.0,
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to connect to NIPOST infrastructure: {str(exc)}",
            )

    if response.status_code != 200:
        return {
            "status": "UPSTREAM_ERROR",
            "nipost_status_code": response.status_code,
            "error_details": response.json(),
        }

    return {
        "status": "SUCCESS",
        "nipost_data": response.json(),
    }
