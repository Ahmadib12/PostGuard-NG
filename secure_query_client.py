import argparse
import hashlib
import hmac
import json
import os
import time
import uuid

import httpx
from dotenv import load_dotenv


load_dotenv()

ENDPOINT_PATH = "/api/v1/secure-query"


def sign_request(body: bytes, client_id: str, timestamp: str, nonce: str, secret: str) -> str:
    canonical_prefix = f"POST:{ENDPOINT_PATH}:{client_id}:{timestamp}:{nonce}:".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical_prefix + body, hashlib.sha256).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a signed sample postcode query to PostGuard NG.")
    parser.add_argument("--postcode", default="FC-03-B06-AG-12")
    parser.add_argument("--level", type=int, default=1)
    parser.add_argument("--region", default="abuja")
    parser.add_argument("--lat", type=float, default=9.0579)
    parser.add_argument("--lon", type=float, default=7.4951)
    parser.add_argument("--client-id", default=os.getenv("POSTGUARD_CLIENT_ID", "demo-client"))
    args = parser.parse_args()

    secret_name = f"POSTGUARD_{args.client_id.upper().replace('-', '_')}_SECRET"
    secret = os.getenv(secret_name)
    if not secret or len(secret.encode("utf-8")) < 32:
        parser.error(f"{secret_name} must be set to a secret of at least 32 bytes in .env")

    payload = {
        "postcode": args.postcode,
        "level": args.level,
        "client_lat": args.lat,
        "client_lon": args.lon,
        "declared_region": args.region,
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    signature = sign_request(body, args.client_id, timestamp, nonce, secret)

    base_url = os.getenv("POSTGUARD_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    try:
        response = httpx.post(
            f"{base_url}{ENDPOINT_PATH}",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Client-ID": args.client_id,
                "X-Timestamp": timestamp,
                "X-Nonce": nonce,
                "X-Signature": signature,
            },
            timeout=httpx.Timeout(10.0, connect=3.0),
        )
    except httpx.RequestError as exc:
        parser.error(f"Could not reach PostGuard API: {type(exc).__name__}")

    print(f"HTTP {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except ValueError:
        print(response.text)


if __name__ == "__main__":
    main()
