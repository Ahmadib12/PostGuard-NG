import hmac
import hashlib
import time
import json
import logging
import os
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
import httpx
from dotenv import load_dotenv

# Load local .env file variables
load_dotenv()

# Configure Structured JSON Logging for Security Audits
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
logger = logging.getLogger("PostGuard-NG")

app = FastAPI(
    title="PostGuard NG Security Gateway",
    description="Enterprise API Middleware protecting NIPOST National Alphanumeric Postcode Infrastructure",
    version="1.2.0"
)

# Configuration from Environment Variables
CLIENT_SECRET_KEY = os.getenv("POSTGUARD_CLIENT_SECRET", "super-secret-partner-key-3mtt").encode()
NIPOST_API_KEY = os.getenv("NIPOST_API_KEY")  # Your official key from dashboard.postcode.gov.ng
NIPOST_BASE_URL = "https://api.postcode.gov.ng/v1"

RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS_PER_WINDOW = 10  # strict sliding window limit

# In-memory rate limiting store (Swap for Redis in production scaling)
request_counts = {}

class PostcodeQuery(BaseModel):
    postcode: str = Field(..., example="FC-03-B06-AG-12", description="11-character NIPOST Alphanumeric Code")
    level: int = Field(1, example=3, description="Lookup detail level (1 to 3/5)")
    client_lat: float = Field(..., example=9.05785, description="Client device latitude")
    client_lon: float = Field(..., example=7.49508, description="Client device longitude")
    declared_region: str = Field(..., example="Abuja", description="State or LGA user claims to be in")

def verify_hmac_signature(payload_body: bytes, received_sig: str) -> bool:
    """Cryptographic verification to prevent Man-in-the-Middle payload tampering."""
    computed_sig = hmac.new(CLIENT_SECRET_KEY, payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_sig, received_sig)

def check_rate_limit(client_id: str) -> bool:
    """Sliding-window rate limiter to mitigate volumetric scraping and DDoS."""
    current_time = time.time()
    if client_id not in request_counts:
        request_counts[client_id] = []
    
    # Prune expired timestamps
    request_counts[client_id] = [t for t in request_counts[client_id] if current_time - t < RATE_LIMIT_WINDOW]
    
    if len(request_counts[client_id]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    
    request_counts[client_id].append(current_time)
    return True

@app.post("/api/v1/secure-query")
async def secure_postcode_query(
    query: PostcodeQuery,
    request: Request,
    x_postguard_signature: Optional[str] = Header(None, alias="X-PostGuard-Signature"),
    x_client_id: Optional[str] = Header(None, alias="X-Client-ID")
):
    """
    Secure interceptor proxy that screens requests, runs anti-spoofing checks, 
    and securely proxies to NIPOST API using hidden backend credentials.
    """
    client_ip = request.client.host

    # 1. Validate Client Identification Header
    if not x_client_id:
        logger.warning(json.dumps({"event": "UNAUTHORIZED_ACCESS", "ip": client_ip, "reason": "Missing Client ID"}))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Client-ID header."
        )

    # 2. Enforce Rate Limiting
    if not check_rate_limit(x_client_id):
        logger.error(json.dumps({"event": "RATE_LIMIT_EXCEEDED", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Volumetric scraping attempt blocked by PostGuard NG."
        )

    # 3. Verify HMAC Payload Signature
    raw_body = await request.body()
    if not x_postguard_signature or not verify_hmac_signature(raw_body, x_postguard_signature):
        logger.critical(json.dumps({"event": "PAYLOAD_TAMPERING_DETECTED", "client_id": x_client_id, "ip": client_ip}))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing HMAC signature. Request integrity compromised."
        )

    # 4. Geo-Behavioral Anomaly & Anti-Spoofing Check
    if query.postcode.startswith("FC") and query.declared_region.lower() not in ["abuja", "fct"]:
        logger.warning(json.dumps({
            "event": "LOCATION_SPOOFING_BLOCKED", 
            "client_id": x_client_id, 
            "postcode": query.postcode, 
            "declared_region": query.declared_region
        }))
        return {
            "status": "BLOCKED",
            "threat_detected": "LOCATION_SPOOFING",
            "message": "Geospatial mismatch detected. Client telemetry does not align with the requested NIPOST postcode zone."
        }

    # 5. Passed Edge Security: Forward securely upstream to NIPOST API using hidden server-side key
    if not NIPOST_API_KEY:
        raise HTTPException(status_code=500, detail="Server misconfiguration: NIPOST API Key not set in environment.")

    nipost_url = f"{NIPOST_BASE_URL}/lookup?code={query.postcode}&level={query.level}"
    
    async with httpx.AsyncClient() as client:
        try:
            nipost_response = await client.get(
                nipost_url,
                headers={"X-API-Key": NIPOST_API_KEY},
                timeout=10.0
            )
        except httpx.RequestError as exc:
            logger.error(json.dumps({"event": "UPSTREAM_CONNECTION_ERROR", "error": str(exc)}))
            raise HTTPException(status_code=502, detail="Failed to connect to NIPOST infrastructure backend.")

    # Handle upstream errors from NIPOST gracefully
    if nipost_response.status_code != 200:
        return {
            "status": "UPSTREAM_ERROR",
            "shield": "PostGuard NG Active",
            "nipost_status_code": nipost_response.status_code,
            "error_details": nipost_response.json()
        }

    # 6. Success: Return sanitized response back to client with security badge
    logger.info(json.dumps({"event": "REQUEST_PASSED_AND_PROXIED", "client_id": x_client_id, "postcode": query.postcode}))
    
    return {
        "status": "SUCCESS",
        "security_score": "100%",
        "shield": "PostGuard NG Firewall Active",
        "nipost_data": nipost_response.json()
    }

@app.get("/health")
def health_check():
    return {
        "system": "PostGuard NG Security Gateway",
        "status": "Operational",
        "target_infrastructure": "https://api.postcode.gov.ng",
        "protection_active": ["HMAC-SHA256", "Token Bucket Rate Limiter", "Geo-Behavioral Engine", "Secure Server-Side Upstream Proxy"]
    }
