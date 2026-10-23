import hmac
import hashlib
import time
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from typing import Optional

app = FastAPI(
    title="PostGuard NG Security Gateway",
    description="API Middleware protecting NIPOST National Alphanumeric Postcode Infrastructure",
    version="1.0.0"
)

# Secret shared with registered enterprise clients (e.g., Logistics / Fintech partners)
CLIENT_SECRET_KEY = b"super-secret-partner-key-3mtt"

# In-memory rate limiting store (For production, swap this out for Redis)
request_counts = {}
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS_PER_WINDOW = 5  # strict limit for demo purposes

class PostcodeQuery(BaseModel):
    postcode: str = Field(..., example="FC 02 A09 DB 09", description="11-character NIPOST Alphanumeric Code")
    client_lat: float = Field(..., example=9.05785, description="Client device latitude")
    client_lon: float = Field(..., example=7.49508, description="Client device longitude")
    declared_region: str = Field(..., example="Abuja", description="State or LGA user claims to be in")

def verify_hmac_signature(payload_body: bytes, received_sig: str) -> bool:
    """Verifies that the request payload has not been tampered with mid-transit."""
    computed_sig = hmac.new(CLIENT_SECRET_KEY, payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_sig, received_sig)

def check_rate_limit(client_id: str) -> bool:
    """Simple sliding-window rate limiter to block DDoS and volumetric scraping."""
    current_time = time.time()
    if client_id not in request_counts:
        request_counts[client_id] = []
    
    # Filter timestamps within the current window
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
    Secure proxy endpoint that intercepts, sanitizes, and evaluates postcode queries 
    before forwarding them to NIPOST's backend infrastructure.
    """
    # 1. Check API Client Identification Header
    if not x_client_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Client-ID header."
        )

    # 2. Enforce Rate Limiting
    if not check_rate_limit(x_client_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Potential volumetric attack or scraping blocked by PostGuard NG."
        )

    # 3. Verify HMAC Payload Signature
    raw_body = await request.body()
    if not x_postguard_signature or not verify_hmac_signature(raw_body, x_postguard_signature):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing HMAC-SHA256 signature. Request payload tampering detected."
        )

    # 4. Geo-Behavioral Anomaly & Spoofing Check (Mock logic for demo)
    # E.g., If someone claims to be in Lagos (Lat ~6.5) but queries an Abuja postcode (FC 02...)
    if query.postcode.startswith("FC") and query.declared_region.lower() != "abuja":
        return {
            "status": "BLOCKED",
            "threat_detected": "LOCATION_SPOOFING",
            "message": "Geospatial mismatch detected. Client metadata does not align with the requested NIPOST postcode zone."
        }

    # 5. Passed all security checks -> Forward to NIPOST API (Mocked successful proxy response)
    return {
        "status": "SUCCESS",
        "security_score": "100%",
        "postcode": query.postcode,
        "resolved_data": {
            "state": "Federal Capital Territory",
            "lga": "Municipal Area Council",
            "building_status": "Verified Active",
            "gis_precision": "11-character Alphanumeric Grid Verified"
        },
        "message": "Request successfully authenticated and scrubbed by PostGuard NG."
    }

@app.get("/health")
def health_check():
    return {"system": "PostGuard NG Firewall", "status": "Operational", "target": "docs.postcode.gov.ng"}
