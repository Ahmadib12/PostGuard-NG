import os
from dataclasses import dataclass
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = "PostGuard NG Security Gateway"
    app_version: str = "2.0.0"
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Required security config
    postguard_client_secret: str = os.getenv("POSTGUARD_CLIENT_SECRET", "")
    nipost_api_key: str = os.getenv("NIPOST_API_KEY", "")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Security parameters
    max_clock_skew_seconds: int = int(os.getenv("MAX_CLOCK_SKEW_SECONDS", "120"))
    nonce_ttl_seconds: int = int(os.getenv("NONCE_TTL_SECONDS", "300"))
    request_ttl_seconds: int = int(os.getenv("REQUEST_TTL_SECONDS", "120"))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))

    # Client policy (demo; replace with DB-backed tenant/auth model)
    client_policy: Dict[str, Dict[str, object]] = {
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

    @property
    def required(self) -> List[str]:
        missing = []
        if not self.postguard_client_secret:
            missing.append("POSTGUARD_CLIENT_SECRET")
        if not self.nipost_api_key:
            missing.append("NIPOST_API_KEY")
        return missing


settings = Settings()
