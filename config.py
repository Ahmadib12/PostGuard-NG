import os
from dataclasses import dataclass, field
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

    # Each client must have an independently managed signing secret.
    nipost_api_key: str = os.getenv("NIPOST_API_KEY", "")
    mock_nipost: bool = os.getenv("MOCK_NIPOST", "false").lower() == "true"
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Security parameters
    max_clock_skew_seconds: int = int(os.getenv("MAX_CLOCK_SKEW_SECONDS", "120"))
    nonce_ttl_seconds: int = int(os.getenv("NONCE_TTL_SECONDS", "300"))
    request_ttl_seconds: int = int(os.getenv("REQUEST_TTL_SECONDS", "120"))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
    max_request_body_bytes: int = int(os.getenv("MAX_REQUEST_BODY_BYTES", "16384"))

    # Client policy (demo; replace with DB-backed tenant/auth model)
    client_policy: Dict[str, Dict[str, object]] = field(default_factory=lambda: {
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
    })

    @property
    def client_secrets(self) -> Dict[str, str]:
        return {
            client_id: os.getenv(
                f"POSTGUARD_{client_id.upper().replace('-', '_')}_SECRET",
                "",
            )
            for client_id in self.client_policy
        }

    @property
    def required(self) -> List[str]:
        missing = []
        for client_id, secret in self.client_secrets.items():
            env_name = f"POSTGUARD_{client_id.upper().replace('-', '_')}_SECRET"
            if len(secret.encode("utf-8")) < 32:
                missing.append(f"{env_name} (must be at least 32 bytes)")
        if not self.nipost_api_key and not self.mock_nipost:
            missing.append("NIPOST_API_KEY")
        if self.max_request_body_bytes < 1:
            missing.append("MAX_REQUEST_BODY_BYTES (must be positive)")
        return missing


settings = Settings()
