import os
from dataclasses import dataclass, field
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name, str(default)).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be one of: true, false, 1, 0, yes, no, on, off.")


def _env_positive_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default))
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer value.") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return parsed


@dataclass(frozen=True)
class Settings:
    app_name: str = "PostGuard NG Security Gateway"
    app_version: str = "2.0.0"
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = _env_positive_int("PORT", 8000)
    debug: bool = _env_bool("DEBUG", False)

    # Upstream integration remains mock-first; live NIPOST credentials are optional only while mock mode is enabled.
    nipost_api_key: str = os.getenv("NIPOST_API_KEY", "").strip()
    mock_nipost: bool = _env_bool("MOCK_NIPOST", False)
    nipost_base_url: str = os.getenv("NIPOST_BASE_URL", "https://api.postcode.gov.ng").rstrip("/")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0").strip()

    # Security parameters
    max_clock_skew_seconds: int = _env_positive_int("MAX_CLOCK_SKEW_SECONDS", 120)
    nonce_ttl_seconds: int = _env_positive_int("NONCE_TTL_SECONDS", 300)
    request_ttl_seconds: int = _env_positive_int("REQUEST_TTL_SECONDS", 120)
    rate_limit_window_seconds: int = _env_positive_int("RATE_LIMIT_WINDOW_SECONDS", 60)
    rate_limit_per_minute: int = _env_positive_int("RATE_LIMIT_PER_MINUTE", 10)
    max_request_body_bytes: int = _env_positive_int("MAX_REQUEST_BODY_BYTES", 16384)

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

    def client_secret_env_name(self, client_id: str) -> str:
        return f"POSTGUARD_{client_id.upper().replace('-', '_')}_SECRET"

    @property
    def client_secrets(self) -> Dict[str, str]:
        return {
            client_id: os.getenv(self.client_secret_env_name(client_id), "").strip()
            for client_id in self.client_policy
        }

    @property
    def required(self) -> List[str]:
        missing: List[str] = []
        for client_id, secret in self.client_secrets.items():
            env_name = self.client_secret_env_name(client_id)
            if len(secret.encode("utf-8")) < 32:
                missing.append(f"{env_name} (must be at least 32 bytes)")
        if not self.mock_nipost and not self.nipost_api_key:
            missing.append("NIPOST_API_KEY (required unless MOCK_NIPOST=true)")
        if not self.redis_url:
            missing.append("REDIS_URL")
        return missing

    def validate(self) -> None:
        missing = self.required
        if missing:
            raise RuntimeError("Missing or invalid required configuration: " + "; ".join(missing))

        for client_id, policy in self.client_policy.items():
            regions = policy.get("allowed_regions", [])
            if not isinstance(regions, list) or not regions:
                raise RuntimeError(f"Client policy for {client_id} must declare at least one allowed region.")
            for region in regions:
                if not isinstance(region, str) or not region.strip():
                    raise RuntimeError(f"Client policy for {client_id} contains an invalid region entry.")


settings = Settings()
settings.validate()
