import json
import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import urlsplit

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
    deployment_mode: str = os.getenv("POSTGUARD_DEPLOYMENT_MODE", "customer_hosted").strip().lower()
    organization_id: str = os.getenv("POSTGUARD_ORGANIZATION_ID", "default").strip()
    client_organization_ids: Dict[str, str] = field(default_factory=lambda: json.loads(
        os.getenv("POSTGUARD_CLIENT_ORGANIZATIONS", "{}")
    ))
    app_environment: str = os.getenv("APP_ENV", "development").strip().lower()
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = _env_positive_int("PORT", 8000)
    debug: bool = _env_bool("DEBUG", False)
    trusted_hosts: tuple[str, ...] = tuple(
        host.strip()
        for host in os.getenv("TRUSTED_HOSTS", "").split(",")
        if host.strip()
    )
    trusted_proxies: tuple[str, ...] = tuple(
        proxy.strip()
        for proxy in os.getenv("TRUSTED_PROXIES", "").split(",")
        if proxy.strip()
    )

    # Upstream integration remains mock-first; live NIPOST credentials are optional only while mock mode is enabled.
    nipost_api_key: str = os.getenv("NIPOST_API_KEY", "").strip()
    mock_nipost: bool = _env_bool("MOCK_NIPOST", True)
    nipost_base_url: str = os.getenv("NIPOST_BASE_URL", "https://api.postcode.gov.ng").rstrip("/")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0").strip()
    dashboard_database_url: str = os.getenv("DASHBOARD_DATABASE_URL", "sqlite:///./postguard_dashboard.db").strip()
    max_upstream_response_bytes: int = _env_positive_int("MAX_UPSTREAM_RESPONSE_BYTES", 1_048_576)

    # Administrator authentication is separate from client HMAC credentials.
    admin_username: str = os.getenv("ADMIN_USERNAME", "").strip()
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")
    admin_bootstrap_file: str = os.getenv("ADMIN_BOOTSTRAP_FILE", ".admin-bootstrap-credential")
    admin_session_ttl_seconds: int = _env_positive_int("ADMIN_SESSION_TTL_SECONDS", 3600)
    admin_cookie_secure: bool = _env_bool("ADMIN_COOKIE_SECURE", True)
    admin_login_attempts: int = _env_positive_int("ADMIN_LOGIN_ATTEMPTS", 5)
    admin_login_window_seconds: int = _env_positive_int("ADMIN_LOGIN_WINDOW_SECONDS", 900)

    # Optional OpenAI-compatible threat investigation; disabled unless explicitly enabled.
    intelligence_enabled: bool = _env_bool("INTELLIGENCE_ENABLED", False)
    intelligence_base_url: str = os.getenv("INTELLIGENCE_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
    intelligence_api_key: str = os.getenv("INTELLIGENCE_API_KEY", "").strip()
    intelligence_model: str = os.getenv("INTELLIGENCE_MODEL", "").strip()
    intelligence_timeout_seconds: int = _env_positive_int("INTELLIGENCE_TIMEOUT_SECONDS", 15)

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
        if self.deployment_mode not in {"customer_hosted", "managed"}:
            raise RuntimeError("POSTGUARD_DEPLOYMENT_MODE must be customer_hosted or managed.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", self.organization_id):
            raise RuntimeError("POSTGUARD_ORGANIZATION_ID must be 1 to 32 letters, digits, underscores, or hyphens.")
        if not isinstance(self.client_organization_ids, dict):
            raise RuntimeError("POSTGUARD_CLIENT_ORGANIZATIONS must be a JSON object.")
        for client_id, organization_id in self.client_organization_ids.items():
            if client_id not in self.client_policy:
                raise RuntimeError(f"POSTGUARD_CLIENT_ORGANIZATIONS references unknown client {client_id}.")
            if not isinstance(organization_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", organization_id):
                raise RuntimeError("Client organization IDs must contain 1 to 32 letters, digits, underscores, or hyphens.")
        try:
            for trusted_proxy in self.trusted_proxies:
                ipaddress.ip_network(trusted_proxy, strict=False)
        except ValueError as exc:
            raise RuntimeError("TRUSTED_PROXIES must contain valid IP addresses or CIDR ranges.") from exc

        if self.app_environment not in {"development", "production"}:
            raise RuntimeError("APP_ENV must be either development or production.")

        if self.app_environment == "production":
            if self.debug:
                raise RuntimeError("DEBUG must be false in production.")
            if not self.admin_cookie_secure:
                raise RuntimeError("ADMIN_COOKIE_SECURE must be true in production.")
            if not self.trusted_hosts or "*" in self.trusted_hosts:
                raise RuntimeError("TRUSTED_HOSTS must list allowed hostnames in production.")
            if not self.admin_username or not self.admin_password:
                raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be configured in production.")
            if "MOCK_NIPOST" not in os.environ:
                raise RuntimeError("MOCK_NIPOST must be set explicitly in production.")

        missing = self.required
        if missing:
            raise RuntimeError("Missing or invalid required configuration: " + "; ".join(missing))

        if bool(self.admin_username) != bool(self.admin_password):
            raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be configured together.")
        if self.admin_password and len(self.admin_password) < 16:
            raise RuntimeError("ADMIN_PASSWORD must contain at least 16 characters.")

        if self.intelligence_enabled:
            if not self.intelligence_api_key or len(self.intelligence_api_key) > 4096:
                raise RuntimeError("INTELLIGENCE_API_KEY is required when INTELLIGENCE_ENABLED=true.")
            if not self.intelligence_model or len(self.intelligence_model) > 128:
                raise RuntimeError("INTELLIGENCE_MODEL is required when INTELLIGENCE_ENABLED=true.")
            try:
                intelligence_url = urlsplit(self.intelligence_base_url)
                intelligence_port = intelligence_url.port
            except ValueError as exc:
                raise RuntimeError("INTELLIGENCE_BASE_URL must be a valid absolute URL.") from exc
            local_http = intelligence_url.scheme == "http" and intelligence_url.hostname in {
                "localhost", "127.0.0.1", "::1",
            }
            if (
                not intelligence_url.hostname
                or intelligence_url.username
                or intelligence_url.password
                or intelligence_url.query
                or intelligence_url.fragment
                or intelligence_port == 0
                or (intelligence_url.scheme != "https" and not local_http)
            ):
                raise RuntimeError(
                    "INTELLIGENCE_BASE_URL must use HTTPS, except for a local development endpoint."
                )

        try:
            upstream = urlsplit(self.nipost_base_url)
            upstream_port = upstream.port
        except ValueError as exc:
            raise RuntimeError("NIPOST_BASE_URL must be a valid absolute URL.") from exc

        if not upstream.hostname or upstream.username or upstream.password or upstream.query or upstream.fragment:
            raise RuntimeError("NIPOST_BASE_URL must contain only an absolute upstream origin and optional path.")
        if not self.mock_nipost:
            if upstream.scheme != "https" or upstream_port not in (None, 443):
                raise RuntimeError("NIPOST_BASE_URL must use HTTPS on the standard port when live mode is enabled.")
            try:
                address = ipaddress.ip_address(upstream.hostname)
            except ValueError:
                address = None
            if address is not None and (not address.is_global):
                raise RuntimeError("NIPOST_BASE_URL must not use a private or non-public IP address.")

        for client_id, policy in self.client_policy.items():
            regions = policy.get("allowed_regions", [])
            if not isinstance(regions, list) or not regions:
                raise RuntimeError(f"Client policy for {client_id} must declare at least one allowed region.")
            for region in regions:
                if not isinstance(region, str) or not region.strip():
                    raise RuntimeError(f"Client policy for {client_id} contains an invalid region entry.")


settings = Settings()
settings.validate()
