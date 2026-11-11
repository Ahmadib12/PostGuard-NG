import asyncio
import hashlib
import ipaddress
import logging
import re
import threading
import time
from datetime import datetime
from typing import Annotated

import redis
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from config import settings
from dashboard_store import (
    analytics,
    check_csrf,
    clients_activity,
    engine,
    list_audit_logs,
    list_events,
    AdminAccount,
    Organization,
    OrganizationAdminMembership,
    SessionLocal,
    overview,
    record_audit,
)
from iam import (
    AdminPrincipal,
    change_admin_password,
    create_organization,
    create_organization_admin,
    create_admin_session,
    get_admin_principal,
    organization_is_active,
    revoke_admin_session,
    revoke_admin_sessions,
    reset_admin_password,
    set_organization_status,
    update_organization_admin,
)
from intelligence import investigate_incidents, list_incidents
from security import redis_client

logger = logging.getLogger("PostGuard-NG.admin")
router = APIRouter(prefix="/api/admin", tags=["administration"])

SESSION_COOKIE = "postguard_admin"
CSRF_COOKIE = "postguard_admin_csrf"
_login_attempts: dict[str, list[float]] = {}
_login_attempts_lock = threading.Lock()
_MAX_LOCAL_LOGIN_IPS = 4096
_intelligence_attempts: dict[str, list[float]] = {}
_intelligence_attempts_lock = threading.Lock()

_LOGIN_RATE_LIMIT_SCRIPT = """
local count = redis.call("INCR", KEYS[1])
if count == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
if count > tonumber(ARGV[2]) then
    return 0
end
return 1
"""


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    organization_id: str | None = Field(default=None, min_length=1, max_length=32)


class PasswordChangeBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=16, max_length=1024)


class AdminCreateBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=32)


class AdminUpdateBody(BaseModel):
    role: str | None = Field(default=None, min_length=1, max_length=32)
    active: bool | None = None


class OrganizationCreateBody(BaseModel):
    organization_id: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=128)


def _permit_intelligence(admin_id: str) -> bool:
    now = time.monotonic()
    with _intelligence_attempts_lock:
        attempts = [
            item for item in _intelligence_attempts.get(admin_id, [])
            if now - item < 60
        ]
        if len(attempts) >= 3:
            _intelligence_attempts[admin_id] = attempts
            return False
        attempts.append(now)
        _intelligence_attempts[admin_id] = attempts
        return True


def _record_admin_audit(request: Request, admin: AdminPrincipal, action: str, details: dict | None = None):
    return _database_call(
        record_audit,
        admin.username,
        action,
        details or {},
        admin.organization_id,
        admin.admin_id,
        getattr(request.state, "request_id", None),
    )


def _database_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except SQLAlchemyError as exc:
        logger.exception("Dashboard database operation failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "dashboard_storage_unavailable", "message": "Dashboard storage is temporarily unavailable."},
        ) from exc


def _permit_login(ip_address: str) -> bool:
    if settings.app_environment == "production":
        key = f"postguard:v1:admin-login:{hashlib.sha256(ip_address.encode('utf-8')).hexdigest()}"
        try:
            return bool(redis_client.eval(
                _LOGIN_RATE_LIMIT_SCRIPT,
                1,
                key,
                settings.admin_login_window_seconds,
                settings.admin_login_attempts,
            ))
        except redis.RedisError as exc:
            logger.error("Admin login rate-limiting failed closed; Redis is unavailable in production.", exc_info=exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "login_rate_limit_unavailable", "message": "The login rate limiter is temporarily unavailable."},
            ) from exc

    if settings.app_environment != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "login_rate_limit_unavailable", "message": "The login rate limiter is temporarily unavailable."},
        )

    now = time.monotonic()
    cutoff = now - settings.admin_login_window_seconds
    with _login_attempts_lock:
        for address, attempts in tuple(_login_attempts.items()):
            active_attempts = [attempt for attempt in attempts if attempt > cutoff]
            if active_attempts:
                _login_attempts[address] = active_attempts
            else:
                del _login_attempts[address]

        attempts = _login_attempts.get(ip_address)
        if attempts is not None and len(attempts) >= settings.admin_login_attempts:
            return False

        if attempts is None:
            if len(_login_attempts) >= _MAX_LOCAL_LOGIN_IPS:
                del _login_attempts[next(iter(_login_attempts))]
            attempts = []
            _login_attempts[ip_address] = attempts
        attempts.append(now)
        return True


def _clear_login_attempts(ip_address: str) -> None:
    if settings.app_environment == "production":
        key = f"postguard:v1:admin-login:{hashlib.sha256(ip_address.encode('utf-8')).hexdigest()}"
        try:
            redis_client.delete(key)
        except redis.RedisError:
            logger.warning("Failed to clear admin login rate-limit counter for %s after a successful login.", ip_address)
    elif settings.app_environment == "development":
        with _login_attempts_lock:
            _login_attempts.pop(ip_address, None)


def _remote_address(request: Request) -> str:
    peer_address = request.client.host if request.client else "unknown"
    try:
        peer_ip = ipaddress.ip_address(peer_address)
    except ValueError:
        return peer_address

    if any(
        peer_ip in ipaddress.ip_network(proxy, strict=False)
        for proxy in settings.trusted_proxies
    ):
        try:
            return str(ipaddress.ip_address(request.headers.get("x-real-ip", "")))
        except ValueError:
            pass
    return peer_address


async def require_admin(
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> AdminPrincipal:
    resolved = await asyncio.to_thread(_database_call, get_admin_principal, session_token)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "admin_auth_required", "message": "Administrator authentication is required."},
        )
    return resolved[0]


def require_permission(permission: str, allow_suspended: bool = False):
    async def dependency(admin: AdminPrincipal = Depends(require_admin)) -> AdminPrincipal:
        if admin.must_change_password and permission != "profile.password.change":
            raise HTTPException(
                status_code=403,
                detail={"code": "password_change_required", "message": "Change the temporary password before continuing."},
            )
        if permission not in admin.permissions:
            await asyncio.to_thread(
                _database_call,
                record_audit,
                admin.username,
                "authorization_denied",
                {"permission": permission},
                admin.organization_id,
                admin.admin_id,
            )
            raise HTTPException(status_code=403, detail="Permission denied.")
        if not allow_suspended:
            active = await asyncio.to_thread(
                _database_call,
                organization_is_active,
                admin.organization_id,
            )
            if not active:
                raise HTTPException(status_code=403, detail="Organization is suspended.")
        return admin

    return dependency


async def require_csrf(
    request: Request,
    admin: AdminPrincipal = Depends(require_admin),
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
) -> AdminPrincipal:
    if not check_csrf(admin.csrf_hash, csrf_token, csrf_cookie):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "csrf_validation_failed", "message": "CSRF token is missing or invalid."},
        )
    return admin


def _valid_date(value: datetime | None, name: str) -> datetime | None:
    if value is not None and value.tzinfo is None:
        raise HTTPException(status_code=400, detail={"code": "invalid_date", "message": f"{name} must include a timezone."})
    return value


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response):
    ip_address = _remote_address(request)
    if not _permit_login(ip_address):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "login_rate_limited", "message": "Too many login attempts. Try again later."},
        )
    created = await asyncio.to_thread(
        _database_call,
        create_admin_session,
        body.username,
        body.password,
        body.organization_id,
    )
    if created is None:
        await asyncio.to_thread(
            _database_call,
            record_audit,
            "anonymous",
            "login_failed",
            {"reason": "invalid_credentials_or_membership"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_admin_credentials", "message": "Invalid administrator credentials."},
        )

    _clear_login_attempts(ip_address)
    session_token, csrf_token, admin = created
    await asyncio.to_thread(
        _database_call,
        record_audit,
        admin.username,
        "login",
        {"role": admin.role},
        admin.organization_id,
        admin.admin_id,
    )
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=settings.admin_session_ttl_seconds,
        httponly=True,
        secure=settings.admin_cookie_secure,
        samesite="strict",
        path="/api/admin",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=settings.admin_session_ttl_seconds,
        httponly=False,
        secure=settings.admin_cookie_secure,
        samesite="strict",
        path="/",
    )
    return {
        "username": admin.username,
        "admin_id": admin.admin_id,
        "organization_id": admin.organization_id,
        "role": admin.role,
        "permissions": sorted(admin.permissions),
        "must_change_password": admin.must_change_password,
        "csrf_token": csrf_token,
        "expires_in": settings.admin_session_ttl_seconds,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    admin: AdminPrincipal = Depends(require_csrf),
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
):
    await asyncio.to_thread(_database_call, revoke_admin_session, session_token)
    await asyncio.to_thread(_record_admin_audit, request, admin, "logout")
    response.delete_cookie(SESSION_COOKIE, path="/api/admin", secure=settings.admin_cookie_secure, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.admin_cookie_secure, httponly=False, samesite="strict")
    return {"status": "logged_out"}


@router.get("/session")
async def session_status(admin: AdminPrincipal = Depends(require_admin)):
    return {
        "authenticated": True,
        "username": admin.username,
        "admin_id": admin.admin_id,
        "organization_id": admin.organization_id,
        "role": admin.role,
        "permissions": sorted(admin.permissions),
        "must_change_password": admin.must_change_password,
    }


@router.post("/password")
async def change_password(
    body: PasswordChangeBody,
    request: Request,
    response: Response,
    admin: AdminPrincipal = Depends(require_csrf),
):
    await asyncio.to_thread(
        _database_call,
        change_admin_password,
        admin.admin_id,
        body.current_password,
        body.new_password,
    )
    await asyncio.to_thread(_record_admin_audit, request, admin, "password_changed")
    response.delete_cookie(SESSION_COOKIE, path="/api/admin", secure=settings.admin_cookie_secure, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.admin_cookie_secure, httponly=False, samesite="strict")
    return {"status": "password_changed", "sessions_revoked": True}


@router.get("/overview")
async def get_overview(
    hours: int = Query(default=24, ge=1, le=720),
    admin: AdminPrincipal = Depends(require_permission("dashboard.read")),
):
    return await asyncio.to_thread(_database_call, overview, hours, admin.organization_id)


@router.get("/analytics")
async def get_analytics(
    hours: int = Query(default=24, ge=1, le=720),
    admin: AdminPrincipal = Depends(require_permission("dashboard.read")),
):
    return await asyncio.to_thread(_database_call, analytics, hours, admin.organization_id)


@router.get("/clients")
async def get_clients(admin: AdminPrincipal = Depends(require_permission("dashboard.read"))):
    return {"items": await asyncio.to_thread(_database_call, clients_activity, admin.organization_id)}


@router.get("/events")
async def get_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    event_type: str | None = Query(default=None, min_length=1, max_length=64),
    client_id: str | None = Query(default=None, min_length=1, max_length=128),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    admin: AdminPrincipal = Depends(require_permission("events.read")),
):
    since = _valid_date(since, "since")
    until = _valid_date(until, "until")
    if since and until and since > until:
        raise HTTPException(status_code=400, detail={"code": "invalid_date_range", "message": "since must not be after until."})
    return await asyncio.to_thread(
        _database_call,
        list_events,
        page,
        page_size,
        event_type,
        client_id,
        severity,
        since,
        until,
        organization_id=admin.organization_id,
    )


@router.get("/security/replays")
async def get_replays(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    admin: AdminPrincipal = Depends(require_permission("events.read")),
):
    return await asyncio.to_thread(
        _database_call, list_events, page, page_size, "REPLAY_DETECTED", organization_id=admin.organization_id
    )


@router.get("/security/suspicious")
async def get_suspicious(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    admin: AdminPrincipal = Depends(require_permission("events.read")),
):
    event_types = ("INVALID_SIGNATURE", "UNKNOWN_CLIENT", "INVALID_NONCE", "CLIENT_POLICY_VIOLATION", "GEO_FENCE_MISMATCH")
    return await asyncio.to_thread(
        _database_call,
        list_events,
        page,
        page_size,
        None,
        None,
        None,
        None,
        None,
        event_types,
        admin.organization_id,
    )


@router.get("/health")
async def get_health(_admin: AdminPrincipal = Depends(require_permission("health.read"))):
    try:
        redis_ok = bool(await asyncio.to_thread(redis_client.ping))
    except redis.RedisError:
        redis_ok = False
    try:
        def database_probe():
            with engine.connect() as connection:
                return connection.execute(text("SELECT 1")).scalar_one()

        await asyncio.to_thread(database_probe)
        database_ok = True
    except SQLAlchemyError:
        logger.exception("Dashboard health database probe failed.")
        database_ok = False
    return {
        "status": "healthy" if redis_ok and database_ok else "degraded",
        "application": "ok",
        "redis": "ok" if redis_ok else "unavailable",
        "database": "ok" if database_ok else "unavailable",
        "deployment_mode": settings.deployment_mode,
        "upstream": "mock_mode" if settings.mock_nipost else "not_checked",
        "upstream_is_mock": settings.mock_nipost,
    }


@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    admin: AdminPrincipal = Depends(require_permission("audit.read")),
):
    return await asyncio.to_thread(_database_call, list_audit_logs, page, page_size, admin.organization_id)


@router.get("/users")
async def get_organization_admins(
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("users.read")),
):
    def load_members():
        with SessionLocal() as db:
            rows = db.execute(
                select(AdminAccount, OrganizationAdminMembership.role)
                .join(OrganizationAdminMembership, OrganizationAdminMembership.admin_id == AdminAccount.id)
                .where(OrganizationAdminMembership.organization_id == admin.organization_id)
                .order_by(AdminAccount.username)
            ).all()
            return [{
                "admin_id": account.id,
                "username": account.username,
                "active": account.active,
                "role": role,
                "must_change_password": account.must_change_password,
            } for account, role in rows]

    return {"items": await asyncio.to_thread(_database_call, load_members)}


@router.post("/users", status_code=201)
async def create_organization_admin_endpoint(
    body: AdminCreateBody,
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("users.manage")),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    if not re.fullmatch(r"[A-Za-z0-9._@-]{1,128}", body.username):
        raise HTTPException(status_code=422, detail="Username contains unsupported characters.")
    created, temporary_password = await asyncio.to_thread(
        _database_call,
        create_organization_admin,
        admin.organization_id,
        body.username,
        body.role,
        admin.platform_super_admin,
    )
    await asyncio.to_thread(
        _record_admin_audit,
        request,
        admin,
        "administrator_created",
        {"target_admin_id": created.id, "role": body.role},
    )
    requires_password_update = True
    return {
        "admin_id": created.id,
        "username": created.username,
        "role": body.role,
        "temporary_password": temporary_password,
        "must_change_password": requires_password_update,
    }


@router.patch("/users/{target_admin_id}")
async def update_organization_admin_endpoint(
    target_admin_id: str,
    body: AdminUpdateBody,
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("users.manage")),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    if body.role is None and body.active is None:
        raise HTTPException(status_code=422, detail="Provide an account status or role change.")
    if target_admin_id == admin.admin_id and body.active is False:
        raise HTTPException(status_code=409, detail="Administrators cannot deactivate their own account.")
    await asyncio.to_thread(
        _database_call,
        update_organization_admin,
        admin.organization_id,
        target_admin_id,
        body.role,
        body.active,
        admin.platform_super_admin,
    )
    await asyncio.to_thread(
        _record_admin_audit,
        request,
        admin,
        "administrator_updated",
        {"target_admin_id": target_admin_id, "role": body.role, "active": body.active},
    )
    return {"status": "updated"}


@router.post("/users/{target_admin_id}/revoke-sessions")
async def revoke_organization_admin_sessions(
    target_admin_id: str,
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("users.manage")),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    def verify_membership_and_revoke():
        with SessionLocal() as db:
            membership = db.get(
                OrganizationAdminMembership,
                (target_admin_id, admin.organization_id),
            )
            account = db.get(AdminAccount, target_admin_id)
            if membership is None or account is None:
                raise HTTPException(status_code=404, detail="Organization administrator not found.")
        return revoke_admin_sessions(target_admin_id, admin.organization_id)

    revoked = await asyncio.to_thread(_database_call, verify_membership_and_revoke)
    await asyncio.to_thread(
        _record_admin_audit,
        request,
        admin,
        "administrator_sessions_revoked",
        {"target_admin_id": target_admin_id, "count": revoked},
    )
    return {"revoked_sessions": revoked}


@router.post("/users/{target_admin_id}/reset-password")
async def reset_organization_admin_password(
    target_admin_id: str,
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("users.manage")),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    temporary_password = await asyncio.to_thread(
        _database_call,
        reset_admin_password,
        admin.organization_id,
        target_admin_id,
    )
    await asyncio.to_thread(
        _record_admin_audit,
        request,
        admin,
        "administrator_password_reset",
        {"target_admin_id": target_admin_id},
    )
    requires_password_update = True
    return {
        "temporary_password": temporary_password,
        "must_change_password": requires_password_update,
        "sessions_revoked": True,
    }


@router.get("/organizations")
async def get_organizations(
    admin: AdminPrincipal = Depends(require_permission("organizations.manage", allow_suspended=True)),
):
    def load_organizations():
        with SessionLocal() as db:
            return [{
                "organization_id": organization.id,
                "name": organization.name,
                "status": organization.status,
            } for organization in db.scalars(select(Organization).order_by(Organization.id)).all()]

    return {"items": await asyncio.to_thread(_database_call, load_organizations)}


@router.post("/organizations", status_code=201)
async def create_organization_endpoint(
    body: OrganizationCreateBody,
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("organizations.manage", allow_suspended=True)),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", body.organization_id):
        raise HTTPException(status_code=422, detail="Invalid organization ID.")
    await asyncio.to_thread(_database_call, create_organization, body.organization_id, body.name)
    await asyncio.to_thread(
        _database_call,
        record_audit,
        admin.username,
        "organization_created",
        {"target_organization_id": body.organization_id},
        body.organization_id,
        admin.admin_id,
        getattr(request.state, "request_id", None),
    )
    return {"organization_id": body.organization_id, "status": "active"}


@router.post("/organizations/{organization_id}/suspend")
async def suspend_organization(
    organization_id: str,
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("organizations.manage", allow_suspended=True)),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    await asyncio.to_thread(_database_call, set_organization_status, organization_id, "suspended")
    await asyncio.to_thread(
        _database_call,
        record_audit,
        admin.username,
        "organization_suspended",
        {"target_organization_id": organization_id},
        organization_id,
        admin.admin_id,
        getattr(request.state, "request_id", None),
    )
    return {"organization_id": organization_id, "status": "suspended"}


@router.post("/organizations/{organization_id}/restore")
async def restore_organization(
    organization_id: str,
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("organizations.manage", allow_suspended=True)),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    await asyncio.to_thread(_database_call, set_organization_status, organization_id, "active")
    await asyncio.to_thread(
        _database_call,
        record_audit,
        admin.username,
        "organization_restored",
        {"target_organization_id": organization_id},
        organization_id,
        admin.admin_id,
        getattr(request.state, "request_id", None),
    )
    return {"organization_id": organization_id, "status": "active"}


@router.get("/intelligence/incidents")
async def get_intelligence_incidents(
    admin: AdminPrincipal = Depends(require_permission("incidents.read")),
):
    items = await asyncio.to_thread(_database_call, list_incidents, admin.organization_id)
    return {
        "items": items,
        "provider_enabled": settings.intelligence_enabled,
    }


@router.post("/intelligence/investigate")
async def investigate_security_incidents(
    request: Request,
    admin: AdminPrincipal = Depends(require_permission("analyst.investigate")),
    _csrf_admin: AdminPrincipal = Depends(require_csrf),
):
    if not settings.intelligence_enabled:
        raise HTTPException(status_code=503, detail="AI investigation is disabled.")
    if not _permit_intelligence(admin.admin_id):
        raise HTTPException(status_code=429, detail="AI investigation is limited to three requests per minute.")
    incidents = await asyncio.to_thread(_database_call, list_incidents, admin.organization_id)
    await asyncio.to_thread(
        _record_admin_audit,
        request,
        admin,
        "ai_investigation_requested",
        {"incident_count": len(incidents)},
    )
    return await investigate_incidents(incidents)
