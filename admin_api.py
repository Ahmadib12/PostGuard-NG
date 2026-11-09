import asyncio
import hashlib
import hmac
import ipaddress
import logging
import secrets
import threading
import time
from datetime import datetime
from typing import Annotated

import redis
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from config import settings
from dashboard_store import (
    analytics,
    check_csrf,
    clients_activity,
    create_admin_session,
    delete_admin_session,
    engine,
    get_admin_session,
    initialize_admin_credentials,
    list_audit_logs,
    list_events,
    overview,
    record_audit,
    verify_stored_admin,
)
from security import redis_client

logger = logging.getLogger("PostGuard-NG.admin")
router = APIRouter(prefix="/api/admin", tags=["administration"])

SESSION_COOKIE = "postguard_admin"
CSRF_COOKIE = "postguard_admin_csrf"
_configured_password_salt = secrets.token_bytes(32)
_configured_password_hash = (
    hashlib.scrypt(
        settings.admin_password.encode("utf-8"),
        salt=_configured_password_salt,
        n=2**14,
        r=8,
        p=1,
    )
    if settings.admin_password
    else None
)
_login_attempts: dict[str, list[float]] = {}
_login_attempts_lock = threading.Lock()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


def _database_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except SQLAlchemyError as exc:
        logger.exception("Dashboard database operation failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "dashboard_storage_unavailable", "message": "Dashboard storage is temporarily unavailable."},
        ) from exc


def _verify_admin(username: str, password: str) -> bool:
    if settings.admin_username and settings.admin_password and _configured_password_hash is not None:
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_configured_password_salt,
            n=2**14,
            r=8,
            p=1,
        )
        return hmac.compare_digest(username.encode(), settings.admin_username.encode()) and hmac.compare_digest(
            candidate, _configured_password_hash
        )
    return verify_stored_admin(username, password)


def _permit_login(ip_address: str) -> bool:
    now = time.monotonic()
    with _login_attempts_lock:
        attempts = [item for item in _login_attempts.get(ip_address, []) if now - item < settings.admin_login_window_seconds]
        if len(attempts) >= settings.admin_login_attempts:
            _login_attempts[ip_address] = attempts
            return False
        attempts.append(now)
        _login_attempts[ip_address] = attempts
        return True


def _clear_login_attempts(ip_address: str) -> None:
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
) -> tuple[str, str, str]:
    session = await asyncio.to_thread(_database_call, get_admin_session, session_token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "admin_auth_required", "message": "Administrator authentication is required."},
        )
    return session


async def require_csrf(
    request: Request,
    admin: tuple[str, str, str] = Depends(require_admin),
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
) -> tuple[str, str, str]:
    if not check_csrf(admin[1], csrf_token, csrf_cookie):
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
    try:
        valid = await asyncio.to_thread(_database_call, _verify_admin, body.username, body.password)
    except (ValueError, MemoryError) as exc:
        logger.exception("Administrator password verification failed.")
        raise HTTPException(status_code=503, detail={"code": "admin_auth_unavailable", "message": "Administrator authentication is unavailable."}) from exc
    if not valid:
        await asyncio.to_thread(_database_call, record_audit, body.username[:128], "login_failed", {})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_admin_credentials", "message": "Invalid administrator credentials."},
        )

    _clear_login_attempts(ip_address)
    session_token, csrf_token = await asyncio.to_thread(
        _database_call, create_admin_session, body.username, settings.organization_id
    )
    await asyncio.to_thread(
        _database_call, record_audit, body.username, "login", {}, settings.organization_id
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
        "username": body.username,
        "organization_id": settings.organization_id,
        "csrf_token": csrf_token,
        "expires_in": settings.admin_session_ttl_seconds,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    admin: tuple[str, str, str] = Depends(require_csrf),
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
):
    await asyncio.to_thread(_database_call, delete_admin_session, session_token)
    await asyncio.to_thread(
        _database_call, record_audit, admin[0], "logout", {}, admin[2]
    )
    response.delete_cookie(SESSION_COOKIE, path="/api/admin", secure=settings.admin_cookie_secure, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.admin_cookie_secure, httponly=False, samesite="strict")
    return {"status": "logged_out"}


@router.get("/session")
async def session_status(admin: tuple[str, str, str] = Depends(require_admin)):
    return {"authenticated": True, "username": admin[0], "organization_id": admin[2]}


@router.get("/overview")
async def get_overview(
    hours: int = Query(default=24, ge=1, le=720),
    admin: tuple[str, str, str] = Depends(require_admin),
):
    return await asyncio.to_thread(_database_call, overview, hours, admin[2])


@router.get("/analytics")
async def get_analytics(
    hours: int = Query(default=24, ge=1, le=720),
    admin: tuple[str, str, str] = Depends(require_admin),
):
    return await asyncio.to_thread(_database_call, analytics, hours, admin[2])


@router.get("/clients")
async def get_clients(admin: tuple[str, str, str] = Depends(require_admin)):
    return {"items": await asyncio.to_thread(_database_call, clients_activity, admin[2])}


@router.get("/events")
async def get_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    event_type: str | None = Query(default=None, min_length=1, max_length=64),
    client_id: str | None = Query(default=None, min_length=1, max_length=128),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    admin: tuple[str, str, str] = Depends(require_admin),
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
        organization_id=admin[2],
    )


@router.get("/security/replays")
async def get_replays(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    admin: tuple[str, str, str] = Depends(require_admin),
):
    return await asyncio.to_thread(
        _database_call, list_events, page, page_size, "REPLAY_DETECTED", organization_id=admin[2]
    )


@router.get("/security/suspicious")
async def get_suspicious(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    admin: tuple[str, str, str] = Depends(require_admin),
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
        admin[2],
    )


@router.get("/health")
async def get_health(_admin: tuple[str, str, str] = Depends(require_admin)):
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
    admin: tuple[str, str, str] = Depends(require_admin),
):
    return await asyncio.to_thread(_database_call, list_audit_logs, page, page_size, admin[2])
