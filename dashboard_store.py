import hashlib
import json
import logging
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, Integer, LargeBinary, String, Text, case, create_engine, func, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from config import settings

logger = logging.getLogger("PostGuard-NG.telemetry")


def _database_url() -> str:
    url = settings.dashboard_database_url
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://") and "+" not in url.split(":", 1)[0]:
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


_url = _database_url()
_engine_options: dict[str, Any] = {"pool_pre_ping": True}
if _url.startswith("sqlite"):
    _engine_options["connect_args"] = {"check_same_thread": False, "timeout": 10}
    if _url.endswith(":memory:"):
        from sqlalchemy.pool import StaticPool

        _engine_options["poolclass"] = StaticPool
engine = create_engine(_url, **_engine_options)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
_migration_lock = threading.Lock()


class Base(DeclarativeBase):
    pass


class RequestRecord(Base):
    __tablename__ = "request_records"
    __table_args__ = (Index("ix_request_timestamp_client", "timestamp", "client_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    client_id: Mapped[str | None] = mapped_column(String(128), index=True)
    status_code: Mapped[int] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(16))
    duration_ms: Mapped[int] = mapped_column(Integer)
    authenticated: Mapped[bool] = mapped_column(Boolean, default=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_timestamp_type", "timestamp", "event_type"),
        Index("ix_security_client_timestamp", "client_id", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    client_id: Mapped[str | None] = mapped_column(String(128), index=True)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    http_status: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    safe_metadata: Mapped[str] = mapped_column(Text, default="{}")


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    username: Mapped[str] = mapped_column(String(128), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AdminCredential(Base):
    __tablename__ = "admin_credentials"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    username: Mapped[str] = mapped_column(String(128))
    password_salt: Mapped[bytes] = mapped_column(LargeBinary(32))
    password_hash: Mapped[bytes] = mapped_column(LargeBinary(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_timestamp_action", "timestamp", "action"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[str] = mapped_column(Text, default="{}")


SAFE_EVENT_METADATA = {
    "path",
    "region",
    "lookup_level",
    "upstream_status",
    "upstream_source",
    "component",
    "error_type",
    "reason",
}
SEVERITY_BY_TYPE = {
    "INVALID_SIGNATURE": "critical",
    "REPLAY_DETECTED": "high",
    "RATE_LIMIT_EXCEEDED": "medium",
    "UNKNOWN_CLIENT": "high",
    "INVALID_NONCE": "medium",
    "CLIENT_POLICY_VIOLATION": "medium",
    "REDIS_FAILURE": "critical",
    "UPSTREAM_FAILURE": "high",
    "GEO_FENCE_MISMATCH": "medium",
}


def initialize_database() -> None:
    from alembic import command
    from alembic.config import Config
    from pathlib import Path

    with _migration_lock:
        base_dir = Path(__file__).resolve().parent
        migration_config = Config(str(base_dir / "alembic.ini"))
        migration_config.set_main_option("script_location", str(base_dir / "migrations"))
        migration_config.set_main_option("sqlalchemy.url", str(engine.url).replace("%", "%%"))
        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
        if "alembic_version" in existing_tables:
            with engine.connect() as connection:
                applied = connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
            if not applied and existing_tables.intersection(Base.metadata.tables):
                Base.metadata.create_all(engine)
                for table in Base.metadata.tables.values():
                    for index in table.indexes:
                        index.create(engine, checkfirst=True)
                command.stamp(migration_config, "head")
                return
        command.upgrade(migration_config, "head")


def initialize_admin_credentials() -> tuple[str, str] | None:
    if settings.admin_username and settings.admin_password:
        return None

    import hashlib
    import secrets
    from sqlalchemy.exc import IntegrityError

    username = "admin"
    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(32)
    password_hash = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=64)
    try:
        with SessionLocal() as db:
            if db.get(AdminCredential, "primary") is not None:
                return None
            db.add(AdminCredential(
                id="primary",
                username=username,
                password_salt=salt,
                password_hash=password_hash,
                created_at=_now(),
            ))
            db.commit()
    except IntegrityError:
        return None
    return username, password


def verify_stored_admin(username: str, password: str) -> bool:
    import hashlib
    import secrets

    with SessionLocal() as db:
        credential = db.get(AdminCredential, "primary")
        if credential is None or not secrets.compare_digest(
            username.encode(), credential.username.encode()
        ):
            return False
        candidate = hashlib.scrypt(
            password.encode(),
            salt=credential.password_salt,
            n=2**14,
            r=8,
            p=1,
            dklen=64,
        )
        return secrets.compare_digest(candidate, credential.password_hash)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def record_request(
    request_id: str,
    client_id: str | None,
    status_code: int,
    duration_ms: int,
    authenticated: bool,
) -> None:
    with SessionLocal() as db:
        db.add(RequestRecord(
            id=request_id,
            timestamp=_now(),
            client_id=client_id,
            status_code=status_code,
            outcome="success" if 200 <= status_code < 300 else "failed",
            duration_ms=duration_ms,
            authenticated=authenticated,
        ))
        db.commit()


def record_security_event(
    event_type: str,
    request_id: str | None = None,
    client_id: str | None = None,
    http_status: int | None = None,
    outcome: str | None = None,
    severity: str | None = None,
    **metadata: Any,
) -> None:
    safe_metadata = {
        key: value
        for key, value in metadata.items()
        if key in SAFE_EVENT_METADATA and isinstance(value, (str, int, float, bool))
    }
    with SessionLocal() as db:
        db.add(SecurityEvent(
            id=uuid.uuid4().hex,
            timestamp=_now(),
            event_type=event_type,
            client_id=client_id,
            request_id=request_id,
            http_status=http_status,
            outcome=outcome or ("blocked" if http_status and http_status >= 400 else "recorded"),
            severity=severity or SEVERITY_BY_TYPE.get(event_type, "info"),
            safe_metadata=json.dumps(safe_metadata, separators=(",", ":"), sort_keys=True),
        ))
        db.commit()


def record_audit(actor: str, action: str, details: dict[str, Any] | None = None) -> None:
    with SessionLocal() as db:
        db.add(AuditLog(
            id=uuid.uuid4().hex,
            timestamp=_now(),
            actor=actor,
            action=action,
            details=json.dumps(details or {}, separators=(",", ":"), sort_keys=True),
        ))
        db.commit()


def _json_details(value: str) -> dict[str, Any]:
    try:
        result = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return result if isinstance(result, dict) else {}


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def create_admin_session(username: str) -> tuple[str, str]:
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(seconds=settings.admin_session_ttl_seconds)
    with SessionLocal() as db:
        db.query(AdminSession).where(AdminSession.expires_at <= _now()).delete(synchronize_session=False)
        db.add(AdminSession(
            token_hash=hashlib.sha256(session_token.encode()).hexdigest(),
            csrf_hash=hashlib.sha256(csrf_token.encode()).hexdigest(),
            username=username,
            expires_at=expires_at,
        ))
        db.commit()
    return session_token, csrf_token


def get_admin_session(session_token: str | None) -> tuple[str, str] | None:
    if not session_token:
        return None
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    with SessionLocal() as db:
        session = db.get(AdminSession, token_hash)
        if session is None or _utc(session.expires_at) <= _now():
            return None
        return session.username, session.csrf_hash


def delete_admin_session(session_token: str | None) -> str | None:
    if not session_token:
        return None
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    with SessionLocal() as db:
        session = db.get(AdminSession, token_hash)
        if session is None:
            return None
        username = session.username
        db.delete(session)
        db.commit()
        return username


def check_csrf(csrf_hash: str, csrf_token: str | None, csrf_cookie: str | None) -> bool:
    if not csrf_token or not csrf_cookie or not secrets.compare_digest(csrf_token, csrf_cookie):
        return False
    supplied_hash = hashlib.sha256(csrf_token.encode()).hexdigest()
    return secrets.compare_digest(supplied_hash, csrf_hash)


def _range_start(hours: int | None) -> datetime | None:
    return _now() - timedelta(hours=hours) if hours is not None else None


def _apply_since(query, model, since: datetime | None):
    return query.where(model.timestamp >= since) if since else query


def overview(hours: int = 24) -> dict[str, Any]:
    since = _range_start(hours)
    with SessionLocal() as db:
        requests = _apply_since(select(RequestRecord), RequestRecord, since).subquery()
        events = _apply_since(select(SecurityEvent), SecurityEvent, since).subquery()
        total, successful, failed = db.execute(select(
            func.count(requests.c.id),
            func.sum(case((requests.c.outcome == "success", 1), else_=0)),
            func.sum(case((requests.c.outcome == "failed", 1), else_=0)),
        )).one()
        event_counts = {
            key: value or 0
            for key, value in db.execute(
                select(events.c.event_type, func.count()).group_by(events.c.event_type)
            ).all()
        }
        client_count = db.scalar(
            select(func.count(func.distinct(RequestRecord.client_id))).where(
                RequestRecord.authenticated.is_(True),
                *([RequestRecord.timestamp >= since] if since else []),
            )
        ) or 0
        return {
            "range_hours": hours,
            "total_requests": total or 0,
            "successful_requests": successful or 0,
            "failed_requests": failed or 0,
            "authenticated_clients": client_count,
            "blocked_requests": sum(event_counts.get(name, 0) for name in (
                "INVALID_SIGNATURE", "REPLAY_DETECTED", "RATE_LIMIT_EXCEEDED",
                "UNKNOWN_CLIENT", "INVALID_NONCE", "CLIENT_POLICY_VIOLATION", "REDIS_FAILURE",
            )),
            "replay_attacks": event_counts.get("REPLAY_DETECTED", 0),
            "suspicious_requests": sum(value for name, value in event_counts.items() if name in {
                "INVALID_SIGNATURE", "UNKNOWN_CLIENT", "INVALID_NONCE",
                "CLIENT_POLICY_VIOLATION", "GEO_FENCE_MISMATCH",
            }),
        }


def _time_bucket(ts: datetime, hours: int) -> str:
    if hours <= 1:
        minute = (ts.minute // 5) * 5
        return ts.replace(minute=minute, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:00Z")
    if hours <= 24:
        return ts.strftime("%Y-%m-%dT%H:00:00Z")
    return ts.strftime("%Y-%m-%dT00:00:00Z")


def analytics(hours: int = 24) -> dict[str, Any]:
    since = _range_start(hours)
    with SessionLocal() as db:
        rows = db.scalars(_apply_since(select(RequestRecord).order_by(RequestRecord.timestamp), RequestRecord, since)).all()
        buckets: dict[str, dict[str, int]] = {}
        for row in rows:
            key = _time_bucket(row.timestamp, hours)
            bucket = buckets.setdefault(key, {"total": 0, "successful": 0, "failed": 0})
            bucket["total"] += 1
            outcome_key = "successful" if row.outcome == "success" else "failed"
            bucket[outcome_key] += 1
        return {"range_hours": hours, "points": [{"timestamp": key, **value} for key, value in sorted(buckets.items())]}


def clients_activity() -> list[dict[str, Any]]:
    now = _now()
    with SessionLocal() as db:
        rows = db.execute(select(
            RequestRecord.client_id,
            func.count(RequestRecord.id),
            func.sum(case((RequestRecord.outcome == "success", 1), else_=0)),
            func.sum(case((RequestRecord.status_code.in_([401, 403, 409, 429, 503]), 1), else_=0)),
            func.max(RequestRecord.timestamp),
            func.sum(case((RequestRecord.authenticated.is_(True), 1), else_=0)),
            func.max(case((RequestRecord.authenticated.is_(True), RequestRecord.timestamp), else_=None)),
        ).where(RequestRecord.client_id.is_not(None)).group_by(RequestRecord.client_id)).all()
    by_id = {
        row[0]: {
            "client_id": row[0],
            "total_requests": row[1] or 0,
            "successful_requests": row[2] or 0,
            "blocked_requests": row[3] or 0,
            "last_activity": _iso(row[4]) if row[4] else None,
            "authenticated_requests": row[5] or 0,
            "authenticated_recently": bool(row[6] and _utc(row[6]) >= now - timedelta(hours=24)),
        }
        for row in rows
    }
    for client_id, policy in settings.client_policy.items():
        by_id.setdefault(client_id, {
            "client_id": client_id,
            "total_requests": 0,
            "successful_requests": 0,
            "blocked_requests": 0,
            "last_activity": None,
            "authenticated_requests": 0,
            "authenticated_recently": False,
        })
        by_id[client_id]["enabled"] = bool(policy)
    return [by_id[client_id] for client_id in settings.client_policy]


def list_events(
    page: int,
    page_size: int,
    event_type: str | None = None,
    client_id: str | None = None,
    severity: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    event_types: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    query = select(SecurityEvent)
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    if client_id:
        query = query.where(SecurityEvent.client_id == client_id)
    if severity:
        query = query.where(SecurityEvent.severity == severity)
    if since:
        query = query.where(SecurityEvent.timestamp >= since)
    if until:
        query = query.where(SecurityEvent.timestamp <= until)
    if event_types:
        query = query.where(SecurityEvent.event_type.in_(event_types))
    with SessionLocal() as db:
        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = db.scalars(query.order_by(SecurityEvent.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)).all()
        return {
            "items": [{
                "id": item.id,
                "timestamp": _iso(item.timestamp),
                "event_type": item.event_type,
                "client_id": item.client_id,
                "request_id": item.request_id,
                "http_status": item.http_status,
                "outcome": item.outcome,
                "severity": item.severity,
                "metadata": _json_details(item.safe_metadata),
            } for item in rows],
            "page": page,
            "page_size": page_size,
            "total": total,
        }


def list_audit_logs(page: int, page_size: int) -> dict[str, Any]:
    with SessionLocal() as db:
        total = db.scalar(select(func.count()).select_from(AuditLog)) or 0
        rows = db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)).all()
        return {
            "items": [{
                "id": row.id,
                "timestamp": _iso(row.timestamp),
                "actor": row.actor,
                "action": row.action,
                "details": _json_details(row.details),
            } for row in rows],
            "page": page,
            "page_size": page_size,
            "total": total,
        }
