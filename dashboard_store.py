import hashlib
import json
import logging
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String, Text, case, create_engine, func, inspect, select, text
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
_audit_lock = threading.Lock()


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="active")
    plan: Mapped[str] = mapped_column(String(32), default="development")
    limits_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: _now())


class RequestRecord(Base):
    __tablename__ = "request_records"
    __table_args__ = (
        Index("ix_request_timestamp_client", "timestamp", "client_id"),
        Index("ix_request_org_timestamp", "organization_id", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), default="default", index=True)
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
        Index("ix_security_org_timestamp", "organization_id", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), default="default", index=True)
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
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), default="default", index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AdminCredential(Base):
    __tablename__ = "admin_credentials"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    username: Mapped[str] = mapped_column(String(128))
    password_salt: Mapped[bytes] = mapped_column(LargeBinary(32))
    password_hash: Mapped[bytes] = mapped_column(LargeBinary(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AdminAccount(Base):
    __tablename__ = "admin_accounts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_salt: Mapped[bytes] = mapped_column(LargeBinary(32))
    password_hash: Mapped[bytes] = mapped_column(LargeBinary(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    platform_super_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OrganizationAdminMembership(Base):
    __tablename__ = "organization_admin_memberships"

    admin_id: Mapped[str] = mapped_column(
        ForeignKey("admin_accounts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AdminIAMSession(Base):
    __tablename__ = "admin_iam_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    admin_id: Mapped[str] = mapped_column(
        ForeignKey("admin_accounts.id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_timestamp_action", "timestamp", "action"),
        Index("ix_audit_org_timestamp", "organization_id", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), default="default", index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[str] = mapped_column(Text, default="{}")
    actor_admin_id: Mapped[str | None] = mapped_column(String(32))
    request_id: Mapped[str | None] = mapped_column(String(64))
    sequence: Mapped[int] = mapped_column(Integer)
    previous_digest: Mapped[str] = mapped_column(String(64))
    digest: Mapped[str] = mapped_column(String(64))


class AuditChainState(Base):
    __tablename__ = "audit_chain_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer)
    digest: Mapped[str] = mapped_column(String(64))


class SecurityIncident(Base):
    __tablename__ = "security_incidents"
    __table_args__ = (
        Index("ix_security_incidents_org_updated", "organization_id", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(64))
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
                legacy_tables = [
                    table for table in Base.metadata.sorted_tables
                    if table.name != "organizations"
                ]
                Base.metadata.create_all(engine, tables=legacy_tables)
                command.stamp(migration_config, "0002_generated_admin_credential")
        command.upgrade(migration_config, "head")


def initialize_organizations() -> None:
    organization_ids = {
        "default",
        settings.organization_id,
        *settings.client_organization_ids.values(),
    }
    with SessionLocal() as db:
        for organization_id in organization_ids:
            if db.get(Organization, organization_id) is None:
                db.add(Organization(
                    id=organization_id,
                    slug=organization_id,
                    name=organization_id,
                    status="active",
                    plan="development",
                    limits_json="{}",
                    created_at=_now(),
                ))
        db.commit()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def organization_for_client(client_id: str | None) -> str:
    if not client_id:
        return settings.organization_id
    return settings.client_organization_ids.get(client_id, settings.organization_id)


def record_request(
    request_id: str,
    client_id: str | None,
    status_code: int,
    duration_ms: int,
    authenticated: bool,
    organization_id: str | None = None,
) -> None:
    with SessionLocal() as db:
        db.add(RequestRecord(
            id=request_id,
            organization_id=organization_id or (
                organization_for_client(client_id) if authenticated else settings.organization_id
            ),
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
    organization_id: str | None = None,
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
            organization_id=organization_id or organization_for_client(client_id),
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


def record_audit(
    actor: str,
    action: str,
    details: dict[str, Any] | None = None,
    organization_id: str | None = None,
    actor_admin_id: str | None = None,
    request_id: str | None = None,
) -> None:
    details_json = json.dumps(details or {}, separators=(",", ":"), sort_keys=True)
    with _audit_lock, SessionLocal() as db:
        state = db.scalar(select(AuditChainState).where(AuditChainState.id == 1).with_for_update())
        if state is None:
            raise RuntimeError("Audit-chain state is unavailable.")
        sequence = state.sequence + 1
        previous_digest = state.digest
        timestamp = _now()
        entry_id = uuid.uuid4().hex
        digest = _audit_digest(
            entry_id,
            sequence,
            previous_digest,
            organization_id or settings.organization_id,
            actor_admin_id,
            request_id,
            timestamp,
            actor,
            action,
            details_json,
        )
        db.add(AuditLog(
            id=entry_id,
            organization_id=organization_id or settings.organization_id,
            timestamp=timestamp,
            actor=actor,
            action=action,
            details=details_json,
            actor_admin_id=actor_admin_id,
            request_id=request_id,
            sequence=sequence,
            previous_digest=previous_digest,
            digest=digest,
        ))
        state.sequence = sequence
        state.digest = digest
        db.commit()


def _audit_digest(
    entry_id: str,
    sequence: int,
    previous_digest: str,
    organization_id: str,
    actor_admin_id: str | None,
    request_id: str | None,
    timestamp: datetime,
    actor: str,
    action: str,
    details: str,
) -> str:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)
    payload = {
        "id": entry_id,
        "sequence": sequence,
        "previous_digest": previous_digest,
        "organization_id": organization_id,
        "actor_admin_id": actor_admin_id,
        "request_id": request_id,
        "timestamp": timestamp.isoformat(),
        "actor": actor,
        "action": action,
        "details": details,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def verify_audit_chain() -> bool:
    with SessionLocal() as db:
        records = db.scalars(select(AuditLog).order_by(AuditLog.sequence)).all()
        previous_digest = "0" * 64
        for expected_sequence, record in enumerate(records, start=1):
            if record.sequence != expected_sequence or record.previous_digest != previous_digest:
                return False
            timestamp = record.timestamp
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            expected_digest = _audit_digest(
                record.id,
                record.sequence,
                record.previous_digest,
                record.organization_id,
                record.actor_admin_id,
                record.request_id,
                timestamp,
                record.actor,
                record.action,
                record.details,
            )
            if not secrets.compare_digest(record.digest, expected_digest):
                return False
            previous_digest = record.digest
        state = db.get(AuditChainState, 1)
        return bool(
            state
            and state.sequence == len(records)
            and secrets.compare_digest(state.digest, previous_digest)
        )


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


def check_csrf(csrf_hash: str, csrf_token: str | None, csrf_cookie: str | None) -> bool:
    if not csrf_token or not csrf_cookie or not secrets.compare_digest(csrf_token, csrf_cookie):
        return False
    supplied_hash = hashlib.sha256(csrf_token.encode()).hexdigest()
    return secrets.compare_digest(supplied_hash, csrf_hash)


def _range_start(hours: int | None) -> datetime | None:
    return _now() - timedelta(hours=hours) if hours is not None else None


def _apply_since(query, model, since: datetime | None):
    return query.where(model.timestamp >= since) if since else query


def overview(hours: int = 24, organization_id: str | None = None) -> dict[str, Any]:
    organization_id = organization_id or settings.organization_id
    since = _range_start(hours)
    with SessionLocal() as db:
        requests_query = select(RequestRecord).where(RequestRecord.organization_id == organization_id)
        events_query = select(SecurityEvent).where(SecurityEvent.organization_id == organization_id)
        requests = _apply_since(requests_query, RequestRecord, since).subquery()
        events = _apply_since(events_query, SecurityEvent, since).subquery()
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
                RequestRecord.organization_id == organization_id,
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


def analytics(hours: int = 24, organization_id: str | None = None) -> dict[str, Any]:
    organization_id = organization_id or settings.organization_id
    since = _range_start(hours)
    with SessionLocal() as db:
        query = select(RequestRecord).where(RequestRecord.organization_id == organization_id)
        rows = db.scalars(_apply_since(query.order_by(RequestRecord.timestamp), RequestRecord, since)).all()
        buckets: dict[str, dict[str, int]] = {}
        for row in rows:
            key = _time_bucket(row.timestamp, hours)
            bucket = buckets.setdefault(key, {"total": 0, "successful": 0, "failed": 0})
            bucket["total"] += 1
            outcome_key = "successful" if row.outcome == "success" else "failed"
            bucket[outcome_key] += 1
        return {"range_hours": hours, "points": [{"timestamp": key, **value} for key, value in sorted(buckets.items())]}


def clients_activity(organization_id: str | None = None) -> list[dict[str, Any]]:
    organization_id = organization_id or settings.organization_id
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
        ).where(
            RequestRecord.client_id.is_not(None),
            RequestRecord.organization_id == organization_id,
        ).group_by(RequestRecord.client_id)).all()
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
        if organization_for_client(client_id) != organization_id:
            continue
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
    return [
        by_id[client_id]
        for client_id in settings.client_policy
        if organization_for_client(client_id) == organization_id
    ]


def list_events(
    page: int,
    page_size: int,
    event_type: str | None = None,
    client_id: str | None = None,
    severity: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    event_types: tuple[str, ...] | None = None,
    organization_id: str | None = None,
) -> dict[str, Any]:
    query = select(SecurityEvent).where(
        SecurityEvent.organization_id == (organization_id or settings.organization_id)
    )
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


def list_audit_logs(page: int, page_size: int, organization_id: str | None = None) -> dict[str, Any]:
    organization_id = organization_id or settings.organization_id
    with SessionLocal() as db:
        query = select(AuditLog).where(AuditLog.organization_id == organization_id)
        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = db.scalars(query.order_by(AuditLog.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)).all()
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
