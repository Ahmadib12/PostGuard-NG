import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from config import settings
from dashboard_store import (
    AdminAccount,
    AdminIAMSession,
    Organization,
    OrganizationAdminMembership,
    SessionLocal,
)


ROLE_PERMISSIONS = {
    "organization_owner": frozenset({
        "dashboard.read", "health.read", "events.read", "audit.read", "users.read",
        "users.manage", "incidents.read", "analyst.investigate", "actions.approve",
        "profile.password.change",
    }),
    "organization_admin": frozenset({
        "dashboard.read", "health.read", "events.read", "audit.read", "users.read",
        "users.manage", "incidents.read", "analyst.investigate", "profile.password.change",
    }),
    "security_auditor": frozenset({
        "dashboard.read", "health.read", "events.read", "audit.read",
        "incidents.read", "analyst.investigate", "profile.password.change",
    }),
    "read_only_operator": frozenset({
        "dashboard.read", "health.read", "events.read", "incidents.read",
        "profile.password.change",
    }),
}
PLATFORM_PERMISSIONS = frozenset({
    "dashboard.read", "health.read", "events.read", "audit.read", "users.read",
    "users.manage", "incidents.read", "analyst.investigate", "actions.approve",
    "organizations.manage", "system.admin", "profile.password.change",
})
ASSIGNABLE_ROLES = frozenset(ROLE_PERMISSIONS)
_DUMMY_SALT = b"PostGuard-IAM-dummy-salt-32bytes"
_DUMMY_HASH = hashlib.scrypt(
    b"not-a-real-password",
    salt=_DUMMY_SALT,
    n=2**14,
    r=8,
    p=1,
    dklen=64,
)


@dataclass(frozen=True)
class AdminPrincipal:
    admin_id: str
    username: str
    organization_id: str
    role: str
    permissions: frozenset[str]
    platform_super_admin: bool
    must_change_password: bool
    csrf_hash: str = ""


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)


def _validate_username_password(username: str, password: str) -> None:
    if not username or len(username) > 128 or any(ord(char) < 33 for char in username):
        raise HTTPException(status_code=422, detail="Invalid administrator username.")
    if len(password) < 16 or len(password) > 1024:
        raise HTTPException(status_code=422, detail="Administrator passwords must be 16 to 1024 characters.")


def bootstrap_platform_admin(username: str, password: str) -> tuple[str, str] | None:
    _validate_username_password(username, password)
    now = datetime.now(timezone.utc)
    salt = secrets.token_bytes(32)
    account = AdminAccount(
        id=uuid.uuid4().hex,
        username=username,
        password_salt=salt,
        password_hash=_password_hash(password, salt),
        active=True,
        platform_super_admin=True,
        must_change_password=False,
        created_at=now,
        updated_at=now,
    )
    try:
        with SessionLocal() as db:
            if db.scalar(select(AdminAccount.id).limit(1)) is not None:
                return None
            db.add(account)
            db.commit()
    except IntegrityError:
        return None
    return account.id, account.username


def create_generated_platform_admin() -> tuple[str, str, str] | None:
    username = "platform-admin"
    password = secrets.token_urlsafe(32)
    created = bootstrap_platform_admin(username, password)
    return (created[0], username, password) if created else None


def discard_bootstrap_admin(admin_id: str, password: str) -> bool:
    with SessionLocal() as db:
        account = db.get(AdminAccount, admin_id)
        if account is None or not account.platform_super_admin:
            return False
        if not secrets.compare_digest(_password_hash(password, account.password_salt), account.password_hash):
            return False
        db.delete(account)
        db.commit()
        return True


def create_admin_session(
    username: str,
    password: str,
    requested_organization_id: str | None,
) -> tuple[str, str, AdminPrincipal] | None:
    with SessionLocal() as db:
        account = db.scalar(select(AdminAccount).where(AdminAccount.username == username))
        if account is None:
            _password_hash(password, _DUMMY_SALT)
            return None
        password_matches = secrets.compare_digest(
            _password_hash(password, account.password_salt),
            account.password_hash,
        )
        if not account.active or not password_matches:
            return None

        memberships = db.scalars(
            select(OrganizationAdminMembership).where(
                OrganizationAdminMembership.admin_id == account.id
            )
        ).all()
        if account.platform_super_admin:
            organization_id = requested_organization_id or settings.organization_id
            organization = db.get(Organization, organization_id)
            if organization is None:
                return None
            role = "platform_super_admin"
            permissions = PLATFORM_PERMISSIONS
        else:
            membership = next(
                (
                    item for item in memberships
                    if item.organization_id == requested_organization_id
                ),
                None,
            ) if requested_organization_id else (memberships[0] if len(memberships) == 1 else None)
            if membership is None:
                return None
            organization_id = membership.organization_id
            organization = db.get(Organization, organization_id)
            if organization is None or organization.status != "active":
                return None
            role = membership.role
            permissions = ROLE_PERMISSIONS.get(role, frozenset())
        if not account.platform_super_admin and len(memberships) > 1 and not requested_organization_id:
            return None

        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        db.add(AdminIAMSession(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            csrf_hash=hashlib.sha256(csrf.encode()).hexdigest(),
            admin_id=account.id,
            organization_id=organization_id,
            expires_at=now + timedelta(seconds=settings.admin_session_ttl_seconds),
            revoked_at=None,
            created_at=now,
        ))
        db.commit()
        principal = AdminPrincipal(
            admin_id=account.id,
            username=account.username,
            organization_id=organization_id,
            role=role,
            permissions=permissions,
            platform_super_admin=account.platform_super_admin,
            must_change_password=account.must_change_password,
            csrf_hash=hashlib.sha256(csrf.encode()).hexdigest(),
        )
        return token, csrf, principal


def get_admin_principal(session_token: str | None) -> tuple[AdminPrincipal, str] | None:
    if not session_token:
        return None
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    with SessionLocal() as db:
        session = db.get(AdminIAMSession, token_hash)
        if session is None or session.revoked_at is not None:
            return None
        now = datetime.now(timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            return None
        account = db.get(AdminAccount, session.admin_id)
        organization = db.get(Organization, session.organization_id)
        if account is None or not account.active or organization is None:
            return None
        if account.platform_super_admin:
            role = "platform_super_admin"
            permissions = PLATFORM_PERMISSIONS
        else:
            membership = db.get(
                OrganizationAdminMembership,
                (account.id, session.organization_id),
            )
            if membership is None:
                return None
            role = membership.role
            permissions = ROLE_PERMISSIONS.get(role, frozenset())
        return (
            AdminPrincipal(
                admin_id=account.id,
                username=account.username,
                organization_id=session.organization_id,
                role=role,
                permissions=permissions,
                platform_super_admin=account.platform_super_admin,
                must_change_password=account.must_change_password,
                csrf_hash=session.csrf_hash,
            ),
            session.csrf_hash,
        )


def organization_is_active(organization_id: str) -> bool:
    with SessionLocal() as db:
        organization = db.get(Organization, organization_id)
        if organization is None:
            raise RuntimeError("The administrator organization is missing.")
        return organization.status == "active"


def create_organization_admin(
    organization_id: str,
    username: str,
    role: str,
    allow_owner: bool = False,
) -> tuple[AdminAccount, str]:
    if role not in ASSIGNABLE_ROLES:
        raise HTTPException(status_code=422, detail="Invalid organization role.")
    if role == "organization_owner" and not allow_owner:
        raise HTTPException(status_code=403, detail="Only a platform administrator may assign the owner role.")
    if not username or len(username) > 128:
        raise HTTPException(status_code=422, detail="Invalid administrator username.")
    temporary_password = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(32)
    now = datetime.now(timezone.utc)
    account = AdminAccount(
        id=uuid.uuid4().hex,
        username=username,
        password_salt=salt,
        password_hash=_password_hash(temporary_password, salt),
        active=True,
        platform_super_admin=False,
        must_change_password=True,
        created_at=now,
        updated_at=now,
    )
    with SessionLocal() as db:
        if db.get(Organization, organization_id) is None:
            raise HTTPException(status_code=404, detail="Organization not found.")
        db.add(account)
        db.add(OrganizationAdminMembership(
            admin_id=account.id,
            organization_id=organization_id,
            role=role,
            created_at=now,
        ))
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="Administrator username already exists.") from exc
    return account, temporary_password


def update_organization_admin(
    organization_id: str,
    admin_id: str,
    role: str | None,
    active: bool | None,
    allow_owner: bool = False,
) -> None:
    if role is not None and role not in ASSIGNABLE_ROLES:
        raise HTTPException(status_code=422, detail="Invalid organization role.")
    if role == "organization_owner" and not allow_owner:
        raise HTTPException(status_code=403, detail="Only a platform administrator may assign the owner role.")
    with SessionLocal() as db:
        account = db.get(AdminAccount, admin_id)
        membership = db.get(OrganizationAdminMembership, (admin_id, organization_id))
        if account is None or membership is None or account.platform_super_admin:
            raise HTTPException(status_code=404, detail="Organization administrator not found.")
        affected_organizations = []
        if account.active and active is False:
            affected_organizations.extend(
                item.organization_id
                for item in db.scalars(
                    select(OrganizationAdminMembership).where(
                        OrganizationAdminMembership.admin_id == admin_id,
                        OrganizationAdminMembership.role == "organization_owner",
                    )
                ).all()
            )
        if (
            account.active
            and membership.role == "organization_owner"
            and role is not None
            and role != "organization_owner"
        ):
            affected_organizations.append(organization_id)
        if affected_organizations:
            db.scalars(
                select(Organization)
                .where(Organization.id.in_(set(affected_organizations)))
                .order_by(Organization.id)
                .with_for_update()
            ).all()
        for affected_organization_id in set(affected_organizations):
            owner_count = db.scalar(
                select(func.count(AdminAccount.id))
                .join(
                    OrganizationAdminMembership,
                    OrganizationAdminMembership.admin_id == AdminAccount.id,
                )
                .where(
                    OrganizationAdminMembership.organization_id == affected_organization_id,
                    OrganizationAdminMembership.role == "organization_owner",
                    AdminAccount.active.is_(True),
                )
            ) or 0
            if owner_count <= 1:
                raise HTTPException(
                    status_code=409,
                    detail="The last active organization owner cannot be removed or deactivated.",
                )
        if role is not None:
            membership.role = role
        if active is not None:
            account.active = active
            account.updated_at = datetime.now(timezone.utc)
            if not active:
                db.query(AdminIAMSession).filter(
                    AdminIAMSession.admin_id == admin_id
                ).update({AdminIAMSession.revoked_at: datetime.now(timezone.utc)})
        db.commit()


def revoke_admin_sessions(admin_id: str, organization_id: str | None = None) -> int:
    with SessionLocal() as db:
        query = db.query(AdminIAMSession).filter(AdminIAMSession.admin_id == admin_id)
        if organization_id is not None:
            query = query.filter(AdminIAMSession.organization_id == organization_id)
        count = query.filter(AdminIAMSession.revoked_at.is_(None)).update(
            {AdminIAMSession.revoked_at: datetime.now(timezone.utc)}
        )
        db.commit()
        return count


def set_organization_status(organization_id: str, status_value: str) -> None:
    if status_value not in {"active", "suspended"}:
        raise HTTPException(status_code=422, detail="Invalid organization status.")
    with SessionLocal() as db:
        organization = db.get(Organization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="Organization not found.")
        organization.status = status_value
        db.commit()


def reset_admin_password(organization_id: str, admin_id: str) -> str:
    temporary_password = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(32)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        membership = db.get(OrganizationAdminMembership, (admin_id, organization_id))
        account = db.get(AdminAccount, admin_id)
        if account is None or membership is None or account.platform_super_admin:
            raise HTTPException(status_code=404, detail="Organization administrator not found.")
        account.password_salt = salt
        account.password_hash = _password_hash(temporary_password, salt)
        account.must_change_password = True
        account.updated_at = now
        db.query(AdminIAMSession).filter(AdminIAMSession.admin_id == admin_id).update(
            {AdminIAMSession.revoked_at: now}
        )
        db.commit()
    return temporary_password


def create_organization(organization_id: str, name: str) -> None:
    if not organization_id or len(organization_id) > 32:
        raise HTTPException(status_code=422, detail="Invalid organization ID.")
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(Organization(
            id=organization_id,
            slug=organization_id,
            name=name,
            status="active",
            plan="standard",
            limits_json="{}",
            created_at=now,
        ))
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="Organization ID or slug already exists.") from exc


def change_admin_password(admin_id: str, old_password: str, new_password: str) -> None:
    _validate_username_password("password-change", new_password)
    with SessionLocal() as db:
        account = db.get(AdminAccount, admin_id)
        if account is None or not account.active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Administrator is unavailable.")
        if not secrets.compare_digest(_password_hash(old_password, account.password_salt), account.password_hash):
            raise HTTPException(status_code=403, detail="Current password is incorrect.")
        salt = secrets.token_bytes(32)
        account.password_salt = salt
        account.password_hash = _password_hash(new_password, salt)
        account.must_change_password = False
        account.updated_at = datetime.now(timezone.utc)
        db.query(AdminIAMSession).filter(AdminIAMSession.admin_id == admin_id).update(
            {AdminIAMSession.revoked_at: datetime.now(timezone.utc)}
        )
        db.commit()


def revoke_admin_session(session_token: str | None) -> None:
    if not session_token:
        return
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    with SessionLocal() as db:
        session = db.get(AdminIAMSession, token_hash)
        if session and session.revoked_at is None:
            session.revoked_at = datetime.now(timezone.utc)
            db.commit()
