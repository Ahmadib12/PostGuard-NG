import json
import os
import re

from alembic import op
import sqlalchemy as sa

revision = "0004_validate_legacy_tenant_scopes"
down_revision = "0003_organization_scopes"
branch_labels = None
depends_on = None


ORGANIZATION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")


def _configured_organizations():
    organization_id = os.getenv("POSTGUARD_ORGANIZATION_ID", "default").strip()
    if not ORGANIZATION_ID_PATTERN.fullmatch(organization_id):
        raise RuntimeError("POSTGUARD_ORGANIZATION_ID must be valid before tenant-scope validation.")
    try:
        client_map = json.loads(os.getenv("POSTGUARD_CLIENT_ORGANIZATIONS", "{}"))
    except ValueError as exc:
        raise RuntimeError("POSTGUARD_CLIENT_ORGANIZATIONS must be valid JSON.") from exc
    if not isinstance(client_map, dict):
        raise RuntimeError("POSTGUARD_CLIENT_ORGANIZATIONS must be a JSON object.")
    legacy_unscoped_organization_id = os.getenv(
        "POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID", ""
    ).strip() or None
    if legacy_unscoped_organization_id and not ORGANIZATION_ID_PATTERN.fullmatch(
        legacy_unscoped_organization_id
    ):
        raise RuntimeError(
            "POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID must be valid before tenant-scope validation."
        )
    for client_id, mapped_organization_id in client_map.items():
        if (
            not isinstance(client_id, str)
            or not client_id
            or not isinstance(mapped_organization_id, str)
            or not ORGANIZATION_ID_PATTERN.fullmatch(mapped_organization_id)
        ):
            raise RuntimeError("POSTGUARD_CLIENT_ORGANIZATIONS contains an invalid mapping.")
    return organization_id, client_map, legacy_unscoped_organization_id


def upgrade():
    bind = op.get_bind()
    tenant_ids = set()
    organization_id, client_map, legacy_unscoped_organization_id = _configured_organizations()
    tenant_ids.add(organization_id)
    tenant_ids.update(client_map.values())
    if legacy_unscoped_organization_id:
        tenant_ids.add(legacy_unscoped_organization_id)
    multiple_organizations = len(tenant_ids) > 1
    single_organization_id = next(iter(tenant_ids)) if not multiple_organizations else None

    mismatches = []
    for table_name in ("request_records", "security_events"):
        rows = bind.execute(sa.text(
            f'SELECT id, client_id, organization_id FROM "{table_name}"'
        )).all()
        for row in rows:
            expected = client_map.get(row.client_id) if row.client_id is not None else None
            if expected is not None and row.organization_id != expected:
                mismatches.append(f"{table_name}:{row.id}")
            elif expected is None and multiple_organizations and (
                legacy_unscoped_organization_id is None
                or row.organization_id != legacy_unscoped_organization_id
            ):
                mismatches.append(f"{table_name}:{row.id}")
            elif not multiple_organizations and row.organization_id != single_organization_id:
                mismatches.append(f"{table_name}:{row.id}")

    for table_name in ("admin_sessions", "audit_logs"):
        if multiple_organizations and legacy_unscoped_organization_id is None:
            count = bind.execute(sa.text(f'SELECT COUNT(*) FROM "{table_name}"')).scalar_one()
            if count:
                mismatches.append(
                    f"{table_name} ({count} rows without historical client ownership)"
                )
            continue

        expected_organization_id = (
            legacy_unscoped_organization_id if multiple_organizations else single_organization_id
        )
        count = bind.execute(
            sa.text(
                f'SELECT COUNT(*) FROM "{table_name}" '
                "WHERE organization_id != :organization_id OR organization_id IS NULL"
            ),
            {"organization_id": expected_organization_id},
        ).scalar_one()
        if count:
            mismatches.append(
                f"{table_name} ({count} rows assigned outside the reviewed organization)"
            )

    if mismatches:
        sample = ", ".join(mismatches[:10])
        raise RuntimeError(
            "Tenant-scope validation found legacy records whose ownership cannot be proven from "
            "the configured client mapping. Startup is blocked to prevent cross-organization "
            f"exposure; no data was changed. Review and explicitly backfill these records: {sample}"
        )


def downgrade():
    pass
