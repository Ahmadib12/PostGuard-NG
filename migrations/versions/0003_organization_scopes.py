import json
import os
import re
from collections import Counter
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0003_organization_scopes"
down_revision = "0002_generated_admin_credential"
branch_labels = None
depends_on = None


TENANT_TABLES = {
    "request_records": ("id", "client_id"),
    "security_events": ("id", "client_id"),
    "admin_sessions": ("token_hash", None),
    "audit_logs": ("id", None),
}
ORGANIZATION_COLUMNS = {
    "id",
    "slug",
    "name",
    "status",
    "plan",
    "limits_json",
    "created_at",
}
ORGANIZATION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")


def _client_organizations() -> dict[str, str]:
    raw = os.getenv("POSTGUARD_CLIENT_ORGANIZATIONS", "{}")

    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate client ID {key!r}")
            result[key] = value
        return result

    try:
        mapping = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("POSTGUARD_CLIENT_ORGANIZATIONS must be a JSON object with unique client IDs.") from exc
    if not isinstance(mapping, dict):
        raise RuntimeError("POSTGUARD_CLIENT_ORGANIZATIONS must be a JSON object.")
    for client_id, organization_id in mapping.items():
        if (
            not isinstance(client_id, str)
            or not client_id
            or len(client_id) > 128
            or not isinstance(organization_id, str)
            or not ORGANIZATION_ID_PATTERN.fullmatch(organization_id)
        ):
            raise RuntimeError("POSTGUARD_CLIENT_ORGANIZATIONS contains an invalid client or organization ID.")
    return mapping


def _organization_id() -> str:
    organization_id = os.getenv("POSTGUARD_ORGANIZATION_ID", "default").strip()
    if not ORGANIZATION_ID_PATTERN.fullmatch(organization_id):
        raise RuntimeError("POSTGUARD_ORGANIZATION_ID must be a valid organization ID before migrating.")
    return organization_id


def _legacy_unscoped_organization_id() -> str | None:
    organization_id = os.getenv("POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID", "").strip()
    if not organization_id:
        return None
    if not ORGANIZATION_ID_PATTERN.fullmatch(organization_id):
        raise RuntimeError(
            "POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID must be a valid organization ID."
        )
    return organization_id


def _validate_existing_organizations(bind, inspector, organization_ids):
    if "organizations" not in inspector.get_table_names():
        return {}

    columns = {column["name"] for column in inspector.get_columns("organizations")}
    if not ORGANIZATION_COLUMNS.issubset(columns):
        missing = sorted(ORGANIZATION_COLUMNS - columns)
        raise RuntimeError(
            "Existing organizations table is incomplete; migration stopped without changes "
            f"(missing columns: {', '.join(missing)})."
        )

    rows = bind.execute(sa.text(
        "SELECT id, slug FROM organizations ORDER BY id"
    )).all()
    slugs = [row.slug for row in rows]
    duplicates = sorted(slug for slug, count in Counter(slugs).items() if count > 1)
    if duplicates:
        raise RuntimeError(
            "Existing organizations contain duplicate slugs; resolve them before migrating: "
            + ", ".join(repr(slug) for slug in duplicates)
        )

    existing = {}
    for row in rows:
        if not isinstance(row.id, str) or not ORGANIZATION_ID_PATTERN.fullmatch(row.id):
            raise RuntimeError("Existing organizations contain an invalid ID; migration stopped without changes.")
        if not isinstance(row.slug, str) or not row.slug or len(row.slug) > 64:
            raise RuntimeError("Existing organizations contain an invalid slug; migration stopped without changes.")
        existing[row.id] = row.slug

    missing_slugs = {
        organization_id: organization_id
        for organization_id in organization_ids
        if organization_id not in existing
    }
    slug_owners = {slug: organization_id for organization_id, slug in existing.items()}
    conflicts = [
        organization_id
        for organization_id, slug in missing_slugs.items()
        if slug in slug_owners and slug_owners[slug] != organization_id
    ]
    if conflicts:
        raise RuntimeError(
            "A configured organization ID conflicts with an existing organization slug; "
            "resolve the naming conflict before migrating."
        )
    return existing


def _row_plan(
    bind,
    inspector,
    table_name,
    primary_key,
    client_column,
    organization_ids,
    client_map,
    legacy_unscoped_organization_id,
    existing_orgs,
):
    columns = {column["name"] for column in inspector.get_columns(table_name)}
    has_organization_id = "organization_id" in columns
    selected_columns = [primary_key]
    if client_column:
        selected_columns.append(client_column)
    if has_organization_id:
        selected_columns.append("organization_id")
    projection = ", ".join(f'"{column}"' for column in selected_columns)
    rows = bind.execute(sa.text(f'SELECT {projection} FROM "{table_name}"')).all()
    assignments = {}
    discovered_ids = set()

    known_organization_ids = set(organization_ids) | set(existing_orgs)
    if has_organization_id:
        known_organization_ids.update(
            row.organization_id for row in rows if row.organization_id is not None
        )

    for row in rows:
        current_organization_id = getattr(row, "organization_id", None)
        if current_organization_id is not None:
            if not isinstance(current_organization_id, str) or not ORGANIZATION_ID_PATTERN.fullmatch(
                current_organization_id
            ):
                raise RuntimeError(
                    f"{table_name} contains an invalid organization ID; migration stopped without changes."
                )
            if existing_orgs and current_organization_id not in existing_orgs:
                raise RuntimeError(
                    f"{table_name} references missing organization {current_organization_id!r}; "
                    "repair the reference before migrating."
                )
            discovered_ids.add(current_organization_id)
            continue

        client_id = getattr(row, client_column, None) if client_column else None
        if client_id in client_map:
            organization_id = client_map[client_id]
        elif len(known_organization_ids) == 1:
            organization_id = next(iter(known_organization_ids))
        elif legacy_unscoped_organization_id:
            organization_id = legacy_unscoped_organization_id
        else:
            raise RuntimeError(
                f"Cannot determine organization ownership for a legacy row in {table_name}; "
                "migration stopped before changing data. Set an unambiguous organization/client mapping "
                "or resolve the row ownership before retrying."
            )
        assignments[getattr(row, primary_key)] = organization_id
        discovered_ids.add(organization_id)

    return has_organization_id, assignments, discovered_ids


def _ensure_index(inspector, name, table_name, columns, unique=False):
    indexes = {index["name"]: index for index in inspector.get_indexes(table_name)}
    if name in indexes:
        index = indexes[name]
        if index["column_names"] != columns or bool(index["unique"]) != unique:
            raise RuntimeError(
                f"Existing index {name} has an unexpected definition; migration stopped without changes."
            )
        return
    if unique and any(
        index["column_names"] == columns and index["unique"]
        for index in indexes.values()
    ):
        return
    op.create_index(name, table_name, columns, unique=unique)


def _validate_index(inspector, name, table_name, columns, unique=False):
    indexes = {index["name"]: index for index in inspector.get_indexes(table_name)}
    if name in indexes:
        index = indexes[name]
        if index["column_names"] != columns or bool(index["unique"]) != unique:
            raise RuntimeError(
                f"Existing index {name} has an unexpected definition; migration stopped without changes."
            )
        return
    if unique and any(
        index["column_names"] == columns and index["unique"]
        for index in indexes.values()
    ):
        return


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    available_tables = set(inspector.get_table_names())
    missing_tables = sorted(set(TENANT_TABLES) - available_tables)
    if missing_tables:
        raise RuntimeError(
            "Cannot add organization scopes because required legacy tables are missing: "
            + ", ".join(missing_tables)
        )

    configured_organization_id = _organization_id()
    legacy_unscoped_organization_id = _legacy_unscoped_organization_id()
    client_map = _client_organizations()
    configured_ids = {configured_organization_id, *client_map.values()}
    if legacy_unscoped_organization_id:
        configured_ids.add(legacy_unscoped_organization_id)
    existing_orgs = _validate_existing_organizations(bind, inspector, configured_ids)
    if "organizations" in available_tables:
        _validate_index(inspector, "ix_organizations_slug", "organizations", ["slug"], unique=True)

    table_plans = {}
    discovered_ids = set()
    for table_name, (primary_key, client_column) in TENANT_TABLES.items():
        existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
        if "organization_id" in existing_columns:
            _validate_index(
                inspector,
                f"ix_{table_name}_organization_id",
                table_name,
                ["organization_id"],
            )
            if table_name in {"request_records", "security_events", "audit_logs"}:
                _validate_index(
                    inspector,
                    {
                        "request_records": "ix_request_org_timestamp",
                        "security_events": "ix_security_org_timestamp",
                        "audit_logs": "ix_audit_org_timestamp",
                    }[table_name],
                    table_name,
                    ["organization_id", "timestamp"],
                )
        has_org_column, assignments, table_org_ids = _row_plan(
            bind,
            inspector,
            table_name,
            primary_key,
            client_column,
            configured_ids,
            client_map,
            legacy_unscoped_organization_id,
            existing_orgs,
        )
        if has_org_column:
            for foreign_key in inspector.get_foreign_keys(table_name):
                if "organization_id" in foreign_key["constrained_columns"] and (
                    foreign_key["referred_table"] != "organizations"
                    or foreign_key["referred_columns"] != ["id"]
                ):
                    raise RuntimeError(
                        f"{table_name} has an unexpected organization foreign key; "
                        "migration stopped without changes."
                    )
        table_plans[table_name] = (has_org_column, assignments)
        discovered_ids.update(table_org_ids)

    # Existing scopes are authoritative; create metadata only for explicit IDs.
    organization_ids = configured_ids | discovered_ids
    if existing_orgs:
        for organization_id in discovered_ids:
            if organization_id not in existing_orgs and organization_id not in configured_ids:
                raise RuntimeError(
                    f"Tenant data references missing organization {organization_id!r}; "
                    "migration stopped without changing data."
                )

    if "organizations" not in available_tables:
        op.create_table(
            "organizations",
            sa.Column("id", sa.String(length=32), primary_key=True),
            sa.Column("slug", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("plan", sa.String(length=32), nullable=False),
            sa.Column("limits_json", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    now = datetime.now(timezone.utc)
    organization_table = sa.table(
        "organizations",
        sa.column("id", sa.String(length=32)),
        sa.column("slug", sa.String(length=64)),
        sa.column("name", sa.String(length=128)),
        sa.column("status", sa.String(length=16)),
        sa.column("plan", sa.String(length=32)),
        sa.column("limits_json", sa.Text()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    if existing_orgs:
        new_organization_ids = configured_ids - set(existing_orgs)
    else:
        new_organization_ids = organization_ids
    if new_organization_ids:
        op.bulk_insert(organization_table, [
            {
                "id": organization_id,
                "slug": organization_id,
                "name": organization_id,
                "status": "active",
                "plan": "development",
                "limits_json": "{}",
                "created_at": now,
            }
            for organization_id in sorted(new_organization_ids)
        ])

    inspector = sa.inspect(bind)
    _ensure_index(inspector, "ix_organizations_slug", "organizations", ["slug"], unique=True)

    for table_name, (primary_key, _) in TENANT_TABLES.items():
        has_org_column, assignments = table_plans[table_name]
        if not has_org_column:
            op.add_column(
                table_name,
                sa.Column("organization_id", sa.String(length=32), nullable=True),
            )
        for row_id, organization_id in assignments.items():
            bind.execute(
                sa.text(
                    f'UPDATE "{table_name}" SET organization_id = :organization_id '
                    f'WHERE "{primary_key}" = :row_id AND organization_id IS NULL'
                ),
                {"organization_id": organization_id, "row_id": row_id},
            )

        inspector = sa.inspect(bind)
        column = next(
            column for column in inspector.get_columns(table_name)
            if column["name"] == "organization_id"
        )
        foreign_keys = inspector.get_foreign_keys(table_name)
        has_organization_fk = any(
            foreign_key["constrained_columns"] == ["organization_id"]
            and foreign_key["referred_table"] == "organizations"
            and foreign_key["referred_columns"] == ["id"]
            for foreign_key in foreign_keys
        )
        if column["nullable"] or not has_organization_fk:
            with op.batch_alter_table(table_name) as batch:
                if column["nullable"]:
                    batch.alter_column(
                        "organization_id",
                        existing_type=sa.String(length=32),
                        nullable=False,
                    )
                if not has_organization_fk:
                    batch.create_foreign_key(
                        f"fk_{table_name}_organization_id",
                        "organizations",
                        ["organization_id"],
                        ["id"],
                    )

        inspector = sa.inspect(bind)
        _ensure_index(
            inspector,
            f"ix_{table_name}_organization_id",
            table_name,
            ["organization_id"],
        )

    for name, table_name, columns in (
        ("ix_request_org_timestamp", "request_records", ["organization_id", "timestamp"]),
        ("ix_security_org_timestamp", "security_events", ["organization_id", "timestamp"]),
        ("ix_audit_org_timestamp", "audit_logs", ["organization_id", "timestamp"]),
    ):
        _ensure_index(sa.inspect(bind), name, table_name, columns)


def downgrade():
    raise RuntimeError(
        "Downgrade is intentionally disabled: removing organization scopes would erase "
        "tenant ownership from existing rows. Restore a pre-migration backup instead."
    )
