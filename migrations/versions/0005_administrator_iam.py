import hashlib
import json
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = "0005_administrator_iam"
down_revision = "0004_validate_legacy_tenant_scopes"
branch_labels = None
depends_on = None


def _digest(record, sequence, previous_digest):
    timestamp = record["timestamp"]
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)
    payload = {
        "id": record["id"],
        "sequence": sequence,
        "previous_digest": previous_digest,
        "organization_id": record["organization_id"],
        "actor_admin_id": None,
        "request_id": None,
        "timestamp": timestamp.isoformat(),
        "actor": record["actor"],
        "action": record["action"],
        "details": record["details"],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "admin_accounts" not in tables:
        op.create_table(
            "admin_accounts",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("username", sa.String(128), nullable=False, unique=True),
            sa.Column("password_salt", sa.LargeBinary(32), nullable=False),
            sa.Column("password_hash", sa.LargeBinary(64), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("platform_super_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "organization_admin_memberships" not in tables:
        op.create_table(
            "organization_admin_memberships",
            sa.Column(
                "admin_id",
                sa.String(32),
                sa.ForeignKey("admin_accounts.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "organization_id",
                sa.String(32),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("role", sa.String(32), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "admin_iam_sessions" not in tables:
        op.create_table(
            "admin_iam_sessions",
            sa.Column("token_hash", sa.String(64), primary_key=True),
            sa.Column("csrf_hash", sa.String(64), nullable=False),
            sa.Column(
                "admin_id",
                sa.String(32),
                sa.ForeignKey("admin_accounts.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column(
                "organization_id",
                sa.String(32),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=True,
                index=True,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if "audit_logs" not in set(inspector.get_table_names()):
        raise RuntimeError("Cannot initialize the audit chain: audit_logs is missing.")
    audit_columns = {column["name"] for column in inspector.get_columns("audit_logs")}
    if "sequence" not in audit_columns:
        op.add_column("audit_logs", sa.Column("sequence", sa.Integer(), nullable=True))
    if "previous_digest" not in audit_columns:
        op.add_column("audit_logs", sa.Column("previous_digest", sa.String(64), nullable=True))
    if "digest" not in audit_columns:
        op.add_column("audit_logs", sa.Column("digest", sa.String(64), nullable=True))
    if "actor_admin_id" not in audit_columns:
        op.add_column("audit_logs", sa.Column("actor_admin_id", sa.String(32), nullable=True))
    if "request_id" not in audit_columns:
        op.add_column("audit_logs", sa.Column("request_id", sa.String(64), nullable=True))

    rows = bind.execute(
        sa.text(
            "SELECT id, organization_id, timestamp, actor, action, details, sequence, "
            "previous_digest, digest FROM audit_logs ORDER BY timestamp, id"
        )
    ).mappings().all()
    populated = [
        all(row[column] is not None for column in ("sequence", "previous_digest", "digest"))
        for row in rows
    ]
    has_chain_data = any(
        any(row[column] is not None for column in ("sequence", "previous_digest", "digest"))
        for row in rows
    )
    if has_chain_data and not all(populated):
        raise RuntimeError(
            "Audit-chain rows are only partially populated; verify and repair the chain before retrying."
        )

    previous_digest = "0" * 64
    for sequence, row in enumerate(rows, start=1):
        value = dict(row)
        if all(populated):
            expected_digest = _digest(value, sequence, previous_digest)
            if (
                value["sequence"] != sequence
                or value["previous_digest"] != previous_digest
                or value["digest"] != expected_digest
            ):
                raise RuntimeError(
                    "Existing audit-chain data failed verification; refusing to alter existing audit data."
                )
        else:
            value["sequence"] = sequence
            value["previous_digest"] = previous_digest
            value["digest"] = _digest(value, sequence, previous_digest)
            bind.execute(
                sa.text(
                    "UPDATE audit_logs SET sequence=:sequence, previous_digest=:previous_digest, "
                    "digest=:digest WHERE id=:id"
                ),
                value,
            )
        previous_digest = value["digest"]

    if "audit_chain_state" not in set(sa.inspect(bind).get_table_names()):
        op.create_table(
            "audit_chain_state",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("sequence", sa.Integer(), nullable=False),
            sa.Column("digest", sa.String(64), nullable=False),
        )
    state_rows = bind.execute(sa.text("SELECT id, sequence, digest FROM audit_chain_state")).mappings().all()
    if not state_rows:
        bind.execute(
            sa.text("INSERT INTO audit_chain_state (id, sequence, digest) VALUES (1, :sequence, :digest)"),
            {"sequence": len(rows), "digest": previous_digest},
        )
    elif len(state_rows) != 1 or state_rows[0]["id"] != 1:
        raise RuntimeError("Audit-chain state is invalid; refusing to alter existing audit data.")
    elif state_rows[0]["sequence"] != len(rows) or state_rows[0]["digest"] != previous_digest:
        raise RuntimeError("Audit-chain state does not match the audit log; refusing to alter existing data.")

    existing_indexes = {index["name"] for index in sa.inspect(bind).get_indexes("audit_logs")}
    if "uq_audit_logs_sequence" not in existing_indexes:
        op.create_index("uq_audit_logs_sequence", "audit_logs", ["sequence"], unique=True)


def downgrade():
    raise RuntimeError(
        "Downgrade is disabled because it would remove administrator identities or audit integrity data."
    )
