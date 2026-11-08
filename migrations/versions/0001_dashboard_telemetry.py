from alembic import op
import sqlalchemy as sa

revision = "0001_dashboard_telemetry"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "request_records",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("client_id", sa.String(length=128)),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("authenticated", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_request_records_timestamp", "request_records", ["timestamp"])
    op.create_index("ix_request_records_client_id", "request_records", ["client_id"])
    op.create_index("ix_request_timestamp_client", "request_records", ["timestamp", "client_id"])

    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=128)),
        sa.Column("request_id", sa.String(length=64)),
        sa.Column("http_status", sa.Integer()),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("safe_metadata", sa.Text(), nullable=False),
    )
    for name in ("timestamp", "event_type", "client_id", "request_id", "severity"):
        op.create_index(f"ix_security_events_{name}", "security_events", [name])
    op.create_index("ix_security_timestamp_type", "security_events", ["timestamp", "event_type"])
    op.create_index("ix_security_client_timestamp", "security_events", ["client_id", "timestamp"])

    op.create_table(
        "admin_sessions",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column("csrf_hash", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_admin_sessions_username", "admin_sessions", ["username"])
    op.create_index("ix_admin_sessions_expires_at", "admin_sessions", ["expires_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_actor", "audit_logs", ["actor"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_timestamp_action", "audit_logs", ["timestamp", "action"])


def downgrade():
    op.drop_table("audit_logs")
    op.drop_table("admin_sessions")
    op.drop_table("security_events")
    op.drop_table("request_records")
