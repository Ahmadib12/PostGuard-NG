from alembic import op
import sqlalchemy as sa


revision = "0006_security_incidents"
down_revision = "0005_administrator_iam"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "security_incidents" not in set(inspector.get_table_names()):
        op.create_table(
            "security_incidents",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "organization_id",
                sa.String(32),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("event_type", sa.String(64), nullable=False),
            sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("event_count", sa.Integer(), nullable=False),
            sa.Column("risk_score", sa.Integer(), nullable=False),
            sa.Column("severity", sa.String(16), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("security_incidents")}
    if "ix_security_incidents_org_updated" not in indexes:
        op.create_index(
            "ix_security_incidents_org_updated",
            "security_incidents",
            ["organization_id", "updated_at"],
        )


def downgrade():
    raise RuntimeError("Downgrade is disabled because it would remove security incident history.")
