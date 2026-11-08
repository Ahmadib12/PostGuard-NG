from alembic import op
import sqlalchemy as sa

revision = "0002_generated_admin_credential"
down_revision = "0001_dashboard_telemetry"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admin_credentials",
        sa.Column("id", sa.String(length=16), primary_key=True),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("password_salt", sa.LargeBinary(length=32), nullable=False),
        sa.Column("password_hash", sa.LargeBinary(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    op.drop_table("admin_credentials")
