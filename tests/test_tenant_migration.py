import importlib.util
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.exc import IntegrityError


ROOT = Path(__file__).resolve().parents[1]


def load_migration(name):
    migration_path = ROOT / "migrations" / "versions" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, migration_path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


MIGRATION_0001 = load_migration("0001_dashboard_telemetry")
MIGRATION_0002 = load_migration("0002_generated_admin_credential")
MIGRATION_0003 = load_migration("0003_organization_scopes")
MIGRATION_0004 = load_migration("0004_validate_legacy_tenant_scopes")
MIGRATION_0005 = load_migration("0005_administrator_iam")
MIGRATION_0006 = load_migration("0006_security_incidents")


class TenantMigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")

        @event.listens_for(self.engine, "connect")
        def enable_foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")

        self.connection_context = self.engine.begin()
        self.connection = self.connection_context.__enter__()
        self.run_migration(MIGRATION_0001)
        self.run_migration(MIGRATION_0002)

    def tearDown(self):
        self.connection_context.__exit__(None, None, None)
        self.engine.dispose()

    def run_migration(self, migration):
        with Operations.context(MigrationContext.configure(self.connection)):
            migration.upgrade()

    def insert_legacy_data(self):
        self.connection.execute(text(
            "INSERT INTO request_records "
            "(id, timestamp, client_id, status_code, outcome, duration_ms, authenticated) "
            "VALUES ('request-1', '2026-01-01 00:00:00', 'demo-client', 200, 'success', 12, 1)"
        ))
        self.connection.execute(text(
            "INSERT INTO security_events "
            "(id, timestamp, event_type, client_id, request_id, http_status, outcome, severity, safe_metadata) "
            "VALUES ('event-1', '2026-01-01 00:00:00', 'REPLAY_DETECTED', 'demo-client', "
            "'request-1', 409, 'blocked', 'high', '{\"region\":\"abuja\"}')"
        ))
        self.connection.execute(text(
            "INSERT INTO admin_sessions (token_hash, csrf_hash, username, expires_at) "
            "VALUES ('token-hash', 'csrf-hash', 'admin', '2027-01-01 00:00:00')"
        ))
        self.connection.execute(text(
            "INSERT INTO audit_logs (id, timestamp, actor, action, details) "
            "VALUES ('audit-1', '2026-01-01 00:00:00', 'admin', 'login', '{\"result\":\"ok\"}')"
        ))

    @staticmethod
    def migration_environment(
        organization_id="customer-a",
        client_organizations="{}",
        legacy_unscoped_organization_id="",
    ):
        return patch.dict(os.environ, {
            "POSTGUARD_ORGANIZATION_ID": organization_id,
            "POSTGUARD_CLIENT_ORGANIZATIONS": client_organizations,
            "POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID": legacy_unscoped_organization_id,
        })

    def test_fresh_migration_creates_only_the_explicit_configured_organization(self):
        with self.migration_environment("customer-a"):
            self.run_migration(MIGRATION_0003)

        rows = self.connection.execute(text("SELECT id, slug FROM organizations")).all()
        self.assertEqual([(row.id, row.slug) for row in rows], [("customer-a", "customer-a")])
        for table_name in MIGRATION_0003.TENANT_TABLES:
            columns = {column["name"]: column for column in inspect(self.connection).get_columns(table_name)}
            self.assertFalse(columns["organization_id"]["nullable"])
            self.assertTrue(any(
                foreign_key["constrained_columns"] == ["organization_id"]
                and foreign_key["referred_table"] == "organizations"
                for foreign_key in inspect(self.connection).get_foreign_keys(table_name)
            ))

    def test_customer_hosted_upgrade_preserves_legacy_rows_and_assigns_configured_org(self):
        self.insert_legacy_data()

        with self.migration_environment("customer-production"):
            self.run_migration(MIGRATION_0003)

        self.assertEqual(
            self.connection.execute(text("SELECT id, client_id FROM request_records")).one(),
            ("request-1", "demo-client"),
        )
        self.assertEqual(
            self.connection.execute(text(
                "SELECT id, safe_metadata FROM security_events"
            )).one(),
            ("event-1", '{"region":"abuja"}'),
        )
        for table_name, key in (
            ("request_records", "id"),
            ("security_events", "id"),
            ("admin_sessions", "token_hash"),
            ("audit_logs", "id"),
        ):
            row = self.connection.execute(
                text(f'SELECT organization_id FROM "{table_name}" WHERE "{key}" = :key'),
                {"key": {
                    "request_records": "request-1",
                    "security_events": "event-1",
                    "admin_sessions": "token-hash",
                    "audit_logs": "audit-1",
                }[table_name]},
            ).one()
            self.assertEqual(row.organization_id, "customer-production")
        self.assertEqual(
            self.connection.execute(text("SELECT details FROM audit_logs")).scalar_one(),
            '{"result":"ok"}',
        )

    def test_audit_chain_backfill_normalizes_sqlite_timestamps_and_is_retry_safe(self):
        self.insert_legacy_data()
        with self.migration_environment("customer-a"):
            self.run_migration(MIGRATION_0003)
            self.run_migration(MIGRATION_0004)
        self.run_migration(MIGRATION_0005)

        row = dict(self.connection.execute(text(
            "SELECT id, organization_id, timestamp, actor, action, details, sequence, "
            "previous_digest, digest FROM audit_logs"
        )).mappings().one())
        self.assertEqual(row["sequence"], 1)
        self.assertEqual(row["previous_digest"], "0" * 64)
        self.assertEqual(
            row["digest"],
            MIGRATION_0005._digest(row, 1, "0" * 64),
        )
        self.run_migration(MIGRATION_0005)
        self.assertEqual(
            self.connection.execute(
                text("SELECT sequence, digest FROM audit_chain_state WHERE id=1")
            ).one(),
            (1, row["digest"]),
        )
        self.connection.execute(text("UPDATE audit_logs SET previous_digest=NULL"))
        with self.assertRaisesRegex(RuntimeError, "partially populated"):
            self.run_migration(MIGRATION_0005)

    def test_client_mapping_assigns_known_records_and_preserves_existing_organization(self):
        self.connection.execute(text(
            "CREATE TABLE organizations ("
            "id VARCHAR(32) PRIMARY KEY, slug VARCHAR(64) NOT NULL, name VARCHAR(128) NOT NULL, "
            "status VARCHAR(16) NOT NULL, plan VARCHAR(32) NOT NULL, limits_json TEXT NOT NULL, "
            "created_at DATETIME NOT NULL)"
        ))
        self.connection.execute(text(
            "INSERT INTO organizations VALUES "
            "('tenant-a', 'customer-a-slug', 'Customer A', 'active', 'standard', '{}', "
            "'2025-01-01 00:00:00')"
        ))
        self.connection.execute(text(
            "INSERT INTO request_records "
            "(id, timestamp, client_id, status_code, outcome, duration_ms, authenticated) "
            "VALUES ('request-a', '2026-01-01 00:00:00', 'demo-client', 200, 'success', 12, 1), "
            "('request-b', '2026-01-01 00:00:00', 'partner-x', 200, 'success', 12, 1)"
        ))
        with self.migration_environment(
            "tenant-a",
            '{"demo-client":"tenant-a","partner-x":"tenant-b"}',
        ):
            self.run_migration(MIGRATION_0003)

        assigned = self.connection.execute(text(
            "SELECT id, organization_id FROM request_records ORDER BY id"
        )).all()
        self.assertEqual(
            [(row.id, row.organization_id) for row in assigned],
            [("request-a", "tenant-a"), ("request-b", "tenant-b")],
        )
        self.assertEqual(
            self.connection.execute(
                text("SELECT slug, name FROM organizations WHERE id='tenant-a'")
            ).one(),
            ("customer-a-slug", "Customer A"),
        )
        self.assertIsNotNone(self.connection.execute(
            text("SELECT id FROM organizations WHERE id='tenant-b'")
        ).scalar_one())

    def test_existing_null_organization_id_is_filled_without_reassigning_existing_scope(self):
        self.connection.execute(text(
            "CREATE TABLE organizations ("
            "id VARCHAR(32) PRIMARY KEY, slug VARCHAR(64) NOT NULL, name VARCHAR(128) NOT NULL, "
            "status VARCHAR(16) NOT NULL, plan VARCHAR(32) NOT NULL, limits_json TEXT NOT NULL, "
            "created_at DATETIME NOT NULL)"
        ))
        self.connection.execute(text(
            "INSERT INTO organizations VALUES "
            "('tenant-a', 'tenant-a', 'Tenant A', 'active', 'development', '{}', '2025-01-01'), "
            "('tenant-b', 'tenant-b', 'Tenant B', 'active', 'development', '{}', '2025-01-01')"
        ))
        self.connection.execute(text(
            "ALTER TABLE request_records ADD COLUMN organization_id VARCHAR(32)"
        ))
        self.connection.execute(text(
            "INSERT INTO request_records "
            "(id, timestamp, client_id, status_code, outcome, duration_ms, authenticated, organization_id) "
            "VALUES ('null-scope', '2026-01-01 00:00:00', 'demo-client', 200, 'success', 1, 1, NULL), "
            "('existing-scope', '2026-01-01 00:00:00', 'demo-client', 200, 'success', 1, 1, 'tenant-b')"
        ))
        with self.migration_environment("tenant-a", '{"demo-client":"tenant-a"}'):
            self.run_migration(MIGRATION_0003)

        self.assertEqual(
            self.connection.execute(text(
                "SELECT organization_id FROM request_records WHERE id='null-scope'"
            )).scalar_one(),
            "tenant-a",
        )
        self.assertEqual(
            self.connection.execute(text(
                "SELECT organization_id FROM request_records WHERE id='existing-scope'"
            )).scalar_one(),
            "tenant-b",
        )

    def test_duplicate_existing_slugs_fail_before_schema_or_data_changes(self):
        self.connection.execute(text(
            "CREATE TABLE organizations ("
            "id VARCHAR(32) PRIMARY KEY, slug VARCHAR(64) NOT NULL, name VARCHAR(128) NOT NULL, "
            "status VARCHAR(16) NOT NULL, plan VARCHAR(32) NOT NULL, limits_json TEXT NOT NULL, "
            "created_at DATETIME NOT NULL)"
        ))
        self.connection.execute(text(
            "INSERT INTO organizations VALUES "
            "('tenant-a', 'duplicate', 'A', 'active', 'development', '{}', '2025-01-01'), "
            "('tenant-b', 'duplicate', 'B', 'active', 'development', '{}', '2025-01-01')"
        ))
        with self.migration_environment("tenant-a"):
            with self.assertRaisesRegex(RuntimeError, "duplicate slugs"):
                self.run_migration(MIGRATION_0003)

        self.assertNotIn(
            "organization_id",
            {column["name"] for column in inspect(self.connection).get_columns("request_records")},
        )
        self.assertEqual(
            self.connection.execute(text("SELECT COUNT(*) FROM organizations")).scalar_one(),
            2,
        )

    def test_invalid_existing_organization_id_fails_without_rewriting_rows(self):
        self.connection.execute(text(
            "ALTER TABLE request_records ADD COLUMN organization_id VARCHAR(32)"
        ))
        self.connection.execute(text(
            "INSERT INTO request_records "
            "(id, timestamp, client_id, status_code, outcome, duration_ms, authenticated, organization_id) "
            "VALUES ('bad-scope', '2026-01-01 00:00:00', 'demo-client', 200, 'success', 1, 1, 'not valid')"
        ))
        with self.migration_environment("tenant-a"):
            with self.assertRaisesRegex(RuntimeError, "invalid organization ID"):
                self.run_migration(MIGRATION_0003)

        self.assertEqual(
            self.connection.execute(text(
                "SELECT organization_id FROM request_records WHERE id='bad-scope'"
            )).scalar_one(),
            "not valid",
        )
        self.assertNotIn("organizations", inspect(self.connection).get_table_names())

    def test_ambiguous_migration_fails_before_changes_and_can_be_retried_safely(self):
        self.connection.execute(text(
            "INSERT INTO audit_logs (id, timestamp, actor, action, details) "
            "VALUES ('unscoped-audit', '2026-01-01 00:00:00', 'admin', 'login', '{}')"
        ))
        with self.migration_environment(
            "tenant-a",
            '{"demo-client":"tenant-a","partner-x":"tenant-b"}',
        ):
            with self.assertRaisesRegex(RuntimeError, "Cannot determine organization ownership"):
                self.run_migration(MIGRATION_0003)

        self.assertNotIn("organizations", inspect(self.connection).get_table_names())
        self.assertNotIn(
            "organization_id",
            {column["name"] for column in inspect(self.connection).get_columns("audit_logs")},
        )
        self.assertEqual(
            self.connection.execute(text("SELECT COUNT(*) FROM audit_logs")).scalar_one(),
            1,
        )

        with self.migration_environment(
            "tenant-a",
            '{"demo-client":"tenant-a","partner-x":"tenant-b"}',
            "legacy-audit-owner",
        ):
            self.run_migration(MIGRATION_0003)
            self.run_migration(MIGRATION_0004)
        self.assertEqual(
            self.connection.execute(text(
                "SELECT organization_id FROM audit_logs WHERE id='unscoped-audit'"
            )).scalar_one(),
            "legacy-audit-owner",
        )

    def test_tenant_foreign_key_and_slug_uniqueness_are_enforced(self):
        with self.migration_environment("tenant-a"):
            self.run_migration(MIGRATION_0003)

        with self.assertRaises(IntegrityError):
            with self.connection.begin_nested():
                self.connection.execute(text(
                    "INSERT INTO request_records "
                    "(id, organization_id, timestamp, client_id, status_code, outcome, duration_ms, authenticated) "
                    "VALUES ('orphan', 'missing-tenant', '2026-01-01', 'client', 200, 'success', 1, 1)"
                ))
        with self.assertRaises(IntegrityError):
            with self.connection.begin_nested():
                self.connection.execute(text(
                    "INSERT INTO organizations "
                    "(id, slug, name, status, plan, limits_json, created_at) "
                    "VALUES ('tenant-b', 'tenant-a', 'Tenant B', 'active', 'development', '{}', "
                    "'2025-01-01')"
                ))

    def test_downgrade_refuses_to_discard_organization_ownership(self):
        with self.migration_environment("tenant-a"):
            self.run_migration(MIGRATION_0003)
        with Operations.context(MigrationContext.configure(self.connection)):
            with self.assertRaisesRegex(RuntimeError, "Downgrade is intentionally disabled"):
                MIGRATION_0003.downgrade()
        self.assertIn("organizations", inspect(self.connection).get_table_names())

    def test_duplicate_client_mapping_keys_are_rejected(self):
        with self.migration_environment("tenant-a", '{"demo-client":"tenant-a","demo-client":"tenant-b"}'):
            with self.assertRaisesRegex(RuntimeError, "unique client IDs"):
                self.run_migration(MIGRATION_0003)
        self.assertNotIn("organizations", inspect(self.connection).get_table_names())

    def test_followup_validation_blocks_previously_backfilled_mixed_tenant_data(self):
        self.insert_legacy_data()
        with self.migration_environment("default"):
            self.run_migration(MIGRATION_0003)

        with self.migration_environment(
            "tenant-a",
            '{"demo-client":"tenant-a","partner-x":"tenant-b"}',
        ):
            with self.assertRaisesRegex(RuntimeError, "Startup is blocked"):
                self.run_migration(MIGRATION_0004)

        self.assertEqual(
            self.connection.execute(text(
                "SELECT organization_id FROM request_records WHERE id='request-1'"
            )).scalar_one(),
            "default",
        )
        self.assertEqual(
            self.connection.execute(text("SELECT COUNT(*) FROM audit_logs")).scalar_one(),
            1,
        )

    def test_followup_validation_accepts_proven_client_ownership(self):
        with self.migration_environment(
            "tenant-a",
            '{"demo-client":"tenant-a","partner-x":"tenant-b"}',
        ):
            self.run_migration(MIGRATION_0003)
            self.connection.execute(text(
                "INSERT INTO request_records "
                "(id, organization_id, timestamp, client_id, status_code, outcome, duration_ms, authenticated) "
                "VALUES ('mapped-row', 'tenant-b', '2026-01-01', 'partner-x', 200, 'success', 1, 1)"
            ))
            self.run_migration(MIGRATION_0004)
        self.assertEqual(
            self.connection.execute(text(
                "SELECT organization_id FROM request_records WHERE id='mapped-row'"
            )).scalar_one(),
            "tenant-b",
        )

    def run_alembic(
        self,
        database_path,
        revision,
        organization_id="customer-a",
        client_map="{}",
        legacy_unscoped_organization_id="",
    ):
        environment = os.environ.copy()
        environment.update({
            "DASHBOARD_DATABASE_URL": f"sqlite:///{database_path}",
            "POSTGUARD_ORGANIZATION_ID": organization_id,
            "POSTGUARD_CLIENT_ORGANIZATIONS": client_map,
            "POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID": legacy_unscoped_organization_id,
        })
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(ROOT / "alembic.ini"),
                "upgrade",
                revision,
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_alembic_fresh_database_upgrade_runs_all_migrations(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "fresh.sqlite")
            result = self.run_alembic(database_path, "head", "fresh-customer")
            self.assertEqual(result.returncode, 0, result.stderr)

            with sqlite3.connect(database_path) as database:
                self.assertEqual(
                    database.execute("SELECT id FROM organizations").fetchall(),
                    [("fresh-customer",)],
                )
                self.assertEqual(
                    database.execute("SELECT version_num FROM alembic_version").fetchone(),
                    (MIGRATION_0006.revision,),
                )

    def test_alembic_upgrade_from_previous_schema_preserves_customer_data(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "upgrade.sqlite")
            base_result = self.run_alembic(
                database_path,
                MIGRATION_0002.revision,
                "existing-customer",
            )
            self.assertEqual(base_result.returncode, 0, base_result.stderr)
            with sqlite3.connect(database_path) as database:
                database.execute(
                    "INSERT INTO request_records "
                    "(id, timestamp, client_id, status_code, outcome, duration_ms, authenticated) "
                    "VALUES ('kept-request', '2026-01-01', 'demo-client', 200, 'success', 4, 1)"
                )
                database.execute(
                    "INSERT INTO audit_logs (id, timestamp, actor, action, details) "
                    "VALUES ('kept-audit', '2026-01-01', 'admin', 'login', '{}')"
                )
                database.commit()

            upgrade_result = self.run_alembic(
                database_path,
                "head",
                "existing-customer",
            )
            self.assertEqual(upgrade_result.returncode, 0, upgrade_result.stderr)
            with sqlite3.connect(database_path) as database:
                self.assertEqual(
                    database.execute(
                        "SELECT id, client_id, organization_id FROM request_records"
                    ).fetchone(),
                    ("kept-request", "demo-client", "existing-customer"),
                )
                self.assertEqual(
                    database.execute(
                        "SELECT id, details, organization_id FROM audit_logs"
                    ).fetchone(),
                    ("kept-audit", "{}", "existing-customer"),
                )

    def test_alembic_failure_preserves_previous_revision_and_retry_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "recover.sqlite")
            base_result = self.run_alembic(
                database_path,
                MIGRATION_0002.revision,
                "tenant-a",
            )
            self.assertEqual(base_result.returncode, 0, base_result.stderr)
            with sqlite3.connect(database_path) as database:
                database.execute(
                    "INSERT INTO audit_logs (id, timestamp, actor, action, details) "
                    "VALUES ('recover-audit', '2026-01-01', 'admin', 'login', '{}')"
                )
                database.commit()

            ambiguous_result = self.run_alembic(
                database_path,
                "head",
                "tenant-a",
                '{"demo-client":"tenant-a","partner-x":"tenant-b"}',
            )
            self.assertNotEqual(ambiguous_result.returncode, 0)
            self.assertIn("Cannot determine organization ownership", ambiguous_result.stderr)
            with sqlite3.connect(database_path) as database:
                self.assertEqual(
                    database.execute("SELECT version_num FROM alembic_version").fetchone(),
                    (MIGRATION_0002.revision,),
                )
                self.assertNotIn(
                    "organizations",
                    {row[0] for row in database.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )},
                )
                self.assertEqual(
                    database.execute("SELECT details FROM audit_logs").fetchone(),
                    ("{}",),
                )

            retry_result = self.run_alembic(
                database_path,
                "head",
                "tenant-a",
                '{"demo-client":"tenant-a","partner-x":"tenant-b"}',
                "tenant-a",
            )
            self.assertEqual(retry_result.returncode, 0, retry_result.stderr)
            with sqlite3.connect(database_path) as database:
                self.assertEqual(
                    database.execute("SELECT version_num FROM alembic_version").fetchone(),
                    (MIGRATION_0006.revision,),
                )
                self.assertEqual(
                    database.execute(
                        "SELECT organization_id FROM audit_logs WHERE id='recover-audit'"
                    ).fetchone(),
                    ("tenant-a",),
                )


if __name__ == "__main__":
    unittest.main()
