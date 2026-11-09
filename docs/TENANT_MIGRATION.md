# Tenant-scope migration safety

The organization-scope migration adds `organizations` and an `organization_id` foreign key to request telemetry, security events, administrator sessions, and audit logs.

## Ownership assignment

The migration does not use a fixed `default` organization:

- It preserves any existing non-null `organization_id` values and existing organization rows.
- Request and security-event rows with a configured client mapping use `POSTGUARD_CLIENT_ORGANIZATIONS`.
- A legacy installation with exactly one unambiguous organization uses `POSTGUARD_ORGANIZATION_ID`.
- If ownership cannot be derived because more than one organization is configured, the migration stops before making schema or data changes.
- When a reviewed historical data inventory proves a single owner for otherwise unscoped legacy rows, set `POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID` for the migration run. This applies to rows with missing/unmapped client IDs, administrator sessions, and audit logs. It is an explicit operator assertion, not an automatic inference. Remove it after the migration completes.

Existing organization slugs must be unique, organization IDs must be valid, and existing tenant references must resolve. The migration fails without rewriting data when these checks do not pass. The follow-up validation migration blocks startup if an already-upgraded database contains rows whose ownership conflicts with the configured mapping or cannot be proven in a multi-organization configuration.

Managed multi-tenancy remains unsupported. A successful migration does not provide tenant administration, membership/RBAC, or a managed control plane.

## Upgrade and rollback

1. Stop application writes and make a verified database backup before upgrading. For PostgreSQL, use the operator's normal consistent `pg_dump` procedure. For SQLite, stop all application processes before copying the database or use SQLite's online backup API.
2. Record the current Alembic revision and retain the backup until the upgraded installation has been checked.
3. Configure `POSTGUARD_ORGANIZATION_ID` and `POSTGUARD_CLIENT_ORGANIZATIONS` to the reviewed ownership values. For ambiguous legacy rows, use `POSTGUARD_LEGACY_UNSCOPED_ORGANIZATION_ID` only after independently establishing their owner.
4. Upgrade in a non-production environment first. Startup migrations fail closed on ambiguous ownership; resolve the ownership evidence and retry rather than assigning rows to an arbitrary organization.
5. Verify the migration revision, row counts, organization assignments, and dashboard visibility before resuming writes.

The tenant-scope migration intentionally refuses to downgrade because dropping `organization_id` would erase ownership information. Roll back by restoring the verified pre-upgrade backup and starting the prior application version. Do not rely on Alembic downgrade to recover deleted or overwritten data.

Databases that already applied the earlier `0003_organization_scopes` implementation may contain historical rows previously assigned to `default`. Their original organization cannot always be reconstructed from the database. The follow-up validation stops ambiguous multi-organization startup without changing these rows; operators must review backups and historical client ownership and perform a separately reviewed, explicit repair. The migration does not automatically reassign those records.
