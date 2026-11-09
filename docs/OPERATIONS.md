# Operations

This runbook applies to the single-operator customer-hosted Compose deployment. It does not define managed-service operations or complete tenant isolation.

## Health and monitoring

- Check `docker compose ps` and container health status. The app health check verifies the app responds and Redis is ready. PostgreSQL, Redis, and the static dashboard have their own service health checks.
- `/health` reports application liveness and Redis readiness. It does not prove that the configured live upstream is available or that a postcode lookup succeeds.
- Monitor container logs with `docker compose logs --since=15m app`; protect and retain logs under the operator's policy. Do not send secrets, signatures, or raw request bodies to logs.
- Alert on unhealthy/restarting containers, persistent database/Redis failures, disk pressure, and unusual security events. Restrict access to monitoring and logs.

## Backups and recovery

- Back up PostgreSQL regularly using an operator-controlled, encrypted, access-restricted process. Test restoration into an isolated environment.
- Preserve Redis state because it contains replay nonces and rate-limit counters. Redis append-only persistence is enabled in Compose; include its volume in an appropriate backup plan and test recovery. A Redis data loss/reset can permit replay of recently used signed requests until their timestamps expire and resets rate-limit state.
- Protect backups as sensitive data, define retention and deletion, and keep encryption keys separately controlled.
- Before restore, stop or isolate application traffic and coordinate PostgreSQL and Redis recovery. Verify schema, app health, and security behavior before reopening traffic.
- Docker named volumes are persistent storage, not backups. Do not use `docker compose down -v` unless intentionally deleting all persisted database and Redis data.

## Secrets and access

- Keep `.env` owner-readable only and outside version control and image layers. Rotate client/admin credentials through an approved process and restart the service after changing environment configuration.
- Restrict host, Docker daemon, database, Redis, logs, and backup access to trusted operators. Do not publish PostgreSQL or Redis ports.
- Use TLS at a trusted reverse proxy/load balancer and limit access to administrative routes. Keep `TRUSTED_HOSTS` narrow and `ADMIN_COOKIE_SECURE=true`.
- If credentials may have been exposed, revoke/rotate them, review access and logs, and consider Redis nonce state and database/backups in the response.

## Updates and incidents

Review application and dependency changes, migration compatibility, and backup validity before upgrading. Apply updates in a maintenance window, monitor health and logs, and retain a tested recovery path. The app applies schema migrations at startup; do not assume an application image rollback also rolls back the database schema.

For suspected compromise, restrict ingress, preserve relevant logs and state, rotate exposed secrets, investigate host and data access, and restore only from a known-good backup after the cause is addressed. Document decisions and customer/operator notifications according to the operator's policies.
