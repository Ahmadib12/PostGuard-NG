# Security architecture and operations

PostGuard-NG is an API gateway prototype for signed postcode lookup requests. The controls below describe the current implementation; they are not a claim that the project has been penetration-tested or is production-ready.

## Implemented controls

- Client requests use HMAC-SHA256 over the method, fixed endpoint path, client ID, timestamp, nonce, and exact raw body. Signature comparison is constant-time.
- Timestamp checks, nonce registration, and per-client rate limiting are enforced by Redis. New nonce keys hash client IDs and nonces; the gateway also checks the previous nonce-key format to preserve replay protection across upgrades. Rate limiting and nonce registration for a request are atomic, and Redis failures fail closed.
- Request bodies have a configured maximum size. Secure lookup requests require JSON, reject extra schema fields, and apply region and lookup-level policies.
- The upstream is configured by the operator, redirects are disabled, ambient HTTP proxy settings are ignored, upstream responses have a size cap, and response errors are not returned verbatim.
- Administrator sessions and CSRF tokens are random, stored in the database only as hashes, expire, and use `HttpOnly`, `SameSite=Strict` session cookies. State-changing cookie-authenticated requests require a matching CSRF header and cookie.
- Dashboard APIs require an administrator session. Audit and security-event metadata use allowlists to avoid persisting arbitrary request data. The dashboard renders data through React rather than injecting HTML.
- The backend sends basic security headers, disables caching on administrator API responses, and supports host allowlisting and production-disabled API docs.
- Alembic migrations manage the telemetry schema. Database queries use SQLAlchemy expressions or bound SQL.

## Production deployment checklist

1. Use Python 3.11, set `APP_ENV=production` and `DEBUG=false`, explicitly set `MOCK_NIPOST`, and configure non-placeholder client secrets and administrator credentials in a secret manager.
2. Set `ADMIN_COOKIE_SECURE=true`; terminate TLS at a trusted ingress and serve the frontend and API on the same origin. Have the ingress apply HSTS and a dashboard-appropriate Content Security Policy to static dashboard files.
3. Configure `TRUSTED_HOSTS` with exact externally served hostnames. Do not trust client-supplied forwarding headers unless the ingress strips and sets them and the application is explicitly configured to trust only that proxy.
4. Set `MOCK_NIPOST` explicitly. For live mode use an operator-verified HTTPS upstream, and restrict outbound network access to that service. The application does not implement DNS pinning; network egress controls are required to mitigate DNS rebinding and unexpected private-address resolution.
5. Use Redis with authentication/TLS where supported, network isolation, persistence appropriate to the deployment, and monitoring. Redis URL secrets must come from deployment secrets, not source control.
6. Prefer PostgreSQL with a least-privilege application account for production. For local SQLite, restrict the database file and parent directory to the service account; database files are ignored by Git.
7. Store backups securely, apply migrations deliberately, monitor application and infrastructure logs, and test restore and credential-rotation procedures.
8. Run `python -m unittest discover -s tests -v`, `cd dashboard && npm run build`, `alembic upgrade head`, `bandit -q -r app.py admin_api.py config.py dashboard_store.py iam.py intelligence.py security.py migrations/versions/0005_administrator_iam.py migrations/versions/0006_security_incidents.py`, `pip-audit -r requirements.txt`, and `cd dashboard && npm audit --audit-level=high` before release.

## Identity, credentials, and known limitations

Administrator IAM supports organization memberships, platform-super-admin access, organization owner/admin, security auditor, and read-only operator roles. Passwords are scrypt-hashed and session/CSRF tokens are hashed at rest. On an empty IAM store, configured bootstrap credentials create the platform administrator; in development, blank credentials generate a one-time `platform-admin` password in an owner-only bootstrap file, never in logs. This does not migrate or authenticate the legacy singleton credential row. User creation/reset returns a one-time temporary password, enforces a change at first sign-in, and revokes sessions on password change, account disablement, reset, or explicit revocation. The last active organization owner cannot be removed. Administrator login throttling uses an atomic Redis counter in production and fails closed with HTTP 503 if Redis is unavailable; it does not fall back to worker-local storage. Development uses a bounded in-process fallback (maximum 4,096 IP entries) with expired-entry cleanup, so development throttling is not shared across workers. API client identity and policy remain environment-backed; there is no per-tenant credential lifecycle.

API client identities and policies are configuration-backed and read-only. Secrets are environment-provided; rotation requires a coordinated configuration change and process restart. The application does not yet support generated credentials, credential revocation, per-client activation, or a database-backed client registry.

The upstream hostname is selected by operator configuration, not by request data. The application enforces HTTPS and rejects literal non-public IP addresses in live mode, but does not pin DNS resolution to the connection. Enforce egress restrictions outside the application. No official live NIPOST integration is assumed.

The audit log is hash-chained and verified at startup; detected corruption blocks startup. The database is not an external immutable ledger: a database administrator able to rewrite all rows and recompute the chain can defeat this control. Protect the database and retain independent backups. Log retention and archival are deployment responsibilities. Optional AI investigation is disabled by default; when enabled it sends only aggregate event types, severity, scores, and counts to the configured provider, and returns validated recommendations without taking action. Review provider privacy/retention terms before enabling. The dashboard build is a static frontend; a production reverse proxy must add suitable headers to those static responses. CORS is intentionally not enabled; keep the dashboard and API same-origin.

The login throttle uses the direct peer address unless that peer is explicitly listed in `TRUSTED_PROXIES`; only then is a valid `X-Real-IP` accepted. The Compose dashboard proxy uses a fixed private-network address. If another ingress sits in front of it, configure the dashboard proxy to trust only that ingress and to derive the client address from its sanitized forwarding header.

## Incident response

If a client secret is exposed, remove or replace it in the deployment secret store, restart all gateway workers, and investigate audit/security events for the affected client. Client credential revocation remains a coordinated configuration change. If administrator credentials may be exposed, reset the affected IAM password or disable the account; these operations revoke its active sessions. Review the audit chain and preserve relevant logs and database backups before cleanup; do not include secrets or request bodies in incident reports.

## Vulnerability reporting

Report suspected vulnerabilities privately to the repository maintainers rather than publishing exploit details before a fix is available. Include affected versions, impact, and concise reproduction steps. Do not test against third-party services or systems without authorization.
