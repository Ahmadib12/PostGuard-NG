# Customer-hosted deployment

This deployment runs one PostGuard-NG installation for one customer/operator. The operator owns the host, public ingress, secrets, Redis, PostgreSQL, backups, monitoring, and upgrades. It is not a tenant-isolation boundary for multiple organizations.

## Prerequisites

- A supported Docker Engine and Docker Compose v2 (`docker compose`).
- A host with persistent storage for PostgreSQL and Redis.
- A TLS-terminating reverse proxy or load balancer for public access. The Compose port binds to loopback by default; do not expose the app directly to the internet without a reviewed TLS and ingress configuration.
- Securely generated, unique client secrets and administrator credentials.

## Configure

From the repository root, create a private environment file:

```sh
cp .env.example .env
chmod 600 .env
```

Edit `.env` before starting:

- Set `TRUSTED_HOSTS` to the exact public hostname(s) accepted by the gateway (no wildcard).
- Set `ADMIN_USERNAME` and `ADMIN_PASSWORD`; the password must be at least 16 characters. Use a separate administrator credential, never a client HMAC secret.
- These values bootstrap the initial platform administrator only when the IAM store is empty. They do not reset existing IAM passwords or migrate a legacy singleton credential.
- Replace every configured `POSTGUARD_*_SECRET` placeholder with a unique, random secret of at least 32 bytes.
- Set `MOCK_NIPOST` explicitly. Keep it `true` unless an authorized live integration and credentials have been verified; for live mode set `NIPOST_API_KEY` and verify the upstream configuration.
- Add `POSTGRES_PASSWORD` with a strong URL-safe value. For example, generate a 32-byte hexadecimal value with `openssl rand -hex 32`. It is used in the PostgreSQL URL and therefore must not contain URL-reserved characters.
- Optionally set `POSTGUARD_BIND_ADDRESS` and `POSTGUARD_PORT`. The default binds `127.0.0.1:8000` on the host for a local reverse proxy.

Do not commit `.env`, pass secrets as Docker build arguments, or put credentials in the Dockerfile. `.dockerignore` excludes local environment files and databases from the build context. The app uses the Compose service network for Redis and PostgreSQL; neither service publishes a host port.

## Start and verify

```sh
docker compose config
docker compose up -d --build
docker compose ps
curl --fail -H 'Host: gateway.example.com' http://127.0.0.1:8000/health
```

Replace `gateway.example.com` with a hostname listed in `TRUSTED_HOSTS`. The application should report `readiness.ready: true`. `/health` reports liveness and Redis readiness; it is not an end-to-end upstream-service check. In development, the API docs may be available, but this deployment sets production mode, which disables them.

The Compose file uses health checks for all services, a persistent PostgreSQL volume, and Redis append-only persistence for nonce/rate-limit continuity across restarts. The app image runs as a non-root user with a read-only root filesystem and no Linux capabilities. The gateway API and static dashboard ports are published on loopback by default. Keep PostgreSQL and Redis on the private Compose network.

Configure the reverse proxy to terminate TLS, forward only the required application traffic, and preserve the original host expected by `TRUSTED_HOSTS`. Set `ADMIN_COOKIE_SECURE=true` (already set in Compose); do not change it for a public HTTPS deployment. Restrict administrative endpoints at the network layer as appropriate for the deployment.

The Compose stack also serves the built dashboard at `http://127.0.0.1:8080` by default, with same-origin `/api` and `/health` proxying. Put the TLS reverse proxy in front of this dashboard port for a browser deployment; do not make the app API port publicly reachable. The dashboard image is built from source and contains no runtime secrets.

The app trusts the dashboard container at `172.30.0.2` only for `X-Real-IP`; the dashboard overwrites that header using its peer address. If a separate TLS ingress sits in front of the dashboard, configure `dashboard/nginx.conf` to trust only that ingress with Nginx's `set_real_ip_from`, `real_ip_header`, and (if needed) `real_ip_recursive` directives. The ingress must overwrite, not append untrusted client-supplied forwarding headers. Keep the Compose subnet and trusted-proxy address aligned if you change the network configuration.

## Upgrade and rollback

Review release notes and migration changes before upgrading. Back up PostgreSQL and Redis data before deploying a new image. Run `docker compose pull` if using a published image (the repository Compose file builds locally), then `docker compose up -d --build`. The application applies schema migrations during startup; keep a recoverable database backup until the new version is verified. Do not roll back application code across an incompatible database migration without a tested restore/rollback procedure.

See [Operations](OPERATIONS.md) for backup, restore, monitoring, and incident guidance. No tenant-specific data separation is provided; see [Tenant isolation](TENANT_ISOLATION.md).
