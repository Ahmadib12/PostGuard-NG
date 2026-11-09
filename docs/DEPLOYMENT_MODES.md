# Deployment modes

PostGuard-NG currently supports a **customer-hosted, single-operator installation**. Docker Compose assets in the repository are intended for that mode. The `POSTGUARD_DEPLOYMENT_MODE` setting selects configuration; it does not provision infrastructure, tenants, or isolation.

| Mode | Current status | Meaning |
| --- | --- | --- |
| Customer-hosted | Deployment path provided | The operator runs the gateway, Redis, and telemetry database in infrastructure they control. |
| Managed | Not a hosted service | Administrator IAM, organization memberships/roles, organization provisioning/status controls, and scoped dashboard APIs exist. There is no hosted service, tenant-specific client policy/secrets/upstreams, managed control plane, or managed operations. Setting `POSTGUARD_DEPLOYMENT_MODE=managed` does not provide these. |

The application still uses a static in-process client policy and client secrets loaded from environment variables. `POSTGUARD_CLIENT_ORGANIZATIONS` is a server-side map used to assign authenticated clients to organizations. IAM login selects an organization membership, and dashboard queries and administrative operations are scoped to that session. Organization suspension blocks mapped client requests and ordinary tenant administration. This is not a complete multi-tenant service: client provisioning, tenant-specific credentials/upstreams, and managed hosting/operations are not provided. Do not use one shared instance to serve mutually untrusted organizations without independently reviewing those boundaries.

## Choosing a mode

- Choose customer-hosted mode when the organization will own network access, secrets, database/Redis lifecycle, backups, upgrades, and incident response. Start with [Customer-hosted deployment](CUSTOMER_HOSTED_DEPLOYMENT.md).
- Do not select managed mode for production use. [Managed deployment](MANAGED_DEPLOYMENT.md) describes the missing product and operational prerequisites; it is not an installation guide.

See [Multi-tenant security](MULTI_TENANT_SECURITY.md) and [Tenant isolation](TENANT_ISOLATION.md) for the current boundaries and prerequisites. Operational guidance for a customer-hosted installation is in [Operations](OPERATIONS.md).

For ownership backfill, pre-upgrade backup, validation, and rollback guidance, see [Tenant-scope migration safety](TENANT_MIGRATION.md).
