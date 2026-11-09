# Deployment modes

PostGuard-NG currently supports a **customer-hosted, single-operator installation**. Docker Compose assets in the repository are intended for that mode. The `POSTGUARD_DEPLOYMENT_MODE` setting selects configuration; it does not provision infrastructure, tenants, or isolation.

| Mode | Current status | Meaning |
| --- | --- | --- |
| Customer-hosted | Deployment path provided | The operator runs the gateway, Redis, and telemetry database in infrastructure they control. |
| Managed | Not implemented | There is no hosted service, tenant provisioning, tenant membership/RBAC, per-tenant credentials/upstreams, or managed control plane. Setting `POSTGUARD_DEPLOYMENT_MODE=managed` does not enable any of these. |

The application still uses a static in-process client policy and client secrets loaded from environment variables. Telemetry and administrator sessions have organization ownership fields and organization-scoped queries; the single configured administrator is bound to `POSTGUARD_ORGANIZATION_ID`. `POSTGUARD_CLIENT_ORGANIZATIONS` is a server-side map used to scope client telemetry. This is only an isolation foundation: there is no tenant membership/RBAC, tenant-aware administrator login, provisioning workflow, platform administration, or per-tenant upstream/client credential lifecycle. Do not use one shared instance to serve mutually untrusted organizations as if it were a complete multi-tenant service.

## Choosing a mode

- Choose customer-hosted mode when the organization will own network access, secrets, database/Redis lifecycle, backups, upgrades, and incident response. Start with [Customer-hosted deployment](CUSTOMER_HOSTED_DEPLOYMENT.md).
- Do not select managed mode for production use. [Managed deployment](MANAGED_DEPLOYMENT.md) describes the missing product and operational prerequisites; it is not an installation guide.

See [Multi-tenant security](MULTI_TENANT_SECURITY.md) and [Tenant isolation](TENANT_ISOLATION.md) for the current boundaries and prerequisites. Operational guidance for a customer-hosted installation is in [Operations](OPERATIONS.md).

For ownership backfill, pre-upgrade backup, validation, and rollback guidance, see [Tenant-scope migration safety](TENANT_MIGRATION.md).
