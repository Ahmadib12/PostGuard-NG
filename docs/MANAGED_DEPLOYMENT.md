# Managed deployment

**Status: not implemented.** This document records prerequisites and must not be read as an offer or guide for an available hosted service. The `managed` value of `POSTGUARD_DEPLOYMENT_MODE` is a configuration label only. It does not create a service, tenant boundary, or managed operations capability.

The current application has a static in-process client policy and environment-loaded secrets. Organization-owned telemetry and organization-scoped queries exist as an initial foundation, with server-side client-to-organization configuration. Administrator authentication still has one configured identity bound to one organization; there is no tenant membership/RBAC, tenant provisioning, per-tenant client credential/provider lifecycle, or managed control plane. There is also no billing, service-level commitment, or production hosting runbook in this repository.

## Required before offering a managed service

At minimum, a future managed service would need:

- An explicit tenant identity and authorization model, including server-side tenant resolution and tenant-scoped client credentials and policy.
- Enforced isolation across requests, Redis keys, persistent records, administrator access, logs, exports, backups, and support tooling.
- Security design and threat modeling for cross-tenant access, administrative roles, secret lifecycle, data retention, and deletion.
- Automated isolation tests and independent security review, including backup/restore and migration coverage.
- Production-ready deployment, monitoring, incident response, vulnerability management, capacity planning, and tested disaster recovery.
- Documented data processing, privacy, availability, support, and customer access controls appropriate to the service.

Until these controls are implemented and verified, deploy each customer-owned instance as described in [Customer-hosted deployment](CUSTOMER_HOSTED_DEPLOYMENT.md). Do not use one shared instance for multiple mutually untrusted customers.
