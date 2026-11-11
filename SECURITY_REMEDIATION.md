# Security Remediation

## Admin login rate-limit memory growth

**Status:** Remediated and regression-tested.

Production admin login throttling now uses the atomic Redis Lua counter as its
only rate-limit storage. Successful checks and denials do not add requesting IPs
to the process-local `_login_attempts` dictionary. If Redis is unavailable in
production, login attempts fail closed with HTTP 503.

The in-memory fallback is used only when `APP_ENV=development`, where Redis is
intentionally not used for admin login throttling. Expired entries are removed
on each fallback check. The fallback is capped at 4,096 IP entries and evicts
the oldest entry when a new IP arrives at capacity. Successful development
logins clear their local entry; successful production logins clear the
corresponding Redis counter.

Regression coverage verifies that production Redis checks never populate local
storage, Redis denials remain effective, production Redis failures return 503,
development throttling works without querying Redis, expired entries are
cleaned, and local storage remains bounded under requests from many unique IPs.

See [SECURITY_TEST_REPORT.md](./SECURITY_TEST_REPORT.md) for the executed test
results. These changes address the reported memory-growth issue; they do not
constitute a guarantee that the application is free of other security risks.
