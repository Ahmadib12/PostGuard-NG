# Security Test Report

## Admin login rate-limit memory-growth fix

The regression tests cover:

- Successful production Redis checks do not add the client IP to
  `_login_attempts`.
- Redis rate-limit denials remain effective and do not use local storage.
- Redis unavailability in production returns HTTP 503 without local fallback.
- Development uses the in-memory limiter without querying Redis.
- Expired development entries are removed.
- Development storage remains within its configured cap after requests from
  many unique IPs.

## Backend test suite

Command:

```text
pytest -q
```

Result: **92 passed, 1 skipped, 13 subtests passed**.

The skipped test is the existing Redis concurrency integration test, which
requires `RUN_REDIS_INTEGRATION_TESTS=1` and a configured reachable Redis
instance. The suite also reported existing deprecation warnings; there were no
test failures.

This report records automated test results only. It is not a comprehensive
security certification or a claim that no other vulnerabilities exist.
