import asyncio
import hashlib
import hmac
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

os.environ["POSTGUARD_DEMO_CLIENT_SECRET"] = "test-demo-secret-" + ("d" * 32)
os.environ["POSTGUARD_PARTNER_X_SECRET"] = "test-partner-secret-" + ("p" * 32)
os.environ["MOCK_NIPOST"] = "true"

import redis
import httpx
from fastapi import HTTPException

from config import settings
from security import (
    _RATE_LIMIT_SCRIPT,
    check_rate_limit,
    proxy_to_nipost,
    register_nonce,
    redis_client,
    verify_hmac_signature,
)


class RedisProtectionTests(unittest.TestCase):
    @patch("security.redis_client.set", return_value=True)
    def test_nonce_registration_is_atomic(self, set_nonce):
        self.assertTrue(register_nonce("demo-client", "unique-nonce"))
        set_nonce.assert_called_once_with(
            "postguard:nonce:demo-client:unique-nonce",
            "1",
            ex=settings.nonce_ttl_seconds,
            nx=True,
        )

    @patch("security.redis_client.eval", return_value=11)
    def test_rate_limit_uses_atomic_counter(self, eval_script):
        self.assertFalse(check_rate_limit("demo-client"))
        eval_script.assert_called_once_with(
            _RATE_LIMIT_SCRIPT,
            1,
            "postguard:rate:demo-client",
        )

    @patch("security.redis_client.eval", side_effect=redis.RedisError("unavailable"))
    def test_rate_limit_fails_closed_when_redis_is_unavailable(self, _eval_script):
        with self.assertRaises(HTTPException) as raised:
            check_rate_limit("demo-client")
        self.assertEqual(raised.exception.status_code, 503)

    @patch("security.redis_client.set", return_value=None)
    def test_existing_nonce_is_rejected(self, set_nonce):
        self.assertFalse(register_nonce("demo-client", "unique-nonce"))
        set_nonce.assert_called_once()

    @patch("security.redis_client.set", side_effect=redis.RedisError("unavailable"))
    def test_nonce_registration_fails_closed_when_redis_is_unavailable(self, _set_nonce):
        with self.assertRaises(HTTPException) as raised:
            register_nonce("demo-client", "unique-nonce")
        self.assertEqual(raised.exception.status_code, 503)

    def test_signatures_use_the_selected_clients_secret(self):
        timestamp = str(int(time.time()))
        body = b'{"value":"signed"}'
        prefix = f"POST:/api/v1/secure-query:demo-client:{timestamp}:nonce1234567890:".encode()
        signature = hmac.new(
            settings.client_secrets["demo-client"].encode(),
            prefix + body,
            hashlib.sha256,
        ).hexdigest()
        self.assertTrue(
            verify_hmac_signature(
                body, "demo-client", timestamp, "nonce1234567890", signature,
                "POST", "/api/v1/secure-query",
            )
        )
        self.assertFalse(
            verify_hmac_signature(
                body, "partner-x", timestamp, "nonce1234567890", signature,
                "POST", "/api/v1/secure-query",
            )
        )

    def test_upstream_error_body_is_not_returned_to_callers(self):
        async def run_test(response):
            transport = httpx.MockTransport(lambda _request: response)
            async with httpx.AsyncClient(transport=transport) as client:
                return await proxy_to_nipost("FC-03-B06-AG-12", 1, client)

        with patch(
            "security.settings",
            SimpleNamespace(mock_nipost=False, nipost_api_key="test-api-key"),
        ):
            error_result = asyncio.run(
                run_test(httpx.Response(502, text="sensitive upstream response"))
            )
            malformed_result = asyncio.run(run_test(httpx.Response(200, text="not JSON")))
        self.assertEqual(
            error_result,
            {"status": "UPSTREAM_ERROR", "nipost_status_code": 502},
        )
        self.assertNotIn("sensitive upstream response", str(error_result))
        self.assertEqual(
            malformed_result,
            {"status": "UPSTREAM_ERROR", "nipost_status_code": 200},
        )


@unittest.skipUnless(
    os.getenv("RUN_REDIS_INTEGRATION_TESTS") == "1",
    "Set RUN_REDIS_INTEGRATION_TESTS=1 to run against the configured Redis instance.",
)
class RedisConcurrencyIntegrationTests(unittest.TestCase):
    def test_nonce_and_rate_limit_are_atomic_under_concurrency(self):
        try:
            redis_client.ping()
        except redis.RedisError as exc:
            self.skipTest(f"Redis is unavailable: {exc}")

        unique_id = f"integration-{os.getpid()}-{time.time_ns()}"
        nonce_key = f"postguard:nonce:{unique_id}:same-nonce-value"
        rate_key = f"postguard:rate:{unique_id}"
        try:
            with ThreadPoolExecutor(max_workers=32) as pool:
                nonce_results = list(
                    pool.map(lambda _: register_nonce(unique_id, "same-nonce-value"), range(32))
                )
                rate_results = list(pool.map(lambda _: check_rate_limit(unique_id), range(32)))
            self.assertEqual(sum(nonce_results), 1)
            self.assertEqual(sum(rate_results), settings.rate_limit_per_minute)
        finally:
            redis_client.delete(nonce_key, rate_key)


if __name__ == "__main__":
    unittest.main()
