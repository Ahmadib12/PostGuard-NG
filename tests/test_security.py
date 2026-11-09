import asyncio
import hashlib
import hmac
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, patch

os.environ["POSTGUARD_DEMO_CLIENT_SECRET"] = "test-demo-secret-" + ("d" * 32)
os.environ["POSTGUARD_PARTNER_X_SECRET"] = "test-partner-secret-" + ("p" * 32)
os.environ["MOCK_NIPOST"] = "true"
os.environ["DASHBOARD_DATABASE_URL"] = "sqlite:///:memory:"

import redis
import httpx
from fastapi import HTTPException

import security
from config import Settings, _env_bool, settings
from security import (
    _RATE_LIMIT_SCRIPT,
    _REGISTER_NONCE_SCRIPT,
    _REQUEST_CONTROLS_SCRIPT,
    _client_key,
    _nonce_key,
    check_rate_limit,
    check_rate_limit_and_register_nonce,
    detect_geo_anomaly,
    proxy_to_nipost,
    register_nonce,
    redis_client,
    validate_client_policy,
    verify_hmac_signature,
)


class SecurityCoreTests(unittest.TestCase):
    def make_signature(self, body: bytes, client_id: str = "demo-client", timestamp: str | None = None, nonce: str = "nonce123456789012") -> str:
        timestamp = timestamp or str(int(time.time()))
        prefix = f"POST:/api/v1/secure-query:{client_id}:{timestamp}:{nonce}:".encode()
        return hmac.new(settings.client_secrets[client_id].encode(), prefix + body, hashlib.sha256).hexdigest()

    def test_valid_signature_is_accepted(self):
        body = b'{"postcode":"FC-03-B06-AG-12","level":1,"client_lat":9.0,"client_lon":7.0,"declared_region":"Abuja"}'
        timestamp = str(int(time.time()))
        signature = self.make_signature(body, timestamp=timestamp)
        self.assertTrue(verify_hmac_signature(body, "demo-client", timestamp, "nonce123456789012", signature, "POST", "/api/v1/secure-query"))

    def test_invalid_signature_is_rejected(self):
        body = b'{"postcode":"FC-03-B06-AG-12"}'
        self.assertFalse(verify_hmac_signature(body, "demo-client", str(int(time.time())), "nonce123456789012", "0" * 64, "POST", "/api/v1/secure-query"))

    def test_expired_timestamp_is_rejected(self):
        stale = str(int(time.time()) - settings.max_clock_skew_seconds - 5)
        body = b'{"postcode":"FC-03-B06-AG-12"}'
        signature = self.make_signature(body, timestamp=stale)
        self.assertFalse(verify_hmac_signature(body, "demo-client", stale, "nonce123456789012", signature, "POST", "/api/v1/secure-query"))

    def test_future_timestamp_outside_skew_is_rejected(self):
        future = str(int(time.time()) + settings.max_clock_skew_seconds + 5)
        body = b'{"postcode":"FC-03-B06-AG-12"}'
        signature = self.make_signature(body, timestamp=future)
        self.assertFalse(verify_hmac_signature(body, "demo-client", future, "nonce123456789012", signature, "POST", "/api/v1/secure-query"))

    def test_unknown_client_is_rejected(self):
        body = b'{"postcode":"FC-03-B06-AG-12"}'
        self.assertFalse(verify_hmac_signature(body, "unknown-client", str(int(time.time())), "nonce123456789012", "0" * 64, "POST", "/api/v1/secure-query"))

    def test_invalid_nonce_format_is_rejected(self):
        body = b'{"postcode":"FC-03-B06-AG-12"}'
        signature = self.make_signature(body)
        self.assertFalse(verify_hmac_signature(body, "demo-client", str(int(time.time())), "bad!nonce", signature, "POST", "/api/v1/secure-query"))

    @patch("security.redis_client.eval", return_value=1)
    def test_nonce_registration_checks_legacy_and_hashed_keys_atomically(self, eval_script):
        self.assertTrue(register_nonce("demo-client", "unique-nonce"))
        eval_script.assert_called_once_with(
            _REGISTER_NONCE_SCRIPT,
            2,
            f"postguard:v1:nonce:{_client_key('demo-client')}:{_nonce_key('unique-nonce')}",
            "postguard:nonce:demo-client:unique-nonce",
            settings.nonce_ttl_seconds,
        )

    @patch("security.redis_client.eval", return_value=11)
    def test_rate_limit_uses_atomic_counter(self, eval_script):
        self.assertFalse(check_rate_limit("demo-client"))
        eval_script.assert_called_once_with(
            _RATE_LIMIT_SCRIPT,
            1,
            f"postguard:v1:rate:{_client_key('demo-client')}",
            settings.rate_limit_window_seconds,
        )

    @patch("security.redis_client.eval", side_effect=redis.RedisError("unavailable"))
    def test_rate_limit_fails_closed_when_redis_is_unavailable(self, _eval_script):
        with self.assertRaises(HTTPException) as raised:
            check_rate_limit("demo-client")
        self.assertEqual(raised.exception.status_code, 503)

    @patch("security.redis_client.eval", return_value=1)
    def test_request_controls_are_atomic_in_one_script(self, eval_script):
        self.assertEqual(check_rate_limit_and_register_nonce("demo-client", "unique-nonce"), "allowed")
        eval_script.assert_called_once_with(
            _REQUEST_CONTROLS_SCRIPT,
            4,
            f"postguard:v1:rate:{_client_key('demo-client')}",
            "postguard:rate:demo-client",
            f"postguard:v1:nonce:{_client_key('demo-client')}:{_nonce_key('unique-nonce')}",
            "postguard:nonce:demo-client:unique-nonce",
            settings.rate_limit_window_seconds,
            settings.client_policy["demo-client"]["rate_limit_per_minute"],
            settings.nonce_ttl_seconds,
        )

    @patch("security.redis_client.eval", side_effect=[0, -1])
    def test_request_controls_distinguish_rate_limit_and_replay(self, _eval_script):
        self.assertEqual(check_rate_limit_and_register_nonce("demo-client", "nonce-a"), "rate_limited")
        self.assertEqual(check_rate_limit_and_register_nonce("demo-client", "nonce-b"), "replay")

    @patch("security.redis_client.eval", side_effect=redis.RedisError("unavailable"))
    def test_request_controls_fail_closed_when_redis_is_unavailable(self, _eval_script):
        with self.assertRaises(HTTPException) as raised:
            check_rate_limit_and_register_nonce("demo-client", "unique-nonce")
        self.assertEqual(raised.exception.status_code, 503)

    @patch("security.redis_client.eval", return_value=0)
    def test_existing_nonce_is_rejected(self, eval_script):
        self.assertFalse(register_nonce("demo-client", "unique-nonce"))
        eval_script.assert_called_once_with(
            _REGISTER_NONCE_SCRIPT,
            2,
            f"postguard:v1:nonce:{_client_key('demo-client')}:{_nonce_key('unique-nonce')}",
            "postguard:nonce:demo-client:unique-nonce",
            settings.nonce_ttl_seconds,
        )

    @patch("security.redis_client.eval", side_effect=redis.RedisError("unavailable"))
    def test_nonce_registration_fails_closed_when_redis_is_unavailable(self, _eval_script):
        with self.assertRaises(HTTPException) as raised:
            register_nonce("demo-client", "unique-nonce")
        self.assertEqual(raised.exception.status_code, 503)

    def test_client_policy_validates_region_and_level(self):
        validate_client_policy("demo-client", "Abuja", 2)
        with self.assertRaises(HTTPException):
            validate_client_policy("demo-client", "Kaduna", 1)
        with self.assertRaises(HTTPException):
            validate_client_policy("demo-client", "Abuja", 99)

    def test_geo_anomaly_is_advisory_only(self):
        self.assertEqual(detect_geo_anomaly("FC-03-B06-AG-12", "Abuja", 9.1, 7.1), None)
        self.assertEqual(detect_geo_anomaly("FC-03-B06-AG-12", "Lagos", 6.5244, 3.3792), None)
        self.assertEqual(detect_geo_anomaly("NG-01-ABC-99", "Kaduna", 10.5, 7.4), None)
        self.assertEqual(detect_geo_anomaly("NG-01-ABC-99", "Kaduna", 91.0, 7.4), "GEO_FENCE_MISMATCH")

    def test_env_bool_accepts_only_documented_values(self):
        for value in ("true", "1", "yes", "on", " TRUE "):
            with self.subTest(value=value), patch.dict(os.environ, {"TEST_BOOL": value}):
                self.assertTrue(_env_bool("TEST_BOOL", False))
        for value in ("false", "0", "no", "off", " FALSE "):
            with self.subTest(value=value), patch.dict(os.environ, {"TEST_BOOL": value}):
                self.assertFalse(_env_bool("TEST_BOOL", True))
        with patch.dict(os.environ, {"TEST_BOOL": "perhaps"}):
            with self.assertRaisesRegex(ValueError, "TEST_BOOL must be one of"):
                _env_bool("TEST_BOOL", False)

    def test_mock_upstream_is_the_default(self):
        self.assertTrue(Settings().mock_nipost)

    def test_invalid_deployment_mode_fails_validation(self):
        configured = Settings(deployment_mode="shared")
        with self.assertRaisesRegex(RuntimeError, "POSTGUARD_DEPLOYMENT_MODE"):
            configured.validate()

    def test_customer_hosted_is_the_deployment_mode_default(self):
        self.assertEqual(Settings().deployment_mode, "customer_hosted")

    def test_managed_deployment_mode_is_an_explicit_valid_setting(self):
        configured = Settings(deployment_mode="managed")
        configured.validate()
        self.assertEqual(configured.deployment_mode, "managed")

    def test_client_organization_mapping_requires_configured_client_ids(self):
        configured = Settings(client_organization_ids={"unknown-client": "tenant-a"})
        with self.assertRaisesRegex(RuntimeError, "unknown client"):
            configured.validate()

    def test_live_upstream_rejects_private_ip_literals(self):
        configured = Settings(
            mock_nipost=False,
            nipost_api_key="test-api-key",
            nipost_base_url="https://127.0.0.1",
        )
        with self.assertRaisesRegex(RuntimeError, "private or non-public IP"):
            configured.validate()

    def test_production_requires_explicit_secure_settings(self):
        configured = Settings(
            app_environment="production",
            admin_cookie_secure=False,
            trusted_hosts=("gateway.example",),
            admin_username="operations",
            admin_password="a-strong-administrator-password",
        )
        with patch.dict(os.environ, {"MOCK_NIPOST": "true"}):
            with self.assertRaisesRegex(RuntimeError, "ADMIN_COOKIE_SECURE"):
                configured.validate()

    def test_proxy_to_nipost_handles_failed_connect(self):
        async def run():
            async with httpx.AsyncClient() as client:
                with patch.object(security, "settings", security.settings.__class__(mock_nipost=False, nipost_api_key="abc", nipost_base_url="https://api.postcode.gov.ng")):
                    with patch.object(client, "send", new_callable=AsyncMock, side_effect=httpx.ConnectError("down")):
                        return await proxy_to_nipost("FC-03-B06-AG-12", 1, client)

        self.assertEqual(asyncio.run(run())["status"], "UPSTREAM_ERROR")

    def test_proxy_to_nipost_handles_timeout(self):
        async def run():
            async with httpx.AsyncClient() as client:
                with patch.object(security, "settings", security.settings.__class__(mock_nipost=False, nipost_api_key="abc", nipost_base_url="https://api.postcode.gov.ng")):
                    with patch.object(client, "send", new_callable=AsyncMock, side_effect=httpx.TimeoutException("timeout")):
                        return await proxy_to_nipost("FC-03-B06-AG-12", 1, client)

        self.assertEqual(asyncio.run(run())["status"], "UPSTREAM_ERROR")

    def test_proxy_to_nipost_handles_http_error_and_malformed_json(self):
        async def run_test(response):
            transport = httpx.MockTransport(lambda _request: response)
            async with httpx.AsyncClient(transport=transport) as client:
                return await proxy_to_nipost("FC-03-B06-AG-12", 1, client)

        with patch.object(security, "settings", security.settings.__class__(mock_nipost=False, nipost_api_key="abc", nipost_base_url="https://api.postcode.gov.ng")):
            error_result = asyncio.run(run_test(httpx.Response(502, text="sensitive upstream response")))
            malformed_result = asyncio.run(run_test(httpx.Response(200, text="not JSON")))
            object_result = asyncio.run(run_test(httpx.Response(200, json={"provider-defined": "value"})))
            non_object_result = asyncio.run(run_test(httpx.Response(200, json=["not", "an object"])))
            redirect_result = asyncio.run(run_test(httpx.Response(302, json={"unverified": True})))

        self.assertEqual(error_result["status"], "UPSTREAM_ERROR")
        self.assertEqual(malformed_result["status"], "UPSTREAM_ERROR")
        self.assertEqual(object_result["status"], "SUCCESS")
        self.assertEqual(object_result["nipost_data"], {"provider-defined": "value"})
        self.assertEqual(non_object_result["status"], "UPSTREAM_ERROR")
        self.assertEqual(redirect_result["status"], "UPSTREAM_ERROR")

    def test_proxy_rejects_responses_over_configured_limit(self):
        async def run():
            transport = httpx.MockTransport(
                lambda _request: httpx.Response(200, content=b'{"large":"' + b"x" * 64 + b'"}')
            )
            async with httpx.AsyncClient(transport=transport) as client:
                configured_settings = security.settings.__class__(
                    mock_nipost=False,
                    nipost_api_key="abc",
                    nipost_base_url="https://api.postcode.gov.ng",
                    max_upstream_response_bytes=32,
                )
                with patch.object(security, "settings", configured_settings):
                    return await proxy_to_nipost("FC-03-B06-AG-12", 1, client)

        self.assertEqual(asyncio.run(run())["status"], "UPSTREAM_ERROR")

    def test_proxy_handles_upstream_read_errors(self):
        class FailingStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b'{"partial":'
                raise httpx.ReadError("upstream connection interrupted")

            async def aclose(self):
                return None

        async def run():
            transport = httpx.MockTransport(
                lambda _request: httpx.Response(200, stream=FailingStream())
            )
            async with httpx.AsyncClient(transport=transport) as client:
                configured_settings = security.settings.__class__(
                    mock_nipost=False,
                    nipost_api_key="abc",
                    nipost_base_url="https://api.postcode.gov.ng",
                )
                with patch.object(security, "settings", configured_settings):
                    return await proxy_to_nipost("FC-03-B06-AG-12", 1, client)

        result = asyncio.run(run())
        self.assertEqual(result["status"], "UPSTREAM_ERROR")
        self.assertEqual(result["status_code"], 502)

    def test_redis_key_material_does_not_expose_client_or_nonce(self):
        client_key = _client_key("demo-client")
        nonce_key = _nonce_key("unique-nonce")
        self.assertNotIn("demo-client", client_key)
        self.assertNotIn("unique-nonce", nonce_key)
        self.assertEqual(len(client_key), 64)
        self.assertEqual(len(nonce_key), 64)


@unittest.skipUnless(
    os.getenv("RUN_REDIS_INTEGRATION_TESTS") == "1",
    "Set RUN_REDIS_INTEGRATION_TESTS=1 to run against the configured Redis instance.",
)
class RedisConcurrencyIntegrationTests(unittest.TestCase):
    def test_request_controls_are_atomic_under_concurrency(self):
        try:
            redis_client.ping()
        except redis.RedisError as exc:
            self.skipTest(f"Redis is unavailable: {exc}")

        unique_id = f"integration-{os.getpid()}-{time.time_ns()}"
        client_key = _client_key(unique_id)
        nonce_key = f"postguard:v1:nonce:{client_key}:{_nonce_key('same-nonce-value')}"
        limited_nonce_key = f"postguard:v1:nonce:{client_key}:{_nonce_key('limited-nonce-value')}"
        rate_key = f"postguard:v1:rate:{client_key}"
        legacy_nonce_key = f"postguard:nonce:{unique_id}:same-nonce-value"
        legacy_limited_nonce_key = f"postguard:nonce:{unique_id}:limited-nonce-value"
        legacy_rate_key = f"postguard:rate:{unique_id}"
        try:
            with ThreadPoolExecutor(max_workers=32) as pool:
                results = list(pool.map(
                    lambda _: check_rate_limit_and_register_nonce(unique_id, "same-nonce-value"),
                    range(32),
                ))
            self.assertEqual(results.count("allowed"), 1)
            self.assertEqual(results.count("replay"), settings.rate_limit_per_minute - 1)
            self.assertEqual(results.count("rate_limited"), 32 - settings.rate_limit_per_minute)
            self.assertEqual(
                check_rate_limit_and_register_nonce(unique_id, "limited-nonce-value"),
                "rate_limited",
            )
            self.assertFalse(redis_client.exists(limited_nonce_key, legacy_limited_nonce_key))
        finally:
            redis_client.delete(
                nonce_key, limited_nonce_key, rate_key, legacy_nonce_key,
                legacy_limited_nonce_key, legacy_rate_key,
            )


if __name__ == "__main__":
    unittest.main()
