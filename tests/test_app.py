import hashlib
import hmac
import json
import os
import threading
import time
import unittest
import uuid
from unittest.mock import patch

os.environ["POSTGUARD_DEMO_CLIENT_SECRET"] = "test-demo-secret-" + ("d" * 32)
os.environ["POSTGUARD_PARTNER_X_SECRET"] = "test-partner-secret-" + ("p" * 32)
os.environ["MOCK_NIPOST"] = "true"

import httpx
from fastapi import status

from app import app
from config import settings


class SecureQueryAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.lifespan = app.router.lifespan_context(app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        )

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)

    def signed_request(self, nonce=None, secret=None, client_id="demo-client", timestamp=None, payload=None):
        timestamp = timestamp or str(int(time.time()))
        nonce = nonce or uuid.uuid4().hex
        secret = secret or settings.client_secrets[client_id]
        payload = payload or {
            "postcode": "FC-03-B06-AG-12",
            "level": 1,
            "client_lat": 9.0,
            "client_lon": 7.0,
            "declared_region": "Abuja",
        }
        body = json.dumps(payload, separators=(",", ":")).encode()
        prefix = f"POST:/api/v1/secure-query:{client_id}:{timestamp}:{nonce}:".encode()
        signature = hmac.new(secret.encode(), prefix + body, hashlib.sha256).hexdigest()
        headers = {
            "X-Client-ID": client_id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature,
            "Content-Type": "application/json",
        }
        return body, headers

    @patch("app.register_nonce", return_value=True)
    @patch("app.check_rate_limit", return_value=True)
    async def test_valid_signed_request_succeeds(self, _rate_limit, _register_nonce):
        body, headers = self.signed_request()
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["nipost_data"]["source"], "mock")
        self.assertNotIn("security_score", response.json())
        _register_nonce.assert_called_once()
        _rate_limit.assert_called_once()

    @patch("app.register_nonce")
    @patch("app.check_rate_limit")
    async def test_invalid_signature_does_not_consume_redis_controls(self, rate_limit, register_nonce):
        body, headers = self.signed_request()
        headers["X-Signature"] = "0" * 64
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        register_nonce.assert_not_called()
        rate_limit.assert_not_called()

    async def test_expired_timestamp_is_rejected(self):
        body, headers = self.signed_request(timestamp=str(int(time.time()) - settings.max_clock_skew_seconds - 5))
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    async def test_future_timestamp_outside_skew_is_rejected(self):
        body, headers = self.signed_request(timestamp=str(int(time.time()) + settings.max_clock_skew_seconds + 5))
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    async def test_unknown_client_is_rejected(self):
        body, headers = self.signed_request(client_id="unknown-client", secret="a" * 32)
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    async def test_reused_nonce_is_rejected_after_rate_limit_check(self):
        checks = []

        def check_rate_limit(_client_id):
            checks.append("rate_limit")
            return True

        def register_nonce(_client_id, _nonce):
            checks.append("nonce")
            return False

        body, headers = self.signed_request()
        with patch("app.check_rate_limit", side_effect=check_rate_limit), patch(
            "app.register_nonce", side_effect=register_nonce
        ):
            response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(checks, ["rate_limit", "nonce"])

    async def test_malformed_nonce_is_rejected(self):
        body, headers = self.signed_request(nonce="bad!nonce")
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("app.check_rate_limit", return_value=False)
    async def test_rate_limit_is_enforced(self, _rate_limit):
        body, headers = self.signed_request()
        with patch("app.register_nonce") as register_nonce:
            response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        register_nonce.assert_not_called()

    async def test_invalid_region_is_rejected(self):
        body, headers = self.signed_request(payload={
            "postcode": "FC-03-B06-AG-12",
            "level": 1,
            "client_lat": 9.0,
            "client_lon": 7.0,
            "declared_region": "Kaduna",
        })
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    async def test_excessive_lookup_level_is_rejected(self):
        body, headers = self.signed_request(payload={
            "postcode": "FC-03-B06-AG-12",
            "level": 99,
            "client_lat": 9.0,
            "client_lon": 7.0,
            "declared_region": "Abuja",
        })
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    async def test_oversized_request_body_is_rejected(self):
        response = await self.client.post("/api/v1/secure-query", content=b"x" * (settings.max_request_body_bytes + 1))
        self.assertEqual(response.status_code, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    async def test_malformed_security_headers_are_rejected(self):
        body, headers = self.signed_request()
        headers["X-Nonce"] = "short"
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    async def test_invalid_json_is_rejected(self):
        response = await self.client.post(
            "/api/v1/secure-query",
            content=b'{bad json',
            headers={
                "Content-Type": "application/json",
                "X-Client-ID": "demo-client",
                "X-Timestamp": str(int(time.time())),
                "X-Nonce": "nonce1234567890",
                "X-Signature": "0" * 64,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    async def test_invalid_coordinates_are_rejected(self):
        body, headers = self.signed_request(payload={
            "postcode": "FC-03-B06-AG-12",
            "level": 1,
            "client_lat": 500.0,
            "client_lon": 7.0,
            "declared_region": "Abuja",
        })
        response = await self.client.post("/api/v1/secure-query", content=body, headers=headers)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    async def test_health_and_readiness_report_dependency_status(self):
        ping_threads = []

        def ping():
            ping_threads.append(threading.get_ident())
            return True

        with patch("security.redis_client.ping", side_effect=ping):
            response = await self.client.get("/health")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        body = response.json()
        self.assertIn("readiness", body)
        self.assertIn("upstream", body)
        self.assertIn("status", body)
        self.assertTrue(body["readiness"]["ready"])
        self.assertNotEqual(ping_threads[0], threading.get_ident())


if __name__ == "__main__":
    unittest.main()
