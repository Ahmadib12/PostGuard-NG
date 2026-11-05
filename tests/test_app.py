import hashlib
import hmac
import json
import os
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

    def signed_request(self, nonce=None, secret=None):
        client_id = "demo-client"
        timestamp = str(int(time.time()))
        nonce = nonce or uuid.uuid4().hex
        secret = secret or settings.client_secrets[client_id]
        payload = {
            "postcode": "FC-03-B06-AG-12",
            "level": 1,
            "client_lat": 0.0,
            "client_lon": 0.0,
            "declared_region": "Abuja",
        }
        body = json.dumps(payload, separators=(",", ":")).encode()
        prefix = (
            f"POST:/api/v1/secure-query:{client_id}:{timestamp}:{nonce}:"
        ).encode()
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
    async def test_signed_query_succeeds_and_geo_mismatch_is_advisory(
        self, _rate_limit, _register_nonce
    ):
        body, headers = self.signed_request()
        response = await self.client.post(
            "/api/v1/secure-query",
            content=body,
            headers=headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["nipost_data"]["source"], "mock")
        _register_nonce.assert_called_once()
        _rate_limit.assert_called_once()

    @patch("app.register_nonce")
    @patch("app.check_rate_limit")
    async def test_invalid_signature_does_not_consume_redis_controls(
        self, rate_limit, register_nonce
    ):
        body, headers = self.signed_request()
        headers["X-Signature"] = "0" * 64
        response = await self.client.post(
            "/api/v1/secure-query",
            content=body,
            headers=headers,
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        register_nonce.assert_not_called()
        rate_limit.assert_not_called()

    async def test_oversized_request_body_is_rejected(self):
        response = await self.client.post(
            "/api/v1/secure-query",
            content=b"x" * (settings.max_request_body_bytes + 1),
        )
        self.assertEqual(response.status_code, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    async def test_malformed_security_headers_are_rejected(self):
        body, headers = self.signed_request()
        headers["X-Nonce"] = "short"
        response = await self.client.post(
            "/api/v1/secure-query",
            content=body,
            headers=headers,
        )
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)


if __name__ == "__main__":
    unittest.main()
