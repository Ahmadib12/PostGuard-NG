import asyncio
import hashlib
import hmac
import json
import os
import time
import unittest
import uuid
from unittest.mock import patch

os.environ["POSTGUARD_DEMO_CLIENT_SECRET"] = "dashboard-test-client-" + ("d" * 32)
os.environ["POSTGUARD_PARTNER_X_SECRET"] = "dashboard-test-partner-" + ("p" * 32)
os.environ["MOCK_NIPOST"] = "true"

import httpx
from fastapi import status
from sqlalchemy.exc import SQLAlchemyError

import admin_api
from app import app
from config import settings
from dashboard_store import (
    AdminCredential,
    AdminSession,
    AuditLog,
    RequestRecord,
    SecurityEvent,
    SessionLocal,
    initialize_admin_credentials,
    overview,
    record_request,
    record_security_event,
)


class DashboardAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        object.__setattr__(settings, "admin_username", "operations-admin")
        object.__setattr__(settings, "admin_password", "Dashboard-Test-Password-95!")
        object.__setattr__(settings, "admin_cookie_secure", False)
        admin_api._configured_password_salt = b"dashboard-unit-test-salt-32bytes"
        admin_api._configured_password_hash = hashlib.scrypt(
            settings.admin_password.encode(),
            salt=admin_api._configured_password_salt,
            n=2**14,
            r=8,
            p=1,
        )
        admin_api._login_attempts.clear()
        with SessionLocal() as db:
            db.query(SecurityEvent).delete()
            db.query(RequestRecord).delete()
            db.query(AdminSession).delete()
            db.query(AuditLog).delete()
            db.query(AdminCredential).delete()
            db.commit()
        self.lifespan = app.router.lifespan_context(app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        )

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)

    async def login(self):
        response = await self.client.post(
            "/api/admin/login",
            json={"username": settings.admin_username, "password": settings.admin_password},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.text)
        return response.json()["csrf_token"]

    async def test_admin_login_sets_secure_session_and_audits_without_credentials(self):
        response = await self.client.post(
            "/api/admin/login",
            json={"username": settings.admin_username, "password": settings.admin_password},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(settings.admin_password, response.text)
        self.assertIn("httponly", response.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", response.headers["set-cookie"].lower())
        audit = (await self.client.get("/api/admin/audit-logs")).json()["items"]
        self.assertEqual(audit[0]["action"], "login")
        self.assertEqual(audit[0]["actor"], settings.admin_username)

    async def test_first_start_generates_and_persists_unique_admin_credential(self):
        object.__setattr__(settings, "admin_username", "")
        object.__setattr__(settings, "admin_password", "")
        credentials = await asyncio.to_thread(initialize_admin_credentials)
        self.assertIsNotNone(credentials)
        username, password = credentials
        self.assertEqual(username, "admin")
        self.assertGreaterEqual(len(password), 16)
        self.assertTrue(admin_api._verify_admin(username, password))
        with SessionLocal() as db:
            stored = db.get(AdminCredential, "primary")
            self.assertNotIn(password.encode(), stored.password_hash)
        self.assertIsNone(await asyncio.to_thread(initialize_admin_credentials))

    async def test_invalid_admin_credentials_are_rejected_and_audited(self):
        response = await self.client.post(
            "/api/admin/login",
            json={"username": settings.admin_username, "password": "incorrect-password"},
        )
        self.assertEqual(response.status_code, 401)
        with SessionLocal() as db:
            self.assertEqual(db.query(AuditLog).filter_by(action="login_failed").count(), 1)

    async def test_unauthorized_dashboard_requests_are_rejected(self):
        for path in ("/api/admin/overview", "/api/admin/events", "/api/admin/clients"):
            with self.subTest(path=path):
                response = await self.client.get(path)
                self.assertEqual(response.status_code, 401)

    async def test_logout_requires_csrf_and_invalidates_session(self):
        csrf = await self.login()
        forbidden = await self.client.post("/api/admin/logout")
        self.assertEqual(forbidden.status_code, 403)
        response = await self.client.post("/api/admin/logout", headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await self.client.get("/api/admin/session")).status_code, 401)
        with SessionLocal() as db:
            self.assertEqual(db.query(AuditLog).filter_by(action="logout").count(), 1)

    async def test_dashboard_metrics_and_client_activity_use_persisted_requests(self):
        record_request("req-success", "demo-client", 200, 21, True)
        record_request("req-blocked", "demo-client", 403, 5, True)
        record_request("req-anonymous", "new-client", 401, 2, False)
        record_security_event("CLIENT_POLICY_VIOLATION", "req-blocked", "demo-client", 403, region="abuja")
        csrf = await self.login()
        headers = {"X-CSRF-Token": csrf}

        response = await self.client.get("/api/admin/overview?hours=24", headers=headers)
        self.assertEqual(response.status_code, 200)
        metrics = response.json()
        self.assertEqual(metrics["total_requests"], 3)
        self.assertEqual(metrics["successful_requests"], 1)
        self.assertEqual(metrics["failed_requests"], 2)
        self.assertEqual(metrics["authenticated_clients"], 1)
        self.assertEqual(metrics["blocked_requests"], 1)

        clients = (await self.client.get("/api/admin/clients")).json()["items"]
        configured = next(item for item in clients if item["client_id"] == "demo-client")
        self.assertEqual(configured["total_requests"], 2)
        self.assertEqual(configured["successful_requests"], 1)
        self.assertEqual(configured["blocked_requests"], 1)
        self.assertTrue(configured["authenticated_recently"])
        self.assertNotIn("new-client", {item["client_id"] for item in clients})
        self.assertNotIn("secret", json.dumps(clients).lower())
        self.assertNotIn("hmac", json.dumps(clients).lower())

        chart = await self.client.get("/api/admin/analytics?hours=1")
        self.assertEqual(sum(point["total"] for point in chart.json()["points"]), 3)
        self.assertEqual(sum(point["successful"] for point in chart.json()["points"]), 1)

    async def test_secure_gateway_requests_feed_dashboard_metrics(self):
        await self.login()
        body = json.dumps({
            "postcode": "FC-03-B06-AG-12",
            "level": 1,
            "client_lat": 9.0,
            "client_lon": 7.0,
            "declared_region": "Abuja",
        }, separators=(",", ":")).encode()
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        prefix = f"POST:/api/v1/secure-query:demo-client:{timestamp}:{nonce}:".encode()
        signature = hmac.new(settings.client_secrets["demo-client"].encode(), prefix + body, hashlib.sha256).hexdigest()
        with patch("app.check_rate_limit_and_register_nonce", return_value="allowed"):
            result = await self.client.post(
                "/api/v1/secure-query",
                content=body,
                headers={
                    "X-Client-ID": "demo-client",
                    "X-Timestamp": timestamp,
                    "X-Nonce": nonce,
                    "X-Signature": signature,
                    "Content-Type": "application/json",
                },
            )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["security"]["upstream_source"], "mock")
        metrics = (await self.client.get("/api/admin/overview")).json()
        self.assertEqual(metrics["total_requests"], 1)
        self.assertEqual(metrics["successful_requests"], 1)
        self.assertEqual(metrics["authenticated_clients"], 1)
        clients = (await self.client.get("/api/admin/clients")).json()["items"]
        demo_client = next(item for item in clients if item["client_id"] == "demo-client")
        self.assertEqual(demo_client["authenticated_requests"], 1)

    async def test_security_events_persist_replay_and_suspicious_reports(self):
        record_security_event("REPLAY_DETECTED", "replay-1", "demo-client", 409)
        record_security_event(
            "INVALID_SIGNATURE",
            "signature-1",
            "demo-client",
            403,
            signature="must-not-persist",
            authorization="must-not-persist",
            region="lagos",
        )
        csrf = await self.login()
        replay = await self.client.get("/api/admin/security/replays", headers={"X-CSRF-Token": csrf})
        suspicious = await self.client.get("/api/admin/security/suspicious")
        self.assertEqual(replay.json()["total"], 1)
        self.assertEqual(replay.json()["items"][0]["event_type"], "REPLAY_DETECTED")
        self.assertEqual(suspicious.json()["total"], 1)
        self.assertNotIn("must-not-persist", suspicious.text)
        self.assertEqual(suspicious.json()["items"][0]["metadata"], {"region": "lagos"})

    async def test_event_pagination_filtering_and_date_validation(self):
        await self.login()
        for index in range(3):
            record_security_event(
                "REPLAY_DETECTED" if index < 2 else "INVALID_NONCE",
                f"filtered-{index}",
                "demo-client" if index != 1 else "partner-x",
                409 if index < 2 else 400,
            )
        response = await self.client.get(
            "/api/admin/events?page=1&page_size=1&event_type=REPLAY_DETECTED&client_id=demo-client"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(response.json()["page_size"], 1)
        bad_range = await self.client.get(
            "/api/admin/events?since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z"
        )
        self.assertEqual(bad_range.status_code, 400)
        oversized = await self.client.get("/api/admin/events?page_size=500")
        self.assertEqual(oversized.status_code, 422)

    async def test_login_rate_limit_is_enforced(self):
        for _ in range(settings.admin_login_attempts):
            await self.client.post("/api/admin/login", json={"username": "bad", "password": "wrong"})
        blocked = await self.client.post("/api/admin/login", json={"username": "bad", "password": "wrong"})
        self.assertEqual(blocked.status_code, 429)

    async def test_database_errors_return_consistent_service_error(self):
        await self.login()
        with patch.object(admin_api, "overview", side_effect=SQLAlchemyError("sensitive database detail")):
            response = await self.client.get("/api/admin/overview")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"]["code"], "dashboard_storage_unavailable")
        self.assertNotIn("sensitive database detail", response.text)

    async def test_health_endpoint_reports_monitored_dependency_status(self):
        await self.login()
        with patch.object(admin_api.redis_client, "ping", return_value=True):
            response = await self.client.get("/api/admin/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["redis"], "ok")
        self.assertEqual(response.json()["database"], "ok")
        self.assertEqual(response.json()["upstream"], "mock_mode")
        self.assertTrue(response.json()["upstream_is_mock"])

    async def test_failed_telemetry_does_not_change_security_enforcement(self):
        body = b'{"postcode":"FC-03-B06-AG-12","level":1,"client_lat":9,"client_lon":7,"declared_region":"Abuja"}'
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        with patch("app.record_security_event", side_effect=SQLAlchemyError("telemetry unavailable")):
            response = await self.client.post(
                "/api/v1/secure-query",
                content=body,
                headers={
                    "X-Client-ID": "demo-client",
                    "X-Timestamp": timestamp,
                    "X-Nonce": nonce,
                    "X-Signature": "0" * 64,
                    "Content-Type": "application/json",
                },
            )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
