import asyncio
import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

os.environ["POSTGUARD_DEMO_CLIENT_SECRET"] = "dashboard-test-client-" + ("d" * 32)
os.environ["POSTGUARD_PARTNER_X_SECRET"] = "dashboard-test-partner-" + ("p" * 32)
os.environ["MOCK_NIPOST"] = "true"
os.environ["DASHBOARD_DATABASE_URL"] = "sqlite:///:memory:"

import httpx
import redis
from fastapi import HTTPException, status
from starlette.requests import Request
from sqlalchemy.exc import SQLAlchemyError

import admin_api
from app import app, _write_bootstrap_credentials
from config import settings
from dashboard_store import (
    AdminAccount,
    AdminCredential,
    AdminIAMSession,
    AdminSession,
    AuditLog,
    AuditChainState,
    OrganizationAdminMembership,
    Organization,
    RequestRecord,
    SecurityEvent,
    SecurityIncident,
    SessionLocal,
    initialize_database,
    overview,
    record_audit,
    record_request,
    record_security_event,
    verify_audit_chain,
)
from iam import create_admin_session, create_generated_platform_admin, set_organization_status
from intelligence import investigate_incidents


class DashboardAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        object.__setattr__(settings, "admin_username", "operations-admin")
        object.__setattr__(settings, "admin_password", "Dashboard-Test-Password-95!")
        object.__setattr__(settings, "admin_cookie_secure", False)
        admin_api._login_attempts.clear()
        await asyncio.to_thread(initialize_database)
        with SessionLocal() as db:
            db.query(SecurityEvent).delete()
            db.query(RequestRecord).delete()
            db.query(AdminSession).delete()
            db.query(AdminIAMSession).delete()
            db.query(AuditLog).delete()
            db.query(OrganizationAdminMembership).delete()
            db.query(AdminAccount).delete()
            db.query(AdminCredential).delete()
            state = db.get(AuditChainState, 1)
            state.sequence = 0
            state.digest = "0" * 64
            salt = b"dashboard-unit-test-salt-32bytes"
            now = datetime.now(timezone.utc)
            account = AdminAccount(
                id="dashboard-test-admin",
                username=settings.admin_username,
                password_salt=salt,
                password_hash=hashlib.scrypt(
                    settings.admin_password.encode(),
                    salt=salt,
                    n=2**14,
                    r=8,
                    p=1,
                    dklen=64,
                ),
                active=True,
                platform_super_admin=False,
                must_change_password=False,
                created_at=now,
                updated_at=now,
            )
            db.add(account)
            db.add(OrganizationAdminMembership(
                admin_id=account.id,
                organization_id="default",
                role="organization_owner",
                created_at=now,
            ))
            db.commit()
        self.lifespan = app.router.lifespan_context(app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
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
        self.assertEqual(response.json()["organization_id"], "default")
        self.assertNotIn(settings.admin_password, response.text)
        self.assertIn("httponly", response.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", response.headers["set-cookie"].lower())
        audit = (await self.client.get("/api/admin/audit-logs")).json()["items"]
        self.assertEqual(audit[0]["action"], "login")
        self.assertEqual(audit[0]["actor"], settings.admin_username)

    async def test_first_start_generates_and_persists_platform_admin(self):
        legacy_salt = b"legacy-singleton-salt-32bytes!!"
        legacy_password = "Legacy-Old-Password-802!"
        with SessionLocal() as db:
            db.query(OrganizationAdminMembership).delete()
            db.query(AdminAccount).delete()
            db.add(AdminCredential(
                id="primary",
                username="legacy-admin",
                password_salt=legacy_salt,
                password_hash=hashlib.scrypt(
                    legacy_password.encode(),
                    salt=legacy_salt,
                    n=2**14,
                    r=8,
                    p=1,
                    dklen=64,
                ),
                created_at=datetime.now(timezone.utc),
            ))
            db.commit()
        self.assertIsNone(await asyncio.to_thread(
            create_admin_session,
            "legacy-admin",
            legacy_password,
            "default",
        ))
        credentials = await asyncio.to_thread(create_generated_platform_admin)
        self.assertIsNotNone(credentials)
        admin_id, username, password = credentials
        self.assertEqual(username, "platform-admin")
        self.assertGreaterEqual(len(password), 16)
        self.assertIsNotNone(await asyncio.to_thread(create_admin_session, username, password, "default"))
        with SessionLocal() as db:
            stored = db.get(AdminAccount, admin_id)
            self.assertNotIn(password.encode(), stored.password_hash)
            self.assertIsNotNone(db.get(AdminCredential, "primary"))
        self.assertIsNone(await asyncio.to_thread(create_generated_platform_admin))

    async def test_failed_bootstrap_file_write_removes_generated_admin_credential(self):
        with SessionLocal() as db:
            db.query(OrganizationAdminMembership).delete()
            db.query(AdminAccount).delete()
            db.commit()
        original_username = settings.admin_username
        original_password = settings.admin_password
        object.__setattr__(settings, "admin_username", "")
        object.__setattr__(settings, "admin_password", "")
        with patch("app._write_bootstrap_credentials", side_effect=OSError("read-only filesystem")):
            with self.assertRaisesRegex(OSError, "read-only filesystem"):
                async with app.router.lifespan_context(app):
                    self.fail("Application startup should fail when credentials cannot be persisted.")
        with SessionLocal() as db:
            self.assertEqual(db.query(AdminAccount).count(), 0)
        object.__setattr__(settings, "admin_username", original_username)
        object.__setattr__(settings, "admin_password", original_password)

    def test_successful_redis_login_rate_checks_do_not_use_local_storage(self):
        ip_address = "203.0.113.8"
        expected_key = f"postguard:v1:admin-login:{hashlib.sha256(ip_address.encode('utf-8')).hexdigest()}"
        original_environment = settings.app_environment
        object.__setattr__(settings, "app_environment", "production")
        try:
            with patch("admin_api.redis_client.eval", return_value=1) as mock_eval:
                self.assertTrue(admin_api._permit_login(ip_address))
            mock_eval.assert_called_once_with(
                admin_api._LOGIN_RATE_LIMIT_SCRIPT,
                1,
                expected_key,
                settings.admin_login_window_seconds,
                settings.admin_login_attempts,
            )
            self.assertNotIn(ip_address, admin_api._login_attempts)
        finally:
            object.__setattr__(settings, "app_environment", original_environment)

    def test_redis_rate_limit_rejects_excess_attempts_without_local_storage(self):
        ip_address = "203.0.113.10"
        original_environment = settings.app_environment
        object.__setattr__(settings, "app_environment", "production")
        try:
            with patch("admin_api.redis_client.eval", side_effect=[1, 0]) as mock_eval:
                self.assertTrue(admin_api._permit_login(ip_address))
                self.assertFalse(admin_api._permit_login(ip_address))
            self.assertEqual(mock_eval.call_count, 2)
            self.assertNotIn(ip_address, admin_api._login_attempts)
        finally:
            object.__setattr__(settings, "app_environment", original_environment)

    def test_admin_login_rate_limit_fails_closed_in_production(self):
        original_environment = settings.app_environment
        object.__setattr__(settings, "app_environment", "production")
        try:
            with patch("admin_api.redis_client.eval", side_effect=redis.RedisError("down")):
                with self.assertRaises(HTTPException) as raised:
                    admin_api._permit_login("203.0.113.9")
            self.assertEqual(raised.exception.status_code, 503)
            self.assertNotIn("203.0.113.9", admin_api._login_attempts)
        finally:
            object.__setattr__(settings, "app_environment", original_environment)

    def test_development_login_rate_limit_uses_local_fallback(self):
        ip_address = "203.0.113.11"
        original_environment = settings.app_environment
        object.__setattr__(settings, "app_environment", "development")
        try:
            with patch("admin_api.redis_client.eval", side_effect=redis.RedisError("should not be called")) as mock_eval:
                for _ in range(settings.admin_login_attempts):
                    self.assertTrue(admin_api._permit_login(ip_address))
                self.assertFalse(admin_api._permit_login(ip_address))
            mock_eval.assert_not_called()
            self.assertEqual(len(admin_api._login_attempts[ip_address]), settings.admin_login_attempts)
        finally:
            object.__setattr__(settings, "app_environment", original_environment)

    def test_development_login_rate_limit_cleans_expired_entries(self):
        original_environment = settings.app_environment
        object.__setattr__(settings, "app_environment", "development")
        try:
            expired_ip = "203.0.113.12"
            admin_api._login_attempts[expired_ip] = [
                time.monotonic() - settings.admin_login_window_seconds - 1
            ]
            self.assertTrue(admin_api._permit_login("203.0.113.13"))
            self.assertNotIn(expired_ip, admin_api._login_attempts)
        finally:
            object.__setattr__(settings, "app_environment", original_environment)

    def test_development_login_fallback_bounds_unique_ip_storage(self):
        original_environment = settings.app_environment
        object.__setattr__(settings, "app_environment", "development")
        try:
            with patch.object(admin_api, "_MAX_LOCAL_LOGIN_IPS", 32):
                for index in range(128):
                    self.assertTrue(admin_api._permit_login(f"198.51.100.{index}"))
                self.assertEqual(len(admin_api._login_attempts), 32)
        finally:
            object.__setattr__(settings, "app_environment", original_environment)

    def test_intelligence_rate_limit_enforces_three_requests_per_minute(self):
        admin_api._intelligence_attempts.clear()
        try:
            for _ in range(3):
                self.assertTrue(admin_api._permit_intelligence("admin-one"))
            self.assertFalse(admin_api._permit_intelligence("admin-one"))
        finally:
            admin_api._intelligence_attempts.clear()

    def test_intelligence_rate_limit_cleans_expired_admin_entries(self):
        admin_api._intelligence_attempts.clear()
        try:
            admin_api._intelligence_attempts["expired-admin"] = [
                time.monotonic() - 61
            ]
            self.assertTrue(admin_api._permit_intelligence("active-admin"))
            self.assertNotIn("expired-admin", admin_api._intelligence_attempts)
        finally:
            admin_api._intelligence_attempts.clear()

    def test_intelligence_rate_limit_bounds_unique_admin_storage(self):
        admin_api._intelligence_attempts.clear()
        try:
            with patch.object(admin_api, "_MAX_INTELLIGENCE_ADMINS", 32):
                for index in range(128):
                    self.assertTrue(admin_api._permit_intelligence(f"admin-{index}"))
                self.assertEqual(len(admin_api._intelligence_attempts), 32)
        finally:
            admin_api._intelligence_attempts.clear()

    async def test_login_throttle_uses_forwarded_ip_only_for_configured_proxy(self):
        original_proxies = settings.trusted_proxies
        object.__setattr__(settings, "trusted_proxies", ("172.30.0.0/24",))
        try:
            def request_from(peer, forwarded):
                scope = {
                    "type": "http",
                    "http_version": "1.1",
                    "method": "POST",
                    "scheme": "http",
                    "path": "/api/admin/login",
                    "raw_path": b"/api/admin/login",
                    "query_string": b"",
                    "headers": [(b"x-real-ip", forwarded.encode())],
                    "client": (peer, 12345),
                    "server": ("app", 8000),                }
                return admin_api._remote_address(Request(scope))

            self.assertEqual(request_from("172.30.0.2", "198.51.100.10"), "198.51.100.10")
            self.assertEqual(request_from("172.30.0.2", "not-an-ip"), "172.30.0.2")
            self.assertEqual(request_from("192.0.2.10", "198.51.100.10"), "192.0.2.10")
        finally:
            object.__setattr__(settings, "trusted_proxies", original_proxies)

    async def test_bootstrap_credentials_use_a_private_file_and_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "initial-admin.env")
            _write_bootstrap_credentials("admin", "one-time-test-password", path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with open(path, encoding="utf-8") as credential_file:
                content = credential_file.read()
            self.assertIn("ADMIN_USERNAME=admin", content)
            self.assertIn("ADMIN_PASSWORD=one-time-test-password", content)
            with self.assertRaises(FileExistsError):
                _write_bootstrap_credentials("admin", "replacement", path)

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

    async def test_dashboard_queries_are_scoped_to_the_session_organization(self):
        with SessionLocal() as db:
            db.add(Organization(
                id="tenant-b",
                slug="tenant-b",
                name="Tenant B",
                status="active",
                plan="development",
                limits_json="{}",
                created_at=datetime.now(timezone.utc),
            ))
            db.commit()
        record_request("other-tenant-request", "demo-client", 200, 1, True, "tenant-b")
        record_security_event(
            "REPLAY_DETECTED",
            "other-tenant-event",
            "demo-client",
            409,
            organization_id="tenant-b",
        )
        await self.login()

        overview_response = await self.client.get("/api/admin/overview")
        events_response = await self.client.get("/api/admin/events")
        self.assertEqual(overview_response.json()["total_requests"], 0)
        self.assertEqual(events_response.json()["total"], 0)

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

    async def test_incidents_are_deduplicated_and_scoped_to_the_session_organization(self):
        record_security_event("REPLAY_DETECTED", "replay-a", "demo-client", 409)
        record_security_event("REPLAY_DETECTED", "replay-b", "demo-client", 409)
        record_security_event("INVALID_SIGNATURE", "signature-a", "demo-client", 403)
        record_security_event(
            "UNKNOWN_CLIENT",
            "other-org",
            "partner-x",
            401,
            organization_id="tenant-b",
        )
        await self.login()

        response = await self.client.get("/api/admin/intelligence/incidents")
        self.assertEqual(response.status_code, 200, response.text)
        items = response.json()["items"]
        self.assertEqual({item["event_type"] for item in items}, {"REPLAY_DETECTED", "INVALID_SIGNATURE"})
        replay = next(item for item in items if item["event_type"] == "REPLAY_DETECTED")
        self.assertEqual(replay["event_count"], 2)
        self.assertEqual(replay["risk_score"], 65)
        self.assertEqual(len({item["id"] for item in items}), len(items))
        with SessionLocal() as db:
            self.assertEqual(db.query(SecurityIncident).filter_by(organization_id="default").count(), 2)
        no_csrf = await self.client.post("/api/admin/intelligence/investigate")
        self.assertEqual(no_csrf.status_code, 403)

    async def test_ai_investigation_sends_only_aggregated_nonidentifying_context(self):
        original = {
            "enabled": settings.intelligence_enabled,
            "base_url": settings.intelligence_base_url,
            "api_key": settings.intelligence_api_key,
            "model": settings.intelligence_model,
        }
        object.__setattr__(settings, "intelligence_enabled", True)
        object.__setattr__(settings, "intelligence_base_url", "https://ai.example/v1")
        object.__setattr__(settings, "intelligence_api_key", "test-provider-key")
        object.__setattr__(settings, "intelligence_model", "test-model")
        captured = {}
        result_content = json.dumps({
            "summary": "Repeated replay attempts should be reviewed.",
            "recommendations": ["Review client credential use."],
        })

        def provider(request):
            captured["url"] = str(request.url)
            captured["body"] = request.content.decode()
            return httpx.Response(200, json={
                "choices": [{"message": {"content": result_content}}],
            })

        provider_client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
        try:
            with patch("intelligence.httpx.AsyncClient", return_value=provider_client):
                result = await investigate_incidents([{
                    "event_type": "REPLAY_DETECTED",
                    "severity": "high",
                    "risk_score": 65,
                    "event_count": 4,
                    "client_id": "must-not-send",
                    "request_id": "must-not-send-either",
                }])
        finally:
            object.__setattr__(settings, "intelligence_enabled", original["enabled"])
            object.__setattr__(settings, "intelligence_base_url", original["base_url"])
            object.__setattr__(settings, "intelligence_api_key", original["api_key"])
            object.__setattr__(settings, "intelligence_model", original["model"])
        self.assertEqual(captured["url"], "https://ai.example/v1/chat/completions")
        self.assertNotIn("must-not-send", captured["body"])
        self.assertNotIn("request_id", captured["body"])
        self.assertEqual(result["automated_actions"], False)
        self.assertEqual(len(result["recommendations"]), 1)

    async def test_audit_chain_detects_record_tampering(self):
        record_audit("audit-test", "review", {"source": "unit-test"})
        self.assertTrue(await asyncio.to_thread(verify_audit_chain))
        with SessionLocal() as db:
            entry = db.query(AuditLog).filter_by(action="review").one()
            entry.details = '{"source":"changed"}'
            db.commit()
        self.assertFalse(await asyncio.to_thread(verify_audit_chain))

    async def test_temporary_admin_password_flow_and_role_authorization(self):
        owner_csrf = await self.login()
        csrf_missing = await self.client.post(
            "/api/admin/users",
            json={"username": "auditor-user", "role": "security_auditor"},
        )
        self.assertEqual(csrf_missing.status_code, 403)
        created = await self.client.post(
            "/api/admin/users",
            json={"username": "auditor-user", "role": "security_auditor"},
            headers={"X-CSRF-Token": owner_csrf},
        )
        self.assertEqual(created.status_code, 201, created.text)
        account = created.json()
        self.assertTrue(account["must_change_password"])

        auditor = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
        )
        try:
            login = await auditor.post("/api/admin/login", json={
                "username": account["username"],
                "password": account["temporary_password"],
            })
            self.assertEqual(login.status_code, 200, login.text)
            self.assertTrue(login.json()["must_change_password"])
            self.assertEqual((await auditor.get("/api/admin/overview")).status_code, 403)
            csrf = login.json()["csrf_token"]
            changed = await auditor.post(
                "/api/admin/password",
                json={
                    "current_password": account["temporary_password"],
                    "new_password": "Auditor-New-Password-684!",
                },
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(changed.status_code, 200, changed.text)
            relogin = await auditor.post("/api/admin/login", json={
                "username": account["username"],
                "password": "Auditor-New-Password-684!",
            })
            self.assertFalse(relogin.json()["must_change_password"])
            self.assertEqual((await auditor.get("/api/admin/users")).status_code, 403)
            self.assertEqual((await auditor.get("/api/admin/audit-logs")).status_code, 200)

            revoked = await self.client.post(
                f"/api/admin/users/{account['admin_id']}/revoke-sessions",
                headers={"X-CSRF-Token": owner_csrf},
            )
            self.assertGreaterEqual(revoked.json()["revoked_sessions"], 1)
            self.assertEqual((await auditor.get("/api/admin/session")).status_code, 401)
            await auditor.post("/api/admin/login", json={
                "username": account["username"],
                "password": "Auditor-New-Password-684!",
            })
            reset = await self.client.post(
                f"/api/admin/users/{account['admin_id']}/reset-password",
                headers={"X-CSRF-Token": owner_csrf},
            )
            self.assertEqual(reset.status_code, 200, reset.text)
            self.assertEqual((await auditor.get("/api/admin/session")).status_code, 401)
        finally:
            await auditor.aclose()

    async def test_last_active_organization_owner_cannot_be_removed(self):
        csrf = await self.login()
        with SessionLocal() as db:
            owner_id = db.query(AdminAccount).filter_by(username=settings.admin_username).one().id
        response = await self.client.patch(
            f"/api/admin/users/{owner_id}",
            json={"active": False},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 409)

    async def test_suspended_organization_rejects_valid_gateway_authentication(self):
        original_mappings = settings.client_organization_ids
        object.__setattr__(settings, "client_organization_ids", {"demo-client": "tenant-b"})
        with SessionLocal() as db:
            if db.get(Organization, "tenant-b") is None:
                db.add(Organization(
                    id="tenant-b",
                    slug="tenant-b",
                    name="Tenant B",
                    status="active",
                    plan="standard",
                    limits_json="{}",
                    created_at=datetime.now(timezone.utc),
                ))
                db.commit()
        await asyncio.to_thread(set_organization_status, "tenant-b", "suspended")
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
        try:
            with patch("app.check_rate_limit_and_register_nonce", return_value="allowed"):
                response = await self.client.post(
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
            self.assertEqual(response.status_code, 403)
            self.assertIn("suspended", response.text.lower())
        finally:
            object.__setattr__(settings, "client_organization_ids", original_mappings)
            await asyncio.to_thread(set_organization_status, "tenant-b", "active")

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
        self.assertEqual(response.json()["deployment_mode"], "customer_hosted")

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
