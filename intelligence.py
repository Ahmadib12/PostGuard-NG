import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from config import settings
from dashboard_store import SecurityEvent, SecurityIncident, SessionLocal
from fastapi import HTTPException


logger = logging.getLogger("PostGuard-NG.intelligence")
_SEVERITY_SCORE = {"info": 5, "low": 15, "medium": 35, "high": 60, "critical": 80}


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def list_incidents(organization_id: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=24)
    period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    grouped: dict[str, list[tuple[str, datetime]]] = defaultdict(list)

    with SessionLocal() as db:
        rows = db.execute(
            select(SecurityEvent.event_type, SecurityEvent.severity, SecurityEvent.timestamp)
            .where(
                SecurityEvent.organization_id == organization_id,
                SecurityEvent.timestamp >= window_start,
            )
        ).all()
        for event_type, severity, timestamp in rows:
            grouped[event_type].append((severity, _utc(timestamp)))

        values = []
        for event_type, occurrences in grouped.items():
            severity = max(
                (item[0] for item in occurrences),
                key=lambda item: _SEVERITY_SCORE.get(item, 5),
            )
            score = min(
                100,
                _SEVERITY_SCORE.get(severity, 5) + min((len(occurrences) - 1) * 5, 20),
            )
            incident_id = hashlib.sha256(
                f"{organization_id}|{event_type}|{period_start.isoformat()}".encode()
            ).hexdigest()
            values.append({
                "id": incident_id,
                "organization_id": organization_id,
                "event_type": event_type,
                "period_start": period_start,
                "first_seen": min(item[1] for item in occurrences),
                "last_seen": max(item[1] for item in occurrences),
                "event_count": len(occurrences),
                "risk_score": score,
                "severity": severity,
                "updated_at": now,
            })

        if values:
            dialect = db.get_bind().dialect.name
            if dialect == "sqlite":
                statement = sqlite_insert(SecurityIncident).values(values)
            elif dialect == "postgresql":
                statement = postgresql_insert(SecurityIncident).values(values)
            else:
                for value in values:
                    db.merge(SecurityIncident(**value))
                statement = None
            if statement is not None:
                statement = statement.on_conflict_do_update(
                    index_elements=[SecurityIncident.id],
                    set_={
                        key: getattr(statement.excluded, key)
                        for key in (
                            "first_seen", "last_seen", "event_count", "risk_score", "severity", "updated_at",
                        )
                    },
                )
                db.execute(statement)

        db.execute(
            delete(SecurityIncident).where(
                SecurityIncident.organization_id == organization_id,
                SecurityIncident.last_seen < window_start,
            )
        )
        db.commit()
        incidents = db.scalars(
            select(SecurityIncident)
            .where(
                SecurityIncident.organization_id == organization_id,
                SecurityIncident.period_start >= period_start - timedelta(days=1),
            )
            .order_by(SecurityIncident.risk_score.desc(), SecurityIncident.event_count.desc())
        ).all()
        return [{
            "id": item.id,
            "event_type": item.event_type,
            "severity": item.severity,
            "risk_score": item.risk_score,
            "event_count": item.event_count,
            "first_seen": _utc(item.first_seen).isoformat(),
            "last_seen": _utc(item.last_seen).isoformat(),
        } for item in incidents]


async def investigate_incidents(incidents: list[dict]) -> dict:
    if not settings.intelligence_enabled:
        raise HTTPException(status_code=503, detail="AI investigation is disabled.")

    context = {
        "window": "last 24 hours",
        "incidents": [{
            "event_type": item["event_type"],
            "severity": item["severity"],
            "risk_score": item["risk_score"],
            "occurrences": item["event_count"],
        } for item in incidents[:20]],
    }
    request_body = {
        "model": settings.intelligence_model,
        "temperature": 0,
        "max_tokens": 500,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a defensive security analyst. Assess the aggregate incident counts only. "
                    "Return JSON with a concise summary (up to 500 characters) and up to five "
                    "practical defensive recommendations (each up to 300 characters). Do not claim "
                    "certainty, request identifying data, or instruct automatic actions."
                ),
            },
            {"role": "user", "content": json.dumps(context, separators=(",", ":"), sort_keys=True)},
        ],
    }
    headers = {"Authorization": f"Bearer {settings.intelligence_api_key}"}
    endpoint = f"{settings.intelligence_base_url}/chat/completions"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.intelligence_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with client.stream("POST", endpoint, json=request_body, headers=headers) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 65536:
                        raise ValueError("AI provider response exceeded the size limit.")
        provider_result = json.loads(body)
        if not isinstance(provider_result, dict):
            raise ValueError("AI provider response must be an object.")
        choices = provider_result.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("AI provider response did not contain a completion choice.")
        message = choices[0].get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ValueError("AI provider response did not contain text content.")
        content = message["content"]
        result = json.loads(content)
        if not isinstance(result, dict):
            raise ValueError("AI provider result must be an object.")
        summary = result.get("summary")
        recommendations = result.get("recommendations")
        if (
            not isinstance(summary, str)
            or not summary.strip()
            or len(summary) > 500
            or not isinstance(recommendations, list)
            or len(recommendations) > 5
            or any(not isinstance(item, str) or not item.strip() or len(item) > 300 for item in recommendations)
        ):
            raise ValueError("AI provider response did not match the required result shape.")
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        logger.exception("AI investigation provider request failed or returned an invalid response.")
        raise HTTPException(
            status_code=502,
            detail="AI investigation provider is unavailable or returned an invalid response.",
        ) from exc

    return {
        "summary": summary.strip(),
        "recommendations": [item.strip() for item in recommendations],
        "automated_actions": False,
    }
