FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system --gid 10001 postguard \
    && useradd --system --uid 10001 --gid postguard --home-dir /app postguard

COPY requirements.txt ./
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY --chown=postguard:postguard app.py admin_api.py config.py dashboard_store.py iam.py intelligence.py security.py ./
COPY --chown=postguard:postguard migrations/ ./migrations/
COPY --chown=postguard:postguard alembic.ini ./

USER postguard:postguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import json,os,urllib.request; h=os.environ['TRUSTED_HOSTS'].split(',')[0].strip(); r=urllib.request.Request('http://127.0.0.1:8000/health',headers={'Host':h}); d=json.load(urllib.request.urlopen(r,timeout=3)); raise SystemExit(0 if d['readiness']['ready'] else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
