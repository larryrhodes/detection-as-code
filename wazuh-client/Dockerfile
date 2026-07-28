# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="detection-as-code-wazuh-client"
LABEL org.opencontainers.image.description="Wazuh API client for Detection-as-Code pipeline"
LABEL org.opencontainers.image.source="https://github.com/larryrhodes/detection-as-code"

RUN useradd -m -u 1001 dacuser

WORKDIR /app

COPY --from=builder /install /usr/local

COPY client/ ./client/
COPY scripts/ ./scripts/

RUN chmod +x scripts/*.py

USER dacuser

ENV WAZUH_API_URL=""
ENV WAZUH_API_USER=""
ENV WAZUH_API_PASS=""
ENV WAZUH_INDEXER_URL="https://10.211.55.6:9200"
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python"]
CMD ["scripts/deploy_rules.py", "--help"]
