# ═══════════════════════════════════════════════════════════════════════════════
# ElastiHone — Production Dockerfile for OpenShift
# ═══════════════════════════════════════════════════════════════════════════════
# Multi-stage build:
#   1. Node.js — build React frontend
#   2. Python  — build backend wheel
#   3. Runtime — combine both into a slim production image
#
# OpenShift requirements:
#   - Runs as non-root (arbitrary UID from restricted SCC)
#   - Group 0 (root group) has write access to required dirs
#   - Listens on port 8080 (unprivileged)
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Stage 1: Python Build ───────────────────────────────────────────────────
# NOTE: Build the frontend BEFORE running docker build:
#   cd frontend && npm install && npm run build && cd ..
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip hatchling

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ src/

# Build wheel
RUN pip wheel --no-deps --wheel-dir /wheels .

# ─── Stage 3: Runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="ElastiHone Team" \
      description="ElastiHone — AI-powered detection rule analysis platform" \
      version="0.3.0"

# Security: Create non-root user compatible with OpenShift arbitrary UIDs
# OpenShift runs containers with a random UID but GID=0 (root group)
RUN groupadd -r sda && \
    useradd -r -g 0 -d /app -s /sbin/nologin sda

WORKDIR /app

# Install the wheel from builder stage
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels

# Copy React frontend build output (pre-built locally)
COPY frontend/dist /app/frontend-dist

# Copy examples for reference
COPY examples/ /app/examples/

# Create dirs that OpenShift's arbitrary UID needs to write to
RUN mkdir -p /app/.cache /app/data /tmp/sda && \
    chown -R sda:0 /app && \
    chmod -R g=u /app /tmp/sda

# ─── Environment defaults ────────────────────────────────────────────────────
# All configurable via OpenShift ConfigMap / Secrets
ENV SDA_WEB_HOST="0.0.0.0" \
    SDA_WEB_PORT="8080" \
    SDA_ES_URL="https://localhost:9200" \
    SDA_ES_VERIFY_CERTS="true" \
    SDA_LLM_BASE_URL="https://api.openai.com/v1" \
    SDA_LLM_DEPLOYMENT_NAME="gpt-4o" \
    SDA_FRONTEND_DIR="/app/frontend-dist" \
    PYTHONUNBUFFERED="1" \
    PYTHONDONTWRITEBYTECODE="1"

# Expose the web dashboard port
EXPOSE 8080

# Switch to non-root user (OpenShift will override UID but keeps GID=0)
USER sda

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')" || exit 1

# Run the web dashboard
ENTRYPOINT ["sda"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]
