# ── Stage 1: build dependencies ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools needed for some wheels (e.g. cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Install nmap for network scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        iptables \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the app
# Note: network_agent.py uses iptables which requires root (or NET_ADMIN capability).
# For production, run as root ONLY inside an isolated container / VM sandbox.
RUN useradd -m -u 1000 chainsage

WORKDIR /app

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Remove .env if it was accidentally included — always inject via env vars at runtime
RUN rm -f .env

USER chainsage

EXPOSE 8000

# Health check — pings the public /  endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Uvicorn with 2 workers; scale via --workers or REPLICAS in compose
CMD ["python", "-m", "uvicorn", "api:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--log-level", "info"]
