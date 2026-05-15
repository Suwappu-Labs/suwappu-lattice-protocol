# ETP Node — Multi-stage Docker Build
# Containerization
#
# Build: docker build -t etp-node .
# Run:   docker run -e ETP_REQUIRE_REAL_CRYPTO=1 etp-node
#
# Stage 1: Build dependencies (liboqs, pqcrypto, grpcio)
# Stage 2: Runtime with production deps only

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:d193c6f51a7dbd10395d6328de3a7edb0516fb0608ca138036576f574c3e07d2 AS builder

WORKDIR /build

# System deps for building liboqs and grpcio
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first (layer caching)
COPY pyproject.toml .
COPY src/ src/

# Install production dependencies
RUN pip install --no-cache-dir -e ".[production]"

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:d193c6f51a7dbd10395d6328de3a7edb0516fb0608ca138036576f574c3e07d2 AS runtime

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ src/
COPY config/ config/
COPY pyproject.toml .

# Security hardening
RUN useradd --create-home --shell /bin/bash etp \
    && chown -R etp:etp /app
USER etp

# Environment
ENV ETP_REQUIRE_REAL_CRYPTO=1
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import src.ltp; print('ok')" || exit 1

# Default entrypoint — override per service
ENTRYPOINT ["python", "-m", "src.ltp.node.main"]
