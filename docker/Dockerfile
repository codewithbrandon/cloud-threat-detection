# =============================================================================
# Cloud-Native Threat Detection Platform — Dockerfile
# =============================================================================
# Security design decisions documented inline.
# Each decision maps to a specific CIS Docker Benchmark control or NIST SP 800-190.

# -----------------------------------------------------------------------------
# Stage 1: Build dependencies in isolated environment
# WHY: Multi-stage builds prevent build tools (pip, gcc, etc.) from appearing
# in the final image, reducing the attack surface by eliminating privilege
# escalation vectors through unused binaries.
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Pin specific package versions to prevent supply chain attacks
# WHY: Using `latest` allows malicious package updates to silently compromise
# container builds. Pinned versions enable reproducible, auditable builds.
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# -----------------------------------------------------------------------------
# Stage 2: Minimal production image
# WHY: python:3.12-slim excludes compilers, curl, wget, and package managers.
# Attackers who achieve code execution cannot trivially download additional tools.
# NIST SP 800-190 §4.1.1: Use minimal base images.
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS production

# Security labels for image provenance tracking
LABEL maintainer="security-platform-team" \
      org.opencontainers.image.title="threat-detection-app" \
      org.opencontainers.image.description="Cloud-Native Threat Detection Platform" \
      org.opencontainers.image.version="1.0.0" \
      security.scan-required="true" \
      security.base-image="python:3.12-slim"

# -----------------------------------------------------------------------------
# Create non-root user
# WHY: CIS Docker Benchmark §4.1 — containers must not run as root.
# If an attacker achieves container escape, a non-root UID limits host impact.
# UID 1001 is non-system range, preventing namespace conflicts.
# -----------------------------------------------------------------------------
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid 1001 --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy only the installed packages from the build stage
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source
COPY app.py .
COPY requirements.txt .

# -----------------------------------------------------------------------------
# Filesystem hardening
# WHY: Only /app and /tmp should be writable. Read-only root filesystem
# (enforced in Kubernetes securityContext) blocks persistence mechanisms.
# The /tmp write is needed for the file-write simulation endpoint.
# -----------------------------------------------------------------------------
RUN mkdir -p /tmp && \
    chown -R appuser:appgroup /app /tmp && \
    chmod 750 /app && \
    chmod 1777 /tmp

# Switch to non-root user — all subsequent operations run as UID 1001
USER appuser

# Add local packages to PATH
ENV PATH="/home/appuser/.local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PORT=8080 \
    APP_VERSION=1.0.0

EXPOSE 8080

# -----------------------------------------------------------------------------
# Health check — enables Docker-native health monitoring
# WHY: Kubernetes probes are primary, but Docker health check provides
# fallback visibility during local development and docker-compose testing.
# 30s start period accommodates gunicorn worker initialization.
# -----------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# -----------------------------------------------------------------------------
# Gunicorn production WSGI server
# WHY: Flask's built-in server is single-threaded and not production-safe.
# Gunicorn provides worker process isolation — if one worker crashes, others
# continue serving. 2 workers handle concurrent attack simulation load.
# --timeout 120 prevents hung workers from blocking health probes.
# -----------------------------------------------------------------------------
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "--capture-output", \
     "app:app"]
