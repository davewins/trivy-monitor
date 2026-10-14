# syntax=docker/dockerfile:1
ARG TRIVY_VERSION=0.75.0
FROM ghcr.io/aquasecurity/trivy:${TRIVY_VERSION} AS trivy

FROM python:3.13-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends skopeo ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner \
 && mkdir -p /cache /data && chown scanner /cache /data
USER scanner

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    TRIVY_CACHE_DIR=/cache STATE_DIR=/data HOME=/tmp
VOLUME ["/cache", "/data"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import os,sys,time; sys.exit(0 if time.time()-os.path.getmtime('/tmp/healthy')<300 else 1)"

ENTRYPOINT ["python", "-m", "trivy_monitor"]
