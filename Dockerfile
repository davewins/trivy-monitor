# syntax=docker/dockerfile:1
FROM ghcr.io/aquasecurity/trivy:0.76.1 AS trivy

# Build stage has pip and a shell; the runtime stage below has neither (distroless).
FROM cgr.dev/chainguard/python:latest-dev AS build
USER root
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target /opt/lib -r requirements.txt \
 && mkdir -p /out/cache /out/data /out/archive

FROM cgr.dev/chainguard/python:latest
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /opt/lib /opt/lib
COPY --from=build --chown=10001:10001 /out/cache /cache
COPY --from=build --chown=10001:10001 /out/data /data
COPY --from=build --chown=10001:10001 /out/archive /archive
COPY src/ /app/

# Fixed uid so existing named volumes (owned by 10001) and host ACLs keep working.
USER 10001:10001
ENV PYTHONPATH=/opt/lib:/app PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    TRIVY_CACHE_DIR=/cache STATE_DIR=/data HOME=/tmp
VOLUME ["/cache", "/data", "/archive"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import os,sys,time; sys.exit(0 if time.time()-os.path.getmtime('/tmp/healthy')<300 else 1)"]

ENTRYPOINT ["python", "-m", "trivy_monitor"]
