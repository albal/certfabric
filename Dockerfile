# syntax=docker/dockerfile:1

# --- Dashboard ---------------------------------------------------------------
# Static files, so build them natively once rather than under emulation for each architecture.
FROM --platform=$BUILDPLATFORM node:26-bookworm-slim AS dashboard
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- Application ---------------------------------------------------------------
FROM python:3.15-slim-bookworm

ARG ACME_SH_VERSION=3.1.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --home-dir /var/lib/certfabric --shell /usr/sbin/nologin certfabric

# acme.sh lives outside any writable volume; CertFabric gives each run a throwaway home.
RUN curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz" \
    | tar -xz -C /opt \
 && mv "/opt/acme.sh-${ACME_SH_VERSION}" /opt/acme.sh \
 && chmod 755 /opt/acme.sh/acme.sh

WORKDIR /app
COPY pyproject.toml README.md ./
COPY certfabric/ certfabric/
COPY --from=dashboard /build/dist/ certfabric/static/
RUN pip install --no-cache-dir . && mkdir -p /app/plugins /data && chown certfabric /data

ENV CERTFABRIC_DB_PATH=/data/certfabric.db \
    CERTFABRIC_ACME_SH=/opt/acme.sh/acme.sh \
    CERTFABRIC_PLUGINS_DIR=/app/plugins \
    PYTHONUNBUFFERED=1

USER certfabric
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s CMD curl -fsS http://127.0.0.1:8080/api/auth/status || exit 1
CMD ["certfabric", "serve", "--host", "0.0.0.0", "--port", "8080"]
