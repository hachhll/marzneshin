FROM python:3.12-slim

ARG XRAY_VERSION=v26.6.27
ARG TARGETARCH

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    XRAY_BINARY_PATH=/usr/local/bin/xray \
    XRAY_ASSETS_PATH=/usr/local/share/xray \
    XRAY_CONFIG_PATH=/var/lib/marzneshin/xray/config.json

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    case "$ARCH" in \
      amd64|x86_64) XRAY_ZIP="Xray-linux-64.zip" ;; \
      arm64|aarch64) XRAY_ZIP="Xray-linux-arm64-v8a.zip" ;; \
      *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac && \
    if [ "$XRAY_VERSION" = "latest" ]; then \
      DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/latest/download/${XRAY_ZIP}"; \
    else \
      DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_ZIP}"; \
    fi && \
    curl -fsSL "$DOWNLOAD_URL" -o /tmp/xray.zip && \
    mkdir -p /usr/local/share/xray && \
    unzip -q /tmp/xray.zip -d /usr/local/share/xray && \
    mv /usr/local/share/xray/xray /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -f /tmp/xray.zip

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
RUN chmod +x /app/docker/app-entrypoint.sh /app/scripts/*.sh /app/script.sh 2>/dev/null || true

CMD ["/app/docker/app-entrypoint.sh"]
