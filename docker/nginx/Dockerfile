FROM nginx:1.30.7-alpine

RUN apk add --no-cache \
    bash \
    curl \
    inotify-tools \
    openssl \
    socat

RUN curl -fsSL https://get.acme.sh | sh -s email=admin@localhost || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
