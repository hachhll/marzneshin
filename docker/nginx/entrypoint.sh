#!/usr/bin/env sh
set -eu

RUNTIME_DIR="${NGINX_RUNTIME_DIR:-/var/lib/marzneshin/nginx-runtime}"
WEBROOT_DIR="${NGINX_WEBROOT_DIR:-/var/lib/marzneshin/acme-webroot}"
CERT_FILE="${NGINX_ACME_CERT_PATH:-/var/lib/marzneshin/certs/fullchain.pem}"
KEY_FILE="${NGINX_ACME_KEY_PATH:-/var/lib/marzneshin/certs/privkey.pem}"
DUMMY_CERT_FILE="${NGINX_DUMMY_CERT_PATH:-/var/lib/marzneshin/certs/dummy-fullchain.pem}"
DUMMY_KEY_FILE="${NGINX_DUMMY_KEY_PATH:-/var/lib/marzneshin/certs/dummy-privkey.pem}"
MAIN_CONF="${RUNTIME_DIR}/nginx.conf"

mkdir -p "${RUNTIME_DIR}/conf.d" "${RUNTIME_DIR}/decoy" "${WEBROOT_DIR}" "$(dirname "$CERT_FILE")" "$(dirname "$DUMMY_CERT_FILE")"

# Ensure neutral CN=localhost self-signed cert exists for no-SNI/foreign-SNI default_server
if [ ! -s "$DUMMY_CERT_FILE" ] || [ ! -s "$DUMMY_KEY_FILE" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -days 3650 -subj "/CN=localhost" \
        -keyout "$DUMMY_KEY_FILE" -out "$DUMMY_CERT_FILE" >/dev/null 2>&1
fi

# Ensure bootstrap self-signed cert exists at CERT_FILE/KEY_FILE prior to ACME issuance
# so nginx starts cleanly on :80 and 127.0.0.1:8443 to serve /.well-known/acme-challenge/
if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
    cp "$DUMMY_CERT_FILE" "$CERT_FILE"
    cp "$DUMMY_KEY_FILE" "$KEY_FILE"
fi

# Ensure minimal placeholder main config exists until script.sh renders full appliance.conf
if [ ! -f "$MAIN_CONF" ]; then
    cat > "$MAIN_CONF" <<EOF
worker_processes auto;
pid /tmp/nginx.pid;
error_log /dev/null crit;
events { worker_connections 1024; }
http {
    default_type application/octet-stream;
    client_body_temp_path /tmp/nginx_client_temp;
    proxy_temp_path /tmp/nginx_proxy_temp;
    fastcgi_temp_path /tmp/nginx_fastcgi_temp;
    uwsgi_temp_path /tmp/nginx_uwsgi_temp;
    scgi_temp_path /tmp/nginx_scgi_temp;
    server_tokens off;
    etag off;
    access_log off;
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        location /.well-known/acme-challenge/ { root ${WEBROOT_DIR}; }
        location / { return 444; }
    }
}
EOF
fi

# Watch reload.trigger signaled by script.sh without needing docker.sock
(
    while true; do
        if [ -f "${RUNTIME_DIR}/reload.trigger" ]; then
            rm -f "${RUNTIME_DIR}/reload.trigger" 2>/dev/null || true
            if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ] && nginx -t -e /dev/null -c "$MAIN_CONF" >/dev/null 2>&1; then
                nginx -s reload -e /dev/null -c "$MAIN_CONF" >/dev/null 2>&1 || true
            fi
        fi
        inotifywait -qq -t 5 -e close_write,moved_to,create "${RUNTIME_DIR}" 2>/dev/null || sleep 2
    done
) &

# Periodic ACME renewal check (twice daily)
(
    while true; do
        sleep 43200
        if [ -x /root/.acme.sh/acme.sh ]; then
            /root/.acme.sh/acme.sh --cron --home /root/.acme.sh >/dev/null 2>&1 || true
        fi
    done
) &

exec nginx -g "daemon off;" -e /dev/null -c "$MAIN_CONF"
