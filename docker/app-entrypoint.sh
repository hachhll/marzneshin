#!/usr/bin/env sh
set -eu

CONFIG_PATH="${XRAY_CONFIG_PATH:-/var/lib/marzneshin/xray/config.json}"
mkdir -p "$(dirname "$CONFIG_PATH")" \
    /var/lib/marzneshin/nginx-runtime/conf.d \
    /var/lib/marzneshin/nginx-runtime/decoy \
    /var/lib/marzneshin/acme-webroot \
    /var/lib/marzneshin/certs

exec /usr/local/bin/xray run -config "$CONFIG_PATH" >/dev/null 2>&1
