#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
    exec "${ROOT_DIR}/.venv/bin/python" -m app.utils.self_test "$@"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import httpx, cryptography" >/dev/null 2>&1; then
    exec python3 -m app.utils.self_test "$@"
else
    DATA_DIR_VAL="${MARZNESHIN_DATA_DIR:-/var/lib/marzneshin}"
    exec docker compose -f "${ROOT_DIR}/docker-compose.yml" run --rm \
        -v "${DATA_DIR_VAL}:${DATA_DIR_VAL}" \
        -e APPLIANCE_DOMAIN="${APPLIANCE_DOMAIN:-}" \
        -e XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-${DATA_DIR_VAL}/xray/config.json}" \
        -e NGINX_RUNTIME_DIR="${NGINX_RUNTIME_DIR:-${DATA_DIR_VAL}/nginx-runtime}" \
        -e SSH_PORT="${SSH_PORT:-22}" \
        --entrypoint python3 xray -m app.utils.self_test "$@"
fi
