# Tasks: Zero-Surface Single-User VLESS Self-Reality Appliance

## 1. Remove Web Control Plane, Database & React SPA Bloat

- [x] 1.1 Remove the legacy web control plane, database, and frontend (`dashboard/`, `main.py`, `alembic.ini`, `app/db/`, `app/routes/`, `app/models/`, `app/tasks/`, `app/notification/`, `app/webhooks.py`, `app/marzneshin.py`, `app/dependencies.py`, and obsolete web/DB tests), keeping only a clean, zero-web Python CLI/library package (`app/xray/`, `app/nginx/`, `app/client/`, `app/utils/self_test.py`) with minimal dependencies (`pynacl`, `cryptography`, `httpx`, `pytest`). Verify zero FastAPI/SQLAlchemy/React files remain.

## 2. Harden Xray, Nginx & Client Profile Generators (incorporating RCA_SERVER_FAM_2026-11-15.md)

- [x] 2.1 Update `app/xray/config_builder.py` for single-user operation and RCA anti-leak/socket hardening:
  - Add `sockopt: {"tcpKeepAliveIdle": 120, "tcpKeepAliveInterval": 30, "tcpNoDelay": True}` on VLESS inbounds so dead mobile sockets never hang in `ESTAB`,
  - Set `sniffing.routeOnly = True` on VLESS inbounds,
  - Remove `domain:gvt1.com` and `domain:gvt2.com` from `TELEMETRY_BLACKHOLE_DOMAINS` (preserving `location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `domain:app-measurement.com`, `domain:firebase-settings.crashlytics.com`), and
  - Add server `blackhole` rules for `UDP :443` (`QUIC`), `UDP :3478,19302` (`STUN`), `protocol: ["bittorrent"]`, and `::/0` (when `ipv6_egress_enabled=False`).
  Verify with unit tests in `tests/test_xray_config.py`.
- [x] 2.2 Update `app/nginx/manager.py` and `app/nginx/decoys.py` for zero-surface operation and active-probe resistance (RCA Cause #1 & #2):
  - Remove all `/<panel_slug>/`, `/api/`, `/sub/`, and `/setup` proxy routes,
  - Split port `:80` into a catch-all `default_server` (`server_name _; return 444;`) that drops raw-IP HTTP probes (`http://<IP>/`) and a `server_name <domain>;` block for ACME HTTP-01 + `301` HTTPS redirect,
  - Split `127.0.0.1:8443 ssl proxy_protocol` into a catch-all `default_server` (`server_name _;`) using a local self-signed dummy certificate (`CN=localhost`) + `return 444;` (preventing both `TLS alert 80` and domain ACME cert leakage on no-SNI/foreign-SNI probes) and a `server_name <domain>;` block serving the real ACME cert,
  - Disable `etag off;`, `if_modified_since off;`, and clear `Last-Modified` (`add_header Last-Modified "";`), and inject per-install randomized entropy into static decoy HTML.
  Verify with `nginx -t` container tests in `tests/test_nginx_manager.py`.
- [x] 2.3 Implement `app/client/profile_generator.py` (and update `app/templates/sing-box.json` & `app/templates/xray.json`) to generate:
  - Primary (`Reality + Vision`) and Backup (`XHTTP + TLS`) `vless://<uuid>@<domain>:443` URIs (`fp=chrome`, `packetEncoding=xudp`, never raw IP host),
  - Terminal UTF-8/ANSI QR codes (pure Python, zero external dependencies),
  - **Windows 11 Throne (`throne-windows11.json`)** and **Android (`android-singbox.json`)** `sing-box` profiles (`tun` with `strict_route: true`, DoH/remote DNS via `detour: "proxy"`, `ipv4_only`, `QUIC`/`STUN`/`::/0`/telemetry blackholes, `gvt1.com`/`gvt2.com` allowed, and a manual `selector` defaulting to `vless-vision` without simultaneous `urltest` probing across Vision and XHTTP), and
  - Fixed `xray-client.json` (with `inboundTag: ["dns_out"] -> proxy` routing and `QUIC`/`STUN`/`::/0` blackholes).
  Verify with unit tests in `tests/test_client_profiles.py`.

## 3. Containers, One-Command Ubuntu CLI (`script.sh`) & Triple AI Self-Test

- [x] 3.1 Update `Dockerfile`, `docker/nginx/Dockerfile`, `docker/nginx/entrypoint.sh`, and `docker-compose.yml` to run only two minimal host-networked containers (`xray` and `nginx`) with `logging: driver: none` and zero web server or `docker.sock` mounts. Verify `docker compose config -q` passes.
- [x] 3.2 Update `app/utils/self_test.py` and `scripts/self_test.sh` to verify:
  - Xray & Nginx zero-log, `sockopt` (`tcpKeepAliveIdle`), no-SNI `default_server` isolation, `etag off`, and `QUIC`/`STUN`/`::/0`/telemetry/BitTorrent blackhole invariants (`gvt1.com` unblocked),
  - SSH port + `80`/`443` minimal port exposure and zero WireGuard/WARP/Tor processes,
  - Live `:443` Reality + `127.0.0.1:8443` PROXY protocol TLS 1.3 decoy fallback (confirming raw-IP/no-SNI probe gets neutral `CN=localhost` cert + `444` while `SNI=<domain>` gets the ACME cert + decoy `200`), and
  - Triple anonymous AI egress check (`YouTube INNERTUBE_CONTEXT_GL != RU`, `OpenAI https://chatgpt.com/cdn-cgi/trace loc != RU & warp=off`, `Anthropic https://api.anthropic.com` TLS/HTTP check).
  Verify with unit tests in `tests/test_self_test.py`.
- [x] 3.3 Rewrite `script.sh` to provide one-command Ubuntu provisioning (`./script.sh --domain <fqdn>`) and SSH subcommands (`status`, `xhttp on|off`, `rotate`, `decoy`, `self-test`):
  - Block high-risk spam TLDs (`.xyz`, `.top`, `.club`, `.icu`, `.site`, `.online`, `.fun`, `.space`, `.buzz`, `.monster`) unless `--allow-risky-tld` is passed, and warn against sharing root domains across multiple servers,
  - Auto-detect SSH port (`$SSH_CONNECTION` / `sshd_config`) and configure `ufw limit <ssh_port>/tcp` + `80/tcp` + `443/tcp`,
  - Apply kernel anti-storm `sysctl` (`bbr + fq`, `tcp_fin_timeout=15`, `tcp_keepalive_time=120`, `tcp_synack_retries=2`, `tcp_fastopen=0`, `tcp_mtu_probing=0`, `disable_ipv6=1`) and bidirectional `TCPMSS=1360` clamping,
  - Run DNS & triple anonymous AI preflight checks,
  - Provision ACME EC-256 cert + dummy self-signed `default_server` cert, render `xray` + `nginx` configs and `/root/vpn-credentials/` profiles (`throne-windows11.json`, `android-singbox.json`, `links.txt`), and print `vless://` links + UTF-8 QR code + Windows 11 Throne / Android setup instructions directly to the terminal.
  Verify with tests in `tests/test_installer.py`.

## 4. End-to-End Containerized Verification

- [x] 4.1 Update and run `tests/test_e2e_container.py` verifying the pure `xray` + `nginx` + `script.sh` appliance: confirm `/` with `SNI=<domain>` serves static decoy HTML over TLS 1.3 without `ETag`/`Last-Modified`, raw-IP probes on `:80` and no-SNI/foreign-SNI probes on `:443` close with `444` without leaking the domain cert or `TLS alert 80`, all former panel/API/sub paths (`/api`, `/sub`, `/setup`, `/dashboard`) return decoy `404`, `./script.sh status` outputs valid Throne/Android profiles and QR codes, `./script.sh xhttp on|off` dynamically enables/disables the secret Nginx XHTTP route (`nginx -t` + reload), and `self_test` reports 100% PASS.
