# Proposal

## Why

Even after stripping multi-node agents (`marznode`) and legacy protocols, running a FastAPI/Uvicorn backend, SQLite/SQLAlchemy/Alembic database, background cron schedulers, public `/sub/` subscription endpoints, and a 5,800-module React SPA (`dashboard/`) leaves an unnecessary web attack surface, fingerprinting vectors for Russia's TSPU (DPI/active probing), and operational overhead for a single-owner VPN. Furthermore, protecting active accounts on **Google Antigravity**, **Anthropic (Claude)**, and **OpenAI** requires eliminating split-tunnel leaks on **Windows 11 (Throne)** and **Android**, unblocking Google binary/update CDNs (`gvt1.com`/`gvt2.com`), blocking `QUIC` (`UDP :443`), `STUN` (`UDP :3478/:19302`), and `BitTorrent`, hardening SSH/UFW and TCP BBR on Ubuntu, and running a triple AI-platform IP reputation check (`Google GL != RU`, `OpenAI cdn-cgi/trace`, `Anthropic TLS/HTTP`) before activation.

## What Changes

- **BREAKING**: Completely remove the web control plane, database, and frontend (`app/` FastAPI/SQLAlchemy/Alembic/Uvicorn/APScheduler/Telegram/Webhooks, `dashboard/` React SPA, `main.py`, `/setup` wizard, `/<panel_slug>/` routes, and `/sub/` public HTTP endpoints).
- **BREAKING**: Collapse the runtime into a **Zero-Surface Single-User Appliance** on Ubuntu consisting solely of two minimal host-networked containers (`xray` and `nginx` with `logging: driver: none`) managed exclusively via a single SSH CLI script (`script.sh`).
- Configure **Self-Reality Nginx Gateway** on `:80` and `:443`: `Xray` on `:443` (`VLESS + Reality + xtls-rprx-vision`, single owner UUID, 16-hex `shortId`, `maxTimeDiff: 60000`, `sniffing` with `routeOnly: true`) forwards all non-Reality traffic via `PROXY protocol` (`xver: 1`) to local `Nginx` (`127.0.0.1:8443`, `TLSv1.3` with ACME `ec-256` cert) serving **only** static decoy HTML (`/` and `/404.html`) with zero backend upstreams when backup XHTTP is off.
- Maintain the **SSH-toggled Backup XHTTP Channel** (`VLESS + XHTTP + TLS` on `127.0.0.1:10086` behind a 64-hex secret path in Nginx, disabled by default) controllable via `./script.sh xhttp on|off` without dropping active `Vision` connections.
- Harden **AI Account & Anti-Drift Protection** for **Google Antigravity, Anthropic, and OpenAI**:
  - Remove `domain:gvt1.com` and `domain:gvt2.com` from the `blackhole` list so Google Antigravity, Chrome, and Android components update and operate normally, while keeping `location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `domain:app-measurement.com`, and `domain:firebase-settings.crashlytics.com` blocked.
  - Add server and client `blackhole` rules for `UDP :443` (`QUIC`), `UDP :3478/:19302` (`STUN` / WebRTC leak prevention), `bittorrent` protocol, and private IP ranges (`RFC1918`/loopback/link-local).
  - Enforce triple anonymous AI-egress preflight and `self-test` checks (`YouTube INNERTUBE_CONTEXT_GL != RU`, `OpenAI https://chatgpt.com/cdn-cgi/trace loc != RU & warp=off`, and `Anthropic https://api.anthropic.com` reachability without 403/ASN block).
- Deliver **One-Command Ubuntu Provisioning & Terminal Export (`script.sh`)**:
  - Auto-detect active SSH port (`$SSH_CONNECTION` / `sshd_config`), apply `ufw limit <ssh_port>/tcp` before enabling UFW (`80/tcp`, `443/tcp`), and enable Linux kernel `TCP BBR` (`net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`).
  - Immediately output to the SSH terminal upon install (`./script.sh --domain <fqdn>`) and via `./script.sh status`:
    1. Primary (`Reality + Vision`) and Backup (`XHTTP + TLS`) `vless://` URIs (`fp=chrome`, `packetEncoding=xudp`).
    2. ANSI/UTF-8 **QR codes** rendered directly in the SSH terminal for instant **Android** and **Windows 11 Throne** scanning.
    3. Ready-to-import **Windows 11 Throne (`sing-box`)** full-TUN profile (`strict_route: true`, `ipv4_only`, `hijack-dns`, `QUIC`/`STUN` block, zero `geoip:ru` direct bypass, automatic `Vision -> XHTTP` failover) and Android profile saved under `/root/vpn-credentials/`.

## Capabilities

### New Capabilities

- `single-server-vless-core`: Stateless single-user `xray-core` configuration and lifecycle (`x25519`, 16-hex `shortId`, single UUID, `sniffing` with `routeOnly: true`), complete removal of FastAPI, SQLite, React SPA, and multi-user/admin services.
- `self-reality-nginx-gateway`: Pure static-decoy `Nginx` (`:80` ACME HTTP-01 + `127.0.0.1:8443` `TLSv1.3` `proxy_protocol`) behind `Xray` `:443` with zero `/api/`, `/sub/`, or `/dashboard/` routes and zero disk logs.
- `backup-xhttp-channel`: SSH CLI-controlled (`./script.sh xhttp on|off`) backup `VLESS + XHTTP + TLS` channel behind a 64-hex secret Nginx path on `:443` with atomic `nginx -t` validation and live reload.
- `anti-drift-safety-policy`: Dual protection against Russia TSPU and Google Antigravity / Anthropic / OpenAI bans: `UseIPv4`, `Remote DNS only` (`1.1.1.1`/`8.8.8.8`), `QUIC`/`STUN`/`BitTorrent`/Wi-Fi-Geo `blackhole` (with `gvt1.com`/`gvt2.com` unblocked), triple anonymous AI egress verification, and executable `self-test`.
- `seamless-docker-setup-wizard`: One-command Ubuntu installer & SSH CLI (`script.sh`) with SSH port lockout protection (`ufw limit`), TCP BBR activation, ACME EC-256 bootstrap, and immediate terminal QR + URI output without any browser setup wizard.
- `minimal-profile-constructor`: Automated local generator of hardened client configurations for **Windows 11 Throne (`sing-box` TUN)** and **Android** with built-in primary `Vision` + backup `XHTTP` failover and terminal QR rendering.

### Modified Capabilities

<!-- All capabilities in this change are updated in place to reflect the Zero-Surface Single-User architecture. -->

## Impact

- **Removed Bloat**: Deletes `dashboard/`, `app/` (FastAPI/SQLAlchemy/Alembic/routes/tasks/webhooks/notifications), `main.py`, `alembic.ini`, and Python web dependencies.
- **Core Runtime (`docker/`, `docker-compose.yml`)**: Pure `xray` (`xray-core` binary) + `nginx` (`nginx` + `acme.sh` + `inotify` reload watcher) containers with `network_mode: host` and `logging: driver: none`.
- **CLI & Config Generator (`script.sh`, `scripts/`)**: Unified single-file or modular CLI handling `--domain <fqdn>` install, `status`, `xhttp on|off`, `rotate`, `decoy`, and `self-test`, generating server configs and Windows 11 Throne / Android client bundles.
