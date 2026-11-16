# Design

## Context

The initial iteration adapted Marzneshin's FastAPI + SQLite + React SPA stack into a single-server panel behind a secret path. However, for a single owner whose sole requirements are:
1. One-command deployment on Ubuntu with SSH management and elementary Self-Reality settings,
2. Maximum resistance to server compromise or fingerprinting by Russia's TSPU (incorporating the lessons from `RCA_SERVER_FAM_2026-11-15.md`), and
3. Zero IP/account bans on **Google Antigravity**, **Anthropic (Claude)**, and **OpenAI** across **Windows 11 (Throne)** and **Android**,

any web panel, database, or public `/sub/` endpoint is pure liability. Removing the entire web application stack reduces the server's external HTTP surface to a 100% static Nginx decoy website while shifting configuration delivery and control to SSH.

## Goals / Non-Goals

**Goals:**
- Run **only** `xray-core` and `nginx` (+ `acme.sh`) on Ubuntu (`network_mode: host`, `logging: driver: none`), exposing only TCP `:80`, `:443`, and the host's SSH port.
- Eliminate FastAPI, Uvicorn, SQLite, Alembic, React (`dashboard/`), `/setup`, `/<panel_slug>/`, and `/sub/` endpoints completely (preventing the TSPU correlation between unencrypted `/sub/` HTTPS fetches and subsequent Reality tunnels on the same `IP:443:SNI`).
- Eliminate active-probing fingerprints discovered in `RCA_SERVER_FAM_2026-11-15.md`:
  - **Port `:80` IP probe protection**: Split Nginx port `:80` into a catch-all `default_server` (`server_name _; return 444;`) that silently drops raw-IP HTTP requests (`http://<IP>/`) instead of returning `301 -> https://<IP>/`, and a domain-matched `server_name <domain>;` block for ACME HTTP-01 and HTTPS redirection.
  - **Port `:443` -> `127.0.0.1:8443` SNI isolation**: Split Nginx `127.0.0.1:8443` into a catch-all `default_server` (`server_name _;`) using a neutral local self-signed certificate (`CN=localhost`) and `return 444;` (avoiding both Caddy's `TLS alert 80 internal_error` and leaking the domain's Let's Encrypt certificate to IP-range scanners probing without SNI), and a `server_name <domain>;` block serving the real Let's Encrypt certificate only when `SNI == <domain>`.
  - **Polymorphic decoy & header stripping**: Disable `etag off;`, `if_modified_since off;`, and clear `Last-Modified` (`add_header Last-Modified "";`) in Nginx while injecting randomized per-install entropy into static decoy HTML so file size and timestamps cannot be fingerprinted.
  - **Socket & kernel anti-storm hardening**: Configure `sockopt` (`tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`) on Xray inbounds so dead mobile sessions never hang for 16 hours in `ESTAB`, and configure kernel `sysctl` (`bbr + fq`, `tcp_fin_timeout=15`, `tcp_keepalive_time=120`, `tcp_synack_retries=2`, `tcp_syn_retries=2`, `tcp_fastopen=0`, `tcp_mtu_probing=0`, `disable_ipv6=1`) plus bidirectional `TCPMSS=1360` clamping.
  - **Domain TLD & isolation guardrails**: Reject or warn against high-risk abused TLDs (`.xyz`, `.top`, `.club`, `.icu`, `.site`, `.online`, `.fun`, `.space`, `.buzz`, `.monster`) unless `--allow-risky-tld` is passed, and never hardcode the raw server IP in client profiles.
- Harden server and client routing specifically for **Google Antigravity, Anthropic, and OpenAI** on **Windows 11 (Throne)** and **Android**:
  - Unblock `gvt1.com` and `gvt2.com` (required by Google Antigravity and Chrome updates) while blackholing Wi-Fi/cell geolocation (`location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `app-measurement.com`, `firebase-settings.crashlytics.com`).
  - Block `QUIC` (`UDP :443`), WebRTC `STUN` (`UDP :3478, :19302`), `bittorrent`, private CIDRs (`RFC1918`/loopback), and `::/0` (when IPv6 egress is disabled).
  - Set `sniffing.routeOnly = true` on Xray inbounds so SNI filtering works without overriding client DNS resolution.
  - Validate IP cleanliness before deployment via anonymous checks against Google (`INNERTUBE_CONTEXT_GL != RU`), OpenAI (`chatgpt.com/cdn-cgi/trace` -> `loc != RU`, `warp=off`), and Anthropic (`api.anthropic.com` TLS/HTTP reachability).
- Generate ready-to-use `vless://` links, terminal UTF-8 QR codes, and a **Windows 11 Throne (`sing-box`)** TUN configuration file (`/root/vpn-credentials/throne-windows11.json` + `android-singbox.json`) directly during `./script.sh --domain <fqdn>`.

**Non-Goals:**
- Multi-user management, web dashboards, databases, traffic quotas, or public HTTP subscription URLs.
- Protocols other than VLESS (`Reality + Vision` primary and `XHTTP + TLS` backup).
- Outbound secondary tunnels (WARP, Tor, WireGuard, proxy chains).

## Decisions

### 1. Zero-Surface Container Topology & Probe-Proof Nginx (`xray` + `nginx` Only)
- **Decision**: `docker-compose.yml` defines exactly two lightweight services with `network_mode: host` and `logging: driver: none`:
  1. `xray`: runs `xray-core` listening on `0.0.0.0:443` (`VLESS + Reality + xtls-rprx-vision`, `dest: 127.0.0.1:8443`, `xver: 1`, `sockopt: {tcpKeepAliveIdle: 120, tcpKeepAliveInterval: 30, tcpNoDelay: true}`) and, when backup XHTTP is enabled, `127.0.0.1:10086` (`VLESS + XHTTP`).
  2. `nginx`: runs Nginx + `acme.sh` with two isolated server blocks per port:
     - Port `:80`: `default_server` (`server_name _; return 444;`) drops raw-IP probes (`http://<IP>/`); `server_name <domain>;` serves `/.well-known/acme-challenge/` and `301 https://$host$request_uri`.
     - Port `127.0.0.1:8443 ssl proxy_protocol`: `default_server` (`server_name _;`) uses a local dummy self-signed certificate (`CN=localhost`) and `return 444;` so no-SNI/wrong-SNI probes neither trigger `TLS alert 80` nor leak `<domain>` from the Let's Encrypt certificate; `server_name <domain>;` serves the real Let's Encrypt TLS 1.3 cert with `etag off; if_modified_since off; add_header Last-Modified "";`.

### 2. SSH-First Lifecycle, Kernel Anti-Storm Hardening & One-Command Provisioning (`script.sh`)
- **Decision**: `script.sh` is both the one-command installer and the SSH management CLI:
  - `./script.sh --domain <fqdn> [--email <email>] [--decoy corporate|blog|coming_soon|<https-url>] [--allow-risky-tld] [--dry-run]`:
    1. **Root, NTP, Domain TLD & Kernel Hardening**:
       - Rejects high-risk spam TLDs (`.xyz`, `.top`, `.club`, `.icu`, `.site`, `.online`, `.fun`, `.space`, `.buzz`, `.monster`) unless `--allow-risky-tld` is explicitly provided.
       - Applies `/etc/sysctl.d/99-vpn-hardening.conf`: `bbr + fq`, `tcp_fin_timeout=15`, `tcp_keepalive_time=120`, `tcp_keepalive_intvl=30`, `tcp_keepalive_probes=3`, `tcp_synack_retries=2`, `tcp_syn_retries=2`, `tcp_fastopen=0`, `tcp_mtu_probing=0`, `disable_ipv6=1`, plus bidirectional `iptables -t mangle` `TCPMSS=1360` clamping.
    2. **SSH-Safe Firewall**: Detects the active SSH port from `$SSH_CONNECTION` or `/etc/ssh/sshd_config` (default `22`), configures `ufw limit <ssh_port>/tcp`, `ufw allow 80/tcp`, `ufw allow 443/tcp`, and ensures UFW is active without risking SSH lockout.
    3. **Direct DNS & Triple AI Egress Preflight**:
       - Verifies `<fqdn>` `A` record matches the server's public IPv4 and is not a Cloudflare proxy CIDR.
       - Runs anonymous egress checks (`trust_env=False` / `--noproxy '*'`): Google (`INNERTUBE_CONTEXT_GL != RU`), OpenAI (`chatgpt.com/cdn-cgi/trace` -> `loc != RU`, `warp=off`), and Anthropic (`api.anthropic.com` TLS/HTTP reachability).
    4. **ACME, Dummy Cert & Key Generation**: Issues Let's Encrypt `ec-256` cert for `<domain>` AND generates a dummy self-signed cert (`CN=localhost`) for the `default_server` no-SNI trap, generates `UUID`, Reality `x25519` keypair, 16-hex `shortId`, and 64-hex `xhttp_secret_path`, renders polymorphic static decoy HTML, starts Compose stack, and prints credentials + ANSI QR codes directly to the terminal.
  - Subcommands: `status`, `xhttp on|off`, `rotate`, `decoy <preset_or_url>`, and `self-test`.

### 3. Anti-Ban & Anti-Drift Hardening for Google Antigravity, Anthropic, and OpenAI
- **Decision**:
  1. **Unblock `gvt1.com` / `gvt2.com`**: Keep only `location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `domain:app-measurement.com`, and `domain:firebase-settings.crashlytics.com` in the telemetry `blackhole`.
  2. **Block `QUIC`, `STUN`, `BitTorrent`, and `::/0` on Server and Client**:
     - Block `UDP :443` (`QUIC`), `UDP :3478, 19302` (`STUN`), `protocol: ["bittorrent"]`, `RFC1918` private CIDRs, and `::/0` (when IPv6 is disabled).
  3. **No Simultaneous Reality + Fallback Probing (`selector` Only, No `urltest`)**:
     - Per `RCA_SERVER_FAM_2026-11-15.md` (Cause #3 & #4), opening both a Reality tunnel and a standard TLS fallback session (XHTTP) from the same client IP to the same `IP:443:SNI` simultaneously triggers TSPU ML classifiers.
     - Therefore, `throne-windows11.json` and `android-singbox.json` use a manual `selector` (`default: "vless-vision"`) without automatic `urltest` background probing across both transports, and connect to `<domain>:443` (resolved via encrypted remote DoH `1.1.1.1`/`8.8.8.8`) rather than a hardcoded raw IP.

## Risks / Trade-offs

- **[Risk] Active IP scanners probing `:443` without SNI discover the domain from the Let's Encrypt certificate or see Caddy's `TLS alert 80`** -> **Mitigation**: Nginx `default_server` on `127.0.0.1:8443` presents a neutral `CN=localhost` self-signed certificate and closes the HTTP connection with `444`, while `server_name <domain>` presents the Let's Encrypt cert only when `SNI == <domain>`.
- **[Risk] Dead mobile connections hang in `ESTAB` for 16 hours or trigger `SYN-ACK` retransmission storms during TSPU filtering** -> **Mitigation**: Xray `sockopt` sets `tcpKeepAliveIdle=120` / `tcpKeepAliveInterval=30` and kernel `sysctl` limits `tcp_synack_retries=2` and `tcp_fin_timeout=15`.
- **[Risk] Enabling UFW on a remote Ubuntu server with a non-standard SSH port could lock out the user** -> **Mitigation**: `script.sh` parses `$SSH_CONNECTION` and `/etc/ssh/sshd_config` `Port` directives and applies `ufw limit <port>/tcp` before enabling UFW.
