# Project Operational Rules & Hard Constraints (marzneshin)

These rules apply **unconditionally** to every session, diagnostic check, code edit, and deployment in this repository. They consolidate all safety, anti-TSPU/DPI, and anti-drift invariants of the project.

---

## 1. Hard Constraints (NEVER Violate)

1. **NEVER touch the local workstation VPN:**
   - Do NOT edit, restart, or probe `/etc/sing-box/config.json` or local proxy listeners (`127.0.0.1:1080`, `:10808`, `:3128`) on the host machine.
2. **NO pings, NO active probing, NO storms:**
   - Never run continuous pings, port scans, `speedtest-cli` against Russian servers, or automated HTTP loops against Google, Anthropic, OpenAI, YouTube, or Telegram.
   - All live diagnostics MUST be **100% passive** by default (local files, `/proc`, `nstat`, `ss -s`, `docker ps`, `ufw status`).
3. **Zero-Emission on the Moscow Bridge (`mos`):**
   - Never initiate outbound internet requests from the Russian bridge (`curl`, `openssl`, `apt`/`docker pull` to public registries when avoidable, DNS lookups).
   - For container updates on `mos`, build on the foreign exit node (`server-de`) and stream via `docker save | gzip | ssh mos 'gunzip | sudo docker load'`.
   - Keep `routing.domainStrategy = "AsIs"` and omit `freedom` (`direct`) outbounds on `mos` (fail-closed).
4. **Zero-Logging & Repository Hygiene:**
   - Keep `log.access = "none"`, `log.error = "none"`, `log.loglevel = "none"` in Xray and `access_log off; error_log /dev/null crit;` in Nginx.
   - Never dump or save client IPs (never run raw `ss -tnp` against live VPN ports).
   - **Never commit live IPs, domains, UUIDs, Reality keys, `shortId`, or secret paths to Git.** Live parameters live only in `/var/lib/marzneshin/state.json`, `/root/vpn-credentials/`, and `~/.ssh/config`.
5. **AI Account Protection (Google / Anthropic / OpenAI):**
   - **NO secondary tunnels:** strictly prohibit Cloudflare WARP, Tor, WireGuard outbounds, or third-party proxy chains.
   - **NO IP Flapping:** never load-balance or auto-failover a user across multiple exit IPs; each user is statically pinned to one exit IP.
   - **Strict `ai-isolated` exit separation:** keep the owner's AI exit (`exit-ai`) dedicated strictly to 1 user (`ai-owner`) on its own independent root domain, never mixed with media/family traffic.
   - Never use user accounts, cookies, tokens, or `Accept-Language: ru` headers during server checks; new exit IP reputation checks are run **once**, anonymously from the foreign exit node itself.
6. **Zero-Surface Administration:**
   - SSH CLI only (`./script.sh`, custom SSH port `22222/tcp` with `ufw limit`, key-only auth for `stealth`).
   - Never expose web panels, HTTP admin APIs, or `/sub/` subscription endpoints.

---

## 2. Production Technical Invariants (DO NOT Regress)

| Component | Mandatory Invariant | Reason |
| :--- | :--- | :--- |
| **Cascade Topology** | `Client (VLESS+TCP+Reality+Vision, fp=firefox)` -> `Moscow Bridge (:443, AsIs)` -> `DE Exit (VLESS+XHTTP+Reality+xmux, :443 -> fallback 127.0.0.1:10086)` | Resistant to Russia TSPU/DPI; hides domestic clients behind RU bridge and obfuscates cross-border hop via XHTTP+xmux (keep `xmux.hMaxReusableSecs` bounded to minutes, not multi-hour sessions, when scaling). |
| **Xray Version** | Pinned to **`Xray v26.6.27`** (`Dockerfile`) | `v26.9.8+` enforces PQ `X25519MLKEM768` breaking `sing-box 1.13/1.14` (`SagerNet/sing-box#4520`). Upgrade only after passing `tests/test_cascade_e2e.py`. |
| **Nginx Version** | Pinned to **`nginx:1.30.7-alpine`** or newer patched release (`docker/nginx/Dockerfile`) | Mitigates critical RCE `CVE-2026-123007`. Recreate Nginx with `--no-deps` so `marzneshin-xray` has 0s downtime. |
| **uTLS Fingerprint** | Default **`fp=firefox`** everywhere | Empirically verified on RU ISPs (`fp=chrome` is throttled/dropped by TSPU). |
| **MPTCP Hardening** | `net.mptcp.enabled = 0` (`sysctl`) + `"tcpMptcp": false` in all Xray `sockopt` | Mitigates `CVE-2026-98432` and DPI TCP option anomalies. |
| **TCP Anti-Storm** | Bilateral `TCPMSS --set-mss 1360` (`iptables -t mangle`), `tcp_retries2 = 5`, `tcp_fin_timeout = 15`, `tcp_syn_retries = 1`, `tcp_synack_retries = 2`, `tcp_max_syn_backlog = 4096`, `tcp_syncookies = 1`, `bbr + fq`, `disable_ipv6 = 1`, `sockopt` keepalive (`120s/30s`, `tcpNoDelay=true`) | Prevents hanging sockets and `TCPTimeouts` reconnect storms that trigger TSPU active probing. |
| **Probe Isolation** | `dest: "127.0.0.1:8443"` (`xver: 1`, Zero-Loop), Nginx `default_server` returns neutral `CN=localhost` + `444` (never `TLS alert 80`), `server_tokens off`, `etag off`, `Last-Modified ""`, `0644` file permissions, `:80` closed on `mos` after ACME | Defeats active TSPU probing and raw-IP/no-SNI fingerprinting. |

---

## 3. Unconditional Blocking Policy (ALL Contours, Zero Exceptions)

**Security strictly overrides speed and voice/video call quality.** Do NOT relax ports or protocols on any server or client profile:

- **Blocked everywhere (server blackhole + client `reject`):**
  - `UDP 443` (`quic`), `UDP 3478` & `UDP 19302` (`stun` / WebRTC)
  - `bittorrent`
  - `::/0` (IPv6) and private CIDRs (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`)
  - Telemetry domains: `location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `app-measurement.com`, `firebase-settings.crashlytics.com` (and `firebaselogging*.googleapis.com` on clients)
  - DNS `query_type: "HTTPS"` (SVCB/HTTP3 hints) on **all** `sing-box` clients (both `Full Tunnel` and `Selective`)
- **Blocked on foreign Exit nodes (`blackhole` against domestic snitch apps / `Full Tunnel` leaks, zero WARP):**
  - `domain:ru`, `domain:su`, `domain:xn--p1ai` (`.рф`), and `geoip:ru` MUST route to `block` on foreign Exit nodes (`LocalXrayConfigBuilder.build`), while `mos` keeps `domainStrategy: "AsIs"` and zero `freedom` outbounds.
- **Explicitly ALLOWED (never blackhole):**
  - `gvt1.com` and `gvt2.com` (required for Google/IDE binary updates).

---

## 4. Client & Cluster Standards

- **Mandatory Next Milestone (Blocking Prerequisite before `>2` devices):**
  - Implement and deploy [`openspec/changes/multi-exit-bridge-cluster/`](./openspec/changes/multi-exit-bridge-cluster/proposal.md) before scaling users/devices or issuing mobile media profiles.
- **No `urltest`:** Client outbounds MUST use manual `selector` only (`interrupt_exist_connections: true`).
- **No raw `vless://` / `links.txt` for `media-consumer` users:** Distribute ONLY managed `Selective` `sing-box` JSON profiles (never unrouted raw URIs/QR for `v2rayNG` or unsplit mobile clients). Reserve `links.txt`/QR bootstrapping strictly for `ai-owner`.
- **Subnet, ASN & Quarantine Discipline:**
  - Separate `exit-ai` and `exit-media-*` not only by registrable root domain, but also by `/24` IPv4 subnet and ideally distinct ASN/hoster (mitigates ~80% subnet-level contagion from VPS neighbors).
  - If `cluster_watch.py` or handshake checks indicate an active IP/TLS quarantine (sharp `TCPSynRetrans`/`TCPTimeouts` spike or handshake drop while TCP/SSH works), **immediately halt client traffic and disable auto-reconnects** on that node — never flood VLESS packets into a 3–7 day quarantine, or it escalates to a permanent ban.
- **`media-consumer` role (up to ~20 devices across `exit-media-*`, ~8–10 per exit):**
  - Strictly mobile-only: vanilla **`sing-box >= 1.14`** on **Android (SFA)** and **iOS (SFI — App Store `sing-box MT` by Metamerism LLC, replacing removed `sing-box VT`)** with per-user versioned JSON (`media-selective`), imported manually as a **Local** profile (zero `/sub/` Remote URLs, no `v2rayTun`/`Streisand`/`Shadowrocket`).
  - Proxy ONLY: YouTube, Instagram, Telegram, TikTok, WhatsApp (`route.final: "direct"`, `dns.final: "dns-local"`).
  - iOS profiles MUST omit `package_name`, `process_name`, `override_android_vpn`, `interface_name`, and oversized `.srs` lists (Apple 50 MB NetworkExtension RAM ceiling); disable **iCloud Private Relay** and conflicting third-party DNS/DoH profiles on iOS devices.
- **`ai-owner` role (strictly 1 admin -> `exit-ai`):**
  - Full 5-OS suite: Android (SFA), iOS (SFI / `sing-box MT` Local import), Windows 11 (Throne), Linux (`sing-box` / `xray-client`), OpenWrt (`podkop` + standalone `openwrt-outbound.json` OR router-native `openwrt-singbox.json` using `tproxy`/`fw4`-integrated `tun`).
  - Never copy desktop/mobile `auto_route` JSON verbatim to OpenWrt (conflicts with `fw4`/`nftables` and `dnsmasq`, plus `.srs` RAM limits); never route an entire household LAN in `Full Tunnel` through `exit-ai` (use `Selective` or dedicated VLAN/PBR for trusted work devices, and enforce `UDP 443/3478/19302`, `HTTPS` DNS RR, `::/0`, and telemetry blocks on the router).
  - Full Tunnel and AI-Selective profiles (see [SINGBOX_CLIENT_REQUIREMENTS.md](./SINGBOX_CLIENT_REQUIREMENTS.md)).
- **Multi-exit bridge capacity:** Target `2 GB RAM + 1 GB swap` on `mos` before scaling past 2–3 users; static `UUID -> upstream` binding via SSH CLI.

---

## 5. Safe Passive Diagnostics Playbook

Use ONLY passive commands from the workstation or over SSH (`ssh mos`, `ssh server-de` via `~/.ssh/config`):

```bash
# Recommended one-command passive delta check from workstation (0 server disk writes, 0 retries)
python3 tools/cluster_watch.py
# Or reset bridge in-memory byte counters after reading (3-4h window)
python3 tools/cluster_watch.py --reset-stats

# Direct passive health & kernel counters over SSH (zero network emission)
sudo docker ps --format "table {{.Names}}\t{{.Status}}"
sudo docker exec marzneshin-nginx nginx -v
nstat -az TcpExtEmbryonicRsts TcpExtTCPTimeouts TcpExtTCPSynRetrans TcpExtTCPAbortOnTimeout
ss -s
free -m
sudo ufw status
sudo iptables -t mangle -S | grep -i TCPMSS
timedatectl status | grep -E "synchronized|NTP"
cd /opt/marzneshin && sudo ./script.sh self-test
```

Before any code deployment, run local tests:
```bash
.venv/bin/python -m pytest tests/ -v
```

---

## 6. Reference & Archived Context

- Current client spec: [SINGBOX_CLIENT_REQUIREMENTS.md](./SINGBOX_CLIENT_REQUIREMENTS.md)
- Mandatory next OpenSpec change: [openspec/changes/multi-exit-bridge-cluster/](./openspec/changes/multi-exit-bridge-cluster/)
- Historical RCA & DPI research (archived): [docs/archive/](./docs/archive/) (`RCA_SERVER_FAM_2026-11-15.md`, `RISK_TRACKING_AND_MITIGATION.md`, `DEPLOYMENT_SAFETY_PROTOCOL.md`, `HANDOVER_CONTEXT_2026-11-15.md`, `HANDOVER_CONTEXT_2026-11-16.md`, `DRIFT-TO-XHTTP.md`, `DPI_RESEARCH_HABR_1109052_2026-11-21.md`)
