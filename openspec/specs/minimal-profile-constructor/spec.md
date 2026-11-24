# minimal-profile-constructor Specification

## Purpose

Generates hardened, ready-to-import client configurations and terminal QR codes for Windows 11 (Throne `sing-box` core) and Android directly on the server without any web UI or simultaneous multi-transport probing.

## Requirements

### Requirement: Local terminal QR code and domain-based VLESS URI export
Upon installation (`./script.sh --domain <fqdn>` or `./script.sh --bridge ...`), rotation (`./script.sh rotate`), or `ai-owner` status check, the system SHALL print the `ai-owner` `VLESS + Reality + Vision` URI (`links.txt`) and UTF-8 terminal QR code (`fp=firefox`, `packetEncoding=xudp`, connecting to the bridge `:443` with `<bridge_sni>` in `bridge` mode, plus copy-paste `--bridge` commands in `exit` mode), and SHALL NOT generate `links.txt` or raw unrouted QR URIs for `media-consumer` users so mobile devices only receive managed `Media-Selective` `sing-box` JSON profiles.

#### Scenario: Terminal output includes scannable UTF-8 QR code and domain-based xudp VLESS URI
- **WHEN** `./script.sh status` (or initial install) finishes for the `ai-owner` on an exit node or bridge node
- **THEN** stdout contains a valid `vless://` URI with `security=reality`, `flow=xtls-rprx-vision`, `fp=firefox`, `packetEncoding=xudp`, a multi-line ISO/IEC 18004 UTF-8 QR code block, and (on an exit node) the copy-paste `--bridge` setup command (plus the `bridge-transport xhttp --path <64-hex>` switch command when XHTTP is enabled)

#### Scenario: `media-consumer` credential directory omits raw `vless://` links
- **WHEN** credentials are generated for a `media-consumer` user via `user add` or refresh
- **THEN** `/root/vpn-credentials/users/<user>/` contains only `android-media-selective.json` and `ios-media-selective.json` (plus version metadata), and `links.txt` / raw `vless://` URI output is omitted

### Requirement: Hardened Windows 11 Throne (`sing-box`) and Android profile generation without simultaneous urltest probing
The system SHALL generate versioned, per-user client profiles under `/root/vpn-credentials/users/<user>/` tailored strictly to the user's assigned role (`ai-owner` or `media-consumer`), with a manual `selector` outbound (`interrupt_exist_connections: true`, zero `urltest`), `fp=firefox`, explicit TCP keepalive (`connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`, Xray `tcpMptcp: false`), `sing-box 1.12+`/`1.14+` remote UDP DNS (`1.1.1.1`/`8.8.8.8`, `detour: "proxy"`, `ipv4_only`, `query_type: "HTTPS"` blocked across both Full-tunnel and Selective profiles), and unconditional blocking of `QUIC` (`UDP :443`), `STUN` (`UDP :3478/:19302`), `BitTorrent`, telemetry, private CIDRs, and `::/0`.

#### Scenario: Generated Throne profile passes strict anti-leak and anti-correlation validation
- **WHEN** `throne-windows11.json` is generated for the `ai-owner` user
- **THEN** it contains a `tun` inbound (`auto_route: true`, `strict_route: true`) without `override_android_vpn`, uses `sing-box 1.12+` DNS server objects (`type: "udp"`, `detour: "proxy"`, `strategy: "ipv4_only"`) with `query_type: "HTTPS"` rejected in `dns.rules` and `action: "sniff"`/`"hijack-dns"`/`"reject"`, configures `firefox` uTLS with keepalive timers on `vless-vision`, uses a `selector` (not `urltest`), blocks `quic` (`UDP :443`), `stun` (`UDP :3478/:19302`), and `::/0`, and omits `dns-local`, `geoip:ru`, and `gvt1.com`/`gvt2.com` blocks

#### Scenario: Generated Android profile preserves override_android_vpn and sing-box 1.12+ schema
- **WHEN** `android-singbox.json` is generated for the `ai-owner` user
- **THEN** it sets `override_android_vpn: true` on `route`, uses `sing-box 1.14+` remote DNS and route actions, configures `firefox` uTLS with keepalive timers, and omits Windows-incompatible or leak-prone rules

#### Scenario: Per-user credential bundle is isolated by user name and carries version metadata
- **WHEN** a user is created or refreshed via the SSH CLI
- **THEN** their profiles are written to `/root/vpn-credentials/users/<user>/` with a recorded `profile_version`, target `sing-box` version, and SHA-256 checksum in `state.json`, and no subscription URL (`/sub/`) is created

### Requirement: Strict mobile-only vanilla `sing-box` profiles for `media-consumer` users
For `media-consumer` users (up to ~20 devices), the system SHALL generate strictly mobile-only vanilla `sing-box` (`>= 1.14`) Media-Selective JSON profiles for Android (SFA) and iOS (SFI), proxying ONLY YouTube, Instagram, Telegram, TikTok, and WhatsApp (`route.final: "direct"`, `dns.final: "dns-local"`), omitting desktop profiles and AI/IDE rules, and using modern `http_clients` without deprecated fields.

#### Scenario: Android `media-consumer` profile matches target apps and domains cleanly
- **WHEN** `android-media-selective.json` is generated for a `media-consumer` user
- **THEN** it includes `override_android_vpn: true`, `package_name` rules for YouTube, Instagram, Telegram, TikTok, and WhatsApp plus their domain suffixes/CIDRs, blocks `UDP 443/3478/19302`, `BitTorrent`, `::/0`, and telemetry, and routes all other apps and domestic traffic to `direct`

#### Scenario: iOS `media-consumer` profile respects Apple NetworkExtension constraints
- **WHEN** `ios-media-selective.json` is generated for a `media-consumer` user
- **THEN** it omits `package_name`, `process_name`, `override_android_vpn`, and `interface_name`, routes YouTube, Instagram, Telegram, TikTok, and WhatsApp strictly via domain suffixes, compact IP CIDRs, and lightweight `.srs` rule-sets safe within the 50 MB iOS NetworkExtension memory limit, and enforces the same unconditional UDP/QUIC/STUN/IPv6/telemetry blocks

### Requirement: Multi-OS admin profile suite for `ai-owner`
For the single `ai-owner` user bound to an `ai-isolated` exit, the system SHALL generate hardened profiles across all five admin platforms: Android (SFA), iOS (`sing-box MT` / SFI Local import without Android-only fields or heavy `.srs`), Windows 11 (Throne), Linux (`sing-box` + `xray-client`), and OpenWrt (router-safe `tproxy` `openwrt-singbox.json` avoiding desktop `auto_route`/`dnsmasq` conflicts + standalone `openwrt-outbound.json` for `podkop`).

#### Scenario: Admin bundle contains validated profiles for all five target platforms
- **WHEN** profiles are generated for the `ai-owner` user
- **THEN** `/root/vpn-credentials/users/<owner>/` contains schema-compliant profiles for Android (Full & AI-Selective), iOS (Full & AI-Selective without `package_name`/`override_android_vpn`/`interface_name`), Windows 11 Throne (Full & AI-Selective), Linux (`linux-singbox.json`, `linux-singbox-selective.json`, `xray-client.json`), and OpenWrt (router-safe `openwrt-singbox.json` with `tproxy`/Selective LAN handling and standalone `openwrt-outbound.json` for `podkop`), all pointing to the bridge `:443` with `fp=firefox`, zero `urltest`, and full AI anti-drift protection

### Requirement: Hardened Linux `sing-box` Selective + `mixed-in` profile for `ai-user`
For users with profile `ai-user`, the system SHALL generate a Linux-only `sing-box` (`>= 1.14`) profile (`linux-ai-user.json`, omitting `links.txt`) using hybrid `Selective TUN` (excluding RFC1918 LAN and Docker private subnets) and local `mixed-in` (`127.0.0.1:2080`), `fp=firefox`, manual `selector` (zero `urltest`), unconditional `::/0`/QUIC/STUN/BitTorrent/HTTPS-DNS/telemetry blocks, all 7 `podkop` rule-sets, AI/Dev domain suffixes, and `tmpfs` `cache.db` (`/run/sing-box/cache.db`) with `warn` logging.

#### Scenario: `ai-user` credential bundle generates `linux-ai-user.json` with AI/Dev, `podkop`, and SD-card protections
- **WHEN** `user add <user> --upstream <exit-ai> --profile ai-user` completes
- **THEN** `/root/vpn-credentials/users/<user>/` contains `linux-ai-user.json` and `bundle-manifest.json` (and omits `links.txt`), `linux-ai-user.json` includes `tun` with `route_exclude_address` for `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`, `mixed-in` on `127.0.0.1:2080` routed to `proxy`, all 7 `podkop` rule-sets (`google_ai`, `google_play`, `russia_inside`, `telegram`, `discord`, `twitter`, `meta` via `proxy-http`, with `google_ai`/`google_play`/`russia_inside` in `dns.rules`), `TELEGRAM_DC_CIDRS`, AI/Dev suffixes (OpenAI/ChatGPT, Anthropic/Claude Code, Gemini, OpenRouter, Grok/x.ai, HuggingFace, GitHub, Databricks/Okta/Auth0, Microsoft/Azure/Copilot, PyPI/npm/Docker/crates/Go, AI IDEs; `gvt1.com`/`gvt2.com` allowed), `experimental.cache_file.path: "/run/sing-box/cache.db"`, and `log.level: "warn"`

#### Scenario: Domestic `.ru` traffic and LAN/SSHFS traffic bypass the VPN tunnel
- **WHEN** a process on an `ai-user` host resolves `.ru`/`.su`/`.рф` domains or connects to private LAN/`sshfs` subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- **THEN** `sing-box` routes DNS to `dns-local` and traffic to `direct`, never sending domestic or LAN/SSHFS traffic through `exit-ai`
