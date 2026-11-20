# Spec Delta

## MODIFIED Requirements

### Requirement: Hardened Windows 11 Throne (`sing-box`) and Android profile generation without simultaneous urltest probing
The system SHALL generate versioned, per-user client profiles under `/root/vpn-credentials/users/<user>/` tailored strictly to the user's assigned role (`ai-owner` or `media-consumer`), with a manual `selector` outbound (`interrupt_exist_connections: true`, zero `urltest`), `fp=firefox`, explicit TCP keepalive (`connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`, Xray `tcpMptcp: false`), `sing-box 1.12+`/`1.14+` remote UDP DNS (`1.1.1.1`/`8.8.8.8`, `detour: "proxy"`, `ipv4_only`), and unconditional blocking of `QUIC` (`UDP :443`), `STUN` (`UDP :3478/:19302`), `BitTorrent`, telemetry, private CIDRs, and `::/0`.

#### Scenario: Generated Throne profile passes strict anti-leak and anti-correlation validation
- **WHEN** `throne-windows11.json` is generated for the `ai-owner` user
- **THEN** it contains a `tun` inbound (`auto_route: true`, `strict_route: true`) without `override_android_vpn`, uses `sing-box 1.12+` DNS server objects (`type: "udp"`, `detour: "proxy"`, `strategy: "ipv4_only"`) and `action: "sniff"`/`"hijack-dns"`/`"reject"`, configures `firefox` uTLS with keepalive timers on `vless-vision`, uses a `selector` (not `urltest`), blocks `quic` (`UDP :443`), `stun` (`UDP :3478/:19302`), and `::/0`, and omits `dns-local`, `geoip:ru`, and `gvt1.com`/`gvt2.com` blocks

#### Scenario: Generated Android profile preserves override_android_vpn and sing-box 1.12+ schema
- **WHEN** `android-singbox.json` is generated for the `ai-owner` user
- **THEN** it sets `override_android_vpn: true` on `route`, uses `sing-box 1.14+` remote DNS and route actions, configures `firefox` uTLS with keepalive timers, and omits Windows-incompatible or leak-prone rules

#### Scenario: Per-user credential bundle is isolated by user name and carries version metadata
- **WHEN** a user is created or refreshed via the SSH CLI
- **THEN** their profiles are written to `/root/vpn-credentials/users/<user>/` with a recorded `profile_version`, target `sing-box` version, and SHA-256 checksum in `state.json`, and no subscription URL (`/sub/`) is created

## ADDED Requirements

### Requirement: Strict mobile-only vanilla `sing-box` profiles for `media-consumer` users
For `media-consumer` users (up to ~20 devices), the system SHALL generate strictly mobile-only vanilla `sing-box` (`>= 1.14`) Media-Selective JSON profiles for Android (SFA) and iOS (SFI), proxying ONLY YouTube, Instagram, Telegram, TikTok, and WhatsApp (`route.final: "direct"`, `dns.final: "dns-local"`), omitting desktop profiles and AI/IDE rules, and using modern `http_clients` without deprecated fields.

#### Scenario: Android `media-consumer` profile matches target apps and domains cleanly
- **WHEN** `android-media-selective.json` is generated for a `media-consumer` user
- **THEN** it includes `override_android_vpn: true`, `package_name` rules for YouTube, Instagram, Telegram, TikTok, and WhatsApp plus their domain suffixes/CIDRs, blocks `UDP 443/3478/19302`, `BitTorrent`, `::/0`, and telemetry, and routes all other apps and domestic traffic to `direct`

#### Scenario: iOS `media-consumer` profile respects Apple NetworkExtension constraints
- **WHEN** `ios-media-selective.json` is generated for a `media-consumer` user
- **THEN** it omits `package_name`, `process_name`, `override_android_vpn`, and `interface_name`, routes YouTube, Instagram, Telegram, TikTok, and WhatsApp strictly via domain suffixes, compact IP CIDRs, and lightweight `.srs` rule-sets safe within the 50 MB iOS NetworkExtension memory limit, and enforces the same unconditional UDP/QUIC/STUN/IPv6/telemetry blocks

### Requirement: Multi-OS admin profile suite for `ai-owner`
For the single `ai-owner` user bound to an `ai-isolated` exit, the system SHALL generate hardened profiles across all five admin platforms: Android (SFA), iOS (SFI), Windows 11 (Throne), Linux (`sing-box` + `xray-client`), and OpenWrt (`sing-box` router config + standalone outbound snippet for `podkop`).

#### Scenario: Admin bundle contains validated profiles for all five target platforms
- **WHEN** profiles are generated for the `ai-owner` user
- **THEN** `/root/vpn-credentials/users/<owner>/` contains schema-compliant profiles for Android (Full & AI-Selective), iOS (Full & AI-Selective without Android-only fields), Windows 11 Throne (Full & AI-Selective), Linux (`linux-singbox.json`, `linux-singbox-selective.json`, `xray-client.json`), and OpenWrt (`openwrt-singbox.json`, `openwrt-outbound.json`), all pointing to the bridge `:443` with `fp=firefox`, zero `urltest`, and full AI anti-drift protection
