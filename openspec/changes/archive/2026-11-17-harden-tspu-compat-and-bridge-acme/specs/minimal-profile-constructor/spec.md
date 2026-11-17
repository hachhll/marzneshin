# Spec Delta

## MODIFIED Requirements

### Requirement: Local terminal QR code and domain-based VLESS URI export
Upon installation (`./script.sh --domain <fqdn>` or `./script.sh --bridge ...`), rotation (`./script.sh rotate`), or status check (`./script.sh status`), the system SHALL print the primary `VLESS + Reality + Vision` URI (and the backup `VLESS + XHTTP + TLS` URI when enabled in `exit` mode) using `fp=firefox` by default along with pure-Python ISO/IEC 18004 (versions 1..14) UTF-8/ANSI QR codes with bright-white quiet zones directly in the SSH terminal. In `exit` mode, the output SHALL also include a ready-to-copy `sudo ./script.sh --bridge ...` command pre-populated with the exit node's IP, domain, UUID, public key, and `shortId` plus a `--bridge-sni <DEDICATED_BRIDGE_DOMAIN> --bridge-acme` hint. In `bridge` mode, client URIs and profiles SHALL connect to the bridge's host/IP on `:443` while setting `sni` to the configured `<bridge_sni>` FQDN.

#### Scenario: Terminal output includes scannable UTF-8 QR code and domain-based xudp VLESS URI
- **WHEN** `./script.sh status` (or initial install) finishes on an exit node or bridge node
- **THEN** stdout contains a valid `vless://` URI with `security=reality`, `flow=xtls-rprx-vision`, `fp=firefox`, `packetEncoding=xudp`, a multi-line ISO/IEC 18004 UTF-8 QR code block, and (on an exit node) the copy-paste `--bridge` setup command recommending `--bridge-sni <DEDICATED_BRIDGE_DOMAIN> --bridge-acme`

### Requirement: Hardened Windows 11 Throne (`sing-box`) and Android profile generation without simultaneous urltest probing
The system SHALL generate `/root/vpn-credentials/throne-windows11.json`, `/root/vpn-credentials/android-singbox.json`, and `/root/vpn-credentials/xray-client.json` pre-configured with strict TUN routing (`strict_route: true`, emitting `override_android_vpn: true` solely on Android profiles and omitting it on Windows 11), `sing-box 1.12+` remote-only UDP DNS (`1.1.1.1`/`8.8.8.8` with `detour: "proxy"` and `sniff`/`hijack-dns`/`reject` route actions), `firefox` uTLS fingerprint with explicit TCP keepalive (`connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`, Xray `tcpMptcp: false`), a manual `selector` outbound (`default: "vless-vision"`, no automatic `urltest` probing across Vision and XHTTP simultaneously), and blocking rules for `QUIC`, `STUN`, telemetry, private CIDRs, and `::/0`.

#### Scenario: Generated Throne profile passes strict anti-leak and anti-correlation validation
- **WHEN** `throne-windows11.json` is generated
- **THEN** it contains a `tun` inbound (`auto_route: true`, `strict_route: true`) without `override_android_vpn`, uses `sing-box 1.12+` DNS server objects (`type: "udp"`, `detour: "proxy"`, `strategy: "ipv4_only"`) and `action: "sniff"`/`"hijack-dns"`/`"reject"`, configures `firefox` uTLS with keepalive timers (`connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`) on `vless-vision`, uses a `selector` (not `urltest`) defaulting to `vless-vision` connected to `<domain>:443`, blocks `quic` (`UDP :443`), `stun` (`UDP :3478/:19302`), and `::/0`, and omits `dns-local`, `geoip:ru`, and `gvt1.com`/`gvt2.com` blocks

#### Scenario: Generated Android profile preserves override_android_vpn and sing-box 1.12+ schema
- **WHEN** `android-singbox.json` is generated
- **THEN** it sets `override_android_vpn: true` on `tun` (`auto_route: true`, `strict_route: true`), uses `sing-box 1.12+` remote DNS and route actions, configures `firefox` uTLS with keepalive timers, and omits Windows-incompatible or leak-prone rules
