# Spec Delta

## Purpose

Generates hardened, ready-to-import client configurations and terminal QR codes for Windows 11 (Throne `sing-box` core) and Android directly on the server without any web UI or simultaneous multi-transport probing.

## ADDED Requirements

### Requirement: Local terminal QR code and domain-based VLESS URI export
Upon installation (`./script.sh --domain <fqdn>`), rotation (`./script.sh rotate`), or status check (`./script.sh status`), the system SHALL print the primary `VLESS + Reality + Vision` URI (and the backup `VLESS + XHTTP + TLS` URI when enabled) using `<domain>:443` (never a raw IP host) along with UTF-8/ANSI QR codes directly in the SSH terminal.

#### Scenario: Terminal output includes scannable UTF-8 QR code and domain-based xudp VLESS URI
- **WHEN** `./script.sh status` (or initial install) finishes
- **THEN** stdout contains a valid `vless://<uuid>@<domain>:443` URI with `security=reality`, `flow=xtls-rprx-vision`, `fp=chrome`, `packetEncoding=xudp`, and a multi-line UTF-8 QR code block

### Requirement: Hardened Windows 11 Throne (`sing-box`) and Android profile generation without simultaneous urltest probing
The system SHALL generate `/root/vpn-credentials/throne-windows11.json`, `/root/vpn-credentials/android-singbox.json`, and `/root/vpn-credentials/xray-client.json` pre-configured with strict TUN routing (`strict_route: true`), remote-only IPv4 DoH DNS (`1.1.1.1`/`8.8.8.8`), a manual `selector` outbound (`default: "vless-vision"`, no automatic `urltest` probing across Vision and XHTTP simultaneously), and blocking rules for `QUIC`, `STUN`, telemetry, private CIDRs, and `::/0`.

#### Scenario: Generated Throne profile passes strict anti-leak and anti-correlation validation
- **WHEN** `throne-windows11.json` is generated
- **THEN** it contains a `tun` inbound (`auto_route: true`, `strict_route: true`), routes DNS via `detour: "proxy"` (`strategy: "ipv4_only"`), uses a `selector` (not `urltest`) defaulting to `vless-vision` connected to `<domain>:443`, blocks `quic` (`UDP :443`), `stun` (`UDP :3478/:19302`), and `::/0`, and omits `dns-local`, `geoip:ru`, and `gvt1.com`/`gvt2.com` blocks
