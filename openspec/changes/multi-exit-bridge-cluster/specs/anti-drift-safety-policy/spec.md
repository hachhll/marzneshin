# Spec Delta

## MODIFIED Requirements

### Requirement: Single-IP native IPv4 egress without secondary tunnels
In `exit` mode, the proxy engine SHALL route all allowed outbound traffic solely through a direct `freedom` outbound (`domainStrategy: "UseIPv4"` by default with mandatory keepalive/`tcpMptcp: false` `sockopt`) bound to the server's static IP and SHALL prohibit Cloudflare WARP, Tor, WireGuard, or arbitrary third-party proxy chains. In `bridge` mode, the proxy engine SHALL route all allowed outbound traffic solely through the closed set of explicitly configured `vless` Reality outbounds pointing to the owner's dedicated exit node IPs (`<upstream_ip>:443`) using `firefox` uTLS by default (`mux` disabled), with each user statically pinned to exactly one exit IP (zero cross-exit load-balancing or IP flapping), and SHALL omit `freedom` (`direct`) outbounds so zero traffic can leak onto the domestic bridge network.

#### Scenario: Rendered engine config uses direct IPv4 freedom only
- **WHEN** the server Xray configuration is generated or validated in `exit` mode
- **THEN** outbounds contain only `direct` (`freedom` with `UseIPv4` and `sockopt` setting `tcpMptcp: false`) and `block` (`blackhole`), and any secondary tunnel protocol is rejected

#### Scenario: Rendered engine config uses fail-closed upstream VLESS only in bridge mode
- **WHEN** the server Xray configuration is generated or validated in `bridge` mode with one or more configured upstreams
- **THEN** outbounds contain only the configured `vless` Reality upstream outbounds (each with default `fingerprint: "firefox"`, `sockopt.tcpMptcp: false`, and no `mux`) and `block` (`blackhole`), `freedom` (`direct`) is absent, and every client UUID maps statically to a single upstream

### Requirement: AI-safe telemetry, QUIC, STUN, and BitTorrent blackhole rules
Both server `xray` configs (bridge and every `ai-isolated` and `media` exit) and ALL generated client configs (`ai-owner` and `media-consumer` alike) SHALL unconditionally route Wi-Fi/cell geolocation telemetry, `QUIC` (`UDP :443`), WebRTC `STUN` (`UDP :3478, :19302`), `bittorrent`, private IP ranges, and `::/0` (IPv6) to `blackhole`/`reject`, with zero protocol or port relaxations for voice/video calls, while allowing `gvt1.com` and `gvt2.com` so Google Antigravity and binary updates succeed.

#### Scenario: Geolocation telemetry, QUIC, STUN, and BitTorrent are blocked while gvt1/gvt2 are allowed
- **WHEN** server configs (bridge, `exit-ai`, `exit-media-*`) and client configs (`ai-owner`, `media-consumer`) are validated
- **THEN** `location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `domain:app-measurement.com`, `domain:firebase-settings.crashlytics.com`, `UDP :443` (`quic`), `UDP :3478/:19302` (`stun`), `bittorrent`, private CIDRs, and `::/0` route to `block`/`reject` with zero exceptions for `media-consumer` calls, while `gvt1.com` and `gvt2.com` are not blocked

### Requirement: Remote DNS only without local or geoip:ru split-tunnel leaks
Generated `vless://` links and client profiles SHALL enforce `packetEncoding=xudp`, non-empty allowed uTLS fingerprint defaulting to `fp=firefox`, `sing-box 1.12+` remote UDP DNS (`type: "udp"`, `server: "1.1.1.1"` / `8.8.8.8`, `detour: "proxy"` with `strategy: "ipv4_only"` and `query_type: "HTTPS"` blocked), explicit client outbound keepalive (`connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`) and `xray-client` `sockopt` (`tcpMptcp: false`). Full-tunnel profiles SHALL omit `dns-local` and country-direct bypass rules; Selective profiles (`ai-owner` AI-Selective and `media-consumer` Media-Selective) SHALL resolve all proxied domains/apps via `dns-remote` (`detour: "proxy"`) and route only domestic/unmatched traffic via `direct` + `dns-local`.

#### Scenario: Windows 11 Throne and Xray client profiles route all DNS and traffic through proxy
- **WHEN** the generated `throne-windows11.json` (`sing-box`) and `xray-client.json` Full-tunnel profiles are validated
- **THEN** all DNS queries use `sing-box 1.12+` remote server objects (`detour: "proxy"`, `strategy: "ipv4_only"`), client outbounds carry keepalive settings (`firefox` uTLS, `tcpMptcp: false` in Xray), `tun` enforces `strict_route: true`, Android-only `override_android_vpn` is omitted from Windows profiles, and zero `dns-local` or country-direct bypass rules exist

#### Scenario: Selective profiles isolate proxied DNS from domestic direct DNS
- **WHEN** an `ai-owner` AI-Selective or `media-consumer` Media-Selective profile is validated
- **THEN** every proxied domain/app/rule-set resolves via `dns-remote` (`detour: "proxy"`), `query_type: "HTTPS"` is rejected, and only unmatched/domestic traffic uses `direct` + `dns-local`

## ADDED Requirements

### Requirement: Operational resource and passive audit validation for multi-exit bridges
Passive Zero-Emission `self-test` on a multi-exit bridge SHALL validate all configured upstreams (zero `freedom` outbounds, zero `ai-isolated` role violations, zero root-domain collisions between `ai-isolated` and `media` exits, and mandatory `UDP 443/3478/19302` blackhole rules) and SHALL emit a non-fatal `WARN:` if a multi-user bridge has less than `1800 MB` RAM or `0 MB` swap configured.

#### Scenario: Passive self-test validates multi-exit bridge invariants without emitting traffic
- **WHEN** `./script.sh self-test` runs on a multi-exit bridge
- **THEN** it checks all upstream outbounds, `ai-isolated` guards, blackhole rules, and memory/swap headroom purely from local files and `/proc` without emitting any network packets
