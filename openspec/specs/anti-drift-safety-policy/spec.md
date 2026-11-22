# anti-drift-safety-policy Specification

## Purpose

Enforces server, client-profile, and preflight safety invariants that protect against Russia TSPU blocking and prevent IP/account bans on Google Antigravity, Anthropic (Claude), and OpenAI across Windows 11 (Throne) and Android clients.

## Requirements

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
- **THEN** all DNS queries use `sing-box 1.12+` remote server objects (`detour: "proxy"`, `strategy: "ipv4_only"`) with `query_type: "HTTPS"` rejected in `dns.rules`, client outbounds carry keepalive settings (`firefox` uTLS, `tcpMptcp: false` in Xray), `tun` enforces `strict_route: true`, Android-only `override_android_vpn` is omitted from Windows profiles, and zero `dns-local` or country-direct bypass rules exist

#### Scenario: Selective profiles isolate proxied DNS from domestic direct DNS
- **WHEN** an `ai-owner` AI-Selective or `media-consumer` Media-Selective profile is validated
- **THEN** every proxied domain/app/rule-set resolves via `dns-remote` (`detour: "proxy"`), `query_type: "HTTPS"` is rejected, and only unmatched/domestic traffic uses `direct` + `dns-local`

### Requirement: Triple anonymous AI-platform egress verification
Installer preflight and `self-test` SHALL verify direct server egress anonymously (`--noproxy '*'`, neutral `de-DE,de;q=0.9,en-US;q=0.8` headers, zero user credentials) against Google (`youtube.com` `INNERTUBE_CONTEXT_GL != RU`), OpenAI (`chatgpt.com/cdn-cgi/trace` `loc != RU` and `warp=off`), and Anthropic (`api.anthropic.com` TLS 1.3 handshake + non-blocked HTTP response).

#### Scenario: Clean non-RU VPS passes triple AI egress check
- **WHEN** the anonymous egress check runs on a compliant VPS
- **THEN** Google reports `GL != RU`, OpenAI trace reports `loc != RU` and `warp=off`, and Anthropic API responds without a country/ASN block

#### Scenario: RU geolocation or WARP contamination aborts deployment
- **WHEN** Google reports `GL == RU` or OpenAI trace reports `loc == RU` or `warp != off`
- **THEN** the installer or `self-test` fails immediately and reports the contaminated check

### Requirement: Executable safety self-test via SSH CLI
The system SHALL provide `./script.sh self-test` (and Python verification helpers) operating in **100% passive Zero-Emission mode by default** (verifying Xray and Nginx config safety, local `127.0.0.1:8443` probe isolation config, zero unexpected public listening ports in `/proc/net/tcp`, zero WireGuard/WARP/Tor processes in `/proc`, `/dev/null` logging, QUIC/STUN/telemetry blackholes, and `gvt1.com` allowance without emitting any network packets), while emitting non-fatal `WARN:` notices on healthy bridge deployments using a shared upstream SNI or `CN=localhost` dummy certificate and supporting `--active-probe` for optional live loopback TLS and triple AI egress checks on exit nodes.

#### Scenario: Healthy appliance passes all self-test checks
- **WHEN** the owner runs `./script.sh self-test` on either an exit node or a bridge node
- **THEN** all passive safety checks report `[PASS]` with exit code `0` and zero outbound network packets are emitted

#### Scenario: Bridge node with shared SNI or localhost dummy cert passes self-test with warnings
- **WHEN** `self-test` checks a valid Cascade Bridge configuration whose SNI matches the upstream exit domain or whose fallback certificate has `CN=localhost`
- **THEN** `xray_config_safety` remains `[PASS]` with exit code `0` and appends non-fatal `WARN:` guidance recommending an independent `--bridge-sni` and `--bridge-acme`

### Requirement: MPTCP disabled across kernel sysctl and proxy sockets
The system SHALL explicitly disable Multipath TCP (`tcpMptcp: false` in `xray` `sockopt` and `net.mptcp.enabled = 0` in kernel `sysctl`) on both exit and bridge appliances to avoid MPTCP kernel vulnerabilities (`CVE-2026-98432`) and DPI TCP option anomalies.

#### Scenario: Kernel sysctl and Xray socket options disable MPTCP
- **WHEN** the installer configures host kernel hardening and renders `xray` server or client configurations
- **THEN** `/etc/sysctl.d/99-vpn-hardening.conf` sets `net.mptcp.enabled = 0` and all required `xray` `sockopt` blocks set `tcpMptcp: false`

### Requirement: Server-side domestic RU egress blackhole on foreign exit nodes
In `exit` mode, the proxy engine SHALL block outbound traffic destined for Russian domains (`domain:ru`, `domain:su`, `domain:xn--p1ai`) and Russian IP ranges (`geoip:ru`) via the `block` (`blackhole`) outbound prior to the final `direct` (`freedom`) rule, without introducing Cloudflare WARP or any secondary tunnel, while `bridge` mode continues to enforce `domainStrategy: "AsIs"` with zero `freedom` outbounds.

#### Scenario: Foreign exit node blackholes domestic RU domains and IP ranges
- **WHEN** a foreign exit node Xray configuration is generated or audited by `validate_xray_config` / `self-test`
- **THEN** routing rules include a `block` rule for `domain:ru`, `domain:su`, `domain:xn--p1ai`, and `geoip:ru` ahead of the `direct` outbound rule, and zero secondary tunnels (WARP/Tor/WireGuard) exist

### Requirement: Operational resource and passive audit validation for multi-exit bridges
Passive Zero-Emission `self-test` on a multi-exit bridge SHALL validate all configured upstreams (zero `freedom` outbounds, zero `ai-isolated` role violations, zero un-overridden `/24` subnet collisions between `ai-isolated` and `media` exits, mandatory `UDP 443/3478/19302` blackhole rules, and bounded `xmux` session rotation) and SHALL emit a non-fatal `WARN:` when `ai-isolated` and `media` exits share a registrable root domain or when a multi-user bridge has less than `1800 MB` RAM or `0 MB` swap configured.

#### Scenario: Passive self-test validates multi-exit bridge invariants without emitting traffic
- **WHEN** `./script.sh self-test` runs on a multi-exit bridge
- **THEN** it checks all upstream outbounds, `ai-isolated` guards, `/24` subnet separation, blackhole rules, `xmux` rotation bounds, shared root-domain warnings, and memory/swap headroom purely from local files and `/proc` without emitting any network packets
