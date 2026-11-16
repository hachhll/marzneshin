# anti-drift-safety-policy Specification

## Purpose

Enforces server, client-profile, and preflight safety invariants that protect against Russia TSPU blocking and prevent IP/account bans on Google Antigravity, Anthropic (Claude), and OpenAI across Windows 11 (Throne) and Android clients.

## Requirements

### Requirement: Single-IP native IPv4 egress without secondary tunnels
The proxy engine SHALL route all allowed outbound traffic solely through a direct `freedom` outbound (`domainStrategy: "UseIPv4"` by default) bound to the server's static IP and SHALL prohibit Cloudflare WARP, Tor, WireGuard, or chained proxies.

#### Scenario: Rendered engine config uses direct IPv4 freedom only
- **WHEN** the server Xray configuration is generated or validated
- **THEN** outbounds contain only `direct` (`freedom` with `UseIPv4`) and `block` (`blackhole`), and any secondary tunnel protocol is rejected

### Requirement: AI-safe telemetry, QUIC, STUN, and BitTorrent blackhole rules
Both server `xray` configs and generated client configs SHALL route Wi-Fi/cell geolocation telemetry, `QUIC` (`UDP :443`), WebRTC `STUN` (`UDP :3478, :19302`), `bittorrent`, and private IP ranges to `blackhole`, while allowing `gvt1.com` and `gvt2.com` so Google Antigravity and Chrome binary updates succeed.

#### Scenario: Geolocation telemetry, QUIC, STUN, and BitTorrent are blocked while gvt1/gvt2 are allowed
- **WHEN** server and client routing rules are inspected
- **THEN** `location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `domain:app-measurement.com`, `domain:firebase-settings.crashlytics.com`, `UDP :443` (`quic`), `UDP :3478/:19302` (`stun`), `bittorrent`, and private CIDRs route to `block`, while `gvt1.com` and `gvt2.com` are not blocked

### Requirement: Remote DNS only without local or geoip:ru split-tunnel leaks
Generated `vless://` links and client profiles SHALL enforce `packetEncoding=xudp`, non-empty uTLS `fp=chrome`, and `Remote DNS only` (`1.1.1.1` and `8.8.8.8` routed strictly through the proxy tunnel with `ipv4_only`), and SHALL NOT include `dns-local`, `geoip:ru -> direct`, or `geoip:ir -> direct` rules that cause split-tunnel IP leaks on Google Global Cache or AI endpoints.

#### Scenario: Windows 11 Throne and Xray client profiles route all DNS and traffic through proxy
- **WHEN** the generated `throne-windows11.json` (`sing-box`) and `xray-client.json` profiles are validated
- **THEN** all DNS queries route through the `proxy` outbound (`ipv4_only` / `UseIPv4`), `tun` enforces `strict_route: true`, and zero `dns-local` or country-direct bypass rules exist

### Requirement: Triple anonymous AI-platform egress verification
Installer preflight and `self-test` SHALL verify direct server egress anonymously (`--noproxy '*'`, neutral `de-DE,de;q=0.9,en-US;q=0.8` headers, zero user credentials) against Google (`youtube.com` `INNERTUBE_CONTEXT_GL != RU`), OpenAI (`chatgpt.com/cdn-cgi/trace` `loc != RU` and `warp=off`), and Anthropic (`api.anthropic.com` TLS 1.3 handshake + non-blocked HTTP response).

#### Scenario: Clean non-RU VPS passes triple AI egress check
- **WHEN** the anonymous egress check runs on a compliant VPS
- **THEN** Google reports `GL != RU`, OpenAI trace reports `loc != RU` and `warp=off`, and Anthropic API responds without a country/ASN block

#### Scenario: RU geolocation or WARP contamination aborts deployment
- **WHEN** Google reports `GL == RU` or OpenAI trace reports `loc == RU` or `warp != off`
- **THEN** the installer or `self-test` fails immediately and reports the contaminated check

### Requirement: Executable safety self-test via SSH CLI
The system SHALL provide `./script.sh self-test` (and Python verification helpers) checking UFW SSH/80/443 rules, TCP BBR status, live Reality `:443`, Nginx TLS 1.3 `:8443` decoy fallback, zero unexpected public ports, zero WireGuard/WARP/Tor processes, `/dev/null` logging, QUIC/STUN/telemetry blackholes, `gvt1.com` allowance, and the triple AI egress check.

#### Scenario: Healthy appliance passes all self-test checks
- **WHEN** the owner runs `./script.sh self-test`
- **THEN** all safety checks report `[PASS]` and exit code `0`
