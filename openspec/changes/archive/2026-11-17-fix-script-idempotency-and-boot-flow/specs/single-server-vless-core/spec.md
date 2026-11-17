# Spec Delta

## MODIFIED Requirements

### Requirement: VLESS-only single-owner protocol and TCP keepalive enforcement
The system SHALL configure `xray-core` exclusively with `vless` inbounds (`vless-reality-vision` on `:443` with `dest: "127.0.0.1:8443"` and optional `vless-xhttp-local` on `127.0.0.1:10086`) for a single owner UUID, configure `sockopt` (`tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`) and `sniffing` (`enabled: true`, `destOverride: ["http", "tls", "quic"]`, `routeOnly: true`), and support two explicit operating modes:
1. **Exit mode (`exit`)**: `outbounds` contain only `direct` (`freedom` with `UseIPv4`) and `block` (`blackhole`).
2. **Cascade Bridge mode (`bridge`)**: `outbounds` contain only the upstream `vless` Reality connection to the owner's exit node (`address: <upstream_ip>`, `port: 443`, `serverName: <upstream_domain>`, `fingerprint: "chrome"`, `sockopt` keepalive, and optional persistent `mux` with `xudp`) and `block` (`blackhole`), omitting `direct` (`freedom`) completely so client traffic can never exit directly from the bridge IP.

#### Scenario: Generated Xray configuration enforces VLESS-only, routeOnly sniffing, and TCP keepalive
- **WHEN** the server Xray configuration is rendered or validated in `exit` mode
- **THEN** only VLESS inbounds for the single owner UUID are present, `streamSettings.sockopt` sets `tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, and `tcpNoDelay: true`, `sniffing.routeOnly` is `true`, and `::/0` is blackholed when IPv6 egress is disabled

#### Scenario: Generated Bridge Xray configuration enforces local 127.0.0.1:8443 fallback and fail-closed Frankfurt upstream
- **WHEN** the server Xray configuration is rendered or validated in `bridge` mode
- **THEN** the `:443` VLESS Reality inbound uses `dest: "127.0.0.1:8443"` (zero external loop), `outbounds` contain only the `vless` Reality upstream pointing to `<upstream_ip>:443` (`SNI: <upstream_domain>`, `fingerprint: "chrome"`) and `block` (`blackhole`), zero `freedom`/`direct` outbounds exist, and all non-blackholed `tcp,udp` traffic routes to the Frankfurt upstream
