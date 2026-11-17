# Spec Delta

## ADDED Requirements

### Requirement: Pinned Xray-core runtime with verified sing-box cascade compatibility
The container runtime SHALL pin `XRAY_VERSION=v26.6.27` with compatible `protobuf>=5.27.0` gRPC bindings, ensuring full VLESS Reality + Vision handshake compatibility across `sing-box 1.12+` client -> Cascade Bridge -> Exit Xray topologies verified by isolated E2E regression tests.

#### Scenario: Isolated loopback E2E test verifies sing-box 1.12+ -> bridge -> exit handshake
- **WHEN** the E2E compatibility test runs against the built container `xray` binary, loopback `nginx`, and `sing-box`
- **THEN** both the Bridge Xray server and Exit Xray server complete the Reality handshake cleanly (`hs.c.isHandshakeComplete.Load(): true`) with zero `reality verification failed` or `authentication failed` errors

## MODIFIED Requirements

### Requirement: VLESS-only single-owner protocol and TCP keepalive enforcement
The system SHALL configure `xray-core` exclusively with `vless` inbounds (`vless-reality-vision` on `:443` with `dest: "127.0.0.1:8443"` and optional `vless-xhttp-local` on `127.0.0.1:10086`) for a single owner UUID, configure mandatory `sockopt` (`tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`, `tcpMptcp: false`) on VLESS inbounds, bridge upstream outbounds, and exit `direct` outbounds along with `sniffing` (`enabled: true`, `destOverride: ["http", "tls", "quic"]`, `routeOnly: true`), and support two explicit operating modes:
1. **Exit mode (`exit`)**: `outbounds` contain only `direct` (`freedom` with `UseIPv4` and required `sockopt`) and `block` (`blackhole`).
2. **Cascade Bridge mode (`bridge`)**: `routing.domainStrategy` is `"AsIs"`, `outbounds` contain only the upstream `vless` Reality connection to the owner's exit node (`address: <upstream_ip>`, `port: 443`, `serverName: <upstream_domain>`, allowed uTLS `fingerprint` defaulting to `"firefox"`, mandatory `sockopt` with `tcpMptcp: false`, and `mux` disabled by default via `mux_enabled=False` for raw `xtls-rprx-vision` flow) and `block` (`blackhole`), omitting `direct` (`freedom`) completely so client traffic can never exit directly from the bridge IP.

#### Scenario: Generated Xray configuration enforces VLESS-only, routeOnly sniffing, and TCP keepalive
- **WHEN** the server Xray configuration is rendered or validated in `exit` mode
- **THEN** only VLESS inbounds for the single owner UUID are present, inbound and `direct` `freedom` `streamSettings.sockopt` set `tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`, and `tcpMptcp: false`, `sniffing.routeOnly` is `true`, and `::/0` is blackholed when IPv6 egress is disabled

#### Scenario: Generated Bridge Xray configuration enforces local 127.0.0.1:8443 fallback and fail-closed Frankfurt upstream
- **WHEN** the server Xray configuration is rendered or validated in `bridge` mode
- **THEN** `routing.domainStrategy` is `"AsIs"`, the `:443` VLESS Reality inbound uses `dest: "127.0.0.1:8443"` (zero external loop), `outbounds` contain only the non-muxed `vless` Reality upstream pointing to `<upstream_ip>:443` (`SNI: <upstream_domain>`, default `fingerprint: "firefox"`, `tcpMptcp: false`) and `block` (`blackhole`), zero `freedom`/`direct` outbounds exist, and all non-blackholed `tcp,udp` traffic routes to the Frankfurt upstream
