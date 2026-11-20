# Spec Delta

## MODIFIED Requirements

### Requirement: VLESS-only single-owner protocol and TCP keepalive enforcement
The system SHALL configure `xray-core` exclusively with `vless` inbounds (`vless-reality-vision` on `:443` with `dest: "127.0.0.1:8443"` and optional `vless-xhttp-local` on `127.0.0.1:10086` with `mode: "auto"`, `xPaddingBytes: "100-1000"`, and `scMaxEachPostBytes: 1000000`) for a single owner UUID, configure mandatory `sockopt` (`tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`, `tcpMptcp: false`) on VLESS inbounds, bridge upstream outbounds, and exit `direct` outbounds along with `sniffing` (`enabled: true`, `destOverride: ["http", "tls", "quic"]`, `routeOnly: true`), and support two explicit operating modes:
1. **Exit mode (`exit`)**: `outbounds` contain only `direct` (`freedom` with `UseIPv4` and required `sockopt`) and `block` (`blackhole`). When `xhttp_backup_enabled` is `true`, `vless-reality-vision` (`:443`) SHALL include `"fallbacks": [{"dest": "127.0.0.1:10086"}]` in `settings` so `:443` accepts both `xtls-rprx-vision` and Reality-authenticated `XHTTP` streams simultaneously.
2. **Cascade Bridge mode (`bridge`)**: `routing.domainStrategy` is `"AsIs"`, `outbounds` contain only the upstream `vless` Reality connection to the owner's exit node (`address: <upstream_ip>`, `port: 443`, `serverName: <upstream_domain>`, allowed uTLS `fingerprint` defaulting to `"firefox"`, mandatory `sockopt` with `tcpMptcp: false`, and selectable `upstream_transport`: `"vision"` using `network: "tcp"` + `flow: "xtls-rprx-vision"` with `mux_enabled=False`, or `"xhttp"` using `network: "xhttp"` + `flow: ""` + `xhttpSettings` with `path: "/<64-hex>"`, `mode: "stream-up"`, `xPaddingBytes: "100-1000"`, and `xmux` connection rotation) and `block` (`blackhole`), omitting `direct` (`freedom`) completely so client traffic can never exit directly from the bridge IP.

#### Scenario: Generated Xray configuration enforces VLESS-only, routeOnly sniffing, and TCP keepalive
- **WHEN** the server Xray configuration is rendered or validated in `exit` mode
- **THEN** only VLESS inbounds for the single owner UUID are present, inbound and `direct` `freedom` `streamSettings.sockopt` set `tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`, and `tcpMptcp: false`, `sniffing.routeOnly` is `true`, `::/0` is blackholed when IPv6 egress is disabled, and when `xhttp_backup_enabled` is enabled `vless-reality-vision` configures `fallbacks` to `127.0.0.1:10086` alongside `vless-xhttp-local` (`xPaddingBytes: "100-1000"`, `scMaxEachPostBytes: 1000000`)

#### Scenario: Generated Bridge Xray configuration enforces local 127.0.0.1:8443 fallback and fail-closed Frankfurt upstream
- **WHEN** the server Xray configuration is rendered or validated in `bridge` mode with default `vision` upstream transport
- **THEN** `routing.domainStrategy` is `"AsIs"`, the `:443` VLESS Reality inbound uses `dest: "127.0.0.1:8443"` (zero external loop), `outbounds` contain only the non-muxed `vless` Reality TCP upstream pointing to `<upstream_ip>:443` (`SNI: <upstream_domain>`, default `fingerprint: "firefox"`, `tcpMptcp: false`) and `block` (`blackhole`), zero `freedom`/`direct` outbounds exist, and all non-blackholed `tcp,udp` traffic routes to the Frankfurt upstream

#### Scenario: Generated Bridge Xray configuration in XHTTP mode enforces Reality + XHTTP + xmux upstream
- **WHEN** the server Xray configuration is rendered or validated in `bridge` mode with `upstream_transport="xhttp"`
- **THEN** the `:443` client inbound remains `VLESS + TCP + Reality + Vision` (`dest: "127.0.0.1:8443"`), while the `proxy` outbound uses `network: "xhttp"`, `security: "reality"` (`fingerprint: "firefox"`), `flow: ""`, and `xhttpSettings` (`path: "/<64-hex>"`, `mode: "stream-up"`, `xPaddingBytes: "100-1000"`, `xmux` with `maxConcurrency: "16-32"`, `hMaxRequestTimes: "600-900"`, `hMaxReusableSecs: "1800-3000"`), with `freedom`/`direct` absent
