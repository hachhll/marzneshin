# single-server-vless-core Specification

## Purpose

Restricts the VPN appliance to a stateless, single-user local `xray-core` server running only the VLESS protocol (`Reality + Vision` primary and optional `XHTTP` backup) with TCP keepalive socket hardening and IPv6 blackholing, while completely eliminating any web control plane, database, multi-user/admin services, traffic accounting, and persistent logs.

## Requirements

### Requirement: Stateless zero-web single-user architecture
The system SHALL operate without a web backend (FastAPI/Uvicorn), relational database (SQLite/SQLAlchemy/Alembic), or web frontend (`dashboard/`), and SHALL manage the single owner's VLESS credentials and local `xray-core` configuration exclusively through local state files (`/var/lib/vpn/`) and the SSH CLI (`script.sh`).

#### Scenario: Running appliance has no web application or database process
- **WHEN** the appliance is deployed and running
- **THEN** only the `xray` and `nginx` services run, and no Python web server, SQLite database, or web dashboard routes exist

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

### Requirement: Elimination of traffic accounting and connection metadata
The system SHALL NOT configure `StatsService`, traffic policy counters, access logs, error logs, or connection metadata tracking.

#### Scenario: Xray configuration disables all logging and statistics
- **WHEN** the Xray configuration is validated
- **THEN** `log.access`, `log.error`, and `log.loglevel` are set to `"none"` and neither `stats` nor `policy` sections are present

### Requirement: Pinned Xray-core runtime with verified sing-box cascade compatibility
The container runtime SHALL pin `XRAY_VERSION=v26.6.27` with compatible `protobuf>=5.27.0` gRPC bindings, ensuring full VLESS Reality + Vision handshake compatibility across `sing-box 1.12+` client -> Cascade Bridge -> Exit Xray topologies verified by isolated E2E regression tests.

#### Scenario: Isolated loopback E2E test verifies sing-box 1.12+ -> bridge -> exit handshake
- **WHEN** the E2E compatibility test runs against the built container `xray` binary, loopback `nginx`, and `sing-box`
- **THEN** both the Bridge Xray server and Exit Xray server complete the Reality handshake cleanly (`hs.c.isHandshakeComplete.Load(): true`) with zero `reality verification failed` or `authentication failed` errors
