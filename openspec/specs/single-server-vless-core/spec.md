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
The system SHALL configure `xray-core` exclusively with `vless` inbounds (`vless-reality-vision` on `:443` and optional `vless-xhttp-local` on `127.0.0.1:10086`) for a single owner UUID, configure `sockopt` (`tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`) and `sniffing` (`enabled: true`, `destOverride: ["http", "tls", "quic"]`, `routeOnly: true`), and reject all non-VLESS protocols and outbound proxy chains.

#### Scenario: Generated Xray configuration enforces VLESS-only, routeOnly sniffing, and TCP keepalive
- **WHEN** the server Xray configuration is rendered or validated
- **THEN** only VLESS inbounds for the single owner UUID are present, `streamSettings.sockopt` sets `tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, and `tcpNoDelay: true`, `sniffing.routeOnly` is `true`, and `::/0` is blackholed when IPv6 egress is disabled

### Requirement: Elimination of traffic accounting and connection metadata
The system SHALL NOT configure `StatsService`, traffic policy counters, access logs, error logs, or connection metadata tracking.

#### Scenario: Xray configuration disables all logging and statistics
- **WHEN** the Xray configuration is validated
- **THEN** `log.access`, `log.error`, and `log.loglevel` are set to `"none"` and neither `stats` nor `policy` sections are present
