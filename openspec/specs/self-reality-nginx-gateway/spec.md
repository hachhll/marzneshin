# self-reality-nginx-gateway Specification

## Purpose

Establishes a zero-surface, probe-resistant Self-Reality ingress topology on ports 80 and 443 backed by a local TLS 1.3 Nginx server that isolates raw-IP/no-SNI probes, serves a polymorphic static decoy website without `ETag`/`Last-Modified` fingerprints, and exposes zero backend API, panel, or subscription routes and zero disk logging.

## Requirements

### Requirement: Minimal public port surface with SSH protection
The system SHALL expose only TCP ports `80`, `443`, and the host's active SSH port (protected via `ufw limit`), keeping the Nginx HTTPS fallback port (`127.0.0.1:8443`) and optional XHTTP port (`127.0.0.1:10086`) bound strictly to loopback.

#### Scenario: Public port scan shows only SSH, 80, and 443
- **WHEN** the appliance is running in production mode
- **THEN** only `80/tcp`, `443/tcp`, and the configured SSH port accept external connections, while `127.0.0.1:8443` and `127.0.0.1:10086` refuse external traffic

### Requirement: Self-Reality ingress and PROXY protocol fallback
The VLESS Reality listener on TCP `:443` SHALL use `xtls-rprx-vision`, a non-empty 16-hex-character `shortId`, `maxTimeDiff: 60000`, and SHALL forward all non-Reality connections to local Nginx on `127.0.0.1:8443` using `PROXY protocol` (`xver: 1`) in both `exit` mode and `bridge` mode, so that active DPI/TSPU probes never trigger outbound hair-pin connections to external third-party `dest` hosts.

#### Scenario: Valid Reality client establishes VPN tunnel
- **WHEN** a client connects to `:443` with the owner's UUID, a timestamp within `maxTimeDiff`, and the configured non-empty `shortId`
- **THEN** the connection is terminated by `xray-core` and routed according to the server routing table

#### Scenario: Active TSPU probe or browser with matching SNI falls back to local Nginx
- **WHEN** a browser or DPI probe connects to `:443` without valid Reality authentication on either an exit node or a bridge node
- **THEN** the connection is transparently forwarded over `127.0.0.1:8443` with `PROXY protocol` to local Nginx without generating any outbound TCP connections to external websites

### Requirement: Raw-IP and missing-SNI probe isolation on ports 80 and 8443
Nginx SHALL define catch-all `default_server` blocks (`server_name _;`) on both port `:80` and `127.0.0.1:8443` that terminate requests with `return 444;`, using a neutral self-signed certificate (`CN=localhost`) on `127.0.0.1:8443` so probes without matching SNI neither trigger `TLS alert 80` nor receive the domain's ACME certificate.

#### Scenario: Probe to port 80 by raw IP is dropped without HTTPS redirect
- **WHEN** a scanner sends an HTTP request to `http://<SERVER_IP>/` with `Host: <SERVER_IP>`
- **THEN** the `:80` `default_server` closes the connection (`444`) instead of returning `301 Location: https://<SERVER_IP>/`

#### Scenario: TLS probe to port 443 without SNI or with foreign SNI does not leak domain cert or alert 80
- **WHEN** a scanner connects to `<SERVER_IP>:443` without SNI (`-noservername`) or with a foreign SNI (`example.com`)
- **THEN** Nginx `default_server` on `127.0.0.1:8443` completes the handshake using the neutral `CN=localhost` certificate (not `TLS alert 80` and not the domain's ACME certificate) and closes any HTTP request with `444`

### Requirement: Polymorphic static decoy masking without ETag, Last-Modified, or web panel paths
Nginx SHALL serve a benign decoy website on `/` and `/404.html` for `server_name <domain>`, configure `server_tokens off;`, `etag off;`, `if_modified_since off;`, and `add_header Last-Modified "";`, inject per-install randomized entropy into static decoy files, and expose zero `/api/`, `/sub/`, `/setup`, `/admin`, or `/dashboard/` locations.

#### Scenario: Any probe path on the domain returns static decoy HTML without ETag or Last-Modified
- **WHEN** a scanner or browser requests `/`, `/sub/test`, `/api/status`, `/admin`, or `/dashboard` with `Host: <domain>`
- **THEN** Nginx serves only static decoy content (`200` on `/`, decoy `404` on unknown paths) without `ETag` or `Last-Modified` headers and with zero upstream proxy connections when backup XHTTP is disabled

### Requirement: Automated ACME certificate issuance and zero-disk logging
Nginx on port `:80` (`server_name <domain>;`, disabled by default in `bridge` mode except transiently during `--bridge-acme --acme-http-challenge`) SHALL boot cleanly prior to initial ACME issuance using a bootstrap self-signed certificate pair if a valid `DNS:<domain>` SAN certificate does not yet exist, serve ACME HTTP-01 challenges under `/.well-known/acme-challenge/`, redirect other domain requests on exit nodes to `https://$host$request_uri`, write runtime configs and static decoy files atomically with `0o644` permissions so worker processes can read them consistently, atomically consume reload triggers upon initial ACME certificate installation and cron renewals (`--reloadcmd`), and configure `access_log off;` and `error_log /dev/null crit;`. On Cascade Bridges with `--bridge-acme`, once ACME certificate installation succeeds, Nginx SHALL be re-rendered with port `:80` disabled (`enable_http=False`) while serving the real certificate on `127.0.0.1:8443`.

#### Scenario: First boot succeeds before ACME issuance and hot-reloads into Let's Encrypt certificate
- **WHEN** an exit node (or a `--bridge-acme` bridge during initial certificate provisioning) starts before a valid `DNS:<domain>` SAN certificate exists
- **THEN** a bootstrap self-signed certificate pair with `0o644` world-readable Nginx assets is created so Nginx starts without crashing, serves `/.well-known/acme-challenge/` for `acme.sh --issue`, reloads into the issued Let's Encrypt certificate via `--reloadcmd`, and (in `--bridge-acme` mode) immediately disables HTTP `:80` afterwards

#### Scenario: Requests produce no persistent access or error logs
- **WHEN** VPN clients, browsers, or active probes connect to `:80` or `:443`
- **THEN** zero client IP addresses or request URLs are written to disk
