# Spec Delta

## MODIFIED Requirements

### Requirement: Self-Reality ingress and PROXY protocol fallback
The VLESS Reality listener on TCP `:443` SHALL use `xtls-rprx-vision`, a non-empty 16-hex-character `shortId`, `maxTimeDiff: 60000`, and SHALL forward all non-Reality connections to local Nginx on `127.0.0.1:8443` using `PROXY protocol` (`xver: 1`) in both `exit` mode and `bridge` mode, so that active DPI/TSPU probes never trigger outbound hair-pin connections to external third-party `dest` hosts.

#### Scenario: Valid Reality client establishes VPN tunnel
- **WHEN** a client connects to `:443` with the owner's UUID, a timestamp within `maxTimeDiff`, and the configured non-empty `shortId`
- **THEN** the connection is terminated by `xray-core` and routed according to the server routing table

#### Scenario: Active TSPU probe or browser with matching SNI falls back to local Nginx
- **WHEN** a browser or DPI probe connects to `:443` without valid Reality authentication on either an exit node or a bridge node
- **THEN** the connection is transparently forwarded over `127.0.0.1:8443` with `PROXY protocol` to local Nginx without generating any outbound TCP connections to external websites

### Requirement: Automated ACME certificate issuance and zero-disk logging
Nginx on port `:80` (`server_name <domain>;`) SHALL boot cleanly prior to initial ACME issuance using a bootstrap self-signed certificate pair if the ACME certificate files do not yet exist, serve ACME HTTP-01 challenges under `/.well-known/acme-challenge/`, redirect other domain requests to `https://$host$request_uri`, atomically consume reload triggers and reload cleanly upon initial ACME certificate installation and subsequent cron renewals (`--reloadcmd`), and configure `access_log off;` and `error_log /dev/null crit;`.

#### Scenario: First boot succeeds before ACME issuance and hot-reloads into Let's Encrypt certificate
- **WHEN** the appliance starts for the first time before `acme.sh` has issued a Let's Encrypt certificate for `<domain>`
- **THEN** a bootstrap self-signed certificate pair is created at the configured certificate paths so Nginx starts immediately on `:80` and `127.0.0.1:8443` without crashing, serves `/.well-known/acme-challenge/` for `acme.sh --issue`, and reloads into the issued Let's Encrypt certificate via `--reloadcmd`

#### Scenario: Requests produce no persistent access or error logs
- **WHEN** VPN clients, browsers, or active probes connect to `:80` or `:443`
- **THEN** zero client IP addresses or request URLs are written to disk
