# Spec Delta

## MODIFIED Requirements

### Requirement: Automated ACME certificate issuance and zero-disk logging
Nginx on port `:80` (`server_name <domain>;`, disabled by default in `bridge` mode except transiently during `--bridge-acme --acme-http-challenge`) SHALL boot cleanly prior to initial ACME issuance using a bootstrap self-signed certificate pair if a valid `DNS:<domain>` SAN certificate does not yet exist, serve ACME HTTP-01 challenges under `/.well-known/acme-challenge/`, redirect other domain requests on exit nodes to `https://$host$request_uri`, write runtime configs and static decoy files atomically with `0o644` permissions so worker processes can read them consistently, atomically consume reload triggers upon initial ACME certificate installation and cron renewals (`--reloadcmd`), and configure `access_log off;` and `error_log /dev/null crit;`. On Cascade Bridges with `--bridge-acme`, once ACME certificate installation succeeds, Nginx SHALL be re-rendered with port `:80` disabled (`enable_http=False`) while serving the real certificate on `127.0.0.1:8443`.

#### Scenario: First boot succeeds before ACME issuance and hot-reloads into Let's Encrypt certificate
- **WHEN** an exit node (or a `--bridge-acme` bridge during initial certificate provisioning) starts before a valid `DNS:<domain>` SAN certificate exists
- **THEN** a bootstrap self-signed certificate pair with `0o644` world-readable Nginx assets is created so Nginx starts without crashing, serves `/.well-known/acme-challenge/` for `acme.sh --issue`, reloads into the issued Let's Encrypt certificate via `--reloadcmd`, and (in `--bridge-acme` mode) immediately disables HTTP `:80` afterwards

#### Scenario: Requests produce no persistent access or error logs
- **WHEN** VPN clients, browsers, or active probes connect to `:80` or `:443`
- **THEN** zero client IP addresses or request URLs are written to disk
