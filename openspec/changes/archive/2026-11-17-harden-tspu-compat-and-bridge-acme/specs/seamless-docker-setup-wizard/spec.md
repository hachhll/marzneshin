# Spec Delta

## MODIFIED Requirements

### Requirement: Single-command Ubuntu installation with SSH protection and kernel anti-storm hardening
The installer (`./script.sh --domain <fqdn>` for an exit node, or `./script.sh --bridge ...` for a Russian cascade bridge node) SHALL verify root privileges, NTP sync, and free required ports (allowing idempotent re-runs against own containers and passing `--build` on Compose commands), provision hardened SSH access (creating sudo admin user `stealth` with copied SSH public keys, aborting if zero keys exist, switching off `ssh.socket`, binding IPv4 `Port 22222` with `PermitRootLogin no`, `PasswordAuthentication no`, and `AllowUsers stealth`, and deleting `22/tcp` from UFW once `:22222` is confirmed listening), apply UFW `limit` rules and kernel anti-storm `sysctl` (`bbr + fq`, `tcp_fin_timeout=15`, `tcp_keepalive_time=120`, `tcp_synack_retries=2`, `tcp_retries2=5`, `tcp_max_syn_backlog=4096`, `tcp_syncookies=1`, `tcp_fastopen=0`, `tcp_mtu_probing=0`, `disable_ipv6=1`, `net.mptcp.enabled=0`) plus flush-safe persistent `TCPMSS=1360` clamping, and deploy the `xray` + `nginx` stack while persisting host credentials. In `--bridge` mode without `--bridge-acme`, the installer SHALL keep `80/tcp` closed, detect local IPv4 via kernel routing (rejecting private RFC1918/CGNAT NAT addresses unless `--bridge-ip <PUBLIC_IP>` is explicitly provided), forbid `--bridge-acme` when reusing `--upstream-domain`, and when `--bridge-acme` is set with an independent `--bridge-sni`, temporarily open `80/tcp` for HTTP-01 ACME issuance only if a `DNS:<domain>` SAN certificate is missing, then delete `80/tcp` from UFW permanently.

#### Scenario: Installer hardens kernel, protects active SSH port, and completes in one command
- **WHEN** the owner runs `sudo ./script.sh --domain vpn.example.com` over SSH with authorized keys present
- **THEN** the script provisions `stealth` with passwordless sudo and copied SSH keys, validates `sshd -t`, switches Ubuntu `ssh.socket` to IPv4 `ssh.service` on `Port 22222`, disables root/password auth (`AllowUsers stealth`), adds `ufw limit`, removes `22/tcp` once `:22222` listens, opens `80/tcp` and `443/tcp`, applies anti-storm `sysctl` (`net.mptcp.enabled=0`, `tcp_retries2=5`, `tcp_max_syn_backlog=4096`, `tcp_syncookies=1`) and `TCPMSS=1360`, deploys `xray` and `nginx` via `--build`, writes `/root/vpn-credentials`, and prints credentials, QR code, and a pre-populated `--bridge` command to stdout

#### Scenario: Re-running installer on an already-provisioned server succeeds idempotently
- **WHEN** the owner re-runs `sudo ./script.sh --domain vpn.example.com` while `marzneshin-xray` and `marzneshin-nginx` are already running and listening on `:443` and `:80`
- **THEN** `script.sh` does not fail with a port conflict for its own containers, preserves any previously saved `decoy_target` if `--decoy` is not explicitly specified, avoids duplicating kernel `*mangle` `TCPMSS=1360` rules on `ufw reload`, rebuilds updated container images if needed, and converges cleanly

#### Scenario: Bridge mode deploys on a Russian VPS with zero outbound diagnostic probes
- **WHEN** the owner runs `sudo ./script.sh --bridge --upstream-ip <ip> --upstream-domain <fqdn> --upstream-uuid <uuid> --upstream-pbk <pbk> --upstream-sid <sid> --bridge-ip <public_ip>` without `--bridge-acme` on a clean Ubuntu 26 server in Russia
- **THEN** the installer configures `sysctl` and `TCPMSS=1360`, hardens SSH onto `stealth:22222`, keeps `80/tcp` closed, performs zero `curl`/`openssl`/DNS probes against `<upstream-ip>` or `<fqdn>`, starts local `127.0.0.1:8443` fallback and fail-closed `xray` bridge, and outputs client profiles pointing to the bridge

#### Scenario: Bridge mode guards private NAT IPs and supports optional temporary HTTP-01 ACME issuance
- **WHEN** the owner deploys a Cascade Bridge behind NAT or with `--bridge-sni bridge.example.com --bridge-acme`
- **THEN** `script.sh` aborts if local IPv4 detection yields an RFC1918/CGNAT address without explicit `--bridge-ip`, aborts if `--bridge-acme` shares `--upstream-domain`, and with valid `--bridge-acme` opens `80/tcp` solely for `acme.sh --issue` / `--install-cert` before deleting `80/tcp` from UFW and keeping `443/tcp` + `22222/tcp` only

### Requirement: Direct DNS, CDN-bypass, and high-risk TLD preflight validation
Before requesting ACME certificates or deploying either an exit node or a Cascade Bridge, `script.sh` SHALL reject high-risk abused TLDs (`.xyz`, `.top`, `.club`, `.icu`, `.site`, `.online`, `.fun`, `.space`, `.buzz`, `.monster`) unless `--allow-risky-tld` is passed, and SHALL verify that `<fqdn>` resolves directly to the server's public IPv4 address without Cloudflare proxy CIDRs on exit nodes and on bridge nodes configured with `--bridge-acme`.

#### Scenario: High-risk TLD or proxied/mismatched domain aborts installation
- **WHEN** `<fqdn>` (exit domain or bridge SNI) uses a blocked high-risk TLD without `--allow-risky-tld`, or an ACME-enabled domain resolves to a Cloudflare proxy IP or mismatched IPv4 address
- **THEN** `script.sh` aborts with a clear error message before starting containers
