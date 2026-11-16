# seamless-docker-setup-wizard Specification

## Purpose

Delivers a single-command Ubuntu installer and SSH management CLI (`script.sh`) that enforces domain TLD hygiene, hardens SSH/UFW, kernel TCP anti-storm parameters, and TCPMSS clamping, validates DNS and AI egress reputation, provisions ACME TLS 1.3 and fallback certificates, and outputs ready-to-use `vless://` links, ANSI QR codes, and Windows 11 Throne / Android profiles directly to the SSH terminal.

## Requirements

### Requirement: Single-command Ubuntu installation with SSH protection and kernel anti-storm hardening
The installer (`./script.sh --domain <fqdn>`) SHALL verify root privileges, NTP sync, and free ports `:80`/`:443`, auto-detect the active SSH port (`$SSH_CONNECTION` and `/etc/ssh/sshd_config`) to apply `ufw limit <ssh_port>/tcp`, configure kernel `sysctl` (`bbr + fq`, `tcp_fin_timeout=15`, `tcp_keepalive_time=120`, `tcp_synack_retries=2`, `tcp_fastopen=0`, `tcp_mtu_probing=0`, `disable_ipv6=1`) and `TCPMSS=1360` clamping, and deploy the `xray` + `nginx` stack.

#### Scenario: Installer hardens kernel, protects active SSH port, and completes in one command
- **WHEN** the owner runs `sudo ./script.sh --domain vpn.example.com` over SSH on port `22` or a custom port (e.g. `2222`)
- **THEN** the script adds `ufw limit <detected_ssh_port>/tcp`, opens `80/tcp` and `443/tcp`, applies the anti-storm `sysctl` profile and `TCPMSS=1360` clamping, deploys `xray` and `nginx`, and prints the VPN credentials and QR code to stdout

### Requirement: Direct DNS, CDN-bypass, and high-risk TLD preflight validation
Before requesting ACME certificates, `script.sh` SHALL reject high-risk abused TLDs (`.xyz`, `.top`, `.club`, `.icu`, `.site`, `.online`, `.fun`, `.space`, `.buzz`, `.monster`) unless `--allow-risky-tld` is passed, and verify that `<fqdn>` resolves directly to the server's public IPv4 address without Cloudflare proxy CIDRs.

#### Scenario: High-risk TLD or proxied/mismatched domain aborts installation
- **WHEN** `<fqdn>` uses a blocked high-risk TLD (without `--allow-risky-tld`) or resolves to a Cloudflare proxy IP or a different IPv4 address
- **THEN** `script.sh` aborts with a clear error message before starting containers

### Requirement: Complete SSH CLI subcommands without a web wizard
`script.sh` SHALL support subcommands `status`, `xhttp on|off`, `rotate`, `decoy <preset_or_url>`, and `self-test` over SSH, and SHALL NOT expose any browser `/setup` wizard or HTTP admin endpoints.

#### Scenario: Owner manages appliance state entirely via SSH subcommands
- **WHEN** the owner runs `./script.sh status`, `./script.sh xhttp on`, `./script.sh xhttp off`, or `./script.sh rotate`
- **THEN** the script updates the local Xray/Nginx configuration, validates and reloads cleanly, and prints the updated links and terminal QR codes
