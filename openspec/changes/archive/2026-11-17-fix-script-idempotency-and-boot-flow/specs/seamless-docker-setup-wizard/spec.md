# Spec Delta

## MODIFIED Requirements

### Requirement: Single-command Ubuntu installation with SSH protection and kernel anti-storm hardening
The installer (`./script.sh --domain <fqdn>` for an exit node, or `./script.sh --bridge ...` for a Russian cascade bridge node) SHALL verify root privileges, NTP sync, and free required ports (while allowing idempotent re-runs when ports are bound only by the appliance's own `marzneshin-nginx` and `marzneshin-xray` containers), auto-detect the active SSH port (`$SSH_CONNECTION` and `/etc/ssh/sshd_config`) to apply `ufw limit <ssh_port>/tcp`, configure kernel `sysctl` (`bbr + fq`, `tcp_fin_timeout=15`, `tcp_keepalive_time=120`, `tcp_synack_retries=2`, `tcp_fastopen=0`, `tcp_mtu_probing=0`, `disable_ipv6=1`) and flush-safe persistent `TCPMSS=1360` clamping across reboots and `ufw reload` cycles, and deploy the `xray` + `nginx` stack while persisting generated client bundles on the host filesystem even when executed via the container Python fallback. In `--bridge` mode, the installer SHALL open only SSH and `443/tcp` (keeping `80/tcp` closed), determine the bridge IPv4 locally from the kernel routing table (`ip -4 route get`) or `--bridge-ip`, and emit zero external diagnostic HTTP/TLS/DNS probe packets toward the upstream exit server or external IP-check services.

#### Scenario: Installer hardens kernel, protects active SSH port, and completes in one command
- **WHEN** the owner runs `sudo ./script.sh --domain vpn.example.com` over SSH on port `22` or a custom port (e.g. `2222`)
- **THEN** the script adds `ufw limit <detected_ssh_port>/tcp`, opens `80/tcp` and `443/tcp`, applies the anti-storm `sysctl` profile and flush-safe persistent `TCPMSS=1360` clamping, deploys `xray` and `nginx`, writes client profiles to `/root/vpn-credentials` on the host, and prints the VPN credentials, QR code, and a ready-to-copy `--bridge` command for a downstream cascade node to stdout

#### Scenario: Re-running installer on an already-provisioned server succeeds idempotently
- **WHEN** the owner re-runs `sudo ./script.sh --domain vpn.example.com` while `marzneshin-xray` and `marzneshin-nginx` are already running and listening on `:443` and `:80`
- **THEN** `script.sh` does not fail with a port conflict for its own containers, preserves any previously saved `decoy_target` if `--decoy` is not explicitly specified, avoids duplicating kernel `*mangle` `TCPMSS=1360` rules on `ufw reload`, and converges cleanly

#### Scenario: Bridge mode deploys on a Russian VPS with zero outbound diagnostic probes
- **WHEN** the owner runs `sudo ./script.sh --bridge --upstream-ip <ip> --upstream-domain <fqdn> --upstream-uuid <uuid> --upstream-pbk <pbk> --upstream-sid <sid>` on a clean Ubuntu 26 server in Russia
- **THEN** the installer configures `sysctl` and `TCPMSS=1360`, allows only SSH and `443/tcp` in UFW (keeping `80/tcp` closed), determines the bridge IPv4 locally without calling external HTTP services, performs zero `curl`/`openssl`/DNS probes against `<upstream-ip>` or `<fqdn>`, starts the local `127.0.0.1:8443` zero-loop fallback and fail-closed `xray` bridge, and outputs client profiles pointing to the bridge

### Requirement: Complete SSH CLI subcommands without a web wizard
`script.sh` SHALL support subcommands `status`, `xhttp on|off`, `rotate`, `decoy <preset_or_url>`, and `self-test` over SSH, SHALL NOT expose any browser `/setup` wizard or HTTP admin endpoints, SHALL keep `status` side-effect-free with respect to daemon reload triggers, and SHALL execute `self-test` reliably in 100% passive local mode by default on hosts without local Python virtualenvs while passing detected custom SSH ports.

#### Scenario: Owner manages appliance state entirely via SSH subcommands
- **WHEN** the owner runs `./script.sh status`, `./script.sh xhttp on`, `./script.sh xhttp off`, `./script.sh rotate`, `./script.sh decoy <target>`, or `./script.sh self-test`
- **THEN** mutating subcommands update the local Xray/Nginx configuration, validate and reload cleanly, and print the updated links and terminal QR codes, whereas `status` displays current credentials without triggering a daemon reload and `self-test` runs passively without emitting network probes by default
