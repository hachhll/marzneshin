# Design

## Context

See `proposal.md` for motivation. Following the initial implementation of dual-mode Exit and Cascade Bridge orchestration (`fix-script-idempotency-and-boot-flow`), live deployment diagnostics and isolated loopback integration testing uncovered protocol, fingerprint, compatibility, host SSH surface, and NAT/certificate gaps across `script.sh`, `app/`, `Dockerfile`, and `requirements.txt`.

## Goals / Non-Goals

**Goals:**
- Align default client and bridge uTLS fingerprinting (`firefox`) and raw non-muxed `xtls-rprx-vision` forwarding with TSPU evasion and `sing-box 1.12+` / `Xray-core v26.6.27` compatibility.
- Eliminate MPTCP attack/fingerprint surface across kernel `sysctl` and all Xray `sockopt` blocks (`tcpMptcp: false`).
- Harden host SSH management onto a dedicated sudo user (`stealth`) on IPv4 port `22222` while closing port `22/tcp` safely only after key transfer and listener verification.
- Guard domestic bridges behind NAT against accidentally writing private RFC1918/CGNAT IPs into client bundles, and enable optional `--bridge-acme` issuance without leaving HTTP `:80` open long-term.
- Ensure Nginx/decoy static assets written atomically are world-readable (`0o644`) and add an isolated `127.0.0.1` `sing-box -> bridge -> exit` handshake test.

**Non-Goals:**
- Multi-user panels, traffic quotas, or web dashboards remain explicitly prohibited.
- Keeping port `80/tcp` open permanently on domestic Cascade Bridge nodes remains disallowed (`--bridge-acme` closes `:80` right after certificate issuance).

## Decisions

- **Firefox uTLS (`DEFAULT_UTLS_FINGERPRINT = "firefox"`) and Raw Vision Cascade (`mux_enabled = False`)**
  - *Rationale*: `chrome` post-quantum ML-KEM/Kyber ClientHello extensions and `mux` frame patterns are easier for passive/active DPI classifiers to single out than standard Firefox ClientHello trajectories and native Vision splicing. `validate_utls_fingerprint()` restricts values to the allowed Reality set (`firefox`, `chrome`, `edge`, `safari`, `ios`, `android`, `random`, `randomized`).
  - *Alternative*: Retaining `chrome` + enabled `mux`; rejected to eliminate unnecessary padding overhead and PQ extension fingerprint divergence.
- **MPTCP Disabled Everywhere (`tcpMptcp: false`, `net.mptcp.enabled = 0`) + Mandatory `sockopt` on Exit `direct` Outbound**
  - *Rationale*: Sets `tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`, and `tcpMptcp: false` uniformly across `vless` inbounds, bridge `proxy` outbound, exit `direct` (`freedom`) outbound, and client `xray-client.json` `proxy` outbound via `_validate_required_sockopt()`, alongside kernel `tcp_retries2 = 5`, `tcp_max_syn_backlog = 4096`, and `tcp_syncookies = 1`.
  - *Alternative*: Inbound-only `sockopt`; rejected because upstream/egress sockets also benefit from keepalive/anti-hang tuning and MPTCP mitigation (`CVE-2026-98432`).
- **`sing-box 1.12+` Schema Update and Platform-Scoped `override_android_vpn`**
  - *Rationale*: `sing-box 1.12+` enforces typed DNS server objects (`{"tag": "dns-remote", "type": "udp", "server": "1.1.1.1", "server_port": 53, "detour": "proxy"}`) and route rule actions (`"action": "sniff"`, `"action": "hijack-dns"`, `"action": "reject"`), plus `connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, and `tcp_keep_alive_interval: "30s"` on VLESS outbounds. Emitting `override_android_vpn: true` solely when `platform != "windows11-throne"` avoids schema errors in Windows Throne (`sing-box check`).
  - *Alternative*: Emitting legacy `1.10` DNS string entries; rejected because modern `sing-box` rejects legacy format.
- **SSH Hardening onto `stealth` (`Port 22222/tcp`, IPv4-only)**
  - *Rationale*: `configure_ssh_hardening()` copies authorized keys from `/root/.ssh/authorized_keys`, `/home/stealth/.ssh/authorized_keys`, and `${SUDO_USER}`, aborting before changes if zero keys are present. It disables Ubuntu's dual-stack `ssh.socket`, configures `AddressFamily inet`, `Port 22222`, `PermitRootLogin no`, `PasswordAuthentication no`, `AllowUsers stealth`, validates via `sshd -t`, and deletes `22/tcp` rules in UFW only once `ss -4 -tln` confirms `:22222` is listening.
  - *Alternative*: Leaving `:22` open under `ufw limit`; rejected to cut automated password/root scan noise substantially.
- **Transient HTTP-01 `--bridge-acme` Lifecycle & NAT `--bridge-ip` Guard**
  - *Rationale*: Shared SNI with dummy `CN=localhost` certs remains allowed with explicit `WARN` diagnostics for zero-domain emergency testing, whereas `--bridge-acme` requires an independent `--bridge-sni` pointing to the bridge public IP (`verify_direct_dns "$BRIDGE_IP"`). When `needs_acme_cert()` detects missing cert or `CN=localhost` or missing `DNS:${DOMAIN}` SAN, `deploy_zero_surface_appliance()` opens `80/tcp`, enables `--acme-http-challenge`, runs `acme.sh --issue` / `--install-cert`, then re-renders Nginx with `enable_http=False` and deletes `80/tcp` from UFW. Private RFC1918/CGNAT auto-detected bridge IPs abort unless `--bridge-ip` overrides them.
  - *Alternative*: Permanent `:80` listener on Russian bridge nodes; rejected to minimize active HTTP attack surface on the bridge.
- **Container Runtime Pinning, Permissions, and E2E Cascade Verification**
  - *Rationale*: Pinned `XRAY_VERSION=v26.6.27` in `Dockerfile` and `protobuf>=5.27.0` in `requirements.txt`, `--build` on Compose invocations in `script.sh` so host updates rebuild stale containers automatically, `0o644` permissions inside `NginxManager._atomic_write()`, pure-Python ISO/IEC 18004 QR versions `1..14`, and an isolated `tests/test_cascade_e2e.py` verifying full `sing-box -> bridge -> exit` handshakes over loopback.

## Risks / Trade-offs

- **SSH Port Relocation (`22 -> 22222`)**: Users reconnecting on subsequent sessions must connect as `stealth@<host> -p 22222` using SSH keys → Mitigated by aborting before modifying `sshd_config` if no SSH public keys exist, keeping `22/tcp` allowed if `ss -4 -tln` does not show `:22222` listening, and preserving keys from both root and `$SUDO_USER`.
- **`--bridge-acme` Transient Port `:80` Exposure**: Port `80/tcp` opens briefly during initial issuance → Mitigated by running `needs_acme_cert()` first (skipping `:80` if valid SAN cert already exists) and deleting `80/tcp` from UFW immediately after `acme.sh --install-cert`. Future automated HTTP-01 renewals on bridges will require re-enabling `:80` temporarily if renewed via HTTP-01.
- **Private NAT Bridge Detection**: Bridges behind 1:1 cloud NAT report an RFC1918/CGNAT interface IP → Mitigated by explicit fail-fast validation requiring `--bridge-ip <PUBLIC_IP>`.
