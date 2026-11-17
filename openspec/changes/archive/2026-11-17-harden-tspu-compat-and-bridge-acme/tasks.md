# Tasks

## 1. Xray Core, uTLS Fingerprint, and Socket Hardening

- [x] 1.1 Pin `XRAY_VERSION=v26.6.27` in `Dockerfile` and `protobuf>=5.27.0` in `requirements.txt`, and verify image build plus protobuf serialization via `tests/test_xray_config.py::test_xray_grpc_protobuf_payloads_serialize`.
- [x] 1.2 Set `DEFAULT_UTLS_FINGERPRINT = "firefox"` (`validate_utls_fingerprint`), disable default bridge `mux` (`mux_enabled=False`), enforce `routing.domainStrategy = "AsIs"` on Cascade Bridge configs, and verify via `tests/test_xray_config.py::test_xray_bridge_config_zero_loop_and_fail_closed`.
- [x] 1.3 Enforce `DEFAULT_VLESS_SOCKOPT` (`tcpKeepAliveIdle: 120`, `tcpKeepAliveInterval: 30`, `tcpNoDelay: true`, `tcpMptcp: false`) across `vless` inbounds, bridge `proxy` outbound, and exit `direct` (`freedom`) outbound via `_validate_required_sockopt()`, verified by `tests/test_xray_config.py`.

## 2. Client Profile Schema (`sing-box 1.12+`) and ISO QR Rendering

- [x] 2.1 Update `app/client/profile_generator.py` to default `fingerprint` to `"firefox"`, emit `sing-box 1.12+` typed remote UDP DNS objects (`type: "udp"`, `server: "1.1.1.1"` / `8.8.8.8`, `detour: "proxy"`) and `sniff`/`hijack-dns`/`reject` route actions, add `connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, and `tcp_keep_alive_interval: "30s"`, emit `override_android_vpn: true` solely on Android profiles, include `sockopt` (`tcpMptcp: false`) in `xray-client.json`, and recommend `--bridge-sni <DEDICATED_BRIDGE_DOMAIN> --bridge-acme` in exit-mode output; verified by `tests/test_client_profiles.py`.
- [x] 2.2 Implement and verify pure-Python ISO/IEC 18004 QR code encoding (`v1..v14`) with bright-white ANSI quiet zone (`border=4`) in `app/client/qr.py` and `tests/test_client_profiles.py::test_vless_uris_and_terminal_qr_generation`.

## 3. Nginx Permissions, Cascade Bridge ACME, and Self-Test Warnings

- [x] 3.1 Enforce `0o644` permissions via `os.chmod(tmp_path, 0o644)` in `NginxManager._atomic_write()` and verify Nginx configuration validity with `tests/test_nginx_manager.py`.
- [x] 3.2 Support `--bridge-acme` (`state["bridge_acme_enabled"]`) and transient `--acme-http-challenge` in `app/cli.py` so bridge HTTP `:80` is enabled only during ACME issuance and disabled afterward, verified by `tests/test_installer.py`.
- [x] 3.3 Update `app/utils/self_test.py` so `check_xray_config_safety(..., mode="bridge")` remains `passed=True` while appending non-fatal `WARN:` guidance for shared bridge/upstream SNI or `CN=localhost` dummy certificates, verified by `tests/test_self_test.py`.

## 4. Installer Hardening (`script.sh`) and Isolated Cascade E2E Verification

- [x] 4.1 Implement `configure_ssh_hardening()` in `script.sh` (creating `stealth` user with passwordless sudo, copying SSH keys or aborting if none exist, disabling `ssh.socket`, configuring IPv4 `Port 22222` with `PermitRootLogin no`, `PasswordAuthentication no`, `AllowUsers stealth`, deleting `22/tcp` once `:22222` listens) and extend `99-vpn-hardening.conf` with `net.mptcp.enabled = 0`, `tcp_retries2 = 5`, `tcp_max_syn_backlog = 4096`, and `tcp_syncookies = 1`; verified via `tests/test_installer.py`.
- [x] 4.2 Add private RFC1918/CGNAT NAT `--bridge-ip` guard, bridge TLD hygiene check, Compose `--build` invocation, and `--bridge-acme` temporary `:80` issuance (`needs_acme_cert` + `verify_direct_dns` + auto-delete `80/tcp`) in `script.sh`, verified by `tests/test_installer.py::test_bridge_mode_zero_emission_installer_and_cli`.
- [x] 4.3 Add isolated `127.0.0.1` E2E compatibility test (`tests/test_cascade_e2e.py::test_singbox_reality_handshake_and_bridge_cascade_compatibility`) and confirm the full suite passes via `.venv/bin/python -m pytest tests/ -v`.

## Workflow follow-up

- Validate `harden-tspu-compat-and-bridge-acme`, sync its delta specs into `openspec/specs/`, and archive to `openspec/changes/archive/`.
