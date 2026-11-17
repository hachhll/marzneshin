# Proposal

## Why

Production field validation and E2E testing against modern `sing-box` 1.12+ and `Xray-core` revealed several TSPU evasion, protocol compatibility, host security, and Cascade Bridge usability gaps that require spec-level alignment:
- TSPU post-quantum Chrome Kyber/ML-KEM ClientHello profiling targets `fp=chrome` and Xray `mux` padding anomalies, requiring Firefox uTLS by default, non-muxed `xtls-rprx-vision` cascade forwarding, and MPTCP disabled across socket options and kernel sysctl (`CVE-2026-98432` mitigation).
- `sing-box` 1.12+ rejects legacy DNS server string syntax and Android-specific TUN keys on Windows 11, while `Xray-core` needed an updated compatibility pin (`v26.6.27`), QR encoding fixes, and explicit E2E cascade verification.
- Cascade Bridge nodes behind NAT (`--bridge-ip`), shared SNI setups with dummy certificates, SSH brute-force exposure on `:22`, and file permissions (`0o644` for Nginx static/runtime configs) needed automated safeguards and optional `--bridge-acme` certificate provisioning without keeping port `:80` open permanently.

## What Changes

- Switch default uTLS Reality/TLS fingerprint from `chrome` to `firefox` across server bridge outbounds, client `vless://` URIs, `sing-box` profiles, and `xray-client.json`, while validating against the allowed fingerprint set.
- Enforce `tcpMptcp: false` and TCP keepalive `sockopt` across VLESS inbounds, bridge upstream outbounds, exit `direct` (`freedom`) outbounds, and generated `xray-client.json` configs, alongside kernel `net.mptcp.enabled = 0`, `net.ipv4.tcp_retries2 = 5`, `net.ipv4.tcp_max_syn_backlog = 4096`, and `net.ipv4.tcp_syncookies = 1`.
- Disable Xray bridge `mux` by default (`mux_enabled=False`) so the bridge-to-exit hop uses raw `xtls-rprx-vision`, and enforce `routing.domainStrategy: "AsIs"` on Cascade Bridge nodes so bridged DNS queries/destinations pass cleanly without local resolution drift.
- Update `sing-box` profile output for `1.12+` compatibility (`type: "udp"` remote DNS schema, `sniff`/`hijack-dns`/`reject` route rules, `connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`) and emit `override_android_vpn` on Android only (omitted on `windows11-throne`).
- Add Cascade Bridge `--bridge-acme` support for dedicated bridge domains: verifies direct DNS, opens `80/tcp` temporarily with `--acme-http-challenge` only when a real `DNS:<domain>` SAN certificate is missing, runs `acme.sh --issue` + `--install-cert`, then closes `80/tcp` in UFW and switches Nginx back to HTTPS-fallback-only (`enable_http=False`).
- Reject RFC1918/CGNAT private NAT bridge IPs unless explicitly overridden via `--bridge-ip`, reject `--bridge-acme` with shared upstream SNI, apply TLD hygiene checks to bridge domains, and surface non-fatal `[PASS]` `WARN` notices in `self-test` for shared bridge SNI or `CN=localhost` dummy certs.
- Harden host SSH access during `./script.sh`: provision `stealth` with passwordless sudo and copied authorized keys (aborting if no keys exist), disable `ssh.socket`, bind IPv4 `Port 22222`, disable root/password auth (`AllowUsers stealth`), and remove `22/tcp` from UFW once `:22222` is confirmed listening.
- Pin `XRAY_VERSION=v26.6.27` in `Dockerfile`, pin `protobuf>=5.27.0` in `requirements.txt`, enforce `0o644` permissions on Nginx atomic file writes, rebuild stale images automatically via `docker compose run --build` and `docker compose up -d --build`, ensure ISO/IEC 18004 QR encoding (`v1..v14`), and add an isolated `sing-box -> bridge -> exit` E2E regression test.

## Capabilities

### New Capabilities
<!-- None; all changes extend or refine existing capabilities. -->

### Modified Capabilities
- `anti-drift-safety-policy`: Default `firefox` uTLS fingerprint, `tcpMptcp: false` + `net.mptcp.enabled = 0`, `direct` outbound `sockopt`, `sing-box` 1.12+ remote UDP DNS schema, client outbound keepalive/timeout fields, `xray-client` `sockopt`, `Xray v26.6.27` pin, and passive bridge warnings in `self-test`.
- `minimal-profile-constructor`: Default `fp=firefox` export, Android-only `override_android_vpn`, `sing-box` 1.12+ DNS/routing/outbound compatibility, exit-mode `--bridge-sni <DEDICATED_BRIDGE_DOMAIN> --bridge-acme` recommendation hint, and pure-Python ISO/IEC 18004 QR v1..v14 rendering.
- `seamless-docker-setup-wizard`: SSH hardening (`stealth` user on IPv4 port `22222`, closing `:22`), private NAT `--bridge-ip` guard, bridge TLD hygiene check, `--bridge-acme` temporary `:80` issuance workflow, expanded anti-storm sysctl (`net.mptcp.enabled=0`, `tcp_retries2=5`, `tcp_max_syn_backlog=4096`, `tcp_syncookies=1`), and `--build` on Compose invocations.
- `self-reality-nginx-gateway`: Optional `--bridge-acme` issuance on temporary `:80` (with `DNS:<domain>` SAN check) followed by permanent `:80` closure in bridge mode, plus `0o644` file permissions on atomically written Nginx/decoy files.
- `single-server-vless-core`: `XRAY_VERSION=v26.6.27` container runtime (`protobuf>=5.27.0`), `firefox` uTLS default on bridge outbounds, `mux_enabled=False` default, `routing.domainStrategy: "AsIs"` validation on bridges, and mandatory `sockopt` (`tcpMptcp: false`) on exit `direct` outbounds.

## Impact

- Affected code: `Dockerfile`, `requirements.txt`, `script.sh`, `app/cli.py`, `app/xray/config_builder.py`, `app/client/profile_generator.py`, `app/client/qr.py`, `app/nginx/manager.py`, `app/utils/self_test.py`.
- Tests: `tests/test_cascade_e2e.py`, `tests/test_xray_config.py`, `tests/test_client_profiles.py`, `tests/test_installer.py`, `tests/test_self_test.py`, `tests/test_nginx_manager.py`.
