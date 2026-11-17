# Design

## Context

See `proposal.md` for the full audit and threat-model motivation. The appliance operates in two composable roles on clean Ubuntu 26 servers:
1. **Exit Node (`<EXIT_NODE>`, `<EXIT_DOMAIN>`)**: Terminates the cross-border tunnel and exits to Google Antigravity, Anthropic (Claude), and OpenAI with a clean German IPv4 (`GL=DE`).
2. **Bridge Node (`<BRIDGE_NODE>`)**: Accepts domestic Russian client connections on `:443` and relays them over a persistent inter-datacenter VLESS Reality tunnel to the Frankfurt Exit Node while a TSPU appliance monitors both ingress and egress of the Russian datacenter.

## Goals / Non-Goals

**Goals:**
- Guarantee 100% deterministic first-boot execution (`init` -> `docker compose up -d --build` -> `acme.sh --issue` -> `acme.sh --install-cert --reloadcmd`) without Nginx startup crash loops.
- Guarantee 100% idempotent re-execution when running `sudo ./script.sh` multiple times on an active server.
- Ensure **Zero-Emission Diagnostics**: neither `script.sh --bridge` nor `./script.sh self-test` may emit any TCP/TLS/HTTP/DNS probe packets toward the Frankfurt upstream or external check services from the Russian bridge (preventing JA3/JA4 fingerprint mismatch and state leakage on TSPU).
- Ensure **Zero-Loop Active Probe Resistance** on the bridge: probing `<MOSCOW_IP>:443` must be handled strictly on local loopback (`127.0.0.1:8443` via local Nginx returning `CN=localhost` + `444` or a local domain decoy), never reaching out to a third-party external `dest` on the Russian internet.
- Ensure **Anti-Correlation & Fail-Closed Routing** on the bridge: client connections are multiplexed over a persistent `vless` upstream (`mux` with `xudp` + `tcpKeepAliveIdle=120`) to `<UPSTREAM_IP>:443` (`SNI: <upstream_domain>`), with zero `direct` (`freedom`) outbound on the bridge so Russian IP traffic or DNS leaks are physically impossible.

**Non-Goals:**
- Adding any web UI, subscription HTTP endpoints, or plaintext cross-server management APIs.

## Decisions

### 1. Bootstrap Self-Signed Certificate Pair at `cert_path` / `key_path` Before ACME Issuance
- **Choice**: In both `NginxManager.apply()` (`app/nginx/manager.py`) and `docker/nginx/entrypoint.sh`, ensure that if `cert_path` (`fullchain.pem`) or `key_path` (`privkey.pem`) does not exist yet, a bootstrap self-signed EC-256 certificate (`CN=localhost`) is written to `cert_path` / `key_path` (in addition to `dummy-fullchain.pem` / `dummy-privkey.pem`). In `script.sh`, determine whether ACME issuance is needed by checking if `fullchain.pem` is missing, empty, or still self-signed (`CN=localhost`). Pass `--reloadcmd "nginx -s reload -e /dev/null -c ${DATA_DIR}/nginx-runtime/nginx.conf"` to `acme.sh --install-cert`.
- **Rationale**: Prevents Nginx startup crash loops before ACME HTTP-01 issuance and ensures 60-day cron renewals reload Nginx automatically.

### 2. Host-Persisted `/root/vpn-credentials` and Container Fallback for `self-test`
- **Choice**: Mount `- /root/vpn-credentials:/root/vpn-credentials` in `docker-compose.yml` and pass `-v "${DATA_DIR}:${DATA_DIR}" -v "${CREDENTIALS_DIR}:${CREDENTIALS_DIR}"` in `run_python_cli()` and `scripts/self_test.sh`. Support multiple whitespace/comma-separated ports in `SSH_PORT`.
- **Rationale**: Ensures client profiles persist on clean Ubuntu 26 hosts where Python libraries live inside the `marzneshin-xray` container.

### 3. Idempotent `check_ports_free()`, State-Preserving `init`, Read-Only `status`, and Race-Free `reload.trigger`
- **Choice**: Stop or ignore own `marzneshin-xray`/`marzneshin-nginx` containers during `check_ports_free()`, preserve saved `decoy_target` when `--decoy` is omitted, keep `status` side-effect-free, consume `reload.trigger` with `rm -f` prior to `inotifywait`, and use a flush-safe `ufw-mangle-tcpmss` chain in `/etc/ufw/before.rules`.
- **Rationale**: Makes repeated runs of `script.sh` and `ufw reload` strictly idempotent.

### 4. Zero-Loop Local Fallback and Persistent Multiplexed Upstream in Bridge Mode (`--bridge`)
- **Choice**:
  1. **Zero-Loop Ingress on Bridge**: In `LocalXrayConfigBuilder.build_bridge()`, configure the bridge's `:443` `vless` Reality inbound with `dest: "127.0.0.1:8443"` (`xver: 1`) and `serverNames: ["<bridge_sni>"]`. Run `marzneshin-nginx` on `127.0.0.1:8443` in `default_server` isolation mode (`CN=localhost` + `return 444;`). When TSPU actively probes `<MOSCOW_IP>:443`, the probe terminates locally inside `127.0.0.1:8443` with **zero packets leaving the Moscow server's network interface**.
  2. **Anti-Correlation Fail-Closed Egress (`Moscow -> Frankfurt`)**: Configure `outbounds` in `build_bridge()` with **only two outbounds**:
     - `proxy` (`protocol: "vless"`, `address: "<upstream_ip>"`, `port: 443`, `security: "reality"`, `realitySettings: {"serverName": "<upstream_domain>", "fingerprint": "chrome", "publicKey": "<upstream_pbk>", "shortId": "<upstream_sid>"}`, `mux: {"enabled": true, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}`, `sockopt: {"tcpKeepAliveIdle": 120, "tcpKeepAliveInterval": 30, "tcpNoDelay": true}`). Note: when `mux.enabled` is `true`, Xray requires `flow: ""` on the muxed outbound stream or `flow: "xtls-rprx-vision"` when `mux.enabled` is `false`; we support configurable `mux` (or Vision with persistent keepalive `tcpKeepAliveIdle=120`) and validate that `direct` (`freedom`) is **completely absent** from bridge `outbounds`.
     - `block` (`protocol: "blackhole"`).
  3. **Zero DNS Queries in Russia**: Because the bridge outbound connects directly to the numeric IPv4 `<upstream_ip>:443` while setting TLS `SNI = <upstream_domain>`, the Moscow server never queries Russian DNS resolvers for `<upstream_domain>`.
  4. **Zero-Emission Diagnostics (`script.sh --bridge` and `self-test`)**:
     - In `--bridge` mode, `script.sh` determines the local server IPv4 strictly via the kernel routing table (`ip -4 route get 1.1.1.1`) or `--bridge-ip`, opens only `SSH` and `443/tcp` in UFW (keeping `80/tcp` closed), and performs **zero** `curl`/`openssl`/`dig` calls over the network.
     - `app/utils/self_test.py` defaults to **100% passive local inspection** (`include_network_probes=False` by default in CLI `_main()` unless `--active-probe` is passed), verifying `xray/config.json` invariants, Nginx config invariants, `/proc` forbidden processes, `/proc/net/tcp` exposed ports, and client template anti-drift without sending any network packets.

## Risks / Trade-offs

- **[Risk] Without active network probing on the bridge during install, a typo in `--upstream-ip` or `--upstream-pbk` won't be flagged before starting the container** -> **Mitigation**: The Frankfurt exit node prints the exact copy-paste `sudo ./script.sh --bridge ...` command with all parameters pre-filled and validated, and `app/cli.py` strictly validates IPv4 format, domain syntax, UUID format, base64url key length, and hex `shortId` offline before writing `config.json`.
