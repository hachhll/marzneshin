# Proposal

## Why

A sequential execution and idempotency audit of the Zero-Surface VLESS Self-Reality installer (`script.sh`), container entrypoints (`docker/nginx/entrypoint.sh`, `docker/app-entrypoint.sh`), and CLI state manager (`app/cli.py`), together with the requirement to deploy a **Moscow -> Frankfurt (`<EXIT_DOMAIN>`) cascade bridge** on clean Ubuntu 26 servers where a TSPU sits directly on the Russian datacenter egress uplink, uncovered two sets of critical requirements:
1. **First-Boot & Idempotency Fixes**:
   - On a fresh install, `run_python_cli init` writes `nginx.conf` and `appliance.conf` referencing `/var/lib/marzneshin/certs/fullchain.pem` before ACME certificate issuance, causing `marzneshin-nginx` to crash-loop on startup (`BIO_new_file() failed`) before `acme.sh` can serve HTTP-01 challenges on port `:80`.
   - On a fresh Ubuntu VPS without a host `.venv` or `python3-nacl`, `run_python_cli` falls back to `docker compose run --rm xray`, which lacked a volume mount for `/root/vpn-credentials` (`$CREDENTIALS_DIR`), while `./script.sh self-test` failed on missing host Python packages.
   - Re-running `./script.sh --domain <fqdn>` on an already-provisioned server failed in `check_ports_free()` because ports `:80` and `:443` were occupied by `marzneshin-nginx` and `marzneshin-xray`, and reset any previously customized `--decoy` target back to `corporate`.
   - `docker/nginx/entrypoint.sh` could miss `reload.trigger` events during its `sleep 1` window and never unlinked `reload.trigger`, while `acme.sh --install-cert` lacked a `--reloadcmd` for 60-day automatic renewals.
2. **Zero-Emission / Zero-Loop Moscow -> Frankfurt Cascade Bridge (`--bridge`)**:
   - Because TSPU monitors both ingress and egress of the Russian VPS (`REG.RU`), using an external `dest` (e.g. `vk.com:443`) on the bridge creates a visible hair-pin loop (`TSPU Probe -> Bridge -> vk.com -> Bridge -> TSPU Probe`), while running diagnostic probes (`curl`, `openssl`, Python `ssl`, `/dev/tcp`) from the bridge to Frankfurt leaks non-Chrome TLS fingerprints on the same `IP:443:SNI` tuple prior to `xray` startup.
   - Furthermore, opening a new `Moscow -> Frankfurt` TCP/TLS session on every client connection creates 1:1 timing correlation across the bridge.

## What Changes

- **Bootstrap Self-Signed Fallback Before ACME Issuance**: Ensure `NginxManager.apply()` and `docker/nginx/entrypoint.sh` populate initial self-signed placeholder certificate/key files at `fullchain.pem` and `privkey.pem` whenever they do not exist yet, allowing `marzneshin-nginx` to boot cleanly on `:80` and `127.0.0.1:8443` on first install, serve `/.well-known/acme-challenge/`, and then hot-swap to the real Let's Encrypt certificate via `acme.sh --install-cert --reloadcmd`.
- **Idempotent Re-run & Port Check**: Update `check_ports_free()` in `script.sh` to ignore (or stop before checking) existing listeners owned by `marzneshin-xray` and `marzneshin-nginx`, preserve saved `decoy_target` in `state.json` when `--decoy` is not explicitly passed on re-runs, and keep `status` read-only without triggering unnecessary Nginx reloads.
- **Persistent Host Credentials Mount & Container-Backed `self-test` Runner**: Mount `/root/vpn-credentials:/root/vpn-credentials` in `docker-compose.yml` and pass `-v "${DATA_DIR}:${DATA_DIR}" -v "${CREDENTIALS_DIR}:${CREDENTIALS_DIR}"` in `run_python_cli()` and `scripts/self_test.sh`, while forwarding detected `SSH_PORT` values to `self-test`.
- **Race-Free Nginx Reload Trigger & UFW Mangle Idempotency**: Consume (`rm -f`) `reload.trigger` atomically in `docker/nginx/entrypoint.sh` before reloading, execute synchronous `nginx -s reload` in `reload_services_if_running()`, and make the `/etc/ufw/before.rules` `*mangle` `TCPMSS 1360` rules flush-safe across repeated `ufw reload` runs.
- **Legacy Dead File Cleanup**: Remove leftover broken scripts from the pre-appliance web panel (`marzneshin-cli.py`, `cli/`, `tools/service-install.sh`, `makefile`, `docker-compose.dev.yml`, `Dockerfile.preview`, `db.sqlite3`).
- **Zero-Emission / Zero-Loop Moscow -> Frankfurt Cascade Bridge (`--bridge`)**:
  - Add `--bridge` mode to `script.sh` and `init-bridge` to `app/cli.py` for the Russian entry node (`REG.RU`), paired with automatic bridge-command output on the Frankfurt exit node.
  - Enforce **Zero-Loop Local Fallback** on the bridge: `xray` on the bridge uses local loopback `dest: "127.0.0.1:8443"` (`marzneshin-nginx` serving a neutral `CN=localhost` cert + `return 444;` or optional local domain decoy) so active TSPU probes on `<MOSCOW_IP>:443` produce **zero outbound packets** on the Moscow uplink.
  - Enforce **Anti-Correlation Persistent Multiplexed Upstream**: `xray` on the bridge connects to `<UPSTREAM_IP>:443` (`SNI: <upstream_domain>`, uTLS `chrome`) with persistent multiplexed streams (`mux` with `xudp` and `tcpKeepAliveIdle=120`) and **zero `direct` outbound** (100% fail-closed tunnel to Frankfurt, zero DNS queries in Russia).
  - Enforce **Zero-Emission Diagnostics**: determine server IP locally via kernel routing (`ip -4 route get`) on the bridge without external HTTP calls, prohibit any script/Python/curl/openssl probing of `<UPSTREAM_IP>:443` from the bridge, and make `./script.sh self-test` 100% passive/local by default (`include_network_probes=False` unless `--active-probe` is explicitly requested on an exit node).

## Capabilities

### New Capabilities
<!-- None -->

### Modified Capabilities
- `seamless-docker-setup-wizard`: Add idempotent re-run requirements, `--bridge` deployment mode with zero external network probes from the bridge, local kernel IP detection, and automatic copy-paste `--bridge` command generation on the exit node.
- `self-reality-nginx-gateway`: Require bootstrap certificate initialization before ACME HTTP-01 challenge issuance, race-free `reload.trigger` consumption in `entrypoint.sh`, `--reloadcmd` on `acme.sh --install-cert`, and local `127.0.0.1:8443` zero-loop fallback on bridge nodes.
- `single-server-vless-core`: Support `bridge` mode in `LocalXrayConfigBuilder` where `outbounds` contain only the multiplexed `vless` upstream to the Frankfurt exit node (`address: <upstream_ip>`, `serverName: <upstream_domain>`, `fingerprint: chrome`, `mux` enabled with `xudp`) and `block` (`blackhole`), with `direct` (`freedom`) completely omitted (fail-closed).
- `anti-drift-safety-policy`: Make `self-test` 100% passive/zero-emission by default (inspecting local configs, `/proc/net/tcp`, `/proc` processes, and firewall rules without emitting network probes that could leak JA3/JA4 or state to TSPU), with optional `--active-probe` for exit-node verification.
- `minimal-profile-constructor`: Support distinct `server_host` (`<MOSCOW_IP>`) and `sni` in generated `sing-box` / `xray` client profiles and `vless://` URIs for bridge mode, plus ready-to-copy `--bridge` command output on the exit node.

## Impact

- `script.sh`, `scripts/self_test.sh`, `docker-compose.yml`, `docker/nginx/entrypoint.sh`
- `app/cli.py`, `app/nginx/manager.py`, `app/xray/config_builder.py`, `app/client/profile_generator.py`, `app/utils/self_test.py`
- Removal of dead legacy files: `marzneshin-cli.py`, `cli/`, `tools/service-install.sh`, `makefile`, `docker-compose.dev.yml`, `Dockerfile.preview`, `db.sqlite3`
- Unit & integration tests: `tests/test_installer.py`, `tests/test_nginx_manager.py`, `tests/test_xray_config.py`, `tests/test_client_profiles.py`, `tests/test_self_test.py`, `tests/test_e2e_container.py`
