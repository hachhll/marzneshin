# Tasks

## 1. Legacy Dead File Cleanup

- [x] 1.1 Remove leftover pre-appliance dead files (`marzneshin-cli.py`, `cli/`, `tools/service-install.sh`, `makefile`, `docker-compose.dev.yml`, `Dockerfile.preview`, `db.sqlite3`) and verify `pytest tests/` passes

## 2. Bootstrap Certificate & Race-Free Nginx Gateway Reload

- [x] 2.1 Update `app/nginx/manager.py` and `docker/nginx/entrypoint.sh` to create a bootstrap self-signed EC-256 certificate at `cert_path`/`key_path` (`fullchain.pem`/`privkey.pem`) when missing, atomically consume (`rm -f`) `reload.trigger` before `inotifywait` and reload in `entrypoint.sh`, and verify in `tests/test_nginx_manager.py`

## 3. CLI State Preservation, Host Credentials Mount, and Self-Test SSH Port Support

- [x] 3.1 Update `app/cli.py`, `app/utils/self_test.py`, `scripts/self_test.sh`, and `docker-compose.yml` so `init` preserves existing `decoy_target` when `--decoy` is omitted, `status` does not rewrite daemon configs or touch `reload.trigger`, `/root/vpn-credentials` is mounted in `docker-compose.yml`, and `self-test` supports container execution fallback and multiple `SSH_PORT` values; verify with `pytest tests/test_self_test.py tests/test_installer.py`

## 4. Installer Idempotency, ACME Reload Command, and Flush-Safe UFW TCPMSS

- [x] 4.1 Update `script.sh` so `check_ports_free()` allows re-runs when `marzneshin-xray`/`marzneshin-nginx` are already running, `deploy_zero_surface_appliance()` detects bootstrap self-signed `fullchain.pem` and passes `--reloadcmd` to `acme.sh --install-cert`, `reload_services_if_running()` also reloads `marzneshin-nginx`, `run_python_cli()` mounts `$DATA_DIR` and `$CREDENTIALS_DIR`, and `/etc/ufw/before.rules` uses a flush-safe `ufw-mangle-tcpmss` chain; verify with `pytest tests/test_installer.py tests/test_e2e_container.py`

## 5. Zero-Emission / Zero-Loop Moscow -> Frankfurt Cascade Bridge

- [x] 5.1 Add `LocalXrayConfigBuilder.build_bridge()` and bridge-mode validation to `app/xray/config_builder.py` (local `dest: "127.0.0.1:8443"` zero-loop fallback, fail-closed `vless` Reality upstream to `<upstream_ip>:443` with `serverName: <upstream_domain>`, `fingerprint: "chrome"`, optional persistent `mux` with `xudp`, and zero `freedom`/`direct` outbound) and verify in `tests/test_xray_config.py`
- [x] 5.2 Update `app/client/profile_generator.py` to support distinct `server_host` (`<bridge_ip>`) and `sni` (`<bridge_sni>`) in `build_vless_vision_uri()`, `build_singbox_profile()`, `build_xray_client_profile()`, and `write_client_bundle()`, and output a ready-to-copy `sudo ./script.sh --bridge ...` command on exit nodes; verify in `tests/test_client_profiles.py`
- [x] 5.3 Update `app/utils/self_test.py` to operate in 100% passive Zero-Emission mode by default (`include_network_probes=False` unless `--active-probe` is passed), auto-detect `bridge` vs `exit` mode from `state.json`/`config.json`, and validate bridge-mode ports (`{22, ssh_port, 443}`) and fail-closed `xray/config.json`; verify in `tests/test_self_test.py`
- [x] 5.4 Add `init-bridge` to `app/cli.py` and `--bridge` mode (`--upstream-ip`, `--upstream-domain`, `--upstream-uuid`, `--upstream-pbk`, `--upstream-sid`, `--bridge-sni`, `--bridge-ip`) to `script.sh` using local kernel IP detection (`ip -4 route get`) and zero outbound network probes; verify in `tests/test_installer.py` and `tests/test_e2e_container.py`

## Workflow follow-up

- Archive the change after all verification tests pass and sync delta specs to `openspec/specs/`.
