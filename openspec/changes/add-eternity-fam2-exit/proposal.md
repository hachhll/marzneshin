# Proposal

## Why

The `oblako-fam1` media exit currently serves five `media-consumer` users (`laura`, `sati`, `lena`, `gevorg`, `anya-z`), and two additional family users (`sema` and `sonya`) need access without concentrating all media traffic onto a single exit IP or mixing with the isolated `ai-owner` exit (`server-de`). A new VPS (`eternity-fam2`) is ready to be provisioned as a second `media` exit behind the `mos` Cascade Bridge, receive `anya-z` via zero-reconfiguration migration, and host `sema` and `sonya`.

Passive preflight inspection of `eternity-fam2` (fresh Ubuntu 26.04.1 LTS, 956 MB RAM, 0 swap, `ufw` and `iptables` absent) and `mos` also surfaced two operational gaps in `script.sh`: `configure_ufw_and_kernel` silently skips UFW and `TCPMSS=1360` clamping when `ufw`/`iptables` are not pre-installed, and `run_python_cli` falls back to `docker compose run --build` for routine `upstream`/`user` CLI commands on hosts without `.venv`, causing unnecessary Docker Hub metadata requests from the Zero-Emission `mos` bridge.

## What Changes

- **Harden `script.sh` host prerequisites & Zero-Emission CLI execution:**
  - Ensure `ufw` and `iptables` are installed (or explicitly abort if missing during `--dry-run`) before `configure_ufw_and_kernel`, rather than silently skipping firewall rules and persistent `TCPMSS=1360` clamping on minimal Ubuntu 26.04 images.
  - Prefer `docker exec` on an already-running `marzneshin-xray` container in `run_python_cli` for routine subcommands (`status`, `upstream`, `user`, `stats`, etc.) when no host `.venv` is present, avoiding `docker compose run --build` and outbound registry requests on `mos`.
- **Provision `eternity-fam2` as a hardened `media` exit node:**
  - Configure 1 GB swap on `eternity-fam2`, sync the repository to `/opt/marzneshin`, deploy via `script.sh --domain <eternity-fam2-fqdn>` (Docker, Xray `v26.6.27`, Nginx `>= 1.30.7-alpine` + ACME TLS 1.3, RU egress blackhole, UFW, `TCPMSS=1360`, SSH hardened to `stealth:22222`), and update workstation `~/.ssh/config`.
- **Wire `eternity-fam2` into `mos` and assign users:**
  - Register `eternity-fam2` on `mos` (`role: media`, `transport: xhttp`, distinct `/24` subnet from `server-de` and `oblako-fam1`).
  - Reassign `anya-z` from `oblako-fam1` to `eternity-fam2` (`user assign anya-z eternity-fam2`), preserving her existing UUID and `media-selective` JSON profile with zero client reconfiguration.
  - Create `sema` and `sonya` bound to `eternity-fam2` (`user add`) and collect their generated `media-selective` Android/iOS `sing-box >= 1.14` JSON bundles.
- **Update cluster monitoring & verify passively:**
  - Add `eternity-fam2:exit` to workstation `tools/.env` (`MARZNESHIN_WATCH_NODES`) and verify all 4 nodes (`mos`, `server-de`, `oblako-fam1`, `eternity-fam2`) via `self-test` and `tools/cluster_watch.py`.

## Capabilities

### New Capabilities
- *(none)*

### Modified Capabilities
- `seamless-docker-setup-wizard`: Require `script.sh` to enforce `ufw`/`iptables` availability (installing on non-dry-run exit/bridge setup rather than silently skipping firewall/TCPMSS rules) and execute non-install CLI subcommands via the running `marzneshin-xray` container when present instead of triggering `docker compose run --build`.

## Impact

- **Repository code & tests:** `script.sh` (`configure_ufw_and_kernel`, `run_python_cli`), unit tests under `tests/`.
- **Live infrastructure:** `eternity-fam2` (new exit node), `mos` (`state.json`, `xray/config.json`, `/root/vpn-credentials/users/{sema,sonya}`), workstation `~/.ssh/config` and `tools/.env` (gitignored).
- **Clients:** `anya-z` experiences zero client-side profile changes; `sema` and `sonya` receive new `media-selective` Local JSON profiles for `sing-box >= 1.14` (`Android SFA` / `iOS sing-box MT`).
