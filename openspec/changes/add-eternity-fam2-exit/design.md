# Design

## Context

See `proposal.md` for motivation and observed preflight findings. Currently the live cluster consists of:
- `mos` (Cascade Bridge, 955 MB RAM / 1023 MB swap, `Xray v26.6.27` + loopback `Nginx`) serving:
  - `default` (`role: ai-isolated`, `server-de`, `transport: xhttp`) -> `owner` (`ai-owner`)
  - `oblako-fam1` (`role: media`, `transport: xhttp`) -> `laura`, `sati`, `lena`, `gevorg`, `anya-z` (`media-selective`)
- `eternity-fam2` (fresh Ubuntu 26.04.1 LTS VPS, 1 vCPU, 956 MB RAM, 0 swap, `chronyd` NTP active, SSH on port `22` as `root`, missing `ufw`/`iptables`/`rsync`/`git`, direct DNS A-record configured in Cloudflare).

All multi-exit routing (`app/bridge_state.py`, `app/cli.py`, `app/xray/config_builder.py`, `app/client/profile_generator.py`) and server-side RU egress blackholing are already implemented and active on `mos`, `server-de`, and `oblako-fam1`.

## Goals / Non-Goals

**Goals:**
- Ensure `script.sh` never silently skips `ufw` or `TCPMSS --set-mss 1360` clamping on minimal Ubuntu hosts (`eternity-fam2`) and never triggers `docker compose run --build` (Docker Hub requests) during routine CLI commands on `mos`.
- Provision `eternity-fam2` as a hardened `media` exit node (`VLESS + XHTTP + Reality + RU egress blackhole`) with 1 GB swap and SSH hardened to `stealth:22222`.
- Rebalance `media-consumer` load by migrating `anya-z` from `oblako-fam1` to `eternity-fam2` with zero client-side reconfiguration and adding `sema` and `sonya` on `eternity-fam2`.
- Include `eternity-fam2:exit` in `tools/.env` and verify all 4 nodes passively.

**Non-Goals:**
- Changing client routing policy (`media-selective` domain/package lists remain unchanged).
- Modifying `server-de` (`exit-ai`) or `owner` bindings, or touching local workstation VPN (`/etc/sing-box/config.json`).
- Storing any live IPv4 address, FQDN, UUID, Reality key, or `shortId` in Git-tracked files.

## Decisions

### 1. Explicit `ufw` and `iptables` Prerequisite Enforcement in `script.sh`
- **Decision:** Add an explicit prerequisite helper in `script.sh` invoked by `configure_ufw_and_kernel`:
  - In `--dry-run`, log an error/fail if `ufw` or `iptables` is missing.
  - In normal non-bridge (`exit`) mode, run `apt-get update && apt-get install -y ufw iptables` if either binary is missing.
  - In `--bridge` mode (Zero-Emission), fail loudly with instructions rather than silently skipping `ufw`/`iptables` or initiating unexpected package pulls if missing.
- **Rationale:** On minimal Ubuntu 26.04 images (`eternity-fam2`), `ufw` and `iptables` are absent by default; silent `if command -v ...` guards in `script.sh` previously left the host without a firewall or `TCPMSS=1360` clamping.
- **Alternative considered:** Installing `ufw` and `iptables` manually only in runbook commands. Rejected as fragile for future exit provisioning.

### 2. Zero-Emission Container-Reuse in `run_python_cli`
- **Decision:** In `script.sh`'s `run_python_cli()`, after checking `.venv` and host `python3` (`nacl, cryptography`), check whether `marzneshin-xray` is currently running (`docker ps --format '{{.Names}}' | grep -qx marzneshin-xray`). When running—and when invoked for CLI subcommands (`status`, `upstream`, `user`, `stats`, `xhttp`, `bridge-transport`, `rotate`, `decoy`)—execute `docker exec -i marzneshin-xray python3 -m app.cli --data-dir "$DATA_DIR" --credentials-dir "$CREDENTIALS_DIR" "$@"` (`docker-compose.yml` already bind-mounts both `/var/lib/marzneshin` and `/root/vpn-credentials`). Only during initial deployment (`init`/`init-bridge`) or when no image exists does it fall back to `docker compose run --build --rm`.
- **Rationale:** Prevents `script.sh upstream ...` and `script.sh user ...` on `mos` from initiating outbound Docker Hub pulls/metadata checks, preserving strict Zero-Emission.
- **Alternative considered:** Installing a `.venv` on `mos`. Rejected to avoid host Python package drift and extra outbound `pip` requests from `mos`.

### 3. Swap Provisioning & Exit Rollout Order for `eternity-fam2`
- **Decision:** Create a `1 GB` `/swapfile` on `eternity-fam2` prior to running `script.sh --domain <eternity-fam2-fqdn>` so Docker image builds have memory headroom above 956 MB RAM. After deployment and `self-test`, update `~/.ssh/config` for `eternity-fam2` (`User stealth`, `Port 22222`), read the generated exit credentials from `/var/lib/marzneshin/state.json` on `eternity-fam2`, and register `eternity-fam2` on `mos` via `upstream add eternity-fam2 --role media --transport xhttp ...`.
- **Why:** Reuses the exact `media` exit architecture already proven on `oblako-fam1` (`XHTTP + Reality + xmux` with `hMaxReusableSecs = "180-300"` and exit-side RU egress blackhole) while separating `anya-z`, `sema`, and `sonya` onto a distinct `/24` subnet from both `server-de` and `oblako-fam1`.

### 4. Zero-Reconfiguration User Migration (`anya-z`) & Onboarding (`sema`, `sonya`)
- **Decision:** Use `user assign anya-z eternity-fam2` on `mos` to rebind `anya-z` without modifying her UUID or client JSON profile, then run `user add sema --upstream eternity-fam2` and `user add sonya --upstream eternity-fam2` to generate `media-selective` Android/iOS bundles (`sing-box >= 1.14`, no raw `vless://` links).

## Risks / Trade-offs

- **[Cloudflare orange-cloud proxy left enabled on `<eternity-fam2-fqdn>`] -> Mitigation:** `script.sh` runs `is_cloudflare_proxy_ip` during `verify_direct_dns` and aborts cleanly before container startup or ACME issuance if proxied.
- **[`marzneshin-xray` container code staleness if `/opt/marzneshin` is updated without image rebuild] -> Mitigation:** `run_python_cli` container reuse is safe when `mos` image is already synced; if `app/` changes are deployed to `mos` later, rebuild on `server-de` and stream via `docker save | gzip | ssh mos 'gunzip | sudo docker load'`.
- **[OOM during `docker compose up -d --build` on 956 MB VPS] -> Mitigation:** Create `1 GB` `/swapfile` before running `script.sh` on `eternity-fam2`.
- **[SSH port/user switch lockout during `script.sh`] -> Mitigation:** `script.sh` copies `/root/.ssh/authorized_keys` to `stealth` and verifies `:22222` listening before closing `22/tcp`; update workstation `~/.ssh/config` immediately after `script.sh` completes.

## Migration Plan

1. Implement and unit-test the `script.sh` improvements (`ufw`/`iptables` preflight + `docker exec` CLI reuse) locally via `.venv/bin/python -m pytest tests/ -v`.
2. Prepare `eternity-fam2` (install `rsync` if needed, create `1 GB` swapfile), sync repository to `eternity-fam2:/opt/marzneshin`, and run `sudo ./script.sh --domain <eternity-fam2-fqdn>`.
3. Update workstation `~/.ssh/config` for `eternity-fam2` (`User stealth`, `Port 22222`), run `sudo ./script.sh self-test` on `eternity-fam2`, and verify non-RU egress identity passively/anonymously from `eternity-fam2` (`script.sh` runs `check_triple_ai_egress` automatically during deploy).
4. Register `eternity-fam2` on `mos` (`upstream add eternity-fam2 --role media --transport xhttp ...`), run `user assign anya-z eternity-fam2`, and run `user add sema --upstream eternity-fam2` + `user add sonya --upstream eternity-fam2`.
5. Run `sudo /opt/marzneshin/script.sh self-test` on `mos`, update workstation `tools/.env` (`MARZNESHIN_WATCH_NODES`), and verify all 4 nodes with `python3 tools/cluster_watch.py`.
6. **Rollback:** If `eternity-fam2` exhibits issues, rebind `anya-z` back to `oblako-fam1` (`user assign anya-z oblako-fam1`) and/or migrate users via `upstream migrate eternity-fam2 oblako-fam1` on `mos` with zero client reconfiguration.
