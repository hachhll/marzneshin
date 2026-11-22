# Tasks

## 1. Harden `script.sh` Prerequisites & Zero-Emission Bridge CLI

- [x] 1.1 Update `configure_ufw_and_kernel` in `script.sh` so missing `ufw` or `iptables` binaries are installed via `apt-get` in non-dry-run exit mode (or fail explicitly in `--dry-run` / `--bridge` mode) instead of silently skipping UFW and `TCPMSS=1360` rules; verify with `bash -n script.sh`.
- [x] 1.2 Update `run_python_cli` in `script.sh` to execute routine CLI subcommands via `docker exec -i marzneshin-xray python3 -m app.cli ...` when `marzneshin-xray` is running and no host `.venv` exists, avoiding `docker compose run --build` on `mos`; verify via shell/pytest checks (`tests/`).
- [x] 1.3 Add or update tests covering the `ufw`/`iptables` preflight guard and `docker exec` container-reuse CLI path, and verify `.venv/bin/python -m pytest tests/ -v` passes with zero regressions.

## 2. Provision `eternity-fam2` Exit Node

- [x] 2.1 Prepare `eternity-fam2` host prerequisites (`rsync`, `ufw`, `iptables`, and a persistent 1 GB `/swapfile`) and sync the repository to `eternity-fam2:/opt/marzneshin`; verify `swapon --show` reports 1 GB swap and `/opt/marzneshin/script.sh` is executable.
- [x] 2.2 Run `sudo /opt/marzneshin/script.sh --domain <eternity-fam2-fqdn>` on `eternity-fam2` (confirming direct non-proxied Cloudflare DNS A-record, Docker/Xray/Nginx deployment, ACME TLS 1.3 issuance, UFW, `TCPMSS=1360`, and SSH hardening to `stealth:22222`), and update workstation `~/.ssh/config` for `eternity-fam2`; verify SSH login succeeds via `ssh eternity-fam2`.
- [x] 2.3 Run `sudo /opt/marzneshin/script.sh self-test` on `eternity-fam2` and confirm all passive safety checks (`RU egress blackhole active`, `TCPMSS=1360`, `mptcp=0`, `CN=localhost` default fallback) report `[PASS]`.

## 3. Wire `eternity-fam2` into `mos` & Configure Users

- [x] 3.1 Sync updated `script.sh` to `mos:/opt/marzneshin/script.sh` and register `eternity-fam2` on `mos` (`upstream add eternity-fam2 --role media --transport xhttp ...`) using the exit credentials from `eternity-fam2:/var/lib/marzneshin/state.json`; verify `upstream list` on `mos` shows `default` (`ai-isolated`), `oblako-fam1` (`media`), and `eternity-fam2` (`media`) with zero `/24` subnet warnings/errors.
- [x] 3.2 Reassign `anya-z` from `oblako-fam1` to `eternity-fam2` on `mos` (`user assign anya-z eternity-fam2`) and verify `user show anya-z` preserves her existing UUID and `media-selective` profile without requiring client re-import.
- [x] 3.3 Create `sema` and `sonya` on `mos` (`user add sema --upstream eternity-fam2` and `user add sonya --upstream eternity-fam2`) and verify `/root/vpn-credentials/users/{sema,sonya}/` contain `media-selective` Android/iOS JSON profiles (no raw `vless://` links) and `marzneshin-xray` restarts cleanly after `xray run -test`.

## 4. Cluster Monitoring & Final Verification

- [x] 4.1 Update workstation `tools/.env` to include `eternity-fam2:exit` in `MARZNESHIN_WATCH_NODES` and run `sudo /opt/marzneshin/script.sh self-test` on `mos` to confirm all multi-exit bridge invariants report `[PASS]`.
- [x] 4.2 Run `python3 tools/cluster_watch.py` from the workstation and confirm all 4 nodes (`mos:bridge`, `server-de:exit`, `oblako-fam1:exit`, `eternity-fam2:exit`) report healthy status with zero quarantine/retransmission anomalies.

## Workflow follow-up

- Review `git status` / `git diff` to confirm zero live IPs, domains, UUIDs, or Reality keys appear in tracked files before committing and archiving `add-eternity-fam2-exit`.
