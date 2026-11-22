# Tasks

## 1. Align OpenSpec Project Context

- [x] 1.1 Update `openspec/config.yaml` context note so independent root domain for `exit-ai` is marked recommended rather than mandatory, matching `AGENTS.md` and `app/bridge_state.py`.

## 2. Roll Out Updated Code & RU Egress Blackhole to `server-de`

- [x] 2.1 Sync updated repository code to `server-de:/opt/marzneshin` and rebuild the `marzneshin-xray` Docker image (`docker compose build xray`).
- [x] 2.2 Re-render `/var/lib/marzneshin/xray/config.json` on `server-de` from existing `/var/lib/marzneshin/state.json` (preserving `user_uuid`, Reality keys, `short_id`, and `xhttp_path`), validate with `validate_xray_config` and `xray -test`, and recreate only the `xray` container (`docker compose up -d --no-deps xray`).
- [x] 2.3 Run `sudo ./script.sh self-test` on `server-de` and confirm `[PASS] xray_config_safety` reports `RU egress blackhole active`.

## 3. Cluster Verification & Git Hygiene

- [x] 3.1 Run `python3 tools/cluster_watch.py --nodes mos:bridge server-de:exit oblako-fam1:exit` and `.venv/bin/python -m pytest tests/ -v` to confirm all nodes are `[OK]` and all local tests pass.
- [x] 3.2 Review `git status` / `git diff` to ensure zero live IPs, UUIDs, Reality keys, or secret paths exist in tracked files, commit the repository updates, and archive `sync-server-de-exit` via `openspec archive sync-server-de-exit`.
