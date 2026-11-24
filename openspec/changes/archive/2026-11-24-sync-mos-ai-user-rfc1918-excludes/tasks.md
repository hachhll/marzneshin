# Tasks

## 1. Local Image Build & Zero-Emission Sync to `mos`

- [x] 1.1 Rebuild `marzneshin-xray:latest` locally from commit `16bacd9` and verify `Xray 26.6.27` and `AI_USER_ROUTE_EXCLUDE_ADDRESSES == ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']` inside the image.
- [x] 1.2 Sync `app/` to `mos:/opt/marzneshin/app/` without `--delete` and stream `marzneshin-xray:latest` via `docker save | gzip | ssh mos 'gunzip | sudo docker load'`.
- [x] 1.3 Recreate only `marzneshin-xray` on `mos` with `sudo docker compose up -d --no-build --no-deps xray`, verifying `marzneshin-nginx` remains running without restart and host-local directories remain intact.

## 2. Targeted `ai-user` Bundle Refresh & Passive Verification

- [x] 2.1 Regenerate the `ai-user` bundle on `mos` via `_render_user_bundle_for_state` and atomically persist the updated `profile_sha256` to `state.json` without altering `xray/config.json`, UUIDs, Reality keys, or other users.
- [x] 2.2 Verify exact SHA-256 and JSON parity (`['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']`) across `mos` disk, `marzneshin-xray` container, `mos` generated bundle, and active work-node `sing-box` config.
- [x] 2.3 Run passive `sudo ./script.sh self-test` on `mos` (all 5 checks `[PASS]`) and `python3 tools/cluster_watch.py` from the workstation to confirm healthy `mos` and `exit-ai` state.
