# Proposal

## Why

After updating `AI_USER_ROUTE_EXCLUDE_ADDRESSES` in `app/client/profile_generator.py` to exclude all RFC 1918 private address ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the Cascade Bridge (`mos`) still ran an earlier `marzneshin-xray` container image and disk copy missing `10.0.0.0/8`. Because `script.sh` executes the Python CLI inside `marzneshin-xray`, any subsequent regeneration or new `ai-user` provisioning on `mos` would produce profiles without `10.0.0.0/8`, causing `sing-box` `Selective TUN` (`strict_route: true`) to hijack return traffic to `10.0.0.0/8` private/home-VPN subnets on Linux work nodes.

## What Changes

- Sync updated `app/` files (including RFC 1918 `AI_USER_ROUTE_EXCLUDE_ADDRESSES`) to `mos:/opt/marzneshin/app/` safely without `--delete` (preserving existing host directories such as `.env` and local credential folders).
- Rebuild `marzneshin-xray:latest` (`Xray v26.6.27`) locally on the workstation and stream the image to `mos` via `docker save | gzip | ssh mos 'gunzip | sudo docker load'` (strict Zero-Emission on `mos`).
- Recreate only `marzneshin-xray` with `--no-build --no-deps` so `marzneshin-nginx` remains running with 0s downtime.
- Refresh the existing `ai-user` credential bundle on `mos` and atomically persist its updated `profile_sha256` in `state.json` without rotating UUIDs/Reality keys or modifying `xray/config.json`, Nginx, exit nodes, or other users.
- Verify bit-for-bit parity between `mos` and the active work-node `sing-box` configuration, run passive `self-test` on `mos`, and check cluster health via `tools/cluster_watch.py`.

## Capabilities

### New Capabilities
- *(none)*

### Modified Capabilities
- *(none — operational bridge synchronization matching the existing `minimal-profile-constructor` RFC 1918 `route_exclude_address` specification)*

## Impact

- **Repository code:** None (already committed in `16bacd9`).
- **Live infrastructure:** `mos` (`/opt/marzneshin/app/`, `marzneshin-xray:latest` image, `/root/vpn-credentials/users/<ai-user>/`, and `profile_sha256` in `/var/lib/marzneshin/state.json`); zero changes to `marzneshin-nginx`, `xray/config.json`, `exit-ai`, `media` exits, or other users.
