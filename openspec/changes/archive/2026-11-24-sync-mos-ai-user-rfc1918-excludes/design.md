# Design

## Context

See [proposal.md](./proposal.md) for motivation. In commit `16bacd9`, `AI_USER_ROUTE_EXCLUDE_ADDRESSES` in `app/client/profile_generator.py` was broadened to full RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) so `sing-box` `Selective TUN` on Linux `ai-user` work nodes does not capture LAN, Docker, or private `10.0.0.0/8` VPN traffic. Because `mos` lacked host Python crypto dependencies, `script.sh` ran `docker exec marzneshin-xray python3 -m app.cli`, which executed the `/app` snapshot baked into the previous `marzneshin-xray` image.

## Goals / Non-Goals

**Goals:**
- Bring `mos:/opt/marzneshin/app/`, the running `marzneshin-xray` image, and the rendered `ai-user` bundle on `mos` into exact parity with commit `16bacd9` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- Preserve Zero-Emission on `mos`, 0s downtime on `marzneshin-nginx`, and zero disruption to existing users, UUIDs, Reality keys, `xray/config.json`, and exit nodes.
- Keep `state.json` `profile_sha256` consistent with the regenerated `bundle-manifest.json`.

**Non-Goals:**
- Modifying repository application code or adding new CLI subcommands (`user refresh` or `self-test` drift checks remain optional future changes).
- Re-deploying configs to the work node (already aligned with RFC 1918 excludes) or touching `exit-ai` / `media` exits.

## Decisions

1. **Local workstation build + SSH stream instead of building on `mos` or `exit-ai`:**
   - Preserves Zero-Emission on `mos` (`AGENTS.md` §1.3) and avoids memory pressure on the `907 MB` RAM `exit-ai` VPS.
   - Verified `Xray 26.6.27` and `AI_USER_ROUTE_EXCLUDE_ADDRESSES` inside the built image prior to streaming.
2. **Scoped `rsync` of `app/` without `--delete`:**
   - Avoids accidentally deleting host-local directories under `/opt/marzneshin/` (such as `.env` or local backup folders).
3. **`docker compose up -d --no-build --no-deps xray`:**
   - Recreates only `marzneshin-xray` (~1–2s reconnect window) while leaving `marzneshin-nginx` running untouched.
4. **Targeted bundle refresh (`_render_user_bundle_for_state` + `save_state`) instead of full `apply_state`:**
   - Avoids rewriting `xray/config.json` or Nginx configs and avoids the `copy.deepcopy` behavior inside `apply_state` that leaves `profile_sha256` stale in `state.json`.

## Risks / Trade-offs

- **[Risk] Brief reconnect window on `marzneshin-xray` recreate** -> **Mitigation:** Recreate with `--no-build --no-deps`; clients automatically reconnect without affecting `marzneshin-nginx` or exit nodes.
- **[Risk] Drift between host `/opt/marzneshin/app` and container `/app` in future updates** -> **Mitigation:** Documented; can be addressed systematically later via a dedicated `user refresh` CLI command and container-vs-host/bundle checks in `self-test`.
