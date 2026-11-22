## Context

- `server-de` (`exit-ai`) is currently running live traffic from `mos` (`owner -> default`) over `XHTTP + Reality`.
- Rebuilding or re-rendering `server-de` must be **zero-rotation** for its Reality keypair, `shortId`, client `user_uuid`, and `xhttp_path` so `mos` and existing `ai-owner` profiles continue working without re-issuing credentials.
- `app/cli.py` already provides `xhttp on` (or direct `LocalXrayConfigBuilder.build` re-render from `/var/lib/marzneshin/state.json`) and `xray -test` validation before replacing `/var/lib/marzneshin/xray/config.json`.

## Goals / Non-Goals

- **Goals:**
  - Upgrade `/opt/marzneshin` and `marzneshin-xray:latest` on `server-de` without altering `state.json` credentials (`user_uuid`, `reality_private_key`, `reality_public_key`, `short_id`, `xhttp_path`).
  - Re-render `/var/lib/marzneshin/xray/config.json` on `server-de` with the RU egress blackhole (`domain:ru`, `domain:su`, `domain:xn--p1ai`, `geoip:ru` -> `block`), validate with `xray -test`, and restart `marzneshin-xray` cleanly (leaving `marzneshin-nginx` untouched).
  - Verify `RU egress blackhole active` via `./script.sh self-test` on `server-de` and confirm healthy cluster state via `python3 tools/cluster_watch.py --nodes mos:bridge server-de:exit oblako-fam1:exit`.
  - Keep `openspec/config.yaml` and synced specs aligned with optional root-domain separation and commit clean repo changes to Git.
- **Non-Goals:**
  - Rotating Reality keys, UUIDs, or XHTTP paths on `server-de`.
  - Modifying `mos` or `oblako-fam1` configurations or client JSON bundles.

## Decisions

1. **Zero-credential-rotation config re-render on `server-de`:**
   - Sync repository code to `server-de:/opt/marzneshin`, rebuild `xray` image (`docker compose build xray`), and re-render `/var/lib/marzneshin/xray/config.json` directly from existing `/var/lib/marzneshin/state.json` via `LocalXrayConfigBuilder.build` + `validate_xray_config` + `xray -test` before `docker compose up -d --no-deps xray`.
   - Avoid running `--domain ...` full re-install so Nginx, ACME certs, UFW, and existing Reality keys/XHTTP paths are preserved intact.
2. **Spec & config alignment:**
   - Update `openspec/config.yaml` wording on `independent root domain` to match `AGENTS.md` (`separate root domain is recommended, not mandatory`) alongside syncing the delta specs in this change.

## Risks / Trade-offs

- **Brief Xray restart (~1-2s) on `server-de`:** Mitigated by keeping `marzneshin-nginx` running (`--no-deps xray`) and validating candidate JSON with `xray -test` before swapping `/var/lib/marzneshin/xray/config.json`.
- **Accidental credential change:** Mitigated by snapshotting `/var/lib/marzneshin/state.json` before re-render and asserting `user_uuid`, `reality_public_key`, `short_id`, and `xhttp_path` remain identical.
