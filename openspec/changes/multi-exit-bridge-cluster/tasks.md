# Tasks

## 1. Multi-Exit Bridge State Schema & Isolation Guards

- [ ] 1.1 Implement bridge `state.json` v2 schema (`upstreams` and `users` maps with `role: ai-isolated | media` and `profile: ai-owner | media-selective`) plus automatic backward-compatible v1-to-v2 migration preserving existing `user_uuid` and Reality keys; verify with unit tests covering v1 migration and atomic save/load.
- [ ] 1.2 Implement hard isolation validation guards rejecting >1 user on `ai-isolated`, rejecting `media-selective` bindings on `ai-isolated`, and rejecting registrable root-domain collisions between `ai-isolated` and `media` upstreams; verify with negative unit tests asserting non-zero rejection and unchanged state.

## 2. Multi-Upstream Bridge Xray Config Builder

- [ ] 2.1 Extend `LocalXrayConfigBuilder.build_bridge` in `app/xray/config_builder.py` to render multiple named `XHTTP + Reality + xmux` outbounds (`proxy-<upstream>`), multi-client `:443` `vless-reality-vision` inbound, static `routing.rules` matching `user` -> `proxy-<upstream>` with `domainStrategy: "AsIs"`, fail-closed default `block`, zero `freedom` outbounds, and unconditional `UDP 443/3478/19302` / QUIC / STUN / BitTorrent / `::/0` / telemetry blackholes; verify with unit tests validating rendered Xray JSON invariants.
- [ ] 2.2 Update `app/utils/self_test.py` passive Zero-Emission checks to validate multi-upstream bridge configs (all upstream outbounds, `ai-isolated` guards, root-domain separation, unconditional blackholes) and emit non-fatal `WARN:` when a multi-user bridge has `< 1800 MB` RAM or `0` swap; verify with unit tests mocking `/proc/meminfo` and bridge configs.

## 3. Zero-Surface SSH CLI Administration (`upstream` & `user`)

- [ ] 3.1 Add `upstream add`, `upstream list`, `upstream remove` (refusing deletion while users are bound), and `upstream migrate <from> <to>` (zero-client-reconfiguration rebinding) subcommands in `app/cli.py` and `script.sh`; verify with CLI unit tests confirming atomic Xray re-render and preserved user UUIDs.
- [ ] 3.2 Add `user add`, `user list`, `user show`, `user assign <user> <exit>`, and `user remove` subcommands in `app/cli.py` and `script.sh` writing per-user credential bundles to `/root/vpn-credentials/users/<user>/` with version and SHA-256 tracking; verify with CLI unit tests covering full add/assign/remove lifecycle.

## 4. Role-Based Versioned Client Profile Generation

- [ ] 4.1 Implement `media-consumer` mobile-only vanilla `sing-box` (`>= 1.14`) profile generators (`android-media-selective.json` and `ios-media-selective.json`) in `app/client/profile_generator.py` routing strictly YouTube, Instagram, Telegram, TikTok, and WhatsApp (`final: direct`), enforcing unconditional `UDP 443/3478/19302` / QUIC / STUN / BitTorrent / `::/0` / telemetry blocking, and ensuring iOS omits `package_name`, `override_android_vpn`, `interface_name`, and oversized `.srs` lists; verify with unit tests validating JSON schema, rule footprint, and forbidden keys.
- [ ] 4.2 Extend `ai-owner` profile generation in `app/client/profile_generator.py` to output the full 5-OS admin suite (`Android`, `iOS`, `Windows 11 Throne`, `Linux`, `OpenWrt` including standalone `openwrt-outbound.json`) with version metadata and SHA-256 recording; update `SINGBOX_CLIENT_REQUIREMENTS.md` to document both roles and verify with unit tests.

## 5. End-to-End Integration Verification

- [ ] 5.1 Add cascade E2E test in `tests/test_cascade_e2e.py` exercising 1 bridge routing 2 distinct user UUIDs to 2 distinct local mock XHTTP exits (`ai-isolated` vs `media`), verifying static isolation, `upstream migrate` without client config changes, and full `pytest tests/ -v` pass.

## Workflow follow-up

- Run `openspec validate multi-exit-bridge-cluster` before starting implementation via `/opsx-apply`.
- Archive the change via `/opsx-archive` once implementation and live rollout verification are complete.
