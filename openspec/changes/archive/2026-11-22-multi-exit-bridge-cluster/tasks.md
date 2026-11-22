# Tasks

## 1. Multi-Exit Bridge State Schema & Isolation Guards

- [x] 1.1 Implement bridge `state.json` v2 schema (`upstreams` and `users` maps with `role: ai-isolated | media` and `profile: ai-owner | media-selective`) plus automatic backward-compatible v1-to-v2 migration preserving existing `user_uuid` and Reality keys; verify with unit tests covering v1 migration and atomic save/load.
- [x] 1.2 Implement hard isolation validation guards rejecting >1 user on `ai-isolated`, rejecting `media-selective` bindings on `ai-isolated`, rejecting registrable root-domain collisions between `ai-isolated` and `media` upstreams, and rejecting `/24` IPv4 subnet overlap between `ai-isolated` and `media` exits (unless explicitly overridden); verify with negative unit tests asserting non-zero rejection and unchanged state.

## 2. Multi-Upstream Bridge & Exit Hardening (`config_builder.py` & `self_test.py`)

- [x] 2.1 Extend `LocalXrayConfigBuilder.build_bridge` in `app/xray/config_builder.py` to render multiple named `XHTTP + Reality + xmux` outbounds (`proxy-<upstream>`) with tightened session rotation (`xmux.hMaxReusableSecs` bounded to `"180-300"`), multi-client `:443` `vless-reality-vision` inbound, static `routing.rules` matching `user` -> `proxy-<upstream>` with `domainStrategy: "AsIs"`, fail-closed default `block`, zero `freedom` outbounds, and unconditional `UDP 443/3478/19302` / QUIC / STUN / BitTorrent / `::/0` / telemetry blackholes; verify with unit tests in `tests/test_xray_config.py`.
- [x] 2.2 Add mandatory server-side domestic RU egress blackhole (`domain:ru`, `domain:su`, `domain:xn--p1ai`, `geoip:ru` -> `block` prior to `direct`, zero WARP) in `LocalXrayConfigBuilder.build` (`exit` mode) and enforce it in `validate_xray_config`; verify with unit tests in `tests/test_xray_config.py` confirming RU targets route to `block` while `mos` remains `AsIs` with zero `freedom` outbounds.
- [x] 2.3 Update `app/utils/self_test.py` passive Zero-Emission checks to validate multi-upstream bridge configs (all upstream outbounds, `ai-isolated` guards, root-domain and `/24` subnet separation, bounded `xmux` rotation, unconditional blackholes), Exit RU egress blackholes, and emit non-fatal `WARN:` when a multi-user bridge has `< 1800 MB` RAM or `0` swap; verify with unit tests in `tests/test_self_test.py` mocking `/proc/meminfo` and bridge/exit configs.

## 3. Zero-Surface SSH CLI Administration (`upstream` & `user`)

- [x] 3.1 Add `upstream add`, `upstream list`, `upstream remove` (refusing deletion while users are bound), and `upstream migrate <from> <to>` (zero-client-reconfiguration rebinding) subcommands in `app/cli.py` and `script.sh`; verify with CLI unit tests confirming atomic Xray re-render, `/24`/root-domain isolation checks, and preserved user UUIDs.
- [x] 3.2 Add `user add`, `user list`, `user show`, `user assign <user> <exit>`, and `user remove` subcommands in `app/cli.py` and `script.sh` writing per-user credential bundles to `/root/vpn-credentials/users/<user>/` with version and SHA-256 tracking; verify with CLI unit tests covering full add/assign/remove lifecycle.

## 4. Role-Based Versioned Client Profile Generation

- [x] 4.1 Implement `media-consumer` mobile-only vanilla `sing-box` (`>= 1.14`) profile generators (`android-media-selective.json` and `ios-media-selective.json`) in `app/client/profile_generator.py` routing strictly YouTube, Instagram, Telegram, TikTok, and WhatsApp (`final: direct`), enforcing unconditional `UDP 443/3478/19302` / QUIC / STUN / BitTorrent / `::/0` / telemetry / `query_type: "HTTPS"` blocking, omitting `links.txt` / raw `vless://` URIs so users cannot import unrouted links, and ensuring iOS omits `package_name`, `override_android_vpn`, `interface_name`, and oversized `.srs` lists; verify with unit tests in `tests/test_client_profiles.py`.
- [x] 4.2 Extend `ai-owner` profile generation in `app/client/profile_generator.py` to output the full 5-OS admin suite (`Android`, `iOS` for `sing-box MT` Local import without Android-only fields/heavy `.srs`, `Windows 11 Throne`, `Linux`, and `OpenWrt` router-safe `tproxy` `openwrt-singbox.json` + `podkop` `openwrt-outbound.json`) with `query_type: "HTTPS"` reject added to `Full Tunnel` `dns.rules`, admin-only `links.txt`, version metadata, and SHA-256 recording; reconcile `SINGBOX_CLIENT_REQUIREMENTS.md` once generated filenames/schemas land and verify with unit tests in `tests/test_client_profiles.py`.

## 5. End-to-End Integration Verification

- [x] 5.1 Add cascade E2E test in `tests/test_cascade_e2e.py` exercising 1 bridge routing 2 distinct user UUIDs to 2 distinct local mock XHTTP exits (`ai-isolated` vs `media`) with tightened `xmux.hMaxReusableSecs` (`"180-300"`), verifying static isolation, Exit RU blackhole rule enforcement, `upstream migrate` without client config changes, and full `.venv/bin/python -m pytest tests/ -v` pass.

## Workflow follow-up

- Run `openspec validate multi-exit-bridge-cluster` before starting implementation via `/opsx-apply`.
- Archive the change via `/opsx-archive` once implementation and live rollout verification are complete.
