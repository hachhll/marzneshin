# Proposal

## Why

Currently the Cascade Bridge (`mos`) routes all clients through a single shared UUID to a single German exit node (`server-de`). Scaling up to ~20 media-consumer devices (YouTube, Instagram, Telegram, TikTok, WhatsApp) on that same exit risks contaminating the IP reputation and geolocation of the owner's AI accounts (Google, Anthropic, OpenAI) and creates a high-volume single-IP traffic pattern vulnerable to Russia's TSPU/DPI. We need a multi-exit bridge cluster where one dedicated German exit is strictly isolated for a single AI owner while separate German exits serve media consumers with static per-user routing, strict zero-relaxation TSPU hardening, and role-specific vanilla `sing-box` client profiles.

## What Changes

- **Multi-exit static routing on the Moscow bridge (`bridge` mode v2):** Extend `state.json`, `LocalXrayConfigBuilder.build_bridge`, and the SSH CLI to support multiple named `XHTTP + Reality + xmux` upstreams (e.g., `exit-ai`, `exit-media-1`, `exit-media-2`) behind the single `:443` bridge entrypoint, with zero DNS queries (`domainStrategy: "AsIs"`) and zero `freedom` (`direct`) outbounds.
- **Hard `ai-isolated` role boundary & `/24` subnet/ASN diversity:** Enforce a strict CLI/validator guard ensuring an `ai-isolated` upstream accepts at most 1 owner user (`ai-owner` profile), rejects any `media-consumer` binding, prevents root-domain overlap with `media` upstreams, and checks/prevents `/24` IPv4 subnet overlap between `ai-isolated` and `media` exits (with operational ASN/hoster diversity).
- **Zero-Surface SSH user & upstream administration:** Add SSH CLI commands (`upstream add/list/remove/migrate` and `user add/list/show/assign/remove`) to create, identify, reassign, migrate (without changing client UUIDs or configs), and revoke individual users cleanly, with automatic backward-compatible v1 -> v2 `state.json` migration.
- **Role-based versioned client profile distribution (no raw `vless://` URIs for media users):**
  - **`media-consumer` (up to ~20 devices):** Strictly mobile-only vanilla `sing-box` (`>= 1.14`) profiles for **Android (SFA)** and **iOS (SFI)** in **Media-Selective** mode (proxying only YouTube, Instagram, Telegram, TikTok, WhatsApp; everything else `direct`; iOS-safe compact rule-sets respecting the 50 MB NetworkExtension memory budget and omitting `package_name`/`override_android_vpn`), omitting raw `links.txt`/QR `vless://` URIs so users cannot import unrouted profiles.
  - **`ai-owner` (1 admin user):** Full and AI-Selective profiles across **Android, iOS, Windows 11 (Throne), Linux, and OpenWrt** (`sing-box` TUN/mixed + router outbound export, plus optional `xray-client.json` and admin-only `links.txt`).
- **Uncompromising global TSPU/DPI security baseline + Exit RU egress blackhole:** Preserve strict blocking of `UDP 443, 3478, 19302` (QUIC, STUN/WebRTC), `BitTorrent`, `::/0` (IPv6), and telemetry across ALL contours (both `ai-owner` and `media-consumer`, server and client), enforce `query_type: "HTTPS"` reject in `dns.rules` across **both** Full-tunnel and Selective `sing-box` profiles, add mandatory server-side **RU egress blackhole** (`domain:ru`, `domain:su`, `domain:xn--p1ai`, `geoip:ru` -> `block`, zero WARP) on foreign Exit nodes against domestic snitch apps / Full-tunnel leaks, tighten `xmux` `hMaxReusableSecs` session rotation on `mos -> Exit` to break long asymmetric flows, with zero protocol/port relaxations for voice/video calls, zero `urltest`, zero `/sub/` endpoints, `fp=firefox`, and MPTCP disabled.
- **Bridge capacity baseline:** Document and validate `2 GB RAM + 1 GB swap` operational target for the multi-exit Moscow bridge serving up to ~20 devices across 3+ exits.

## Capabilities

### New Capabilities
- `multi-exit-cluster-routing`: Static per-user UUID-to-upstream routing on a single Cascade Bridge (`mos`) across multiple isolated German `XHTTP + Reality + xmux` exit nodes, including `ai-isolated` vs `media` role enforcement, backward-compatible v2 state schema, and Zero-Surface SSH CLI administration (`upstream` and `user` lifecycle + zero-downtime user migration between exits).

### Modified Capabilities
- `anti-drift-safety-policy`: Extend `bridge` mode outbound invariant from a single `vless` Reality outbound to a closed set of configured `vless` Reality (`XHTTP + xmux`) upstreams with zero `freedom`/`direct` outbounds, enforce `ai-isolated` root-domain and single-owner separation, allow role-scoped `media-selective` client routing (`direct` for non-media domestic traffic) while keeping `ai-owner` strict anti-drift intact and preserving unconditional `UDP 443, 3478, 19302` / QUIC / STUN / IPv6 / telemetry blocking across all contours.
- `minimal-profile-constructor`: Extend per-user versioned client profile generation to support two distinct distribution roles — strict mobile-only (`Android SFA` + `iOS SFI`) vanilla `sing-box` `media-selective` profiles (YouTube, Instagram, Telegram, TikTok, WhatsApp, iOS 50 MB RAM-safe) for regular users, and full multi-OS (`Android`, `iOS`, `Windows 11 Throne`, `Linux`, `OpenWrt`) profiles for the `ai-owner` admin.

## Impact

- **Codebase (future implementation, untouched during planning):**
  - `app/xray/config_builder.py` (multi-upstream `build_bridge`, per-user `routing.rules`, safety validators)
  - `app/cli.py` & `script.sh` (`state.json` v1 -> v2 migration, `upstream` and `user` CLI subcommands, per-user credential directories under `/root/vpn-credentials/users/<name>/`)
  - `app/client/profile_generator.py` (`media-selective` Android/iOS generator, `ai-owner` iOS/Linux/OpenWrt generators, profile version metadata & SHA-256 tracking)
  - `app/utils/self_test.py` (passive Zero-Emission validation of multi-upstream bridge configs and `ai-isolated` invariants)
  - `tests/` (unit and E2E cascade tests for multi-exit routing, isolation guards, and platform profile schemas)
- **Live infrastructure:** Zero modifications during OpenSpec planning; future rollout requires upgrading `mos` RAM to 2 GB + 1 GB swap and provisioning additional independent German exit nodes with separate root domains.
