# Design

## Context

See `proposal.md` for motivation and scope. Currently the appliance operates as a 1-to-1 cascade: one Moscow bridge (`mos`, `Xray v26.6.27` + `Nginx`, `955 MB` RAM / `0` swap) forwarding a single `owner` UUID over `VLESS + XHTTP + Reality + xmux` to a single German exit (`server-de`). All configuration lives in `/var/lib/marzneshin/state.json` (flat single-upstream schema) rendered by `app/xray/config_builder.py` and `app/cli.py`, with client bundles written to `/root/vpn-credentials/` by `app/client/profile_generator.py`.

Strict operational constraints governing this design:
- Zero-Surface administration (SSH CLI only, no web UI, no `/sub/` endpoints).
- Zero-Emission on the domestic Moscow bridge (`domainStrategy: "AsIs"`, zero DNS queries, zero outbound probes, zero `freedom` outbound).
- Uncompromising TSPU/DPI protection: `UDP 443, 3478, 19302` (QUIC/STUN/WebRTC), `BitTorrent`, `::/0`, and telemetry are blocked unconditionally on every node and client (security overrides call quality/speed).
- Complete isolation of the single `ai-owner` contour (`exit-ai`) from the ~20 `media-consumer` devices (`exit-media-1..N`).

## Goals / Non-Goals

**Goals:**
- Support `1` Moscow bridge routing statically by client UUID to `N` independent German `XHTTP + Reality + xmux` exits without adding extra containers or listening ports on the bridge.
- Enforce compile-time/CLI-time isolation of `role: ai-isolated` exits (max 1 `ai-owner` user, distinct registrable root domain from all `media` exits).
- Enable zero-reconfiguration failover/migration of `media-consumer` users between German exits purely on `mos`.
- Generate versioned, minimal-knob vanilla `sing-box` JSON profiles: mobile-only (`Android SFA` + `iOS SFI`) Media-Selective for regular users, and full 5-OS suite (`Android`, `iOS`, `Windows 11`, `Linux`, `OpenWrt`) for the admin.
- Migrate existing v1 `state.json` to v2 seamlessly without breaking active family devices.

**Non-Goals:**
- Automatic cross-exit load balancing, round-robin, or client-side `urltest` failover (explicitly forbidden due to IP flapping and DPI probing).
- Web dashboard, Telegram bot, or HTTP subscription URLs.
- Opening or relaxing `UDP 3478` or any other blocked port/protocol for WhatsApp/Telegram voice calls.
- Modifying any live server configuration or code during this specification phase.

## Decisions

### 1. Bridge State Schema v2 (`state.json`) with Automatic v1 Migration
- **Decision:** Introduce `"schema_version": 2` in bridge `state.json` with two maps: `upstreams` (keyed by logical slug, e.g. `exit-ai`, `exit-media-1`) and `users` (keyed by logical slug, e.g. `owner`, `alice-phone`).
- **Structure (conceptual):**
  ```text
  upstreams[<name>]: {
    role: "ai-isolated" | "media",
    ip: "<ipv4>",
    domain: "<fqdn>",
    uuid: "<exit-uuid>",
    public_key: "<exit-pbk>",
    short_id: "<exit-sid>",
    transport: "xhttp",
    xhttp_path: "<64-hex>",
    xhttp_mode: "stream-up"
  }
  users[<name>]: {
    uuid: "<client-uuid>",
    upstream: "<upstream-name>",
    profile: "ai-owner" | "media-selective",
    platforms: ["android", "ios"] | ["android", "ios", "windows", "linux", "openwrt"],
    note: "<optional label>",
    profile_version: "v1",
    profile_sha256: "<hex>"
  }
  ```
- **Migration:** When v2 code loads a v1 bridge `state.json` (no `schema_version`), it converts the existing `upstream_*` into `upstreams["default"]` (`role: "media"` or explicitly tagged on migration) and `user_uuid` into `users["owner"]`, preserving exact UUIDs and Reality keys.
- **Alternative considered:** SQLite database. Rejected to preserve single-file atomic JSON writes, zero extra dependencies, and trivial backup/inspection over SSH.

### 2. Static Xray `routing.rules` by Client Identity (`user` email)
- **Decision:** Keep the single `:443` `vless-reality-vision` inbound on `mos`. Populate `settings.clients` with one entry per user (`{"id": uuid, "flow": "xtls-rprx-vision", "email": name}`). Render one `vless` outbound per upstream (`tag: "proxy-<upstream_name>"`) with `XHTTP + Reality + xmux` (`fp=firefox`, `mux.enabled: false`, `tcpMptcp: false`). Route strictly via:
  ```text
  1. inboundTag: ["api"] -> "api"
  2. Global blackhole rules (telemetry, UDP 443/3478/19302, quic/bittorrent, private CIDRs, ::/0) -> "block"
  3. Per-upstream user rules: user: [<users bound to upstream>] -> "proxy-<upstream_name>"
  4. Default catch-all: inboundTag: ["vless-reality-vision"] -> "block" (fail-closed)
  ```
- **Why:** Deterministic 1-to-1 IP pinning, zero DNS lookups on `mos` (`domainStrategy: "AsIs"`), zero `freedom` outbound, and instant `upstream migrate <from> <to>` without touching client devices.
- **Alternative considered:** Separate listening ports per exit (`:443`, `:8443`, `:2053`). Rejected because multi-port exposure was a documented TSPU fingerprint in `RCA_SERVER_FAM_2026-11-15.md`.

### 3. Hard `ai-isolated` Guard, Root-Domain & `/24` Subnet Separation
- **Decision:** Enforce in both CLI mutations and `LocalXrayConfigBuilder` / `self_test`:
  - `role == "ai-isolated"` allows at most `1` bound user, and that user MUST have `profile == "ai-owner"`.
  - Extract registrable root domain (eTLD+1) of every upstream and reject any registration where an `ai-isolated` upstream shares a root domain with a `media` upstream.
  - Check `/24` IPv4 subnet overlap between `ai-isolated` and `media` upstreams in `upstream add` (rejecting same-`/24` unless explicitly overridden, and recommending distinct ASNs/hosters operationally to mitigate ~80% subnet-wide TSPU contagion from VPS neighbors).
- **Why:** Prevents accidental operator error from routing family/media traffic through the clean AI exit, linking exits via shared parent domain, or losing `exit-ai` alongside `exit-media-*` in a `/24` subnet quarantine.

### 4. Role-Specific Vanilla `sing-box` Profile Generation (`media-consumer` vs `ai-owner`)
- **Decision:** Split profile generation cleanly by role and platform:
  - **`media-consumer` (Android SFA `1.14+` & iOS SFI `1.14+` only):**
    - Proxy ONLY: YouTube (`youtube.com`, `youtu.be`, `googlevideo.com`, `ytimg.com`, `ggpht.com`), Instagram/Meta (`instagram.com`, `cdninstagram.com`, `fbcdn.net`, `facebook.com`), Telegram (domains + official `TELEGRAM_DC_CIDRS`), TikTok (`tiktok.com`, `tiktokv.com`, `tiktokcdn.com`, `tiktokcdn-eu.com`, `byteoversea.com`, `ibytedtos.com`, `muscdn.com`, `musical.ly`), WhatsApp (`whatsapp.com`, `whatsapp.net`, `wa.me`).
    - Android adds `package_name` rules (`com.google.android.youtube`, `com.instagram.android`, `org.telegram.messenger`, `org.telegram.messenger.web`, `org.thunderdog.challegram`, `com.zhiliaoapp.musically`, `com.ss.android.ugc.trill`, `com.whatsapp`, `com.whatsapp.w4b`) and `override_android_vpn: true`.
    - **iOS (`sing-box MT` / SFI `>= 1.14`) NetworkExtension safety:** Omit `package_name`, `process_name`, `override_android_vpn`, and `interface_name`. Keep remote `.srs` rule-sets minimal (avoid loading giant multi-megabyte domestic lists like `russia_inside`) so NetworkExtension stays well below Apple's ~50 MB RAM ceiling. Import profiles manually as **Local** JSON files (no Remote `/sub/` URLs; instruct users to use official `sing-box MT` from App Store and disable iCloud Private Relay).
    - Omit raw `vless://` URIs / `links.txt` / terminal QR export for `media-consumer` users so devices cannot connect via unrouted `v2rayNG` links that leak domestic traffic.
    - All profiles (including `Full Tunnel`) enforce `UDP 443/3478/19302` reject, `query_type: "HTTPS"` reject in `dns.rules`, `BitTorrent` reject, `::/0` reject, telemetry reject, `fp=firefox`, manual `selector` only (no `urltest`).
  - **`ai-owner` (5 platforms: Android, iOS, Windows 11 Throne, Linux, OpenWrt):**
    - Keeps existing Full and AI-Selective logic for Android and Windows 11 (fixing `Full Tunnel` to also emit `dns.rules` `query_type: "HTTPS"` reject), adds iOS Full/AI-Selective (for `sing-box MT` Local import, without Android-only fields or heavy `.srs`), Linux `sing-box` (`tun` + `mixed 127.0.0.1:2080`) + `xray-client.json`, OpenWrt (`openwrt-outbound.json` for `podkop` native `fw4`/`dnsmasq` integration + router-safe `openwrt-singbox.json` using `tproxy` inbound instead of desktop `auto_route` to avoid `fw4`/`dnsmasq` conflicts and restrict LAN traffic via Selective/VLAN rather than LAN-wide Full Tunnel onto `exit-ai`), and admin-only `links.txt` with a warning not to share raw URIs.

### 5. Bridge Host Capacity Baseline
- **Decision:** Require `2 GB RAM + 1 GB swap` (and recommend `2 vCPU`) on `mos` before scaling past 2–3 users to ~20 devices across 3+ exits. `self-test` passively checks `/proc/meminfo` and warns if a multi-user bridge has `< 1800 MB` RAM or `0` swap.

### 6. Server-Side Exit RU Blackhole & `xmux` Session Rotation Hardening (Habr #1109052 Audit)
- **Decision:**
  - Add a mandatory `block` routing rule on foreign Exit nodes (`LocalXrayConfigBuilder.build`) for `"domain:ru"`, `"domain:su"`, `"domain:xn--p1ai"`, and `"geoip:ru"` (positioned before the final `direct` rule) and enforce it in `validate_xray_config` + `self_test.py`. Meanwhile, `mos` keeps `domainStrategy: "AsIs"` and zero `freedom` outbounds.
  - Tighten `xmux.hMaxReusableSecs` in `LocalXrayConfigBuilder.build_bridge` from `"1800-3000"` (30–50 min) down to `"180-300"` (3–5 min) so cross-border HTTP/2 Reality sessions rotate frequently instead of forming monolithic multi-hour asymmetric streams under multi-user media load (verified via `tests/test_cascade_e2e.py`).
  - Document quarantine discipline operationally: if `cluster_watch.py` flags a handshake/retransmission storm, halt traffic immediately instead of retrying through a 3–7 day quarantine.
- **Why:** Practitioner reports in `DPI_RESEARCH_HABR_1109052_2026-11-21.md` identify domestic "snitch apps" hitting RU endpoints / `ipify` from VPN exits as the #1 trigger of rapid 1–7 day IP bans. Blocking RU destinations at the foreign Exit prevents egress exposure even if a `Full Tunnel` client accidentally accesses a domestic app or tracker — without introducing forbidden WARP chains.

## Risks / Trade-offs

- **[Single Point of Failure on `mos`] -> Mitigation:** All 3+ exits sit behind 1 Moscow IP, so `mos` maintenance briefly interrupts all users (~2s Xray reload). Keep atomic config validation (`xray -test`) before reload and document an optional future split (dedicated small bridge for `exit-ai` if traffic grows).
- **[iOS NetworkExtension 50 MB RAM OOM] -> Mitigation:** Keep `ios-media-selective.json` free of oversized `.srs` lists, relying on compact inline domain/CIDR lists and only small targeted `.srs` sets; validate rule-set footprint in tests.
- **[WhatsApp/Telegram voice call degradation due to strict `UDP 3478` block] -> Mitigation:** Accepted trade-off by explicit security policy (TSPU stealth strictly prioritized over call quality; text, media, and TCP-fallback signaling remain unaffected).
- **[TikTok SIM/region lock on mobile devices] -> Mitigation:** Out of VPN scope; routing ensures TikTok network traffic exits cleanly via Germany, while app-level SIM checks are a client OS concern.

## Migration Plan

*(Executed only after future implementation via `/opsx-apply`; zero live actions during planning.)*
1. Upgrade Moscow bridge (`mos`) VPS to `2 GB RAM` and configure `1 GB` swapfile.
2. Provision new German exit VPS(es) with fresh clean IPv4 in distinct `/24` subnets (ideally separate ASNs/hosters from `exit-ai`) and independent root domains using existing `sudo ./script.sh --domain <new-domain>` (exit deployment automatically inherits the new server-side RU egress blackhole).
3. Verify new `exit-ai` IP anonymously on the exit node itself (`INNERTUBE_CONTEXT_GL == DE`, `chatgpt.com/cdn-cgi/trace` `loc != RU` & `warp=off`, `api.anthropic.com` TLS 1.3).
4. Deploy updated codebase to `mos`, auto-migrate v1 `state.json` -> v2 (preserving existing family UUID on current `server-de`), register `exit-ai` (`role: ai-isolated`) and `exit-media-*` (`role: media`).
5. Create `ai-owner` user bound to `exit-ai` and per-device/per-person `media-consumer` users bound evenly across `exit-media-1` / `exit-media-2` (~8–10 devices per exit).
6. Run passive `./script.sh self-test` on `mos` and all exits; distribute versioned `sing-box` JSON profiles to users.
7. **Rollback:** Restore pre-migration backup of `/var/lib/marzneshin/state.json` and `/var/lib/marzneshin/xray/config.json` on `mos` and restart `marzneshin-xray`.
