# Design

## Context

See [proposal.md](./proposal.md) for motivation. Currently in `app/client/profile_generator.py`:
- `MEDIA_SELECTIVE_DOMAIN_SUFFIXES` and `MEDIA_SELECTIVE_ANDROID_PACKAGES` cover only YouTube, Instagram, Telegram, TikTok, WhatsApp, and Yazio, with `include_podkop_rulesets=False`.
- `_build_singbox_dns_and_route` treats `podkop` community rule-sets (`PODKOP_COMMUNITY_RULESET_NAMES`) as an all-or-nothing boolean flag (`use_podkop`), where `russia_inside.srs` is incompatible with the iOS 50 MB `NetworkExtension` RAM limit and would pull thousands of non-media/non-AI sites onto `media` exits.
- `SELECTIVE_VPN_DOMAIN_SUFFIXES` (used by `ai-owner` Selective) lacks `groq.com`, `grok.com`, `x.ai`, `openrouter.ai`, and several AI providers already listed in `AI_USER_DOMAIN_SUFFIXES`.
- On the Moscow Cascade Bridge (`mos`), `app/cli.py` and `script.sh` have `_render_user_bundle_for_state` internally (invoked on `user add` and `apply_state`), but expose no standalone `user refresh` command to re-render existing user JSON bundles without re-applying Xray/Nginx.

## Goals / Non-Goals

**Goals:**
- Route blocked AI services (Antigravity/Google AI, OpenAI/Codex, Anthropic/Claude Code, Groq, Grok/xAI, OpenRouter, Perplexity, Mistral, HuggingFace, AI IDE web/auth domains, Auth0/reCAPTCHA) via `proxy` + `dns-remote` in `android-media-selective.json` and `ios-media-selective.json`.
- Keep `ai-owner` and `ai-user` traffic on `exit-ai` completely unaffected and isolated (`media-selective` users stay statically pinned to `exit-media-*` on `mos`).
- Keep `ios-media-selective.json` `.srs`-free (`50 MB RAM` safe) and avoid pulling `russia_inside.srs` or non-AI Google traffic (Search, Maps, Drive, Photos) onto `media` exits.
- Provide `script.sh user refresh [<name> | --all]` for safe, zero-downtime JSON re-generation on `mos`.

**Non-Goals:**
- Adding desktop/router profiles (`Windows`, `Linux`, `macOS`, `OpenWrt`) or raw `vless://` `links.txt` for `media-consumer` users (remains strictly mobile-only).
- Attaching `russia_inside.srs` or routing generic `google.com`/`googleapis.com` wildcard traffic in `media-selective`.
- Modifying server-side Xray (`mos`, `exit-ai`, `exit-media-*`) or Nginx configurations.

## Decisions

### 1. Shared AI domain constants + targeted Google AI/Antigravity suffixes (no global `google.com`/`googleapis.com` in `media-selective`)
- **Decision:** Define a shared constant for core blocked AI provider suffixes (`AI_PROVIDER_DOMAIN_SUFFIXES`: OpenAI/Codex, Anthropic/Claude Code, Groq, Grok/xAI, OpenRouter, Perplexity, Mistral, HuggingFace, Together, Fireworks, Replicate, Cohere, AI IDE web domains, Auth0/reCAPTCHA) plus targeted Google AI/Antigravity/OAuth suffixes (`antigravity.google`, `antigravityide.net`, `gemini.google`, `aistudio.google.com`, `makersuite.google.com`, `deepmind.google`, `labs.google`, `notebooklm.google`, `notebooklm-enterprise.google`, `withgoogle.com`, `google.dev`, `google.ai`, `ai.google`, `ai.dev`, `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.sandbox.googleapis.com`, `alkalimakersuite-pa.clients6.google.com`, `proactivebackend-pa.googleapis.com`, `accounts.google.com`, `oauth2.googleapis.com`, `gvt1.com`, `gvt2.com`). Reuse `AI_PROVIDER_DOMAIN_SUFFIXES` across `MEDIA_SELECTIVE_DOMAIN_SUFFIXES`, `SELECTIVE_VPN_DOMAIN_SUFFIXES`, and `AI_USER_DOMAIN_SUFFIXES`.
- **Rationale:** Covers Antigravity, Codex, Claude Code, and Groq end-to-end on mobile apps and browsers while keeping Google Search, Maps, Gmail, Drive, and Photos `direct`, preventing ~20 mobile devices from flooding `media` exits with everyday Google traffic, and keeping `ai-owner` Selective in sync for `groq.com`/`grok.com`/`openrouter.ai`.
- **Alternative:** Adding `google.com` and `googleapis.com` wholesale to `MEDIA_SELECTIVE_DOMAIN_SUFFIXES`. Rejected to avoid proxying all consumer Google services on family phones; easy to extend later if a specific new Google AI endpoint appears.

### 2. Android-only `podkop-google_ai` vs `.srs`-free iOS
- **Decision:** Generalize `_build_singbox_dns_and_route` with `podkop_ruleset_names: list[str] | None = None` so `build_media_selective_profile` attaches `["google_ai"]` on `android` (`android-media-selective.json`) and `[]` on `ios` (`ios-media-selective.json`). Add `com.openai.chatgpt`, `com.anthropic.claude`, and `com.google.android.apps.bard` to `MEDIA_SELECTIVE_ANDROID_PACKAGES`.
- **Rationale:** `google_ai.srs` is domain-only (works in both `dns.rules` and `route.rules`, updated daily via `proxy-http`) and automatically catches dynamic Google AI / Antigravity subdomains on Android without importing the heavy `russia_inside.srs`. Leaving iOS `.srs`-free preserves Apple `50 MB RAM` `NetworkExtension` headroom and avoids startup GitHub dependencies on iOS while keeping identical explicit AI `domain_suffix` coverage.
- **Alternative:** Attaching all 7 `podkop` rule-sets on Android or attaching `google_ai.srs` on iOS as well. Rejected because `russia_inside.srs` would route thousands of unrelated sites onto `media` exits and cause Android/iOS behavioral divergence, while keeping iOS `.srs`-free preserves existing iOS memory guarantees.

### 3. In-JSON selective routing instead of Android SFA `Profile Override -> Per-App Proxy`
- **Decision:** Document in `SINGBOX_CLIENT_REQUIREMENTS.md` that Android `sing-box` (SFA) users MUST keep `Profile Override -> Per-App Proxy` disabled.
- **Rationale:** SFA's GUI `Per-App Proxy` applies `VpnService` `include_package` filters before packets enter `sing-box`, which bypasses `domain_suffix` rules for browsers or any app omitted in GUI and is not exported into JSON profiles. Relying on in-JSON `package_name` + `domain_suffix` works identically across both GitHub and Google Play SFA builds and matches iOS `sing-box MT`.

### 4. Zero-downtime `user refresh [<name> | --all]` CLI command
- **Decision:** Add `user refresh` (`<name>` or `--all`) to `app/cli.py` and `script.sh` using existing `_render_user_bundle_for_state` and `save_state`, updating `bundle-manifest.json`, `profile_version`, `singbox_min_version`, and `profile_sha256` without calling `XrayManager` or `NginxManager`.
- **Rationale:** Provides a clean, atomic, Zero-Emission CLI path on `mos` to regenerate existing `media-selective` user bundles after rule updates without restarting `xray`/`nginx` or rotating UUIDs.
- **Alternative:** Re-running `bridge-transport` or an ad-hoc Python one-liner on `mos`. Rejected as error-prone and unnecessarily touching Xray/Nginx reload paths.

## Risks / Trade-offs

- **[Risk] Shared `exit-media-*` IP rate-limits or CAPTCHAs when multiple `media` users query OpenAI/Anthropic/Google/Groq concurrently** -> **Mitigation:** `exit-ai` remains completely isolated on a distinct VPS, `/24` subnet, and ASN; only `media` exits carry `media-selective` AI traffic, and users can be distributed or migrated across `oblako-fam1`, `eternity-fam2`, `server-de-fam1`, and `server-de-fam2` without client reconfiguration.
- **[Risk] A newly introduced Google AI/Antigravity `*.googleapis.com` endpoint leaks `direct` on iOS** -> **Mitigation:** Android is covered by `podkop-google_ai` auto-updates, and explicit iOS suffixes already include known Cloud Code / Gemini / Antigravity / OAuth endpoints; any new endpoint can be added to the explicit list and pushed via `user refresh`.
- **[Risk] Existing `media-consumer` devices still run cached old JSON until manually re-imported (no `/sub/` URLs)** -> **Mitigation:** Zero-Surface policy intentionally forbids `/sub/`; `user refresh --all` updates SHA-256 manifests on `mos`, and admins distribute the refreshed `.json` files for one-time local import.
- **[Risk] Android users with `Profile Override -> Per-App Proxy` previously enabled in SFA GUI still bypass browser AI rules** -> **Mitigation:** Explicitly instruct affected users to disable `Profile Override` when importing the updated `android-media-selective.json`.

## Migration Plan

1. Implement code, CLI `user refresh`, tests, and docs updates; verify locally with `.venv/bin/python -m pytest tests/ -v`.
2. Sync updated repository to `mos` without triggering outbound registry/internet requests from `mos` (and if container image updates are ever required, build on `server-de` and stream via `docker save | gzip | ssh mos`).
3. Run `sudo /opt/marzneshin/script.sh user refresh --all` and passive `sudo /opt/marzneshin/script.sh self-test` on `mos`.
4. Distribute refreshed `android-media-selective.json` / `ios-media-selective.json` bundles from `/root/vpn-credentials/users/<user>/` to `media` users for local re-import (with `Profile Override` disabled on Android SFA).
