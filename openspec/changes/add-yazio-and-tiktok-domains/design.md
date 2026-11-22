# Design: Media-Selective Domain & Package Expansion

## Context
`app/client/profile_generator.py` defines `MEDIA_SELECTIVE_DOMAINS` and `MEDIA_SELECTIVE_ANDROID_PACKAGES`. On iOS (`ios-media-selective.json`), `package_name` is omitted to comply with Apple NetworkExtension / `sing-box MT` constraints, so all routing relies on `domain_suffix` matching.

## Decisions
1. **Domain-suffix list expansion (`MEDIA_SELECTIVE_DOMAINS`)**:
   - Add `yazio.com` under a `# Yazio` section.
   - Add `tiktokv.eu`, `tiktokv.us`, `bytegecko.com`, `bytedance.com`, `byteimg.com`, `snssdk.com`, `isnssdk.com`, `sgsnssdk.com`, `amemv.com`, `pstatp.com` under `# TikTok`.
2. **Android package parity (`MEDIA_SELECTIVE_ANDROID_PACKAGES`)**:
   - Add `com.yazio.android`.
3. **No `.srs` rule-sets**:
   - Keep inline `domain_suffix` entries to stay well below Apple's 50 MB NetworkExtension RAM ceiling.

## Caveats
- Official iOS TikTok app may still enforce RU-mode if a Russian SIM (MCC 250) is active in the device; Safari (`tiktok.com`) or disabling the RU SIM bypasses SIM-based checks.
