# Proposal: Add Yazio and Missing TikTok/ByteDance Domains to Media-Selective Profiles

## Why
Users on the `media-consumer` iOS profile (`ios-media-selective.json`) cannot use Yazio (recently blocked/degraded in direct access) and still hit Russian regional restrictions on TikTok because iOS relies exclusively on `domain_suffix` routing (`package_name` is unsupported/omitted on iOS) and several ByteDance/TikTok regional domains leak to `direct`.

## What Changes
- Add `yazio.com` to `MEDIA_SELECTIVE_DOMAINS` in `app/client/profile_generator.py` so all Yazio API/auth/CDN traffic routes via `proxy` and `dns-remote`.
- Add missing TikTok/ByteDance domains (`tiktokv.eu`, `tiktokv.us`, `bytegecko.com`, `bytedance.com`, `byteimg.com`, `snssdk.com`, `isnssdk.com`, `sgsnssdk.com`, `amemv.com`, `pstatp.com`) to `MEDIA_SELECTIVE_DOMAINS`.
- Add `com.yazio.android` to `MEDIA_SELECTIVE_ANDROID_PACKAGES` for Android `media-selective` parity.
- Update unit tests in `tests/` to verify the new domains and package are present in generated `ios-media-selective.json` and `android-media-selective.json`.

## Impact
- Affected code: `app/client/profile_generator.py`, `tests/`
- Affected profiles: `ios-media-selective.json`, `android-media-selective.json`
- No server-side Xray/Nginx or `ai-owner` profile changes required.
