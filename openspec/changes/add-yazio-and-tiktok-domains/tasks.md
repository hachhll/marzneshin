# Tasks: Add Yazio and Missing TikTok/ByteDance Domains

- [x] 1.1 Add `yazio.com` and missing TikTok/ByteDance domains (`tiktokv.eu`, `tiktokv.us`, `bytegecko.com`, `bytedance.com`, `byteimg.com`, `snssdk.com`, `isnssdk.com`, `sgsnssdk.com`, `amemv.com`, `pstatp.com`) to `MEDIA_SELECTIVE_DOMAINS` in `app/client/profile_generator.py`.
- [x] 1.2 Add `com.yazio.android` to `MEDIA_SELECTIVE_ANDROID_PACKAGES` in `app/client/profile_generator.py`.
- [x] 1.3 Add unit test assertions in `tests/` verifying `yazio.com` and the extended TikTok/ByteDance domains in `ios-media-selective.json` and `com.yazio.android` in `android-media-selective.json`.
- [x] 1.4 Run `.venv/bin/python -m pytest tests/ -v` to confirm all tests pass.
