# Tasks

## 1. AI Routing in `media-selective` and `ai-owner` Selective Profiles

- [x] 1.1 Refactor shared blocked AI provider domain constants in `app/client/profile_generator.py` (`AI_PROVIDER_DOMAIN_SUFFIXES` + targeted Google AI/Antigravity/OAuth suffixes) and extend `MEDIA_SELECTIVE_DOMAIN_SUFFIXES`, `MEDIA_SELECTIVE_ANDROID_PACKAGES` (`com.openai.chatgpt`, `com.anthropic.claude`, `com.google.android.apps.bard`), and `SELECTIVE_VPN_DOMAIN_SUFFIXES` (`groq.com`, `grok.com`, `x.ai`, `openrouter.ai`, etc.) without adding wildcard `google.com`/`googleapis.com` to `media-selective`; verify generated JSONs route Antigravity, OpenAI/Codex, Anthropic/Claude Code, and Groq via `proxy` + `dns-remote`.
- [x] 1.2 Extend `_build_singbox_dns_and_route` in `app/client/profile_generator.py` with `podkop_ruleset_names` so `build_media_selective_profile` attaches only `["google_ai"]` (`podkop-google_ai`) on `android` while omitting all `rule_set` entries (`[]`, no `russia_inside.srs`) on `ios`; verify `ios-media-selective.json` stays `.srs`-free and `android-media-selective.json` includes only `podkop-google_ai`.
- [x] 1.3 Update unit tests in `tests/test_client_profiles.py` to assert AI domains/packages and `podkop-google_ai` on Android `media-selective`, `.srs`-free AI domain routing on iOS `media-selective`, non-AI Google exclusion (`google.com`/`googleapis.com` absent from `media-selective` suffixes), `groq.com`/`grok.com`/`openrouter.ai` parity in `ai-owner` Selective, and all unconditional safety invariants (`::/0`, `UDP 443/3478/19302`, `query_type: "HTTPS"`, telemetry `reject`), then verify `.venv/bin/python -m pytest tests/test_client_profiles.py -v` passes.
- [x] 1.4 Update `SINGBOX_CLIENT_REQUIREMENTS.md` to document AI service routing in `media-selective` (Android `podkop-google_ai` + AI packages, iOS `.srs`-free `50 MB RAM` compliance, and keeping Android SFA `Profile Override -> Per-App Proxy` disabled); verify documented rules match `app/client/profile_generator.py`.

## 2. Zero-Downtime `user refresh` CLI Command

- [x] 2.1 Implement `user refresh` (`<name>` or `--all`) in `app/cli.py` and `script.sh` to re-render existing users' client bundles via `_render_user_bundle_for_state` and update `profile_version`/`singbox_min_version`/`profile_sha256` in `state.json` without modifying UUIDs, upstream bindings, or running Xray/Nginx configs; verify CLI parser and error handling on unknown users.
- [x] 2.2 Add unit tests in `tests/test_cli_cluster.py` covering `user refresh --all`, `user refresh <name>`, preserved UUIDs/bindings, updated `profile_sha256`, and non-zero exit for missing users; verify `.venv/bin/python -m pytest tests/test_cli_cluster.py -v` passes.

## 3. Verification & Live Rollout on `mos`

- [x] 3.1 Run the full local test suite (`.venv/bin/python -m pytest tests/ -v`) and `openspec validate add-ai-routing-to-media-selective --strict` and verify both pass with zero failures or warnings.
- [x] 3.2 Sync repository updates to `mos` (Zero-Emission, no outbound registry/internet requests from `mos`), run `sudo /opt/marzneshin/script.sh user refresh --all`, verify passive `sudo /opt/marzneshin/script.sh self-test` passes, and collect updated `android-media-selective.json` / `ios-media-selective.json` bundles for affected `media` users.
