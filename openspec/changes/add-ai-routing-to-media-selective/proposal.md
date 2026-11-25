# Proposal

## Why

Mobile `media-consumer` users (`media-selective` profile on Android and iOS) report that all AI services — including Antigravity, OpenAI/Codex, Anthropic/Claude Code, Groq, and related platforms blocked in Russia — route `direct` instead of going through their assigned VPN exit. Currently, `MEDIA_SELECTIVE_DOMAIN_SUFFIXES` only proxies six media/lifestyle services (YouTube, Instagram, Telegram, TikTok, WhatsApp, Yazio) and falls back to `route.final: "direct"`, while `podkop` community rule-sets are only enabled all-or-nothing (`russia_inside.srs` is too heavy for the iOS 50 MB NetworkExtension RAM ceiling and pulls unrelated non-media/non-AI sites onto `media` exits).

## What Changes

- **Route AI services through `proxy` + `dns-remote` in mobile `media-selective` profiles:**
  - Unify core AI domain suffixes in `app/client/profile_generator.py` and include Antigravity/Google AI (`antigravity.google`, `antigravityide.net`, `gemini.google`, `aistudio.google.com`, `makersuite.google.com`, `deepmind.google`, `labs.google`, `notebooklm.google`, `notebooklm-enterprise.google`, `withgoogle.com`, `google.dev`, `google.ai`, `ai.google`, `ai.dev`, `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.sandbox.googleapis.com`, `alkalimakersuite-pa.clients6.google.com`, `proactivebackend-pa.googleapis.com`, `accounts.google.com`, `oauth2.googleapis.com`, `gvt1.com`, `gvt2.com`, `recaptcha.net`), OpenAI/Codex (`openai.com`, `chatgpt.com`, `oaistatic.com`, `oaiusercontent.com`, `sora.com`), Anthropic/Claude Code (`anthropic.com`, `claude.ai`, `claude.com`, `claude.usercontent.com`, `claudeusercontent.com`, `claudemcpclient.com`), Groq/Grok/OpenRouter/AI providers (`groq.com`, `grok.com`, `x.ai`, `openrouter.ai`, `perplexity.ai`, `mistral.ai`, `huggingface.co`, `hf.co`, `together.ai`, `fireworks.ai`, `replicate.com`, `cohere.com`), AI IDE web/auth domains (`cursor.com`, `cursor.sh`, `cursor-cdn.com`, `windsurf.com`, `codeium.com`, `zed.dev`, `githubcopilot.com`), and auth providers (`auth0.com`, `auth0.net`) in `MEDIA_SELECTIVE_DOMAIN_SUFFIXES` (and ensure `ai-owner` `SELECTIVE_VPN_DOMAIN_SUFFIXES` also includes `groq.com`, `grok.com`, `x.ai`, `openrouter.ai`, etc.).
  - Add mobile AI Android packages (`com.openai.chatgpt`, `com.anthropic.claude`, `com.google.android.apps.bard`) to `MEDIA_SELECTIVE_ANDROID_PACKAGES`.
  - Allow selective attachment of individual `podkop` rule-sets so `android-media-selective.json` attaches **only** the lightweight domain-only `podkop-google_ai` rule-set (without `russia_inside.srs`), while `ios-media-selective.json` remains `.srs`-free for iOS 50 MB RAM compliance.
  - Keep non-AI Google services (Search, Maps, Drive, Photos) `direct`, preserve `media-selective` as strictly mobile-only (no `links.txt`, no desktop/router bundles), preserve all unconditional QUIC/STUN/BitTorrent/IPv6/HTTPS-DNS/telemetry blocks, and keep `exit-ai` (`ai-owner`/`ai-user`) 100% isolated from `media` exits.
- **Add zero-downtime `user refresh` CLI command on the Cascade Bridge:**
  - Add `script.sh user refresh [<name> | --all]` (`app/cli.py` / `script.sh`) to re-render per-user client JSON bundles, `bundle-manifest.json`, and `profile_sha256` in `state.json` without rotating UUIDs or restarting `xray`/`nginx`.
- **Update unit tests and client documentation:**
  - Update `tests/test_client_profiles.py` and `tests/test_cli_cluster.py`, plus `SINGBOX_CLIENT_REQUIREMENTS.md` (including guidance to keep Android SFA `Profile Override -> Per-App Proxy` disabled so JSON `package_name` + `domain_suffix` rules apply consistently).

## Capabilities

### New Capabilities
- *(none)*

### Modified Capabilities
- `minimal-profile-constructor`: Expand mobile-only `media-consumer` (`media-selective`) profiles to route AI services (Antigravity/Google AI, OpenAI/Codex, Anthropic/Claude Code, Groq, and related AI/auth domains plus Android AI packages and Android-only `podkop-google_ai`) through `proxy` + `dns-remote`, while keeping iOS `.srs`-free, desktop/router files omitted, and `exit-ai` isolation/safety invariants intact.
- `multi-exit-cluster-routing`: Add `user refresh [<name> | --all]` SSH CLI operation to regenerate existing users' client profile bundles and `profile_sha256` metadata atomically without modifying UUIDs, upstream bindings, or running Xray/Nginx configs.

## Impact

- **Repository code & tests:** `app/client/profile_generator.py`, `app/cli.py`, `script.sh`, `tests/test_client_profiles.py`, `tests/test_cli_cluster.py`, `SINGBOX_CLIENT_REQUIREMENTS.md`.
- **Live infrastructure (post-apply):** `mos` bridge (`/opt/marzneshin` sync + `user refresh --all`); zero `xray`/`nginx` restarts, zero changes to `exit-ai` or `exit-media-*`, and existing `media-consumer` users re-import updated `android-media-selective.json` / `ios-media-selective.json` locally.
