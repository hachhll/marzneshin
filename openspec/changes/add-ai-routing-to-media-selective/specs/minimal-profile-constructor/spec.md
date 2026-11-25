# Spec Delta

## MODIFIED Requirements

### Requirement: Strict mobile-only vanilla `sing-box` profiles for `media-consumer` users
For `media-consumer` users (up to ~20 devices), the system SHALL generate strictly mobile-only vanilla `sing-box` (`>= 1.14`) Media-Selective JSON profiles for Android (SFA) and iOS (SFI), proxying target media services and blocked AI services (`route.final: "direct"`, `dns.final: "dns-local"`), omitting desktop/router profiles and `links.txt`, keeping non-AI Google services direct, and using modern `http_clients` without deprecated fields.

#### Scenario: Android `media-consumer` profile matches target apps and domains cleanly
- **WHEN** `android-media-selective.json` is generated for a `media-consumer` user
- **THEN** it includes `override_android_vpn: true`, `package_name` rules for target media apps and mobile AI apps (ChatGPT, Claude, Gemini), domain suffixes and `dns-remote` rules for media plus AI services (Antigravity/Google AI, OpenAI/Codex, Anthropic/Claude Code, Groq, Grok/xAI, OpenRouter, Perplexity, Mistral, HuggingFace, AI IDE web domains, and Auth0/reCAPTCHA), attaches only the lightweight domain-only `podkop-google_ai` rule-set (never `russia_inside.srs`), blocks `UDP 443/3478/19302`, `BitTorrent`, `::/0`, `query_type: "HTTPS"`, and telemetry, and routes all other apps and domestic traffic to `direct`

#### Scenario: iOS `media-consumer` profile respects Apple NetworkExtension constraints
- **WHEN** `ios-media-selective.json` is generated for a `media-consumer` user
- **THEN** it omits `package_name`, `process_name`, `override_android_vpn`, `interface_name`, and remote `rule_set` entries (including `russia_inside.srs`), routes target media and AI services (including Antigravity/Google AI, OpenAI/Codex, Anthropic/Claude Code, Groq, Grok/xAI, OpenRouter, Perplexity, Mistral, HuggingFace, and Auth0/reCAPTCHA) strictly via `domain_suffix` and compact Telegram DC CIDRs while keeping non-AI Google services direct, and enforces the same unconditional UDP/QUIC/STUN/IPv6/HTTPS-DNS/telemetry blocks

## ADDED Requirements

### Requirement: Shared blocked AI provider parity in `ai-owner` Selective profiles
`ai-owner` Selective profiles (`throne-windows11-selective.json`, `android-singbox-selective.json`, `ios-singbox-selective.json`, `linux-singbox-selective.json`, `openwrt-singbox.json`) SHALL include the same blocked AI provider suffixes (`groq.com`, `grok.com`, `x.ai`, `openrouter.ai`, `hf.co`, `mistral.ai`, `together.ai`, `fireworks.ai`, `replicate.com`, `cohere.com`, `zed.dev`, `githubcopilot.com`) alongside existing Antigravity, OpenAI, and Anthropic rules.

#### Scenario: `ai-owner` Selective profiles route Groq and Grok via `proxy`
- **WHEN** `ai-owner` Selective profiles are generated
- **THEN** `groq.com`, `grok.com`, `x.ai`, and `openrouter.ai` appear in the `proxy` `domain_suffix` and `dns-remote` rules
