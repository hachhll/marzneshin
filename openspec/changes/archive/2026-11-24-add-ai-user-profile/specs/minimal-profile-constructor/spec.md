## ADDED Requirements

### Requirement: Hardened Linux `sing-box` Selective + `mixed-in` profile for `ai-user`
For users with profile `ai-user`, the system SHALL generate a Linux-only `sing-box` (`>= 1.14`) profile (`linux-ai-user.json`, omitting `links.txt`) using hybrid `Selective TUN` (excluding RFC1918 LAN and Docker private subnets) and local `mixed-in` (`127.0.0.1:2080`), `fp=firefox`, manual `selector` (zero `urltest`), unconditional `::/0`/QUIC/STUN/BitTorrent/HTTPS-DNS/telemetry blocks, all 7 `podkop` rule-sets, AI/Dev domain suffixes, and `tmpfs` `cache.db` (`/run/sing-box/cache.db`) with `warn` logging.

#### Scenario: `ai-user` credential bundle generates `linux-ai-user.json` with AI/Dev, `podkop`, and SD-card protections
- **WHEN** `user add <user> --upstream <exit-ai> --profile ai-user` completes
- **THEN** `/root/vpn-credentials/users/<user>/` contains `linux-ai-user.json` and `bundle-manifest.json` (and omits `links.txt`), `linux-ai-user.json` includes `tun` with `route_exclude_address` for `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`, `mixed-in` on `127.0.0.1:2080` routed to `proxy`, all 7 `podkop` rule-sets (`google_ai`, `google_play`, `russia_inside`, `telegram`, `discord`, `twitter`, `meta` via `proxy-http`, with `google_ai`/`google_play`/`russia_inside` in `dns.rules`), `TELEGRAM_DC_CIDRS`, AI/Dev suffixes (OpenAI/ChatGPT, Anthropic/Claude Code, Gemini, OpenRouter, Grok/x.ai, HuggingFace, GitHub, Databricks/Okta/Auth0, Microsoft/Azure/Copilot, PyPI/npm/Docker/crates/Go, AI IDEs; `gvt1.com`/`gvt2.com` allowed), `experimental.cache_file.path: "/run/sing-box/cache.db"`, and `log.level: "warn"`

#### Scenario: Domestic `.ru` traffic and LAN/SSHFS traffic bypass the VPN tunnel
- **WHEN** a process on an `ai-user` host resolves `.ru`/`.su`/`.рф` domains or connects to private LAN/`sshfs` subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- **THEN** `sing-box` routes DNS to `dns-local` and traffic to `direct`, never sending domestic or LAN/SSHFS traffic through `exit-ai`
