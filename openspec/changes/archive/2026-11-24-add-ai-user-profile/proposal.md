# Proposal

## Why

A headless Linux (`arm64`) work node needs dedicated VPN access through the Cascade Bridge (`mos`) to the clean AI exit (`exit-ai`) with its own UUID, independent accounting/revocation, and a hardened Linux `sing-box` Selective profile tailored for AI coding and development workflows (ChatGPT, Claude Code, Gemini, OpenRouter, GitHub, Databricks, Microsoft, package registries). Currently, `ai-isolated` upstreams reject any second user, and only `ai-owner` (5-OS bundle) and `media-selective` (mobile-only) profiles exist.

## What Changes

- Introduce a new `ai-user` user profile alongside `ai-owner` and `media-selective` in bridge state management, CLI (`script.sh user add --profile ai-user`), and profile generation.
- Update the `ai-isolated` upstream isolation guard so `ai-isolated` exits permit `ai-owner` (at most one) and `ai-user` users (still rejecting `media-selective` users).
- Add a Linux `sing-box` (`>= 1.14`) profile generator for `ai-user` (`linux-ai-user.json`) combining `Selective TUN` (excluding RFC1918 LAN/Docker private CIDRs) and a local `mixed-in` proxy (`127.0.0.1:2080`), using all 7 `podkop` community rule-sets (`google_ai`, `google_play`, `russia_inside`, `telegram`, `discord`, `twitter`, `meta`), `TELEGRAM_DC_CIDRS`, and an expanded AI/Dev domain list (OpenAI, Anthropic/Claude Code, Gemini, OpenRouter, Grok/x.ai, GitHub, Databricks, Microsoft/Azure/Copilot, PyPI/npm/Docker/crates/Go).
- Harden the Linux work node for SD-card longevity (`/run/sing-box/cache.db` on `tmpfs`, minimal `warn` logging, `systemd-journald` volatile RAM storage, `noatime`/`nodiratime`, and `sshfs` `/mnt/<share>/{tmp,log,cache,work}` for project/build caches) plus `ufw` restricted to local LAN subnets.

## Capabilities

### New Capabilities
<!-- None; this extends existing routing and profile generation capabilities. -->

### Modified Capabilities
- `multi-exit-cluster-routing`: Allow `ai-isolated` upstreams to host `ai-user` users in addition to `ai-owner` while continuing to reject `media-selective` users.
- `minimal-profile-constructor`: Support generating the `ai-user` Linux `sing-box >= 1.14` Selective + `mixed-in` profile (`linux-ai-user.json`) with `podkop` community rule-sets, AI/Dev domain coverage, RAM-backed `cache.db`, and private/LAN subnet exclusions.

## Impact

- `app/bridge_state.py`: `USER_PROFILES`, `default_platforms_for_profile`, `validate_bridge_isolation`.
- `app/cli.py`: `--profile ai-user` option and user bundle generation.
- `app/client/profile_generator.py`: `AI_USER_DOMAIN_SUFFIXES`, `AI_USER_ROUTE_EXCLUDE_ADDRESSES`, `build_ai_user_profile`, `write_user_bundle` (`linux-ai-user.json`).
- `tests/`: unit tests covering `ai-isolated` with `ai-owner` + `ai-user`, `media-selective` rejection, and `linux-ai-user.json` schema/invariants.
- Bridge & work-node host deployment: update bridge, create `ai-user`, install `sing-box >= 1.14` (`linux-arm64`), `ufw`, and SD-card/network-share hardening on the work node.
