# Design

## Context

See [proposal.md](./proposal.md) for motivation. Target work-node environment (`arm64` SBC / Ubuntu `26.04`, 2 GB RAM, `/dev/net/tun` present):
- `sing-box` is not available in default distribution APT repositories.
- `systemd-resolved` (`127.0.0.53`), `systemd-networkd`, `armbian-ramlog` (`/var/log` on `zram1`), and `zram0` swap are active; `/tmp` is `tmpfs`.
- `/mnt/<share>` is mounted via `fuse.sshfs` (`<user>@<lan-share-host>:/path/to/share`, `x-systemd.automount`, `x-systemd.idle-timeout=600`, `nofail`) with `exec` enabled.
- On the bridge (`mos`), the `ai-isolated` exit (`default`) hosts one `ai-owner` user (`owner`).

## Goals / Non-Goals

**Goals:**
- Support `ai-user` as a first-class bridge user profile in `app/bridge_state.py`, `app/cli.py`, and `app/client/profile_generator.py`.
- Allow `ai-isolated` upstreams to host `ai-owner` (max 1) + `ai-user` users while keeping `media-selective` blocked.
- Balance traffic on the work node so AI/Dev traffic (including dynamic subdomains covered by `podkop` community lists) uses `exit-ai` without leaking RU traffic into the AI exit or breaking LAN/`sshfs`/Docker.
- Protect the work node's SD card from write wear and restrict inbound access via `ufw`.

**Non-Goals:**
- Supporting `Full Tunnel` on the work node (unsafe for an always-on headless LAN node sharing `exit-ai`, as background OS/RU requests would hit the AI exit).
- Putting Docker's `overlay2` `data-root` (`/var/lib/docker`) onto `fuse.sshfs` (unsupported by `overlay2`).
- Provisioning a new exit VPS (reusing the existing `ai-isolated` exit).

## Decisions

### 1. `ai-isolated` isolation guard: `ai-owner` (<= 1) + `ai-user`
- **Decision:** Update `validate_bridge_isolation` in `app/bridge_state.py` so `ai-isolated` upstreams permit at most 1 `ai-owner` plus `ai-user` bindings, while rejecting `media-selective`.
- **Rationale:** Gives each work node its own UUID, byte counters in `cluster_watch.py`, and independent revocation without relaxing isolation against `media-selective` users.
- **Alternative:** Sharing `owner`'s UUID (`linux-singbox-selective.json`). Rejected because it prevents per-device stats/revocation and mixes desktop/mobile `ai-owner` domain rules with work-node dev/registry rules.

### 2. Hybrid `Selective TUN` + `mixed-in` (`127.0.0.1:2080`) for `linux-ai-user.json`
- **Decision:** Use `Selective TUN` (`route.final: "direct"`, `dns.final: "dns-local"`) combined with `mixed-in` (`127.0.0.1:2080` -> unconditionally `proxy`).
- **Rationale:** `Selective TUN` catches processes/DNS that ignore `HTTP_PROXY` (Go/Rust/Node/Claude Code/system resolvers) for all AI/Dev & `podkop` domains while keeping `.ru`, `sshfs`, and OS mirrors `direct`. `mixed-in` provides a deterministic escape hatch (`HTTPS_PROXY=http://127.0.0.1:2080`) when a tool must be forced 100% through `exit-ai`.
- **Alternative:** `Proxy-only` without `TUN` (risks DNS/direct leaks from CLI tools ignoring proxy env vars) or `Full TUN` (risks leaking RU/OS traffic onto `exit-ai`).

### 3. All 7 `podkop` community `.srs` rule-sets + `AI_USER_DOMAIN_SUFFIXES`
- **Decision:** Include all 7 `podkop` rule-sets (`google_ai`, `google_play`, `russia_inside`, `telegram`, `discord`, `twitter`, `meta` via `http_client: "proxy-http"`, with only domain-only sets `google_ai`, `google_play`, `russia_inside` in `dns.rules`) plus `TELEGRAM_DC_CIDRS` and `AI_USER_DOMAIN_SUFFIXES` (OpenAI/ChatGPT, Anthropic/Claude Code, Gemini/AI Studio, OpenRouter, Grok/x.ai, HuggingFace, GitHub, Databricks/Okta/Auth0, Microsoft/Azure/VS Code/Copilot, Docker/PyPI/npm/crates/Go, AI IDEs).
- **Rationale:** Matches `ai-owner` Selective's `podkop` coverage on `exit-ai` while adding missing dev/AI platforms (`openrouter.ai`, `github.com`, `microsoft.com`, registries) so Telegram notifications, Discord, Grok/X, and AI coding agents work without leaking unlisted subdomains.

### 4. SD-card protection & `sshfs` + Docker coexistence on the work node
- **Decision:**
  - Keep OS `/tmp` (`tmpfs`), `/var/log` (`zram1`), `systemd-journald` (`Storage=volatile`), and `sing-box` `experimental.cache_file.path` (`/run/sing-box/cache.db` on `tmpfs`) in RAM, with `sing-box` `log.level: "warn"` and `/` mounted `noatime,nodiratime`.
  - Use `/mnt/<share>/{tmp,log,cache,work}` (mounted via `sshfs`) for **application/script/Docker volume data, build caches (`TMPDIR`, `PIP_CACHE_DIR`, `npm_config_cache`, `UV_CACHE_DIR`), and script logs**, keeping Docker `overlay2` on SD card with bounded JSON log rotation (`max-size=10m`, `max-file=2`).
  - Exclude RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) in `tun.route_exclude_address` + `ip_is_private: true -> direct`.
  - Configure `ufw` allowing inbound traffic only from trusted LAN subnets, and ensure Docker `FORWARD` compatibility.

## Risks / Trade-offs

- **[Risk] `sing-box` `strict_route: true` breaks SSH or `sshfs` on a headless work node** -> **Mitigation:** Set `route_exclude_address` for private/Docker subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); place `ip_is_private: true -> direct` before proxy rules; test with an automatic rollback timer (`systemd-run --on-active=60`) on first start.
- **[Risk] `sshfs` idle unmount (`x-systemd.idle-timeout=600`) or host reboot disrupts `sing-box` if it writes to `/mnt/<share>`** -> **Mitigation:** `sing-box` reads `/etc/sing-box/config.json` locally and writes `cache.db` only to `/run/sing-box/cache.db` (`tmpfs`), completely decoupled from `/mnt/<share>`.
- **[Risk] `ufw` default `FORWARD` policy blocks Docker bridge (`172.17.0.0/16`)** -> **Mitigation:** Configure `ufw` route/forward allowance for Docker subnets (`172.16.0.0/12`) when enabling `ufw`.
- **[Risk] `sing-box` unavailable in distro APT** -> **Mitigation:** Install official static `sing-box >= 1.14` `linux-arm64` binary with SHA256 verification.

## Migration Plan

1. Implement code & unit tests in repo; run `.venv/bin/python -m pytest tests/ -v`.
2. Deploy updated repo to the bridge via zero-emission image transfer, run `script.sh user add <user> --upstream <exit-ai> --profile ai-user`.
3. Harden the work node (sysctl IPv6 off, `noatime`, `journald` volatile, `/mnt/<share>/{tmp,log,cache,work}` env, `nftables`, `ufw`).
4. Install `sing-box >= 1.14` (`linux-arm64`), deploy `linux-ai-user.json` to `/etc/sing-box/config.json`, run `sing-box check`, start with rollback guard, and verify passively via `python3 tools/cluster_watch.py`.
