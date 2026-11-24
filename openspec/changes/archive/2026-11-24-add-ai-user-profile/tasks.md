# Tasks

## 1. Bridge State & `ai-isolated` Policy (`ai-user` Support)

- [x] 1.1 Add `"ai-user"` to `USER_PROFILES`, `default_platforms_for_profile`, and `validate_bridge_isolation` in `app/bridge_state.py` so `ai-isolated` upstreams permit at most one `ai-owner` plus `ai-user` users while rejecting `media-selective` and a second `ai-owner`, and verify with unit tests in `tests/`.
- [x] 1.2 Update `app/cli.py` (`--profile` choices and `user add` handling) to accept `ai-user` and pass it to bundle generation, and verify with CLI unit tests in `tests/`.

## 2. `ai-user` Linux `sing-box` Profile Generator

- [x] 2.1 Define `AI_USER_DOMAIN_SUFFIXES` (OpenAI/ChatGPT, Anthropic/Claude Code, Google Gemini/AI Studio, OpenRouter, Grok/x.ai, HuggingFace, GitHub, Databricks/Okta/Auth0, Microsoft/Azure/VS Code/Copilot, package/container registries, AI IDEs) and `build_ai_user_profile` in `app/client/profile_generator.py` with hybrid `Selective TUN` (`route_exclude_address` for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), `mixed-in` (`127.0.0.1:2080`), all 7 `podkop` rule-sets via `proxy-http`, `TELEGRAM_DC_CIDRS`, unconditional `reject` rules (`::/0`, `UDP 443/3478/19302`, `bittorrent`, `query_type: "HTTPS"`, telemetry), `/run/sing-box/cache.db`, and `log.level: "warn"`.
- [x] 2.2 Update `write_user_bundle` in `app/client/profile_generator.py` to output `linux-ai-user.json` and `bundle-manifest.json` (without `links.txt`) for `ai-user`, add schema/invariant tests in `tests/`, and verify `.venv/bin/python -m pytest tests/ -v` passes with zero failures.

## 3. Cascade Bridge Deployment & User Creation

- [x] 3.1 Deploy the updated repository to the Cascade Bridge (`mos`), run `sudo ./script.sh user add <user> --upstream <exit-ai> --profile ai-user`, and verify `sudo ./script.sh user list` and `sudo ./script.sh self-test` pass cleanly.

## 4. Work-Node Host Hardening (SD Card, Network Share, Firewall)

- [x] 4.1 Disable IPv6 via `/etc/sysctl.d/` (`disable_ipv6=1`), set `Storage=volatile` / `RuntimeMaxUse=32M` for `systemd-journald`, update `/` mount options in `/etc/fstab` to `noatime,nodiratime`, and verify `sysctl` and `mount` output.
- [x] 4.2 Verify `/mnt/<share>` (`sshfs` to LAN workstation) is writable and executable, create `/mnt/<share>/{tmp,log,cache,work}`, configure `TMPDIR` and dev tool cache env vars (`PIP_CACHE_DIR`, `npm_config_cache`, `UV_CACHE_DIR`, `GOPATH`/`GOMODCACHE`), and verify Docker daemon log rotation limits (`max-size=10m`, `max-file=2`).
- [x] 4.3 Enable `ufw` on the work node allowing inbound traffic only from trusted LAN subnets (preserving Docker bridge forwarding), and verify `sudo ufw status` and SSH connectivity.

## 5. `sing-box` Installation & Passive Verification on Work Node

- [x] 5.1 Install official static `sing-box >= 1.14` (`linux-arm64`) with SHA256 verification and ensure `nftables` is installed; verify `sing-box version`.
- [x] 5.2 Deploy `linux-ai-user.json` to `/etc/sing-box/config.json` (`0600`), create `sing-box.service` (`After=network-online.target`), run `sing-box check`, and start with an automatic 60s rollback timer to protect SSH.
- [x] 5.3 Verify `systemctl status sing-box` and routing on the work node, then run `python3 tools/cluster_watch.py` from the workstation to confirm `<user>` traffic flows through `mos -> exit-ai` without elevated `TCPSynRetrans` or `TCPTimeouts`.
