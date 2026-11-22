# Design

## Context

See `proposal.md` for motivation. Preflight checks on both new hosts (`server-de-fam1`, `server-de-fam2`) confirmed:
- Ubuntu (`Linux 7.0.0-44-generic`), `907 MB` RAM, `512 MB` swap (`/swap.img`), `ufw`, `iptables`, and `rsync` pre-installed, `docker` to be installed by `script.sh`.
- All multi-exit routing (`app/bridge_state.py`, `app/cli.py`, `app/xray/config_builder.py`) and RU egress blackholing are already implemented.

## Goals / Non-Goals

**Goals:**
- Provision `server-de-fam1` (`de-fam1.armenytravel.com`) and `server-de-fam2` (`de-fam2.armenytravel.com`) as hardened `media` exit nodes (`VLESS + XHTTP + Reality + RU egress blackhole`) with SSH hardened to `stealth:22222`.
- Register both upstreams on `mos` (`role: media`, `transport: xhttp`) with zero users assigned initially.
- Add `server-de-fam1:exit` and `server-de-fam2:exit` to `tools/.env` and verify all 6 nodes passively via `cluster_watch.py`.

**Non-Goals:**
- Assigning or migrating any users onto `server-de-fam1` or `server-de-fam2` in this change.
- Modifying `script.sh`, Python application code, or existing exit nodes (`server-de`, `oblako-fam1`, `eternity-fam2`).

## Decisions

- **Sequential exit provisioning:** Sync `/opt/marzneshin` and run `script.sh --domain <fqdn>` on `server-de-fam1` and `server-de-fam2`, update workstation `~/.ssh/config` (`User stealth`, `Port 22222`), and run `self-test` on each host before registering them on `mos`.
- **Zero-user upstream registration:** Register both upstreams on `mos` via `upstream add ... --role media --transport xhttp` without `user add` or `user assign`, keeping them ready for future user assignment.

## Risks / Trade-offs

- **[Cloudflare proxy enabled or DNS not propagated] → Mitigation:** `script.sh` validates direct DNS and aborts if a Cloudflare proxy IP is detected.
- **[Shared `/24` subnet with `server-de` (`ai-isolated`)] → Mitigation:** `mos` `upstream add` enforces `/24` isolation checks and will fail/warn if any subnet overlaps.
- **[SSH port/user switch lockout] → Mitigation:** `script.sh` verifies `:22222` before closing `22/tcp`; update `~/.ssh/config` immediately after each deploy.
