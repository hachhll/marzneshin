# Proposal

## Why

As the Cascade Bridge cluster scales from 1–2 users to up to ~20 `media-consumer` devices alongside a dedicated `ai-owner` exit, a single misbehaving client (leaked JSON profile, 24/7 heavy streaming, or broken reconnect loop) can silently degrade bridge stability or draw Russia's TSPU/DPI attention. We need a stealthy, zero-emission, zero-disk-logging cluster watchdog that collects in-memory kernel and per-user byte-counter deltas via SSH, starts strictly in manual read-only inspection mode (Phase 1), and provides built-in protections against memory/disk overflow, process hangs, and accidental disconnect/reconnect storms—with an explicit path to scheduled alerting (Phase 2) and guarded `media-consumer` quarantine (Phase 3).

## What Changes

- **In-memory per-user byte counters on the Moscow bridge (`mos`) only:** Enable Xray's loopback-only (`127.0.0.1:10085`) in-memory `StatsService` (`statsUserUplink` / `statsUserDownlink` only) on `bridge` mode while keeping `log.access = "none"`, `log.error = "none"`, `log.loglevel = "none"`, zero client IP/domain recording, and zero disk writes. German exits (`exit-ai`, `exit-media-*`) remain untouched (`StatsService` disabled).
- **Admin-side passive SSH delta collector (Phase 1 — Manual Only):** Add a standalone read-only CLI tool (`tools/cluster_watch.py`) invoked manually by the administrator from their workstation over SSH. It collects passive kernel counters (`nstat`: `TCPSynRetrans`, `TCPTimeouts`, `EmbryonicRsts`, `TCPAbortOnTimeout`), container health (`RestartCount`, `OOMKilled`), RAM/Swap/disk/NTP/TCPMSS across `mos` and all `exit-*` nodes, plus in-memory per-user byte deltas (`reset=true`) from `mos`, storing only a single bounded atomic snapshot JSON locally on the workstation.
- **Built-in failure-mode, anti-hang, and anti-storm safeguards:**
  - **Overflow protection:** Fixed-size `uint64` in-memory counters reset on read (`< 100 KB` RAM for 20 users, 0 bytes on server disk); single overwritten local snapshot file (no growing logs).
  - **Hang protection:** Hard SSH connect timeout (`8s`), per-host command timeout (`15s`), loopback gRPC query timeout (`3s`), and single-instance `flock` lock preventing overlapping runs.
  - **Anti-storm & fail-safe on connection loss:** Zero retry loops (fail-fast: 1 SSH attempt per node; if unreachable, mark `[UNREACHABLE]` and exit cleanly without hammering SSH or `:443`). Any future mutating action (`user disable`/`user enable`) requires pre-flight `xray -test -config` validation and a circuit breaker (max 1 `media-consumer` user disabled per run, hard whitelist protecting `ai-owner`, abort quarantine if server-wide outage is detected).
- **Phased rollout contract:** Phase 1 ships strictly manual read-only inspection (`status` table in terminal); Phase 2 (3–4h local timer + silent-on-OK anonymized alert, never sent from `mos`) and Phase 3 (opt-in `--auto-quarantine` via `user disable`/`user enable` strictly for `media-consumer`) are specified as opt-in extensions gated behind manual threshold calibration.

## Capabilities

### New Capabilities
- `passive-cluster-watchdog`: Zero-emission, zero-disk-logging SSH delta monitoring for the `mos` + `exit-*` cluster, including in-memory per-user byte-delta inspection on `mos`, bounded local snapshot storage, anti-hang/anti-storm fail-fast guards, and phased manual -> scheduled -> guarded-quarantine workflow with a hard `ai-owner` whitelist.

### Modified Capabilities
- `single-server-vless-core`: Narrow `Elimination of traffic accounting and connection metadata` to permit strictly loopback-only (`127.0.0.1:10085`), in-memory, reset-on-read per-user byte counters (`StatsService` with `statsUserUplink`/`statsUserDownlink` only) exclusively in `bridge` mode while keeping `log.access = "none"`, `log.error = "none"`, `log.loglevel = "none"`, zero disk logging, and zero IP/domain/connection-metadata tracking strictly enforced on all nodes.

## Impact

- **Server-side changes (future implementation via `/opsx-apply`, untouched during planning):**
  - `mos` (`bridge` mode): add in-memory `StatsService` + `policy.levels.0` (`statsUserUplink`/`statsUserDownlink`) on existing `127.0.0.1:10085` loopback API, add read-only CLI helper (`./script.sh stats --reset`) and quarantine toggle (`./script.sh user disable|enable <name>` with mandatory `xray -test` pre-flight).
  - `exit-*` (`exit` mode): **zero Xray/Nginx changes** (queried strictly with existing passive OS/Docker commands).
- **Workstation / codebase (future implementation):**
  - `app/xray/config_builder.py` (enable loopback in-memory `StatsService` in `bridge` mode, keep `exit` mode stats-free)
  - `app/xray/controller.py` / `app/cli.py` / `script.sh` (loopback gRPC stats query with 3s timeout and `reset=true`; `user disable`/`enable`)
  - `tools/cluster_watch.py` (Phase 1 manual SSH delta collector with `flock`, strict timeouts, zero retries, local bounded snapshot, and Phase 2/3 hooks)
  - `app/utils/self_test.py` & `tests/` (validate loopback-only stats, zero disk logs, fail-fast & circuit-breaker tests)
- **Live infrastructure:** Zero modifications during planning; no active probes, pings, or background timers deployed in Phase 1.
