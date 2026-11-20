# Design

## Context

See `proposal.md` for motivation and scope. The production Cascade Bridge (`mos`) currently runs `Xray v26.6.27` with `log.access = "none"`, `log.error = "none"`, `log.loglevel = "none"`, `8.6 GB` disk (`4.7 GB` free), and `955 MB` RAM (planned upgrade to `2 GB RAM + 1 GB swap` under `multi-exit-bridge-cluster`). German exits (`server-de` and future `exit-ai` / `exit-media-*`) see only a single inter-server UUID from `mos` and therefore have no visibility into individual end-user devices.

Hard constraints governing this design (from `AGENTS.md`):
- **Zero-Emission on `mos`**: zero outbound internet requests from the Russian bridge (never send alerts, webhooks, or telemetry from `mos`).
- **Zero-Logging**: zero `access.log`/`error.log` on disk, zero client IP or visited-domain storage, never run raw `ss -tnp`.
- **Anti-TSPU / Anti-Storm**: zero pings, zero active probing, zero retry loops, never drop active VPN clients on a bad config reload.

## Goals / Non-Goals

**Goals:**
- Deliver a **Phase 1 manual read-only CLI** (`tools/cluster_watch.py`) run from the administrator's workstation over SSH to inspect cluster health (`mos` + all `exit-*`) and per-user in-memory byte deltas (`mos`) in one command.
- Keep server memory overhead under `100 KB` RAM (`2 × uint64` counters per user, reset on read) and server disk usage strictly `0 bytes`.
- Guarantee fail-fast behavior against hangs, overlapping runs, connection drops, and misconfigurations so the watchdog itself can never trigger a disconnect/reconnect storm.
- Clearly define the exact server-side work list and the gated upgrade path to Phase 2 (3–4h scheduled alerts) and Phase 3 (guarded `media-consumer` auto-quarantine).

**Non-Goals:**
- Installing any web dashboard, Prometheus exporter, external monitoring agent, or outbound webhook on `mos`.
- Enabling `access.log`, `error.log`, or `StatsService` on German exit nodes (`exit-ai`, `exit-media-*`).
- Enabling automatic user blocking in Phase 1 (auto-quarantine is explicitly deferred to Phase 3 after manual threshold calibration).
- Modifying any live server during this specification phase.

## Decisions

### 1. Pull-Only Architecture Initiated From Admin Workstation (Zero-Emission on `mos`)
- **Decision:** All polling is initiated **inbound via SSH** from the administrator's workstation (`tools/cluster_watch.py`) to `mos` and each `exit-*` host. State snapshots (`snapshot.json`) are stored exclusively on the workstation (e.g. `~/.cache/marzneshin-watch/snapshot.json`, single file overwritten atomically via temp-file + `os.replace`).
- **Why:** Preserves 100% Zero-Emission on `mos` (zero cron jobs, zero outbound sockets, zero disk writes on the Russian bridge).
- **Alternative considered:** Running a `systemd` timer directly on `mos` that pushes alerts to Telegram. Rejected because outbound Telegram/API calls from `mos` violate Zero-Emission and could correlate the Russian bridge IP with admin alerts.

### 2. Loopback-Only In-Memory `StatsService` on `mos` (`127.0.0.1:10085`)
- **Decision:** Enable `StatsService` on the already-existing `127.0.0.1:10085` loopback API inbound on `mos` (`bridge` mode only), alongside `"stats": {}` and `"policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}}`. Query via `./script.sh stats --reset` (invoking `xray api statsquery --server=127.0.0.1:10085 -pattern "user>>>" -reset=true` inside `marzneshin-xray` with a `3s` timeout).
- **Memory & Disk Footprint:** ~100 bytes per user (`< 100 KB` total for 20 users regardless of gigabytes transferred), `0 bytes` on disk, zero client IPs or domains stored, wiped on container restart and reset on every read.
- **Alternative considered:** Parsing `access.log` in `/tmp` tmpfs. Rejected because it records client IPs and visited domains, risks filling tmpfs/RAM under heavy load, and adds CPU/parsing overhead.

### 3. Defense-in-Depth Against Overflow, Hangs, and Reconnect Storms
- **Overflow protection:**
  - Server side: fixed-size `uint64` counters in Xray RAM, reset on read (`-reset=true`), `0` disk writes.
  - Workstation side: single atomic `snapshot.json` (overwritten in place, `< 20 KB`), no unbounded history log.
- **Hang protection:**
  - Single-instance exclusive `flock` on `~/.cache/marzneshin-watch/watch.lock` (non-blocking `LOCK_EX | LOCK_NB`; if locked, exit immediately).
  - Hard SSH options: `-o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=1`.
  - Per-host subprocess wall-clock timeout: `15s` (`subprocess.run(..., timeout=15)`).
  - Loopback gRPC query timeout on `mos`: `3s` (`timeout 3 xray api statsquery ...`).
- **Anti-storm & disconnect fail-safe:**
  - **Zero retry loops:** Exactly 1 SSH attempt per host per run. If a host is unreachable, mark `[UNREACHABLE]` and move on immediately—never hammer SSH `:22222` or `:443`.
  - **Config pre-flight (`xray -test`):** Any mutating CLI command (`user disable` / `user enable`) writes a candidate config to a temp path, validates it via `docker exec marzneshin-xray xray -test -config <tmp>`, and ONLY replaces `/var/lib/marzneshin/xray/config.json` and reloads if validation exits `0`. If validation fails, the running config is untouched so zero clients are disconnected.
  - **Quarantine circuit breaker (Phase 3 opt-in only):**
    1. Hard whitelist: users with `profile == "ai-owner"` are NEVER disabled automatically.
    2. Blast-radius cap: disable at most `1` `media-consumer` user per run.
    3. Outage guard: if `mos` or the target `exit-*` shows global `TCPSynRetrans` / `OOMKilled` / `[UNREACHABLE]` anomalies, abort quarantine (do not blame/disable users during a server or ISP outage).
    4. Instant reversal: `user disable <name>` sets `disabled: true` in `state.json` (preserving UUID/profile) so `user enable <name>` restores access in 1 command without re-issuing configs.

### 4. Exact Server-Side Work List (What Changes Where)

```text
+--------------------+--------------------------------------------------------------+
| Host / Component   | Required Work (future /opsx-apply)                           |
+--------------------+--------------------------------------------------------------+
| mos (Bridge)       | 1. Enable loopback StatsService + policy.levels.0 (RAM only) |
|                    |    in build_bridge() (0 disk logs, loglevel="none" intact).  |
|                    | 2. Add `./script.sh stats [--reset]` (3s timeout gRPC query).|
|                    | 3. Add `./script.sh user disable|enable <name>` with         |
|                    |    mandatory `xray -test` pre-flight before reload.          |
|                    | 4. Update passive `self-test` to verify StatsService is      |
|                    |    loopback-only and disk logging remains off.               |
+--------------------+--------------------------------------------------------------+
| exit-ai /          | ZERO server-side code or config changes.                     |
| exit-media-* (DE)  | Queried read-only via existing OS/Docker commands (nstat,    |
|                    | docker inspect, free -m, timedatectl, iptables mangle).      |
+--------------------+--------------------------------------------------------------+
| Admin Workstation  | 1. Create `tools/cluster_watch.py` (Phase 1: manual only,    |
| (local repo)       |    read-only table, flock, 8s/15s timeouts, 0 retries,       |
|                    |    single atomic local snapshot JSON).                       |
|                    | 2. Optional Phase 2: user systemd timer (3-4h) + silent-on-  |
|                    |    OK alert (Telegram/local notify, never from mos).         |
|                    | 3. Optional Phase 3: opt-in `--auto-quarantine` with circuit |
|                    |    breaker and hard ai-owner whitelist.                      |
+--------------------+--------------------------------------------------------------+
```

## Risks / Trade-offs

- **[Pre-handshake SYN spam is invisible to `StatsService`] -> Mitigation:** Xray only attributes bytes to a `user` after Reality authentication succeeds. Pre-handshake floods are still caught immediately by the kernel `nstat` delta (`TCPSynRetrans`, `EmbryonicRsts`) in the same watchdog report.
- **[Counter reset on container restart] -> Mitigation:** If `marzneshin-xray` restarts between runs, in-memory counters drop to 0; `cluster_watch.py` detects negative deltas or `StartedAt` change and marks that window `[RESTARTED]` instead of computing bogus negative numbers.
- **[False-positive thresholds before calibration] -> Mitigation:** Phase 1 is strictly manual read-only (`--auto-quarantine` does not execute unless explicitly opted in during Phase 3 after observing 1–2 weeks of real household baselines).
- **[Dependency on `multi-exit-bridge-cluster`] -> Mitigation:** Server-side `user disable|enable` builds on `multi-exit-bridge-cluster`'s `state.json` v2 `users` map; however, Phase 1 read-only `cluster_watch.py` (kernel `nstat` + container health + `owner` stats) works immediately even on the current v1 single-owner bridge.

## Migration Plan

*(Executed only after future implementation via `/opsx-apply`; zero live actions during planning.)*
1. Back up live `/var/lib/marzneshin/xray/config.json` to `/var/lib/marzneshin/xray/config.json.bak` on `mos`.
2. Deploy updated `app/xray/config_builder.py` and `script.sh` to `/opt/marzneshin` on `mos` (zero image rebuilds, zero `docker pull`, 100% Zero-Emission).
3. Render candidate config and validate via `sudo docker exec marzneshin-xray xray -test -config <candidate>` **before** restarting `marzneshin-xray`.
   - **Strict fail-closed stop rule:** If `xray -test` exits non-zero, **immediately restore `/var/lib/marzneshin/xray/config.json.bak` (leaving live `config.json` untouched and without restarting `marzneshin-xray`), print the exact `xray -test` error output, and STOP**—never attempt on-the-fly live fixes on the server.
4. Only after `xray -test` prints `Configuration OK`, replace live `config.json` atomically and restart `marzneshin-xray` (~2s reload, zero client config changes).
5. Run passive `./script.sh self-test` on `mos` to verify `StatsService` is bound strictly to `127.0.0.1:10085` and `log.access`/`error`/`loglevel` remain `"none"`.
6. Run `tools/cluster_watch.py` manually from the workstation for 1–2 weeks (Phase 1) to calibrate normal `nstat` and per-user byte thresholds.
7. Optionally enable local `systemd --user` timer every 3–4h with silent-on-OK alerting (Phase 2), and later opt-in `--auto-quarantine` for `media-consumer` once 15–20 devices are onboarded (Phase 3).
8. **Rollback:** Restore `/var/lib/marzneshin/xray/config.json.bak` -> `config.json` and restart `marzneshin-xray`; delete local `snapshot.json` on workstation.
