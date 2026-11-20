# Tasks

## 1. Server-Side Bridge In-Memory Stats (`mos` Only)

- [ ] 1.1 Update `LocalXrayConfigBuilder.build_bridge` in `app/xray/config_builder.py` to include loopback-only (`127.0.0.1:10085`) `StatsService`, `"stats": {}`, and `"policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}}` in `bridge` mode while keeping `exit` mode stats-free and preserving `log.access="none"`, `log.error="none"`, `log.loglevel="none"`; verify with unit tests asserting loopback binding, zero logging, and `exit`-mode exclusion.
- [ ] 1.2 Add `./script.sh stats [--reset]` in `script.sh` and `app/cli.py` executing `timeout 3 xray api statsquery --server=127.0.0.1:10085 -pattern "user>>>"` inside `marzneshin-xray` with JSON output and non-fatal fail-fast on timeout/error; verify with unit tests mocking both normal output and `3s` timeout failure.
- [ ] 1.3 Update passive `app/utils/self_test.py` checks to verify that `StatsService` is allowed exclusively on `bridge` mode bound to `127.0.0.1:10085` with zero disk logs and remains forbidden on `exit` nodes; verify with unit tests.

## 2. Safe Server-Side Quarantine Toggle (`mos` Only, Pre-Flight Validated)

- [ ] 2.1 Add `./script.sh user disable <name>` and `./script.sh user enable <name>` in `app/cli.py` and `script.sh` that mark `disabled: true/false` in `state.json` (preserving UUID/profile), refuse to disable `ai-owner` via automated flags, and run mandatory `xray -test -config <tmp>` pre-flight before replacing `/var/lib/marzneshin/xray/config.json` and reloading; verify with unit tests confirming bad configs leave live Xray untouched and `ai-owner` protection holds.

## 3. Workstation Passive Delta Collector (Phase 1 — Manual Only)

- [ ] 3.1 Create `tools/cluster_watch.py` (Phase 1 manual read-only CLI) that connects over SSH to `mos` and configured `exit-*` aliases with `flock` single-instance locking, `ConnectTimeout=8`, `15s` per-host timeout, and zero retry loops, collecting `nstat` deltas, `docker inspect` (`RestartCount`, `OOMKilled`, `StartedAt`), `free -m`, disk, NTP, `TCPMSS`, and `mos` `./script.sh stats --reset`; verify with unit tests covering normal deltas, container-restart counter reset handling, `[UNREACHABLE]` fail-fast, and `flock` overlap rejection.
- [ ] 3.2 Implement bounded atomic local snapshot storage (`~/.cache/marzneshin-watch/snapshot.json` overwritten via temp-file + `os.replace`) and compact terminal `[OK]`/`[WARN]`/`[CRIT]` table formatting with zero live IPs/secrets in alerts; verify with unit tests confirming single-file bounded storage and sanitized output.

## 4. Opt-In Scheduled Alerting & Guarded Quarantine Hooks (Phase 2 & Phase 3 Ready)

- [ ] 4.1 Add optional Phase 2 silent-on-OK alert dispatcher (workstation local notify / anonymized webhook, strictly prohibited from running on `mos`) and documented `systemd --user` timer example (`3–4h`, disabled by default in Phase 1); verify with unit tests asserting zero alerts on `[OK]` and zero secrets/IPs in alert payloads.
- [ ] 4.2 Add opt-in Phase 3 `--auto-quarantine` mode in `tools/cluster_watch.py` gated behind explicit CLI flag with hard circuit breaker (permanent `ai-owner` whitelist, max `1` `media-consumer` disabled per run, automatic abort on server-wide `TCPSynRetrans`/`OOMKilled`/`[UNREACHABLE]` anomaly); verify with negative unit tests covering every circuit-breaker branch and full `pytest tests/ -v` pass.

## Workflow follow-up

- Validate `passive-cluster-watchdog` via `openspec validate passive-cluster-watchdog` before starting implementation via `/opsx-apply`.
- Run Phase 1 manually for 1–2 weeks to calibrate thresholds before enabling Phase 2 timer or Phase 3 `--auto-quarantine`.
- Archive the change via `/opsx-archive` after implementation and live verification complete.
