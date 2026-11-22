# passive-cluster-watchdog Specification

## Purpose

Defines a stealthy, zero-emission, zero-disk-logging SSH cluster watchdog that collects in-memory kernel and per-user byte-counter deltas across the Moscow bridge and German exit nodes, starting in manual read-only inspection mode with strict anti-overflow, anti-hang, and anti-storm fail-safe protections.

## Requirements

### Requirement: Manual read-only passive cluster delta inspection (Phase 1)
The system SHALL provide a manual read-only workstation CLI (`tools/cluster_watch.py`) that collects passive kernel counters (`nstat`), container restart/OOM state, RAM/Swap, disk, NTP, and `TCPMSS` over SSH from `mos` and all `exit-*` nodes without installing any outbound agent on `mos`, computing deltas against a single bounded local snapshot and printing a compact status table.

#### Scenario: Manual watchdog run produces server and per-user delta table with zero server writes
- **WHEN** the administrator runs `tools/cluster_watch.py` manually in default Phase 1 mode
- **THEN** it connects once per node over SSH, prints `[OK]`/`[WARN]`/`[CRIT]` deltas for `mos` and every `exit-*` node plus per-user byte deltas from `mos`, writes zero bytes to server disks, emits zero outbound packets from `mos`, and overwrites a single local snapshot JSON atomically on the workstation

### Requirement: In-memory per-user byte-delta collection strictly on the Moscow bridge
On `bridge` nodes only, the system SHALL query Xray's loopback gRPC `StatsService` (`127.0.0.1:10085`) with a `3s` timeout and `reset=true` to collect per-user `uplink` and `downlink` byte totals in RAM without recording client IPs, destination domains, or disk logs. German `exit` nodes SHALL NOT enable `StatsService` and SHALL only be inspected via passive OS/Docker counters.

#### Scenario: Per-user counters reset on read and consume bounded RAM
- **WHEN** the bridge stats helper queries `127.0.0.1:10085` with `reset=true`
- **THEN** it returns only logical user names and byte totals (`uplink`/`downlink`), resets the in-memory `uint64` counters to zero, writes zero log files to disk, and leaves `log.access`, `log.error`, and `log.loglevel` set to `"none"`

#### Scenario: Stuck or unavailable gRPC stats API fails fast without hanging Xray or SSH
- **WHEN** `127.0.0.1:10085` is unreachable or does not respond within `3s`
- **THEN** the stats query aborts immediately with a non-fatal `[WARN]` status without retrying, without restarting Xray, and without interrupting active VPN tunnels

### Requirement: Overflow, hang, and reconnect-storm fail-safe protections
The watchdog SHALL enforce hard anti-hang and anti-storm limits: single-instance `flock` locking (skipping overlapping runs), SSH `ConnectTimeout=8s`, per-host command timeout `15s`, zero automatic retry loops (exactly 1 SSH attempt per node; unreachable hosts report `[UNREACHABLE]` immediately), and a single fixed-schema local snapshot file overwritten atomically to prevent unbounded disk or memory growth.

#### Scenario: Unreachable server fails fast without retry storm
- **WHEN** `mos` or an `exit-*` node is temporarily unreachable during a watchdog run
- **THEN** the watchdog waits at most `8s` for SSH connect, performs zero retries, marks that node `[UNREACHABLE]` in the report, continues checking remaining nodes cleanly, and exits without generating reconnect storms

#### Scenario: Overlapping watchdog invocations cannot pile up
- **WHEN** a second watchdog instance starts while a previous instance still holds the lockfile
- **THEN** the second instance exits immediately without opening SSH connections

### Requirement: Guarded future automation with hard `ai-owner` whitelist and circuit breaker
Future scheduled alerts (Phase 2, 3–4h) SHALL stay silent on `[OK]` and send anonymized alerts strictly from the workstation or a foreign exit (never from `mos`). Future opt-in `--auto-quarantine` (Phase 3) SHALL require `xray -test` pre-flight validation, permanently whitelist `ai-owner`, disable at most `1` `media-consumer` per run via reversible `user disable`/`enable`, and abort on server-wide outages.

#### Scenario: `ai-owner` can never be quarantined automatically
- **WHEN** `--auto-quarantine` evaluates a high-traffic event for a user with profile `ai-owner`
- **THEN** the watchdog never disables `ai-owner` and emits an informational warning only

#### Scenario: Broken config or global uplink outage aborts quarantine safely
- **WHEN** pre-flight `xray -test` fails or server-wide `TCPSynRetrans` indicates an uplink/TSPU outage
- **THEN** the watchdog aborts all user-mutating actions so active clients are never disconnected into a reconnect storm

### Requirement: Gitignored workstation `tools/.env` configuration for cluster aliases
The workstation watchdog (`tools/cluster_watch.py`) SHALL support loading cluster node aliases (`MARZNESHIN_WATCH_NODES`), protected user aliases (`MARZNESHIN_PROTECT_USERS`), and optional alert command (`MARZNESHIN_ALERT_CMD`) from a local gitignored `tools/.env` file using stdlib parsing only, with precedence `CLI flags > process environment > tools/.env > fallback defaults`.

#### Scenario: `tools/.env` configures multi-exit node list without CLI flags
- **WHEN** `tools/.env` defines `MARZNESHIN_WATCH_NODES` with a bridge alias and multiple exit aliases and the administrator runs `tools/cluster_watch.py` without `--nodes`
- **THEN** the watchdog inspects all nodes listed in `tools/.env` instead of only the two-node fallback

#### Scenario: CLI flags and process environment override `tools/.env`
- **WHEN** `tools/.env` defines `MARZNESHIN_WATCH_NODES` or `MARZNESHIN_PROTECT_USERS` and the caller passes `--nodes`, `--protect-user`, or process environment variables
- **THEN** CLI flags take highest precedence over process environment variables, which take precedence over `tools/.env`

#### Scenario: Missing `tools/.env` falls back safely and unit tests stay isolated
- **WHEN** `tools/.env` does not exist or tests invoke the watchdog with an isolated `env_file` path
- **THEN** the watchdog falls back to default parameters without error and tests never read the workstation's live `tools/.env`

### Requirement: Repository hygiene for workstation `.env` templates
The repository SHALL ignore `tools/.env` in `.gitignore` while tracking a placeholder-only `tools/.env.example` template that contains no real server aliases, user names, IP addresses, domains, or credentials.

#### Scenario: Local `tools/.env` stays untracked while `tools/.env.example` is tracked
- **WHEN** `tools/.env` is created on the admin workstation alongside `tools/.env.example`
- **THEN** `git check-ignore` ignores `tools/.env` and allows `tools/.env.example` to remain tracked in Git
