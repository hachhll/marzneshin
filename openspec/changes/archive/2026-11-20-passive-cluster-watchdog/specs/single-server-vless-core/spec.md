# Spec Delta

## MODIFIED Requirements

### Requirement: Elimination of traffic accounting and connection metadata
The system SHALL keep `log.access`, `log.error`, and `log.loglevel` set to `"none"` with zero disk logging and zero client IP or destination-domain tracking on all nodes. In `exit` mode, `StatsService` and `policy` SHALL remain completely absent. In `bridge` mode only, the system MAY enable loopback-only (`127.0.0.1:10085`) in-memory `StatsService` with `policy.levels.0` (`statsUserUplink: true`, `statsUserDownlink: true`) solely for bounded, reset-on-read per-user byte totals in RAM without persisting any traffic history or connection metadata to disk.

#### Scenario: Xray configuration disables all logging and statistics
- **WHEN** the Xray configuration is validated in `exit` mode
- **THEN** `log.access`, `log.error`, and `log.loglevel` are set to `"none"` and neither `stats` nor `policy` sections are present

#### Scenario: Bridge Xray configuration permits loopback-only in-memory byte counters without disk logs
- **WHEN** the Xray configuration is validated in `bridge` mode with per-user watchdog stats enabled
- **THEN** `log.access`, `log.error`, and `log.loglevel` remain `"none"`, `api` binds strictly to `127.0.0.1:10085` with `StatsService`, `policy.levels.0` tracks only `statsUserUplink`/`statsUserDownlink` in RAM, and zero client IPs, domains, or disk log files are recorded
