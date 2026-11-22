## MODIFIED Requirements

### Requirement: Operational resource and passive audit validation for multi-exit bridges
Passive Zero-Emission `self-test` on a multi-exit bridge SHALL validate all configured upstreams (zero `freedom` outbounds, zero `ai-isolated` role violations, zero un-overridden `/24` subnet collisions between `ai-isolated` and `media` exits, mandatory `UDP 443/3478/19302` blackhole rules, and bounded `xmux` session rotation) and SHALL emit a non-fatal `WARN:` when `ai-isolated` and `media` exits share a registrable root domain or when a multi-user bridge has less than `1800 MB` RAM or `0 MB` swap configured.

#### Scenario: Passive self-test validates multi-exit bridge invariants without emitting traffic
- **WHEN** `./script.sh self-test` runs on a multi-exit bridge
- **THEN** it checks all upstream outbounds, `ai-isolated` guards, `/24` subnet separation, blackhole rules, `xmux` rotation bounds, shared root-domain warnings, and memory/swap headroom purely from local files and `/proc` without emitting any network packets
