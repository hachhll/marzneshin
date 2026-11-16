# Spec Delta

## MODIFIED Requirements

### Requirement: Single-IP native IPv4 egress without secondary tunnels
In `exit` mode, the proxy engine SHALL route all allowed outbound traffic solely through a direct `freedom` outbound (`domainStrategy: "UseIPv4"` by default) bound to the server's static IP and SHALL prohibit Cloudflare WARP, Tor, WireGuard, or arbitrary third-party proxy chains. In `bridge` mode, the proxy engine SHALL route all allowed outbound traffic solely through the single configured `vless` Reality outbound pointing to the owner's dedicated exit node IP (`<upstream_ip>:443`) and SHALL omit `freedom` (`direct`) outbounds so zero traffic can leak onto the domestic bridge network.

#### Scenario: Rendered engine config uses direct IPv4 freedom only
- **WHEN** the server Xray configuration is generated or validated in `exit` mode
- **THEN** outbounds contain only `direct` (`freedom` with `UseIPv4`) and `block` (`blackhole`), and any secondary tunnel protocol is rejected

#### Scenario: Rendered engine config uses fail-closed upstream VLESS only in bridge mode
- **WHEN** the server Xray configuration is generated or validated in `bridge` mode
- **THEN** outbounds contain only `proxy` (`vless` Reality to `<upstream_ip>:443` with `fingerprint: "chrome"`) and `block` (`blackhole`), and `freedom` (`direct`) is absent

### Requirement: Executable safety self-test via SSH CLI
The system SHALL provide `./script.sh self-test` (and Python verification helpers) operating in **100% passive Zero-Emission mode by default** (verifying Xray and Nginx config safety, local `127.0.0.1:8443` probe isolation config, zero unexpected public listening ports in `/proc/net/tcp`, zero WireGuard/WARP/Tor processes in `/proc`, `/dev/null` logging, QUIC/STUN/telemetry blackholes, and `gvt1.com` allowance without emitting any network packets), while supporting `--active-probe` for optional live loopback TLS and triple AI egress checks on exit nodes.

#### Scenario: Healthy appliance passes all self-test checks
- **WHEN** the owner runs `./script.sh self-test` on either an exit node or a bridge node
- **THEN** all passive safety checks report `[PASS]` with exit code `0` and zero outbound network packets are emitted
