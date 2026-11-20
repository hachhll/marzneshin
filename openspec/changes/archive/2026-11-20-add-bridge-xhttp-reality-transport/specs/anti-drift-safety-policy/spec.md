# Spec Delta

## MODIFIED Requirements

### Requirement: Single-IP native IPv4 egress without secondary tunnels
In `exit` mode, the proxy engine SHALL route all allowed outbound traffic solely through a direct `freedom` outbound (`domainStrategy: "UseIPv4"` by default with mandatory keepalive/`tcpMptcp: false` `sockopt`) bound to the server's static IP and SHALL prohibit Cloudflare WARP, Tor, WireGuard, or arbitrary third-party proxy chains. In `bridge` mode, the proxy engine SHALL route all allowed outbound traffic solely through the single configured `vless` Reality outbound pointing to the owner's dedicated exit node IP (`<upstream_ip>:443`) using `firefox` uTLS by default (supporting either `"vision"` TCP with `mux` disabled or `"xhttp"` with `mode: "stream-up"`, `xPaddingBytes: "100-1000"`, and `xmux` rotation) and SHALL omit `freedom` (`direct`) outbounds so zero traffic can leak onto the domestic bridge network.

#### Scenario: Rendered engine config uses direct IPv4 freedom only
- **WHEN** the server Xray configuration is generated or validated in `exit` mode
- **THEN** outbounds contain only `direct` (`freedom` with `UseIPv4` and `sockopt` setting `tcpMptcp: false`) and `block` (`blackhole`), and any secondary tunnel protocol is rejected

#### Scenario: Rendered engine config uses fail-closed upstream VLESS only in bridge mode
- **WHEN** the server Xray configuration is generated or validated in `bridge` mode (in either `vision` or `xhttp` upstream transport mode)
- **THEN** outbounds contain only `proxy` (`vless` Reality to `<upstream_ip>:443` with default `fingerprint: "firefox"`, `sockopt.tcpMptcp: false`, and either `network: "tcp"` without `mux` or `network: "xhttp"` with `xPaddingBytes` and `xmux`) and `block` (`blackhole`), and `freedom` (`direct`) is absent
