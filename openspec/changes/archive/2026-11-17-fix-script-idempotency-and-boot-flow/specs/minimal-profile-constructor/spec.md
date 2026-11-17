# Spec Delta

## MODIFIED Requirements

### Requirement: Local terminal QR code and domain-based VLESS URI export
Upon installation (`./script.sh --domain <fqdn>` or `./script.sh --bridge ...`), rotation (`./script.sh rotate`), or status check (`./script.sh status`), the system SHALL print the primary `VLESS + Reality + Vision` URI (and the backup `VLESS + XHTTP + TLS` URI when enabled in `exit` mode) along with UTF-8/ANSI QR codes directly in the SSH terminal. In `exit` mode, the output SHALL also include a ready-to-copy `sudo ./script.sh --bridge ...` command pre-populated with the exit node's IP, domain, UUID, public key, and `shortId`. In `bridge` mode, client URIs and profiles SHALL connect to the bridge's host/IP on `:443` while setting `sni` to the configured `<bridge_sni>` FQDN.

#### Scenario: Terminal output includes scannable UTF-8 QR code and domain-based xudp VLESS URI
- **WHEN** `./script.sh status` (or initial install) finishes on an exit node or bridge node
- **THEN** stdout contains a valid `vless://` URI with `security=reality`, `flow=xtls-rprx-vision`, `fp=chrome`, `packetEncoding=xudp`, a multi-line UTF-8 QR code block, and (on an exit node) the copy-paste `--bridge` setup command
