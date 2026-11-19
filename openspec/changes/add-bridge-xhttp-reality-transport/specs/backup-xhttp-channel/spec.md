# Spec Delta

## MODIFIED Requirements

### Requirement: SSH CLI toggle for backup XHTTP channel
The system SHALL default the backup `VLESS + XHTTP` channel to disabled and SHALL allow the owner to enable or disable it on an exit node via `./script.sh xhttp on|off` using a 64-hex-character secret path, activating both the Nginx `location /<64-hex-secret>` proxy (`client_max_body_size 0;`) to `127.0.0.1:10086` and the VLESS Reality `fallbacks` (`{"dest": "127.0.0.1:10086"}`) on `:443` so `vless-xhttp-local` (`xPaddingBytes: "100-1000"`, `scMaxEachPostBytes: 1000000`) serves both direct `XHTTP + TLS` clients and `XHTTP + Reality + xmux` Cascade Bridge nodes simultaneously with `Vision`.

#### Scenario: Disabled backup channel exposes zero proxy locations in Nginx
- **WHEN** the backup XHTTP channel is disabled (default)
- **THEN** `appliance.conf` contains no `proxy_pass` location for XHTTP, `vless-reality-vision` (`:443`) contains no `fallbacks` to `10086`, and requests to the secret path return the static decoy 404 page

#### Scenario: Enabling backup channel via SSH activates secret XHTTP route
- **WHEN** the owner runs `./script.sh xhttp on` on an exit node
- **THEN** the local XHTTP inbound (`127.0.0.1:10086`) is enabled with `mode: "auto"`, `xPaddingBytes: "100-1000"`, and `scMaxEachPostBytes: 1000000`, `vless-reality-vision` (`:443`) adds `fallbacks` to `127.0.0.1:10086`, Nginx validates (`nginx -t`) and reloads with `location /<64-hex-secret>` (`client_max_body_size 0;`) proxying to `127.0.0.1:10086`, and active `Vision` connections remain operational
