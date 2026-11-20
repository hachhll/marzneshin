# backup-xhttp-channel Specification

## Purpose

Provides an SSH-controlled optional `VLESS + XHTTP + TLS` backup transport behind Nginx on port 443 that can be toggled on or off via `script.sh` without dropping active `Vision` sessions.

## Requirements

### Requirement: SSH CLI toggle for backup XHTTP channel
The system SHALL default the backup `VLESS + XHTTP` channel to disabled and SHALL allow the owner to enable or disable it on an exit node via `./script.sh xhttp on|off` using a 64-hex-character secret path, activating both the Nginx `location /<64-hex-secret>` proxy (`client_max_body_size 0;`) to `127.0.0.1:10086` and the VLESS Reality `fallbacks` (`{"dest": "127.0.0.1:10086"}`) on `:443` so `vless-xhttp-local` (`xPaddingBytes: "100-1000"`, `scMaxEachPostBytes: 1000000`) serves both direct `XHTTP + TLS` clients and `XHTTP + Reality + xmux` Cascade Bridge nodes simultaneously with `Vision`.

#### Scenario: Disabled backup channel exposes zero proxy locations in Nginx
- **WHEN** the backup XHTTP channel is disabled (default)
- **THEN** `appliance.conf` contains no `proxy_pass` location for XHTTP, `vless-reality-vision` (`:443`) contains no `fallbacks` to `10086`, and requests to the secret path return the static decoy 404 page

#### Scenario: Enabling backup channel via SSH activates secret XHTTP route
- **WHEN** the owner runs `./script.sh xhttp on` on an exit node
- **THEN** the local XHTTP inbound (`127.0.0.1:10086`) is enabled with `mode: "auto"`, `xPaddingBytes: "100-1000"`, and `scMaxEachPostBytes: 1000000`, `vless-reality-vision` (`:443`) adds `fallbacks` to `127.0.0.1:10086`, Nginx validates (`nginx -t`) and reloads with `location /<64-hex-secret>` (`client_max_body_size 0;`) proxying to `127.0.0.1:10086`, and active `Vision` connections remain operational

### Requirement: Stable secret XHTTP path with SSH rotation
The system SHALL generate a persistent 64-hex-character secret path during initial setup and preserve it across `xhttp on|off` toggles unless `./script.sh rotate` is executed.

#### Scenario: Toggling backup channel preserves existing secret path and client profiles
- **WHEN** the owner runs `./script.sh xhttp off` and later `./script.sh xhttp on`
- **THEN** the same 64-hex secret path and UUID are reused so pre-exported Throne (Windows 11) and Android profiles require no re-import
