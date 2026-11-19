# Spec Delta

## MODIFIED Requirements

### Requirement: Self-Reality ingress and PROXY protocol fallback
The VLESS Reality listener on TCP `:443` SHALL use `xtls-rprx-vision`, a non-empty 16-hex-character `shortId`, `maxTimeDiff: 60000`, and SHALL forward all non-Reality connections at the outer Reality layer to local Nginx on `127.0.0.1:8443` using `PROXY protocol` (`xver: 1`) in both `exit` mode and `bridge` mode before any inner `vless` `fallbacks` (`127.0.0.1:10086`) can be reached, while configuring `client_max_body_size 0;` on the Nginx XHTTP location when backup XHTTP is enabled.

#### Scenario: Valid Reality client establishes VPN tunnel
- **WHEN** a client or cascade bridge connects to `:443` with the owner's UUID, a timestamp within `maxTimeDiff`, and the configured non-empty `shortId` (using either `Vision` TCP or Reality-authenticated `XHTTP` via inner `vless` `fallbacks`)
- **THEN** the connection is terminated by `xray-core` and routed according to the server routing table

#### Scenario: Active TSPU probe or browser with matching SNI falls back to local Nginx
- **WHEN** a browser or DPI probe connects to `:443` without valid Reality authentication on either an exit node (even when `vless` `fallbacks` to `127.0.0.1:10086` is enabled) or a bridge node
- **THEN** the connection is transparently forwarded over `127.0.0.1:8443` with `PROXY protocol` to local Nginx without reaching `127.0.0.1:10086` and without generating any outbound TCP connections to external websites

### Requirement: Polymorphic static decoy masking without ETag, Last-Modified, or web panel paths
Nginx SHALL serve a benign decoy website on `/`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico`, and `/404.html` for `server_name <domain>`, configure `server_tokens off;`, `etag off;`, `if_modified_since off;`, `add_header Last-Modified "";`, and `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`, inject per-install randomized entropy into static decoy files, and expose zero `/api/`, `/sub/`, `/setup`, `/admin`, or `/dashboard/` locations.

#### Scenario: Any probe path on the domain returns static decoy HTML without ETag or Last-Modified
- **WHEN** a scanner or browser requests `/`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico`, `/sub/test`, `/api/status`, `/admin`, or `/dashboard` with `Host: <domain>`
- **THEN** Nginx serves static decoy content (`200` on `/`, `/robots.txt`, `/sitemap.xml`, and `/favicon.ico`; decoy `404` on unknown paths) with `Strict-Transport-Security` and without `ETag` or `Last-Modified` headers and with zero upstream proxy connections when backup XHTTP is disabled
