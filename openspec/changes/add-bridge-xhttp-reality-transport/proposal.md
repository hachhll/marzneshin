# Proposal

## Why

When 5–10 users connect through the domestic Cascade Bridge (Moscow) to the foreign Exit node (Frankfurt), their traffic aggregates onto a single cross-border IP pair (`Moscow -> Frankfurt:443`). While `VLESS + TCP + Reality + Vision` protects individual handshakes, a long-lived high-throughput TCP connection between two fixed VPS IPs is vulnerable to cross-border TSPU statistical/ML flow analysis (session duration, packet-size distribution, and lack of connection rotation). Adding an optional `VLESS + XHTTP + Reality + xmux` upstream transport on the `Bridge -> Exit` leg masks packet lengths (`xPaddingBytes: "100-1000"`) and periodically rotates HTTP/2 sessions (`xmux`) while keeping end-user client profiles (`v2rayNG`, Windows 11 `Throne`/`sing-box`) and direct `Vision` access completely unchanged.

## What Changes

- Enable **Dual-Mode Reality (`Vision` + `XHTTP` fallback) on Exit node port `:443`**: when `./script.sh xhttp on` is active on the Exit node, `vless-reality-vision` (`:443`) adds `"fallbacks": [{"dest": "127.0.0.1:10086"}]` inside `vless.settings`, forwarding Reality-authenticated HTTP/2 (`XHTTP`) streams to `vless-xhttp-local` (`127.0.0.1:10086`) while continuing to serve `xtls-rprx-vision` clients directly on `:443` and sending unauthenticated probes to Nginx (`127.0.0.1:8443`).
- Harden `vless-xhttp-local` (`127.0.0.1:10086`) with `xhttpSettings` obfuscation (`"mode": "auto"`, `"xPaddingBytes": "100-1000"`, `"scMaxEachPostBytes": 1000000`), set `client_max_body_size 0;` on the Nginx `location /<64-hex>` block, and harden the Nginx static decoy gateway with `Strict-Transport-Security` (`HSTS`) plus generated `/robots.txt`, `/sitemap.xml`, and `/favicon.ico` assets so active TSPU web crawlers see a complete site structure.
- Extend Cascade Bridge outbound configuration (`LocalXrayConfigBuilder.build_bridge`) to support `upstream_transport: "vision" | "xhttp"`:
  - `"vision"` (default): `network: "tcp"`, `security: "reality"`, `flow: "xtls-rprx-vision"`.
  - `"xhttp"`: `network: "xhttp"`, `security: "reality"`, `flow: ""`, `xhttpSettings` with `path: "/<64-hex>"`, `mode: "stream-up"` (preserving low-latency WebRTC calls without artificial `scMinPostsIntervalMs` jitter), `xPaddingBytes: "100-1000"`, and `xmux` connection rotation (`maxConcurrency: "16-32"`, `hMaxRequestTimes: "600-900"`, `hMaxReusableSecs: "1800-3000"`).
- Add `./script.sh bridge-transport xhttp [--path <64-hex>]` and `./script.sh bridge-transport vision` SSH CLI subcommands (plus `--upstream-xhttp-path` / `--upstream-transport` installer flags) for 1-second atomic switching and rollback on the bridge node with pre-reload `xray run -test` validation.
- Update exit-node terminal output (`status` / `xhttp on`) to display the 64-hex `XHTTP` secret path and copy-paste `bridge-transport xhttp` command, and extend passive `self-test` / `validate_xray_config` and isolated `127.0.0.1` E2E tests (`test_cascade_e2e.py`) to verify dual-mode `Vision` + `XHTTP + Reality` operation.

## Capabilities

### New Capabilities
<!-- None; extends existing capabilities. -->

### Modified Capabilities
- `single-server-vless-core`: Dual-mode `vless` `fallbacks` (`:443 -> 127.0.0.1:10086`) on Exit node, `xPaddingBytes`/`scMaxEachPostBytes` on `vless-xhttp-local`, and dual-transport (`vision` | `xhttp` with `xmux` and `stream-up`) support on Cascade Bridge `proxy` outbound.
- `backup-xhttp-channel`: Shared `vless-xhttp-local` (`127.0.0.1:10086`) serving both Reality-authenticated `XHTTP` cascade streams (via VLESS `fallbacks`) and Nginx TLS `XHTTP` backup streams when `xhttp on` is enabled.
- `seamless-docker-setup-wizard`: `./script.sh bridge-transport xhttp|vision` CLI subcommand, `--upstream-xhttp-path` / `--upstream-transport` flags, ordered zero-drop switchover/rollback workflow, and pre-reload config validation.
- `self-reality-nginx-gateway`: `client_max_body_size 0;` on Nginx `location /<64-hex>` XHTTP proxy block so large/chunked `XHTTP` POST bodies never trigger HTTP `413`.
- `minimal-profile-constructor`: Terminal credential export on Exit nodes prints the 64-hex `XHTTP` secret path and ready-to-copy `bridge-transport xhttp --path <64-hex>` command when XHTTP is enabled.
- `anti-drift-safety-policy`: Config validator and passive `self-test` accept both `vision` (`tcp`) and `xhttp` (`xPaddingBytes`, `xmux`) on the Bridge `proxy` outbound while preserving zero-emission testing and fail-closed egress invariants.

## Impact

- Affected code: `app/xray/config_builder.py`, `app/nginx/manager.py`, `app/client/profile_generator.py`, `app/cli.py`, `app/utils/self_test.py`, `script.sh`.
- Affected tests: `tests/test_xray_config.py`, `tests/test_nginx_manager.py`, `tests/test_installer.py`, `tests/test_self_test.py`, `tests/test_cascade_e2e.py`.
