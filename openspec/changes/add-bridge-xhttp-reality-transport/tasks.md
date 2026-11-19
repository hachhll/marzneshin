# Tasks

## 1. Dual-Mode Exit & XHTTP Bridge Config Builder (`app/xray/config_builder.py`, `app/nginx/manager.py`, `app/utils/self_test.py`)

- [x] 1.1 Update `LocalXrayConfigBuilder.build_xhttp_inbound()` and `LocalXrayConfigBuilder.build()` in `app/xray/config_builder.py` so `vless-xhttp-local` (`127.0.0.1:10086`) includes `"mode": "auto"`, `"xPaddingBytes": "100-1000"`, and `"scMaxEachPostBytes": 1000000`, and `vless-reality-vision` (`:443`) adds `"fallbacks": [{"dest": f"127.0.0.1:{xhttp_port}"}]` when `xhttp_backup_enabled=True`; verify with unit tests in `tests/test_xray_config.py`.
- [x] 1.2 Extend `LocalXrayConfigBuilder.build_bridge()` and `validate_xray_config()` in `app/xray/config_builder.py` (and `check_xray_config_safety()` in `app/utils/self_test.py`) to support `upstream_transport: "vision" | "xhttp"` and `upstream_xhttp_path`, configuring `network: "xhttp"`, `security: "reality"`, `flow: ""`, and `xhttpSettings` (`path`, `mode: "stream-up"`, `xPaddingBytes: "100-1000"`, `xmux` with `maxConcurrency: "16-32"`, `hMaxRequestTimes: "600-900"`, `hMaxReusableSecs: "1800-3000"`) when `"xhttp"` is selected; verify with `tests/test_xray_config.py` and `tests/test_self_test.py`.
- [x] 1.3 Add `client_max_body_size 0;` to the Nginx `location /<64-hex>` block, add `Strict-Transport-Security` (`HSTS`) to the domain HTTPS block, and generate `/robots.txt`, `/sitemap.xml`, and `/favicon.ico` static decoy assets in `app/nginx/manager.py` and `app/nginx/decoys.py`; verify via `tests/test_nginx_manager.py`.

## 2. CLI Subcommands, Terminal Hints, and Switchover/Rollback (`app/cli.py`, `app/client/profile_generator.py`, `script.sh`)

- [x] 2.1 Update `app/client/profile_generator.py` (`format_terminal_credentials`) so exit nodes with XHTTP enabled print the 64-hex `XHTTP Secret Path` and ready-to-copy `sudo ./script.sh bridge-transport xhttp --path <64-hex>` command, and bridge nodes display their active upstream transport (`vision` or `xhttp`); verify with `tests/test_client_profiles.py`.
- [x] 2.2 Add `bridge-transport` subcommand (`vision` | `xhttp [--path <64-hex>]`) and `--upstream-transport` / `--upstream-xhttp-path` flags to `app/cli.py` and `script.sh` with pre-reload `xray run -test` validation and a safety reminder on `./script.sh xhttp off`; verify with `tests/test_installer.py`.

## 3. Isolated Loopback E2E Verification (`tests/test_cascade_e2e.py`)

- [x] 3.1 Extend `tests/test_cascade_e2e.py` to test Dual-Mode Exit (`:443` serving both `Vision` and `XHTTP + Reality + xmux` via `fallbacks -> 127.0.0.1:10086`) and atomic bridge switching (`vision -> xhttp -> vision`) entirely over `127.0.0.1`, and verify the full test suite passes via `.venv/bin/python -m pytest tests/ -v`.

## Workflow follow-up

- Sync delta specs into `openspec/specs/` and archive `add-bridge-xhttp-reality-transport` once implementation and verification are complete.
