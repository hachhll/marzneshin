# Design

## Context

See `proposal.md` for motivation. An external AI audit proposal (`DRIFT-TO-XHTTP.md`) suggested replacing `VLESS + TCP + Reality + Vision` entirely with `VLESS + XHTTP + Reality` and converting the Moscow node into a transparent L4 TCP relay (`iptables`/`haproxy`). Deep architectural analysis and empirical verification against `Xray-core v26.6.27` identified critical flaws in a naive full-replacement / L4-relay approach and established a superior **Dual-Mode L7 Reality (`Vision` + `XHTTP + Reality + xmux`)** architecture for the `Moscow (Bridge) -> Frankfurt (Exit)` link.

## Goals / Non-Goals

**Goals:**
- Defeat cross-border TSPU statistical/ML flow analysis on the aggregated `Moscow -> Frankfurt:443` trunk (5–10 concurrent users) via `XHTTP` packet-size padding (`xPaddingBytes: "100-1000"`), POST size capping (`scMaxEachPostBytes: 1000000`), and periodic HTTP/2 connection rotation (`xmux`).
- Maintain **Dual-Mode backward compatibility on Exit port `:443`** so `VLESS + TCP + Reality + Vision` and `VLESS + XHTTP + Reality` operate simultaneously on the same port and Reality keypair.
- Require **zero configuration changes** on end-user devices (`v2rayNG` on Android and `Throne` / `sing-box` on Windows 11 continue connecting to Moscow via `Vision`).
- Provide a **1-command zero-downtime switchover and 1-second rollback** (`./script.sh bridge-transport xhttp|vision`) and a **Zero-Emission verification protocol** that never emits anomalous `curl`/`openssl` probe packets between Moscow and Frankfurt.

**Non-Goals:**
- **Rejecting L4 TCP Relay in Moscow**: Converting the Moscow bridge from an L7 Xray Reality terminator into an L4 TCP port forwarder (`iptables DNAT` / `haproxy mode tcp`) is explicitly rejected because forwarding `<exit_domain>` SNI into a Russian IP leaks the foreign SNI to domestic TSPU and exposes identical TLS certificates across both IPs to active probes.
- **Rejecting removal of `Vision` on client ingress**: Native Xray `xhttp` (`SplitHTTP` + `xmux`) is not supported by `sing-box` (`throne-windows11.json`). Keeping `Vision` on client ingress preserves universal client compatibility while applying `XHTTP + Reality + xmux` between the two `Xray-core v26.6.27` servers.
- **Rejecting `Alt-Svc: h3=":443"`**: Since `UDP :443` is blocked in UFW, advertising HTTP/3 via `Alt-Svc` would be a deceptive fingerprint and cause browser delays.

## Decisions

- **Dual-Mode Reality Ingress via Inner VLESS `fallbacks` on Exit Port `:443`**
  - *Mechanism*:
    ```text
                        EXIT NODE (FRANKFURT) — PORT 0.0.0.0:443
                                           |
                       [ 1. Outer streamSettings: security="reality" ]
                                           |
            +------------------------------+------------------------------+
            | Unauthenticated (TSPU Probe / Browser)                      | Valid Reality ClientHello
            v                                                             v
    [ realitySettings.dest ]                                    [ VLESS Protocol (:443) ]
    127.0.0.1:8443 (Local Nginx)                                Inspects first inner frame:
    Serves decoy HTML or 444.                                             |
    Physically cannot reach :10086!                        +--------------+--------------+
                                                           |                             |
                                              Binary VLESS Header            HTTP/2 Frame (XHTTP)
                                              (xtls-rprx-vision)             (triggers settings.fallbacks)
                                                           |                             |
                                                           v                             v
                                              [ Handled in :443 Vision ]     [ 127.0.0.1:10086 ]
                                              (Direct clients /              (vless-xhttp-local:
                                               Bridge in vision mode)         path=/<64-hex>,
                                                                              xPaddingBytes="100-1000",
                                                                              scMaxEachPostBytes=1000000)
    ```
  - *Rationale*: Empirically verified on `Xray-core v26.6.27`: adding `"fallbacks": [{"dest": "127.0.0.1:10086"}]` inside `vless-reality-vision.settings` routes Reality-authenticated HTTP/2 `XHTTP` streams to `vless-xhttp-local` (`127.0.0.1:10086`) in `<0.1 ms` while keeping unauthenticated probes isolated at the outer Reality layer (`127.0.0.1:8443`) and keeping `Vision` active on `:443`.
  - *Alternative*: Replacing `:443` with `network: "xhttp"` only or opening a second external port (e.g., `:8444`); rejected because replacing breaks direct `Vision` clients and requires synchronized two-node cutover, while extra ports attract TSPU scanners.

- **`mode: "stream-up"` + `xmux` + `xPaddingBytes: "100-1000"` Without Artificial `scMinPostsIntervalMs` Delay**
  - *Rationale*: On the `Bridge -> Exit` outbound, `mode: "stream-up"` with `xPaddingBytes: "100-1000"` and `xmux` (`maxConcurrency: "16-32"`, `maxConnections: 0`, `cMaxReuseTimes: 0`, `hMaxRequestTimes: "600-900"`, `hMaxReusableSecs: "1800-3000"`) rotates underlying HTTP/2 connections every 600–900 requests or 30–50 minutes and pads packet lengths without adding per-packet POST buffering delay (`scMinPostsIntervalMs: "10-50"`), preserving WebRTC voice/video call quality.
  - *Alternative*: `mode: "packet-up"` with `scMinPostsIntervalMs: "10-50"`; rejected for the default bridge profile because 10–50 ms artificial uplink delay degrades real-time WebRTC audio/video calls.

- **Nginx `client_max_body_size 0;` on `location /<64-hex>`**
  - *Rationale*: Nginx defaults to `client_max_body_size 1m;`. Setting `client_max_body_size 0;` in `location /<64-hex>` ensures direct backup `XHTTP + TLS` clients sending padded `1000000`-byte POST bodies or streamed uploads never hit HTTP `413 Request Entity Too Large`.

- **Zero-Emission 3-Tier Testing Strategy**
  - *Tier 1 (Local `127.0.0.1` Docker E2E)*: `tests/test_cascade_e2e.py` tests `sing-box client -> Bridge Xray (xhttp+reality+xmux) -> Exit Xray (Dual-Mode :443 -> :10086)` completely inside loopback.
  - *Tier 2 (Passive Pre-Reload & Self-Test)*: `xray run -test` validates generated configs before service restart, and `./script.sh self-test` validates state/sockets passively (`0` packets emitted).
  - *Tier 3 (Production Verification via Standard Client Only)*: Never run `curl` or `openssl s_client` from the Moscow VPS toward the Frankfurt IP:443 (which leaks anomalous non-browser uTLS fingerprints across the monitored route). Verify solely by browsing through a normal connected client (`v2rayNG` / `Throne`).

## Risks / Trade-offs

- **Premature `xhttp off` on Exit While Bridge Uses `xhttp`** → Mitigated by strict operational ordering (always switch Bridge back to `vision` before running `xhttp off` on Exit) and clear CLI warnings printed by `./script.sh xhttp off`.
- **Bandwidth Overhead (~2–4%) from `xPaddingBytes: "100-1000"`** → Acceptable trade-off for masking control/handshake packet sizes on the cross-border trunk.

## Migration Plan

### Switchover Order (`Vision` -> `XHTTP + Reality + xmux`)
1. **Frankfurt (Exit Node — Receiver First)**:
   - Run `sudo ./script.sh xhttp on`.
   - Frankfurt enables `127.0.0.1:10086` (`vless-xhttp-local`) and `vless` `fallbacks` on `:443`, while continuing to serve `Vision` on `:443`. Copy the printed 64-hex `<XHTTP_SECRET_PATH>`.
2. **Moscow (Bridge Node — Transmitter Second)**:
   - Run `sudo ./script.sh bridge-transport xhttp --path <XHTTP_SECRET_PATH>`.
   - Moscow persists `upstream_xhttp_path` in `state.json`, validates the config via `xray run -test`, and reloads `xray` (~0.5s).
3. **Verification**:
   - Run `sudo ./script.sh self-test` (passive) and verify traffic from a connected client device.

### Rollback Order (`XHTTP + Reality + xmux` -> `Vision`)
- **Fast Rollback (1 second, Moscow only)**:
  1. Run `sudo ./script.sh bridge-transport vision` on **Moscow**. Frankfurt already accepts `Vision` on `:443`, so traffic resumes over `Vision` immediately without touching Frankfurt.
- **Full Rollback (if also disabling XHTTP on Frankfurt)**:
  1. **First on Moscow (Transmitter First)**: `sudo ./script.sh bridge-transport vision`.
  2. **Second on Frankfurt (Receiver Last)**: `sudo ./script.sh xhttp off`.
