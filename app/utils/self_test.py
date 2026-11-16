import argparse
import asyncio
import json
import os
import re
import socket
import ssl
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

import httpx
from cryptography import x509

from app.config.env import (
    NGINX_HTTPS_FALLBACK_PORT,
    NGINX_RUNTIME_DIR,
    XRAY_CONFIG_PATH,
    XRAY_LISTEN_PORT,
)
from app.xray.config_builder import (
    TELEMETRY_BLACKHOLE_DOMAINS,
    validate_xray_config,
)

FORBIDDEN_PROCESS_TOKENS = (
    "wg-quick",
    "wireguard",
    "warp-svc",
    "cloudflare-warp",
    "obfs4proxy",
)
FORBIDDEN_EXACT_NAMES = {"tor", "warp-cli"}


@dataclass
class SelfTestCheck:
    name: str
    passed: bool
    detail: str

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SelfTestReport:
    passed: bool
    checks: list[SelfTestCheck]

    def model_dump(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checks": [c.model_dump() for c in self.checks],
        }


def detect_mode_from_config(config_path: str = XRAY_CONFIG_PATH) -> str:
    p = Path(config_path)
    if p.exists():
        try:
            cfg = json.loads(p.read_text(encoding="utf-8"))
            tags = {o.get("tag") for o in cfg.get("outbounds", [])}
            if "proxy" in tags and "direct" not in tags:
                return "bridge"
        except Exception:
            pass
    state_path = p.resolve().parent.parent / "state.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("mode") == "bridge":
                return "bridge"
        except Exception:
            pass
    return "exit"


def check_xray_config_safety(
    config_path: str = XRAY_CONFIG_PATH,
    expected_ipv6: bool = False,
    mode: Optional[str] = None,
) -> SelfTestCheck:
    p = Path(config_path)
    if not p.exists():
        return SelfTestCheck(
            name="xray_config_safety",
            passed=False,
            detail=f"Xray config not found at {config_path}",
        )
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
        resolved_mode = mode or detect_mode_from_config(config_path)
        validate_xray_config(
            cfg, expected_ipv6=expected_ipv6, mode=resolved_mode
        )
        log_cfg = cfg.get("log", {})
        allowed_log_sinks = (None, "", "none", "/dev/null")
        if (
            log_cfg.get("access") not in allowed_log_sinks
            or log_cfg.get("error") not in allowed_log_sinks
        ):
            raise ValueError(
                "Xray access/error logs must be disabled ('none' or '/dev/null')"
            )
        if resolved_mode == "bridge":
            warnings: list[str] = []
            primary = next(
                (i for i in cfg.get("inbounds", []) if i.get("tag") == "vless-reality-vision"),
                {},
            )
            inb_snis = primary.get("streamSettings", {}).get("realitySettings", {}).get("serverNames", [])
            proxy_ob = next((o for o in cfg.get("outbounds", []) if o.get("tag") == "proxy"), {})
            up_sni = proxy_ob.get("streamSettings", {}).get("realitySettings", {}).get("serverName", "")
            if inb_snis and up_sni and inb_snis[0].lower() == up_sni.lower():
                warnings.append(
                    f"shared bridge/upstream SNI '{up_sni}' (RCA Risk #1/#4: set separate --bridge-sni)"
                )
            cert_file = p.resolve().parent.parent / "certs" / "fullchain.pem"
            if cert_file.exists():
                try:
                    cert_obj = x509.load_pem_x509_certificate(cert_file.read_bytes())
                    if "CN=localhost" in cert_obj.subject.rfc4514_string():
                        warnings.append(
                            "bridge fallback uses CN=localhost dummy cert (RCA Risk #1: point a dedicated bridge domain + --bridge-acme)"
                        )
                except Exception:
                    pass
            detail = (
                "mode=bridge, log=none, dest=127.0.0.1:8443 (Zero-Loop), "
                "fail-closed vless Reality proxy outbound (no direct freedom), "
                "QUIC/STUN/::/0/telemetry blackholes active"
            )
            if warnings:
                detail = f"{detail}; WARN: {'; '.join(warnings)}"
        else:
            detail = (
                "log=none, sockopt tcpKeepAliveIdle=120, routeOnly=True, "
                "QUIC/STUN/::/0/telemetry blackholes active, gvt1/gvt2 allowed"
            )
        return SelfTestCheck(
            name="xray_config_safety",
            passed=True,
            detail=detail,
        )
    except Exception as exc:
        return SelfTestCheck(
            name="xray_config_safety",
            passed=False,
            detail=str(exc),
        )


def check_nginx_logging_and_tls_conf(
    nginx_runtime_dir: str = NGINX_RUNTIME_DIR,
) -> SelfTestCheck:
    main_conf = Path(nginx_runtime_dir) / "nginx.conf"
    app_conf = Path(nginx_runtime_dir) / "conf.d" / "appliance.conf"
    if not main_conf.exists() or not app_conf.exists():
        return SelfTestCheck(
            name="nginx_zero_log_and_tls13",
            passed=False,
            detail="Nginx runtime configuration files missing",
        )
    combined = (
        main_conf.read_text(encoding="utf-8")
        + "\n"
        + app_conf.read_text(encoding="utf-8")
    )
    missing = []
    if "access_log off;" not in combined:
        missing.append("access_log off")
    if "error_log /dev/null" not in combined:
        missing.append("error_log /dev/null")
    if "ssl_protocols TLSv1.3;" not in combined:
        missing.append("ssl_protocols TLSv1.3")
    if "proxy_protocol" not in combined:
        missing.append("proxy_protocol")
    if "etag off;" not in combined:
        missing.append("etag off")
    if "if_modified_since off;" not in combined:
        missing.append("if_modified_since off")
    if "server_name _;" not in combined or "return 444;" not in combined:
        missing.append("default_server 444 probe isolation")
    if any(tok in combined for tok in ("/sub/", "/api/", "/dashboard/")):
        missing.append("forbidden web/sub routes present")

    if missing:
        return SelfTestCheck(
            name="nginx_zero_log_and_tls13",
            passed=False,
            detail=f"Nginx safety violation: {', '.join(missing)}",
        )
    return SelfTestCheck(
        name="nginx_zero_log_and_tls13",
        passed=True,
        detail="access_log off, error_log /dev/null, TLSv1.3, proxy_protocol, etag off, and 444 probe isolation configured",
    )


def scan_forbidden_processes(
    proc_cmdlines: Optional[Iterable[list[str]]] = None,
) -> SelfTestCheck:
    found: list[str] = []
    if proc_cmdlines is None:
        cmdlines: list[list[str]] = []
        proc_dir = Path("/proc")
        if proc_dir.exists():
            for entry in proc_dir.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    raw = (entry / "cmdline").read_bytes()
                except OSError:
                    continue
                if raw:
                    parts = [
                        p
                        for p in raw.decode("utf-8", errors="ignore").split(
                            "\x00"
                        )
                        if p
                    ]
                    if parts:
                        cmdlines.append(parts)
    else:
        cmdlines = list(proc_cmdlines)

    for parts in cmdlines:
        exe = os.path.basename(parts[0]).lower()
        joined = " ".join(parts).lower()
        if exe in FORBIDDEN_EXACT_NAMES or any(
            tok in joined for tok in FORBIDDEN_PROCESS_TOKENS
        ):
            found.append(exe)

    if found:
        return SelfTestCheck(
            name="zero_tunnel_stacking",
            passed=False,
            detail=f"Forbidden overlay/tunnel process running: {', '.join(sorted(set(found)))}",
        )
    return SelfTestCheck(
        name="zero_tunnel_stacking",
        passed=True,
        detail="No WireGuard, WARP, or Tor processes detected",
    )


def _decode_proc_net_ipv4(hex_ip: str) -> str:
    val = int(hex_ip, 16)
    return socket.inet_ntoa(struct.pack("<I", val))


def _decode_proc_net_ipv6(hex_ip: str) -> str:
    raw = bytes.fromhex(hex_ip)
    parts = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(parts))


def check_exposed_ports(
    allowed_ports: set[int] | None = None,
    proc_tcp_lines: Optional[list[str]] = None,
    proc_tcp6_lines: Optional[list[str]] = None,
    mode: str = "exit",
) -> SelfTestCheck:
    raw_ssh_ports = os.environ.get("SSH_PORT", "22")
    ssh_ports = {
        int(tok)
        for tok in re.split(r"[\s,]+", raw_ssh_ports.strip())
        if tok.isdigit()
    } or {22}
    base_ports = {22, 443} if mode == "bridge" else {22, 80, 443}
    allowed = allowed_ports or (base_ports | ssh_ports)
    exposed: list[tuple[str, int]] = []

    def _scan(lines: list[str], ipv6: bool) -> None:
        for line in lines:
            cols = line.strip().split()
            if len(cols) < 4 or ":" not in cols[1]:
                continue
            state = cols[3].upper()
            if state != "0A":  # TCP_LISTEN
                continue
            hex_ip, hex_port = cols[1].split(":", 1)
            port = int(hex_port, 16)
            ip = (
                _decode_proc_net_ipv6(hex_ip)
                if ipv6
                else _decode_proc_net_ipv4(hex_ip)
            )
            is_loopback = ip.startswith("127.") or ip in (
                "::1",
                "::ffff:127.0.0.1",
            )
            if not is_loopback and port not in allowed:
                exposed.append((ip, port))

    if proc_tcp_lines is None:
        p4 = Path("/proc/net/tcp")
        proc_tcp_lines = p4.read_text().splitlines()[1:] if p4.exists() else []
    if proc_tcp6_lines is None:
        p6 = Path("/proc/net/tcp6")
        proc_tcp6_lines = (
            p6.read_text().splitlines()[1:] if p6.exists() else []
        )

    _scan(proc_tcp_lines, False)
    _scan(proc_tcp6_lines, True)

    if exposed:
        desc = ", ".join(f"{ip}:{port}" for ip, port in sorted(set(exposed)))
        return SelfTestCheck(
            name="minimal_port_exposure",
            passed=False,
            detail=f"Unexpected non-loopback listening ports: {desc}",
        )
    return SelfTestCheck(
        name="minimal_port_exposure",
        passed=True,
        detail=f"Only allowed external ports exposed ({sorted(allowed)})",
    )


def check_client_templates_safety() -> SelfTestCheck:
    tpl_dir = Path(__file__).resolve().parent.parent / "templates"
    try:
        sb = json.loads(
            (tpl_dir / "sing-box.json").read_text(encoding="utf-8")
        )
        xr = json.loads((tpl_dir / "xray.json").read_text(encoding="utf-8"))
    except Exception as exc:
        return SelfTestCheck(
            name="client_template_anti_drift",
            passed=False,
            detail=f"Failed reading client templates: {exc}",
        )

    sb_serialized = json.dumps(sb)
    xr_serialized = json.dumps(xr)
    if "dns-local" in sb_serialized or '"local"' in sb_serialized:
        return SelfTestCheck(
            name="client_template_anti_drift",
            passed=False,
            detail="sing-box template contains prohibited dns-local rule",
        )
    if '"urltest"' in sb_serialized:
        return SelfTestCheck(
            name="client_template_anti_drift",
            passed=False,
            detail="sing-box template contains prohibited urltest outbound (RCA Cause #3/#4)",
        )
    if "gvt1.com" in sb_serialized or "gvt1.com" in xr_serialized:
        return SelfTestCheck(
            name="client_template_anti_drift",
            passed=False,
            detail="Client templates must not block gvt1.com/gvt2.com",
        )
    if "geoip:ir" in xr_serialized or "domain:ir" in xr_serialized:
        return SelfTestCheck(
            name="client_template_anti_drift",
            passed=False,
            detail="xray template contains prohibited direct country bypass rules",
        )
    for dom in TELEMETRY_BLACKHOLE_DOMAINS[:3]:
        if dom not in sb_serialized or dom not in xr_serialized:
            return SelfTestCheck(
                name="client_template_anti_drift",
                passed=False,
                detail=f"Telemetry blackhole domain '{dom}' missing from client templates",
            )
    return SelfTestCheck(
        name="client_template_anti_drift",
        passed=True,
        detail="Remote DNS only, selector-only (no urltest), QUIC/STUN/::/0 blackholes, and gvt1/gvt2 allowance verified",
    )


async def probe_reality_and_nginx_tls13(
    domain: str,
    reality_port: int = XRAY_LISTEN_PORT,
    nginx_fallback_port: int = NGINX_HTTPS_FALLBACK_PORT,
) -> list[SelfTestCheck]:
    results: list[SelfTestCheck] = []

    # 1. Check live Xray Reality port reachable and completes TLS handshake
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1",
                reality_port,
                ssl=ctx,
                server_hostname=domain or "localhost",
            ),
            timeout=5.0,
        )
        writer.close()
        await writer.wait_closed()
        results.append(
            SelfTestCheck(
                name="live_reality_443_tls",
                passed=True,
                detail=f"Port {reality_port} accepts TLSv1.3 handshake for SNI '{domain}'",
            )
        )
    except Exception as exc:
        results.append(
            SelfTestCheck(
                name="live_reality_443_tls",
                passed=False,
                detail=f"Reality port {reality_port} probe failed: {exc}",
            )
        )

    # 2. Check Nginx loopback HTTPS fallback with matching SNI and PROXY protocol
    try:
        sock = socket.create_connection(
            ("127.0.0.1", nginx_fallback_port), timeout=5.0
        )
        try:
            sock.sendall(b"PROXY TCP4 127.0.0.1 127.0.0.1 12345 443\r\n")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            with ctx.wrap_socket(
                sock, server_hostname=domain or "localhost"
            ) as tls_sock:
                tls_sock.sendall(
                    f"GET / HTTP/1.1\r\nHost: {domain or 'localhost'}\r\nConnection: close\r\n\r\n".encode()
                )
                resp = tls_sock.recv(2048).decode("utf-8", errors="ignore")
            if "HTTP/1.1" in resp and "etag:" not in resp.lower():
                results.append(
                    SelfTestCheck(
                        name="nginx_decoy_tls13_fallback",
                        passed=True,
                        detail=f"Nginx fallback 127.0.0.1:{nginx_fallback_port} served decoy over TLSv1.3 without ETag",
                    )
                )
            else:
                results.append(
                    SelfTestCheck(
                        name="nginx_decoy_tls13_fallback",
                        passed=False,
                        detail="Nginx fallback returned non-HTTP response or leaked ETag header",
                    )
                )
        finally:
            sock.close()
    except Exception as exc:
        results.append(
            SelfTestCheck(
                name="nginx_decoy_tls13_fallback",
                passed=False,
                detail=f"Nginx fallback probe failed: {exc}",
            )
        )

    # 3. RCA Cause #2: Verify foreign/no-SNI probe gets neutral CN=localhost cert and 444 close
    if domain:
        try:
            sock = socket.create_connection(
                ("127.0.0.1", nginx_fallback_port), timeout=5.0
            )
            try:
                sock.sendall(b"PROXY TCP4 127.0.0.1 127.0.0.1 12345 443\r\n")
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                with ctx.wrap_socket(
                    sock, server_hostname="scanner.invalid"
                ) as tls_sock:
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    cert_obj = x509.load_der_x509_certificate(der_cert)
                    subj_str = cert_obj.subject.rfc4514_string()
                    tls_sock.sendall(
                        b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\nConnection: close\r\n\r\n"
                    )
                    probe_resp = tls_sock.recv(1024)
                if domain not in subj_str and probe_resp == b"":
                    results.append(
                        SelfTestCheck(
                            name="nginx_no_sni_probe_isolation",
                            passed=True,
                            detail=f"Foreign/no-SNI probe isolated ({subj_str}, HTTP closed with 444)",
                        )
                    )
                else:
                    results.append(
                        SelfTestCheck(
                            name="nginx_no_sni_probe_isolation",
                            passed=False,
                            detail=f"Foreign SNI leaked domain cert ({subj_str}) or returned HTTP data",
                        )
                    )
            finally:
                sock.close()
        except Exception as exc:
            results.append(
                SelfTestCheck(
                    name="nginx_no_sni_probe_isolation",
                    passed=False,
                    detail=f"Foreign/no-SNI probe check failed: {exc}",
                )
            )

    return results


async def check_egress_gl_not_ru(
    http_client: Optional[httpx.AsyncClient] = None,
) -> SelfTestCheck:
    headers = {
        "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8",
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
    }
    own_client = http_client is None
    client: Optional[httpx.AsyncClient] = None
    try:
        client = http_client or httpx.AsyncClient(
            timeout=8.0, follow_redirects=True, trust_env=False
        )
        resp = await client.get("https://www.youtube.com/", headers=headers)
        m = re.search(r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"', resp.text)
        if not m:
            return SelfTestCheck(
                name="egress_gl_not_ru",
                passed=False,
                detail="INNERTUBE_CONTEXT_GL missing in anonymous response",
            )
        gl = m.group(1)
        if gl == "RU":
            return SelfTestCheck(
                name="egress_gl_not_ru",
                passed=False,
                detail="Detected INNERTUBE_CONTEXT_GL=RU (high attribution/block risk)",
            )
        return SelfTestCheck(
            name="egress_gl_not_ru",
            passed=True,
            detail=f"Anonymous Google egress check passed (GL={gl} != RU)",
        )
    except Exception as exc:
        return SelfTestCheck(
            name="egress_gl_not_ru",
            passed=False,
            detail=f"Egress region check failed: {type(exc).__name__}: {exc}",
        )
    finally:
        if own_client and client is not None:
            await client.aclose()


async def check_triple_ai_egress(
    http_client: Optional[httpx.AsyncClient] = None,
) -> list[SelfTestCheck]:
    """Run anonymous egress reputation checks for Google Antigravity, OpenAI, and Anthropic."""
    headers = {
        "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8",
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
    }
    own_client = http_client is None
    client: Optional[httpx.AsyncClient] = None
    checks: list[SelfTestCheck] = []
    try:
        client = http_client or httpx.AsyncClient(
            timeout=8.0, follow_redirects=True, trust_env=False
        )
        # 1. Google / YouTube GL != RU
        checks.append(await check_egress_gl_not_ru(http_client=client))

        # 2. OpenAI cdn-cgi/trace (loc != RU and warp=off)
        try:
            oa_resp = await client.get(
                "https://chatgpt.com/cdn-cgi/trace", headers=headers
            )
            kv = dict(
                line.split("=", 1)
                for line in oa_resp.text.splitlines()
                if "=" in line
            )
            loc = kv.get("loc", "").strip().upper()
            warp = kv.get("warp", "off").strip().lower()
            if not loc:
                checks.append(
                    SelfTestCheck(
                        name="egress_openai_trace",
                        passed=False,
                        detail="OpenAI cdn-cgi/trace missing 'loc' field",
                    )
                )
            elif loc == "RU" or warp != "off":
                checks.append(
                    SelfTestCheck(
                        name="egress_openai_trace",
                        passed=False,
                        detail=f"OpenAI egress unsafe: loc={loc}, warp={warp}",
                    )
                )
            else:
                checks.append(
                    SelfTestCheck(
                        name="egress_openai_trace",
                        passed=True,
                        detail=f"OpenAI egress check passed (loc={loc} != RU, warp={warp})",
                    )
                )
        except Exception as exc:
            checks.append(
                SelfTestCheck(
                    name="egress_openai_trace",
                    passed=False,
                    detail=f"OpenAI trace check failed: {type(exc).__name__}: {exc}",
                )
            )

        # 3. Anthropic API reachability (no Cloudflare 403 ASN/country block)
        try:
            an_resp = await client.get(
                "https://api.anthropic.com/", headers=headers
            )
            if an_resp.status_code == 403 and (
                "attention required" in an_resp.text.lower()
                or "just a moment" in an_resp.text.lower()
                or "cf-mitigated" in {k.lower() for k in an_resp.headers.keys()}
            ):
                checks.append(
                    SelfTestCheck(
                        name="egress_anthropic_api",
                        passed=False,
                        detail="Anthropic API blocked this IP/ASN with Cloudflare 403",
                    )
                )
            else:
                checks.append(
                    SelfTestCheck(
                        name="egress_anthropic_api",
                        passed=True,
                        detail=f"Anthropic API reachable (HTTP {an_resp.status_code})",
                    )
                )
        except Exception as exc:
            checks.append(
                SelfTestCheck(
                    name="egress_anthropic_api",
                    passed=False,
                    detail=f"Anthropic API check failed: {type(exc).__name__}: {exc}",
                )
            )
    finally:
        if own_client and client is not None:
            await client.aclose()

    return checks


async def run_self_test(
    *,
    domain: str = "",
    ipv6_egress_enabled: bool = False,
    xray_config_path: str = XRAY_CONFIG_PATH,
    nginx_runtime_dir: str = NGINX_RUNTIME_DIR,
    reality_port: int = XRAY_LISTEN_PORT,
    nginx_fallback_port: int = NGINX_HTTPS_FALLBACK_PORT,
    include_network_probes: bool = False,
    mode: Optional[str] = None,
) -> SelfTestReport:
    resolved_mode = mode or detect_mode_from_config(xray_config_path)
    checks: list[SelfTestCheck] = [
        check_xray_config_safety(
            xray_config_path,
            expected_ipv6=ipv6_egress_enabled,
            mode=resolved_mode,
        ),
        check_nginx_logging_and_tls_conf(nginx_runtime_dir),
        scan_forbidden_processes(),
        check_exposed_ports(mode="bridge")
        if resolved_mode == "bridge"
        else check_exposed_ports(),
        check_client_templates_safety(),
    ]
    if include_network_probes and resolved_mode != "bridge":
        checks.extend(
            await probe_reality_and_nginx_tls13(
                domain=domain,
                reality_port=reality_port,
                nginx_fallback_port=nginx_fallback_port,
            )
        )
        checks.extend(await check_triple_ai_egress())

    return SelfTestReport(
        passed=all(c.passed for c in checks),
        checks=checks,
    )


def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zero-Emission local anti-drift self-test"
    )
    parser.add_argument(
        "--active-probe",
        action="store_true",
        help="Explicitly run active loopback and external egress probes (Exit Node only)",
    )
    args = parser.parse_args(argv)

    domain = os.environ.get("APPLIANCE_DOMAIN", "")
    ipv6 = os.environ.get("IPV6_EGRESS_ENABLED", "false").lower() in (
        "1",
        "true",
        "yes",
    )

    report = asyncio.run(
        run_self_test(
            domain=domain,
            ipv6_egress_enabled=ipv6,
            include_network_probes=bool(args.active_probe),
        )
    )
    for chk in report.checks:
        tag = "PASS" if chk.passed else "FAIL"
        print(f"[{tag}] {chk.name}: {chk.detail}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(_main())
