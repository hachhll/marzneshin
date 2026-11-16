import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from app.client.qr import render_qr_utf8
from app.nginx.manager import validate_domain, validate_xhttp_path
from app.xray.config_builder import (
    DEFAULT_UTLS_FINGERPRINT,
    DEFAULT_VLESS_SOCKOPT,
    PRIVATE_IP_BLACKHOLE_CIDRS,
    SAFE_DNS_SERVERS,
    TELEMETRY_BLACKHOLE_DOMAINS,
    validate_short_ids,
    validate_utls_fingerprint,
)

SINGBOX_TELEMETRY_EXACT_DOMAINS = [
    "location.googleapis.com",
    "connectivitycheck.android.com",
    "connectivitycheck.gstatic.com",
]

SINGBOX_TELEMETRY_DOMAIN_SUFFIXES = [
    "app-measurement.com",
    "firebase-settings.crashlytics.com",
]


def _ensure_not_ip_host(domain: str) -> str:
    clean = validate_domain(domain)
    try:
        ipaddress.ip_address(clean)
        raise ValueError(
            f"Client profile host '{clean}' must be an FQDN, not a raw IP address (RCA Cause #2)"
        )
    except ValueError as exc:
        if "RCA Cause #2" in str(exc):
            raise
    return clean


def _resolve_connect_host_and_sni(
    domain: str, server_host: str | None = None
) -> tuple[str, str]:
    sni = _ensure_not_ip_host(domain)
    if not server_host:
        return sni, sni
    raw_host = server_host.strip()
    try:
        ip_obj = ipaddress.ip_address(raw_host)
        if ip_obj.version != 4:
            raise ValueError("Bridge server_host IP must be IPv4")
        return str(ip_obj), sni
    except ValueError as exc:
        if "IPv4" in str(exc):
            raise
        return validate_domain(raw_host), sni


def build_vless_vision_uri(
    *,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    port: int = 443,
    remark: str | None = None,
    server_host: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> str:
    connect_host, sni = _resolve_connect_host_and_sni(domain, server_host)
    validate_short_ids([reality_short_id])
    clean_fp = validate_utls_fingerprint(fingerprint)
    if not reality_public_key:
        raise ValueError("reality_public_key is required")
    query = urlencode(
        {
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": sni,
            "fp": clean_fp,
            "pbk": reality_public_key,
            "sid": reality_short_id,
            "type": "tcp",
            "headerType": "none",
            "packetEncoding": "xudp",
        }
    )
    tag = quote(remark or f"{sni}-Vision")
    return f"vless://{user_uuid}@{connect_host}:{port}?{query}#{tag}"


def build_vless_xhttp_uri(
    *,
    domain: str,
    user_uuid: str,
    xhttp_secret_path: str,
    port: int = 443,
    remark: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> str:
    host = _ensure_not_ip_host(domain)
    clean_path = "/" + validate_xhttp_path(xhttp_secret_path)
    clean_fp = validate_utls_fingerprint(fingerprint)
    query = urlencode(
        {
            "encryption": "none",
            "security": "tls",
            "sni": host,
            "fp": clean_fp,
            "alpn": "h2",
            "type": "xhttp",
            "path": clean_path,
            "mode": "auto",
            "packetEncoding": "xudp",
        }
    )
    tag = quote(remark or f"{host}-XHTTP-Backup")
    return f"vless://{user_uuid}@{host}:{port}?{query}#{tag}"


def build_singbox_profile(
    *,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    xhttp_secret_path: str = "",
    include_xhttp_backup: bool = True,
    platform: str = "windows11-throne",
    port: int = 443,
    ipv6_egress_enabled: bool = False,
    server_host: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> dict[str, Any]:
    """Generate hardened sing-box JSON for Windows 11 Throne or Android."""
    connect_host, sni = _resolve_connect_host_and_sni(domain, server_host)
    validate_short_ids([reality_short_id])
    clean_fp = validate_utls_fingerprint(fingerprint)

    strategy = "prefer_ipv4" if ipv6_egress_enabled else "ipv4_only"
    tun_iface = (
        "throne-tun" if platform == "windows11-throne" else "sbtun0"
    )

    inbounds: list[dict[str, Any]] = [
        {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": tun_iface,
            "address": [
                "172.19.0.1/30",
                "fdfe:dcba:9876::1/126",
            ],
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
        }
    ]
    if platform == "windows11-throne":
        inbounds.append(
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        )

    vision_outbound: dict[str, Any] = {
        "type": "vless",
        "tag": "vless-vision",
        "server": connect_host,
        "server_port": port,
        "uuid": user_uuid,
        "flow": "xtls-rprx-vision",
        "packet_encoding": "xudp",
        "connect_timeout": "5s",
        "tcp_keep_alive": "2m",
        "tcp_keep_alive_interval": "30s",
        "tls": {
            "enabled": True,
            "server_name": sni,
            "utls": {
                "enabled": True,
                "fingerprint": clean_fp,
            },
            "reality": {
                "enabled": True,
                "public_key": reality_public_key,
                "short_id": reality_short_id,
            },
        },
    }

    selector_members = ["vless-vision"]
    vless_outbounds = [vision_outbound]

    if include_xhttp_backup and xhttp_secret_path:
        clean_path = "/" + validate_xhttp_path(xhttp_secret_path)
        xhttp_outbound: dict[str, Any] = {
            "type": "vless",
            "tag": "vless-xhttp-backup",
            "server": connect_host,
            "server_port": port,
            "uuid": user_uuid,
            "packet_encoding": "xudp",
            "connect_timeout": "5s",
            "tcp_keep_alive": "2m",
            "tcp_keep_alive_interval": "30s",
            "tls": {
                "enabled": True,
                "server_name": sni,
                "alpn": ["h2"],
                "utls": {
                    "enabled": True,
                    "fingerprint": clean_fp,
                },
            },
            "transport": {
                "type": "http",
                "host": [sni],
                "path": clean_path,
            },
        }
        selector_members.append("vless-xhttp-backup")
        vless_outbounds.append(xhttp_outbound)

    # RCA Cause #3 & #4: Manual selector only (no urltest) so the client never
    # simultaneously opens Reality and Nginx Fallback sessions on the same IP:443:SNI.
    outbounds: list[dict[str, Any]] = [
        {
            "type": "selector",
            "tag": "proxy",
            "default": "vless-vision",
            "outbounds": selector_members,
            "interrupt_exist_connections": True,
        },
        *vless_outbounds,
    ]

    route_rules: list[dict[str, Any]] = [
        {
            "action": "sniff",
        },
        {
            "protocol": "dns",
            "action": "hijack-dns",
        },
        {
            "protocol": ["quic", "stun", "bittorrent"],
            "action": "reject",
        },
        {
            "network": "udp",
            "port": [443, 3478, 19302],
            "action": "reject",
        },
        {
            "domain": list(SINGBOX_TELEMETRY_EXACT_DOMAINS),
            "domain_suffix": list(SINGBOX_TELEMETRY_DOMAIN_SUFFIXES),
            "action": "reject",
        },
        {
            "ip_is_private": True,
            "action": "reject",
        },
    ]
    if not ipv6_egress_enabled:
        route_rules.append(
            {
                "ip_cidr": ["::/0"],
                "action": "reject",
            }
        )

    route_cfg: dict[str, Any] = {
        "rules": route_rules,
        "final": "proxy",
        "auto_detect_interface": True,
    }
    if platform != "windows11-throne":
        route_cfg["override_android_vpn"] = True

    return {
        "log": {"level": "error"},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dns-remote",
                    "server": "1.1.1.1",
                    "server_port": 53,
                    "detour": "proxy",
                },
                {
                    "type": "udp",
                    "tag": "dns-backup",
                    "server": "8.8.8.8",
                    "server_port": 53,
                    "detour": "proxy",
                },
            ],
            "final": "dns-remote",
            "strategy": strategy,
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route_cfg,
        "experimental": {
            "cache_file": {
                "enabled": True,
                "store_rdrc": True,
            }
        },
    }


def build_xray_client_profile(
    *,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    port: int = 443,
    ipv6_egress_enabled: bool = False,
    server_host: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> dict[str, Any]:
    """Generate hardened Xray client config with DNS-over-proxy and QUIC/STUN/::/0 blackholes."""
    connect_host, sni = _resolve_connect_host_and_sni(domain, server_host)
    validate_short_ids([reality_short_id])
    clean_fp = validate_utls_fingerprint(fingerprint)
    strategy = "UseIP" if ipv6_egress_enabled else "UseIPv4"
    ip_blocks = list(PRIVATE_IP_BLACKHOLE_CIDRS)
    if not ipv6_egress_enabled and "::/0" not in ip_blocks:
        ip_blocks.append("::/0")

    return {
        "log": {"loglevel": "none"},
        "dns": {
            "queryStrategy": strategy,
            "disableFallbackIfMatch": True,
            "servers": list(SAFE_DNS_SERVERS),
            "tag": "dns_out",
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": connect_host,
                            "port": port,
                            "users": [
                                {
                                    "id": user_uuid,
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ],
                    "packetEncoding": "xudp",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": sni,
                        "fingerprint": clean_fp,
                        "publicKey": reality_public_key,
                        "shortId": reality_short_id,
                    },
                    "sockopt": dict(DEFAULT_VLESS_SOCKOPT),
                },
            },
            {
                "tag": "block",
                "protocol": "blackhole",
            },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["dns_out"],
                    "outboundTag": "proxy",
                },
                {
                    "type": "field",
                    "network": "udp",
                    "port": "443,3478,19302",
                    "outboundTag": "block",
                },
                {
                    "type": "field",
                    "protocol": ["bittorrent", "quic"],
                    "outboundTag": "block",
                },
                {
                    "type": "field",
                    "domain": list(TELEMETRY_BLACKHOLE_DOMAINS),
                    "outboundTag": "block",
                },
                {
                    "type": "field",
                    "ip": ip_blocks,
                    "outboundTag": "block",
                },
                {
                    "type": "field",
                    "inboundTag": ["socks", "http"],
                    "outboundTag": "proxy",
                },
            ],
        },
    }


def write_client_bundle(
    output_dir: str | Path,
    *,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    xhttp_secret_path: str = "",
    xhttp_backup_enabled: bool = False,
    port: int = 443,
    ipv6_egress_enabled: bool = False,
    server_host: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> dict[str, Path]:
    """Write ready-to-import Windows 11 Throne, Android, Xray, and URI files to disk."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    clean_fp = validate_utls_fingerprint(fingerprint)

    vision_uri = build_vless_vision_uri(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        port=port,
        server_host=server_host,
        fingerprint=clean_fp,
    )
    uris = [vision_uri]
    if xhttp_secret_path and not server_host:
        xhttp_uri = build_vless_xhttp_uri(
            domain=domain,
            user_uuid=user_uuid,
            xhttp_secret_path=xhttp_secret_path,
            port=port,
            fingerprint=clean_fp,
        )
        uris.append(xhttp_uri)

    throne_cfg = build_singbox_profile(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        xhttp_secret_path=xhttp_secret_path,
        include_xhttp_backup=bool(xhttp_secret_path and not server_host),
        platform="windows11-throne",
        port=port,
        ipv6_egress_enabled=ipv6_egress_enabled,
        server_host=server_host,
        fingerprint=clean_fp,
    )
    android_cfg = build_singbox_profile(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        xhttp_secret_path=xhttp_secret_path,
        include_xhttp_backup=bool(xhttp_secret_path and not server_host),
        platform="android",
        port=port,
        ipv6_egress_enabled=ipv6_egress_enabled,
        server_host=server_host,
        fingerprint=clean_fp,
    )
    xray_cfg = build_xray_client_profile(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        port=port,
        ipv6_egress_enabled=ipv6_egress_enabled,
        server_host=server_host,
        fingerprint=clean_fp,
    )

    throne_path = out / "throne-windows11.json"
    android_path = out / "android-singbox.json"
    xray_path = out / "xray-client.json"
    links_path = out / "links.txt"

    throne_path.write_text(json.dumps(throne_cfg, indent=2) + "\n", encoding="utf-8")
    android_path.write_text(json.dumps(android_cfg, indent=2) + "\n", encoding="utf-8")
    xray_path.write_text(json.dumps(xray_cfg, indent=2) + "\n", encoding="utf-8")
    links_path.write_text("\n".join(uris) + "\n", encoding="utf-8")

    return {
        "throne": throne_path,
        "android": android_path,
        "xray": xray_path,
        "links": links_path,
    }


def format_terminal_credentials(
    *,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    xhttp_secret_path: str = "",
    xhttp_backup_enabled: bool = False,
    credentials_dir: str = "/root/vpn-credentials",
    port: int = 443,
    server_host: str | None = None,
    mode: str = "exit",
    server_ip: str = "",
    upstream_ip: str = "",
    upstream_domain: str = "",
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
    upstream_fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> str:
    """Format SSH terminal summary with VLESS URIs, UTF-8 QR code, and Throne/Android instructions."""
    clean_fp = validate_utls_fingerprint(fingerprint)
    clean_upstream_fp = validate_utls_fingerprint(upstream_fingerprint)
    vision_uri = build_vless_vision_uri(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        port=port,
        server_host=server_host,
        fingerprint=clean_fp,
    )
    qr_block = render_qr_utf8(vision_uri)
    xhttp_status = "ENABLED" if xhttp_backup_enabled else "DISABLED (standby)"
    xhttp_line = ""
    if xhttp_secret_path and mode != "bridge":
        xhttp_uri = build_vless_xhttp_uri(
            domain=domain,
            user_uuid=user_uuid,
            xhttp_secret_path=xhttp_secret_path,
            port=port,
            fingerprint=clean_fp,
        )
        xhttp_line = f"\nBackup VLESS (XHTTP + TLS) [{xhttp_status}]:\n  {xhttp_uri}\n"

    if mode == "bridge":
        title = (
            f" ZERO-LOOP VLESS CASCADE BRIDGE ({server_host or domain} -> {upstream_domain or upstream_ip})"
        )
        bridge_section = (
            "Cascade Bridge Topology (Zero-Emission / Fail-Closed):\n"
            f"  - Bridge Entry:     {server_host or domain}:{port} (SNI={domain})\n"
            f"  - Local Fallback:   127.0.0.1:8443 (0 external probe loops)\n"
            f"  - Frankfurt Exit:   {upstream_ip}:443 (SNI={upstream_domain}, uTLS={clean_upstream_fp}, flow=xtls-rprx-vision)\n\n"
        )
    else:
        title = f" ZERO-SURFACE VLESS SELF-REALITY APPLIANCE ({domain})"
        exit_ip_val = server_ip or "<FRANKFURT_SERVER_IP>"
        bridge_section = (
            "Moscow Cascade Bridge Setup Command (Run on clean Ubuntu 26 RU server):\n"
            "  sudo ./script.sh --bridge \\\n"
            f"    --upstream-ip {exit_ip_val} \\\n"
            f"    --upstream-domain {domain} \\\n"
            f"    --upstream-uuid {user_uuid} \\\n"
            f"    --upstream-pbk {reality_public_key} \\\n"
            f"    --upstream-sid {reality_short_id} \\\n"
            "    --bridge-sni <DEDICATED_BRIDGE_DOMAIN> --bridge-acme\n"
            "  (Do NOT reuse upstream domain/AI server for general family traffic; see RISK_TRACKING_AND_MITIGATION.md)\n\n"
        )

    return (
        "======================================================================\n"
        f"{title}\n"
        "======================================================================\n"
        f"Primary VLESS (Reality + Vision) [ACTIVE]:\n  {vision_uri}\n"
        f"{xhttp_line}\n"
        "Scan QR Code (Android v2rayNG / NekoBox / Sing-box):\n"
        f"{qr_block}\n\n"
        f"{bridge_section}"
        "Client Profile Bundle Saved To:\n"
        f"  - Windows 11 Throne (sing-box TUN): {credentials_dir}/throne-windows11.json\n"
        f"  - Android (sing-box TUN):           {credentials_dir}/android-singbox.json\n"
        f"  - Xray Client JSON:                 {credentials_dir}/xray-client.json\n"
        f"  - VLESS Links:                      {credentials_dir}/links.txt\n\n"
        "Anti-Ban Checklist (Google Antigravity / Anthropic / OpenAI):\n"
        "  1. Windows 11 Throne: Import throne-windows11.json and enable TUN Mode (strict_route).\n"
        "  2. Android: Disable Google Location Accuracy & Wi-Fi/Bluetooth background scanning.\n"
        "  3. Passive Zero-Emission Self-Test: ./script.sh self-test\n"
        "======================================================================"
    )
