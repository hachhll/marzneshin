import hashlib
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
    "firebaselogging.googleapis.com",
    "firebaselogging-pa.googleapis.com",
]

SINGBOX_TELEMETRY_DOMAIN_SUFFIXES = [
    "app-measurement.com",
    "firebase-settings.crashlytics.com",
]

SELECTIVE_ANDROID_DIRECT_PACKAGES = [
    "com.google.android.apps.messaging",
    "com.google.android.dialer",
]

SELECTIVE_DIRECT_BYPASS_DOMAINS = [
    "mobileconfiguration-pa.googleapis.com",
    "reminders-pa.googleapis.com",
    "mtalk.google.com",
    "alt1-mtalk.google.com",
    "alt2-mtalk.google.com",
    "alt3-mtalk.google.com",
    "alt4-mtalk.google.com",
    "alt5-mtalk.google.com",
    "alt6-mtalk.google.com",
    "alt7-mtalk.google.com",
    "alt8-mtalk.google.com",
]

PODKOP_COMMUNITY_RULESET_BASE = (
    "https://github.com/itdoginfo/allow-domains/releases/latest/download"
)

PODKOP_COMMUNITY_RULESET_NAMES = [
    "discord",
    "google_ai",
    "google_play",
    "telegram",
    "meta",
    "twitter",
    "russia_inside",
]

# Pure domain-only rule-sets safe inside dns.rules on sing-box 1.14+ (others include ip_cidr/port_range
# and stay in route.rules while their domains are covered by SELECTIVE_VPN_DOMAIN_SUFFIXES).
PODKOP_DNS_DOMAIN_RULESET_NAMES = [
    "google_ai",
    "google_play",
    "russia_inside",
]

SELECTIVE_VPN_DOMAIN_SUFFIXES = [
    # Netflix / Streaming
    "netflix.com",
    "netflix.net",
    "nflximg.net",
    "nflxvideo.net",
    "nflxso.net",
    "nflxext.com",
    "fast.com",
    # Google / Antigravity / YouTube / Gemini / NotebookLM
    "google.com",
    "google.ru",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "gstatic.com",
    "gvt1.com",
    "gvt2.com",
    "ggpht.com",
    "ytimg.com",
    "youtube.com",
    "youtu.be",
    "withgoogle.com",
    "deepmind.google",
    "antigravity.google",
    "antigravityide.net",
    "notebooklm.google",
    "notebooklm-enterprise.google",
    "gemini.google",
    "labs.google",
    "google.dev",
    "google.ai",
    "ai.google",
    "ai.dev",
    "g.co",
    "goo.gl",
    "firebaseapp.com",
    "gmail.com",
    "recaptcha.net",
    # OpenAI / Anthropic / AI IDEs
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "sora.com",
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "claude.usercontent.com",
    "claudeusercontent.com",
    "claudemcpclient.com",
    "cursor.com",
    "cursor.sh",
    "cursor-cdn.com",
    "windsurf.com",
    "codeium.com",
    "perplexity.ai",
    "huggingface.co",
    # Databricks / Okta / Auth0
    "databricks.com",
    "databricks.com.cn",
    "databricks.cfg",
    "databricks-labs.com",
    "databricks-prod-cloudfront.com",
    "azuredatabricks.net",
    "databricksusercontent.com",
    "evently.com",
    "databriks.com",
    "databriks.net",
    "okta.com",
    "oktacdn.com",
    "oktapreview.com",
    "okta-emea.com",
    "auth0.com",
    "auth0.net",
    # Discord / Telegram
    "discord.com",
    "discordapp.com",
    "discordapp.net",
    "discord.gg",
    "discord.media",
    "discordstatus.com",
    "discordcdn.com",
    "telegram.org",
    "t.me",
    "tdesktop.com",
    "telesco.pe",
    "telegra.ph",
    "tg.dev",
    "telegram.me",
    # Social Media (Instagram / Facebook / Meta / X / LinkedIn)
    "instagram.com",
    "cdninstagram.com",
    "facebook.com",
    "fbcdn.net",
    "fbsbx.com",
    "fb.com",
    "meta.com",
    "threads.net",
    "x.com",
    "twitter.com",
    "twimg.com",
    "t.co",
    "linkedin.com",
    "licdn.com",
]

TELEGRAM_DC_CIDRS = [
    "149.154.160.0/20",
    "91.105.192.0/23",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "185.76.151.0/24",
]

SELECTIVE_WINDOWS_PROCESSES = [
    "Antigravity.exe",
    "Antigravity IDE.exe",
    "language_server_windows_x64.exe",
    "agy.exe",
    "Cursor.exe",
    "Windsurf.exe",
    "Claude.exe",
    "ChatGPT.exe",
    "Discord.exe",
    "Telegram.exe",
    "firefox.exe",
    "brave.exe",
]

SELECTIVE_ANDROID_PACKAGES = [
    "com.google.android.youtube",
    "com.google.android.apps.youtube.music",
    "com.openai.chatgpt",
    "com.anthropic.claude",
    "com.google.android.apps.bard",
    "com.discord",
    "org.telegram.messenger",
    "org.telegram.messenger.web",
    "org.thunderdog.challegram",
    "com.instagram.android",
    "com.facebook.katana",
    "com.twitter.android",
    "com.linkedin.android",
    "org.mozilla.firefox",
    "com.brave.browser",
]

CLIENT_PROFILE_VERSION = "v1"
SINGBOX_TARGET_MIN_VERSION = "1.14"

MEDIA_SELECTIVE_DOMAIN_SUFFIXES = [
    # YouTube
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "youtubei.googleapis.com",
    # Instagram / Meta
    "instagram.com",
    "cdninstagram.com",
    "fbcdn.net",
    "facebook.com",
    "ig.me",
    # Telegram
    "telegram.org",
    "t.me",
    "tdesktop.com",
    "telesco.pe",
    "telegra.ph",
    "tg.dev",
    "telegram.me",
    # TikTok
    "tiktok.com",
    "tiktokv.com",
    "tiktokcdn.com",
    "tiktokcdn-eu.com",
    "tiktokcdn-us.com",
    "byteoversea.com",
    "ibytedtos.com",
    "muscdn.com",
    "musical.ly",
    "ttwstatic.com",
    # WhatsApp
    "whatsapp.com",
    "whatsapp.net",
    "wa.me",
]

MEDIA_SELECTIVE_ANDROID_PACKAGES = [
    "com.google.android.youtube",
    "com.google.android.apps.youtube.music",
    "com.instagram.android",
    "org.telegram.messenger",
    "org.telegram.messenger.web",
    "org.thunderdog.challegram",
    "com.zhiliaoapp.musically",
    "com.ss.android.ugc.trill",
    "com.whatsapp",
    "com.whatsapp.w4b",
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


SUPPORTED_SINGBOX_PLATFORMS = frozenset(
    {"windows11-throne", "android", "ios", "linux", "openwrt"}
)


def _build_singbox_dns_and_route(
    *,
    platform: str,
    strategy: str,
    ipv6_egress_enabled: bool,
    routing_mode: str,
    selective_domains: list[str] | None = None,
    selective_apps: list[str] | None = None,
    selective_cidrs: list[str] | None = None,
    include_podkop_rulesets: bool | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build DNS and route config blocks for either full-tunnel or selective whitelist mode."""
    base_dns_servers: list[dict[str, Any]] = [
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
    ]
    telemetry_reject_rule: dict[str, Any] = {
        "domain": list(SINGBOX_TELEMETRY_EXACT_DOMAINS),
        "domain_suffix": list(SINGBOX_TELEMETRY_DOMAIN_SUFFIXES),
        "action": "reject",
    }

    is_windows = platform == "windows11-throne"
    is_android = platform == "android"
    is_ios = platform == "ios"
    is_linux = platform == "linux"
    is_openwrt = platform == "openwrt"

    if routing_mode == "full":
        route_rules: list[dict[str, Any]] = [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"protocol": ["quic", "stun", "bittorrent"], "action": "reject"},
            {"network": "udp", "port": [443, 3478, 19302], "action": "reject"},
            telemetry_reject_rule,
            {"ip_is_private": True, "action": "reject"},
        ]
        if not ipv6_egress_enabled:
            route_rules.append({"ip_cidr": ["::/0"], "action": "reject"})
        route_cfg: dict[str, Any] = {
            "rules": route_rules,
            "final": "proxy",
            "auto_detect_interface": True,
        }
        if is_android:
            route_cfg["override_android_vpn"] = True
        dns_cfg: dict[str, Any] = {
            "servers": base_dns_servers,
            "rules": [{"query_type": "HTTPS", "action": "reject"}],
            "final": "dns-remote",
            "strategy": strategy,
        }
        return dns_cfg, route_cfg

    use_podkop = (
        include_podkop_rulesets
        if include_podkop_rulesets is not None
        else (not is_ios and not is_openwrt)
    )
    app_field = "process_name" if is_windows else "package_name"
    default_apps: list[str] = []
    if is_windows:
        default_apps = SELECTIVE_WINDOWS_PROCESSES
    elif is_android:
        default_apps = SELECTIVE_ANDROID_PACKAGES
    apps = list(default_apps if selective_apps is None else selective_apps)
    domains = list(
        SELECTIVE_VPN_DOMAIN_SUFFIXES
        if selective_domains is None
        else selective_domains
    )
    cidrs = list(TELEGRAM_DC_CIDRS if selective_cidrs is None else selective_cidrs)
    use_http_client_v14 = not is_windows and not is_openwrt
    http_client_tag = "proxy-http"
    podkop_rulesets = (
        [
            (
                {
                    "type": "remote",
                    "tag": f"podkop-{name}",
                    "format": "binary",
                    "url": f"{PODKOP_COMMUNITY_RULESET_BASE}/{name}.srs",
                    "http_client": http_client_tag,
                    "update_interval": "1d",
                }
                if use_http_client_v14
                else {
                    "type": "remote",
                    "tag": f"podkop-{name}",
                    "format": "binary",
                    "url": f"{PODKOP_COMMUNITY_RULESET_BASE}/{name}.srs",
                    "download_detour": "proxy",
                    "update_interval": "1d",
                }
            )
            for name in PODKOP_COMMUNITY_RULESET_NAMES
        ]
        if use_podkop
        else []
    )
    podkop_tags = [rs["tag"] for rs in podkop_rulesets]
    podkop_dns_tags = [f"podkop-{name}" for name in PODKOP_DNS_DOMAIN_RULESET_NAMES]

    dns_rules: list[dict[str, Any]] = [
        {"query_type": "HTTPS", "action": "reject"},
    ]
    if apps and (is_windows or is_android):
        dns_rules.append({app_field: apps, "action": "route", "server": "dns-remote"})
    if is_android:
        dns_rules.append(
            {
                "package_name": list(SELECTIVE_ANDROID_DIRECT_PACKAGES),
                "action": "route",
                "server": "dns-local",
            }
        )
    dns_rules.append(
        {
            "domain": list(SELECTIVE_DIRECT_BYPASS_DOMAINS),
            "action": "route",
            "server": "dns-local",
        }
    )
    dns_rules.append(
        {"domain_suffix": [".ru", ".su", ".xn--p1ai"], "action": "route", "server": "dns-local"}
    )
    if use_podkop:
        dns_rules.append(
            {"rule_set": podkop_dns_tags, "action": "route", "server": "dns-remote"}
        )
    if domains:
        dns_rules.append(
            {"domain_suffix": domains, "action": "route", "server": "dns-remote"}
        )

    dns_cfg = {
        "servers": [*base_dns_servers, {"type": "local", "tag": "dns-local"}],
        "rules": dns_rules,
        "final": "dns-local",
        "strategy": strategy,
    }

    route_rules: list[dict[str, Any]] = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "action": "route", "outbound": "direct"},
        telemetry_reject_rule,
    ]
    if not ipv6_egress_enabled:
        route_rules.append({"ip_cidr": ["::/0"], "action": "reject"})
    route_rules.extend(
        [
            {"protocol": ["quic", "stun", "bittorrent"], "action": "reject"},
            {"network": "udp", "port": [443, 3478, 19302], "action": "reject"},
        ]
    )
    if is_windows or is_linux:
        route_rules.extend(
            [
                {
                    "inbound": ["mixed-in"],
                    "network": "udp",
                    "port": [443, 3478, 19302],
                    "action": "reject",
                },
                {"inbound": ["mixed-in"], "action": "route", "outbound": "proxy"},
            ]
        )
    if apps and (is_windows or is_android):
        route_rules.extend(
            [
                {
                    app_field: apps,
                    "network": "udp",
                    "port": [443, 3478, 19302],
                    "action": "reject",
                },
                {app_field: apps, "action": "route", "outbound": "proxy"},
            ]
        )
    if is_android:
        route_rules.append(
            {
                "package_name": list(SELECTIVE_ANDROID_DIRECT_PACKAGES),
                "action": "route",
                "outbound": "direct",
            }
        )
    route_rules.append(
        {
            "domain": list(SELECTIVE_DIRECT_BYPASS_DOMAINS),
            "action": "route",
            "outbound": "direct",
        }
    )
    if use_podkop:
        route_rules.extend(
            [
                {
                    "rule_set": podkop_tags,
                    "network": "udp",
                    "port": [443, 3478, 19302],
                    "action": "reject",
                },
                {"rule_set": podkop_tags, "action": "route", "outbound": "proxy"},
            ]
        )
    if domains:
        route_rules.extend(
            [
                {
                    "domain_suffix": domains,
                    "network": "udp",
                    "port": [443, 3478, 19302],
                    "action": "reject",
                },
                {"domain_suffix": domains, "action": "route", "outbound": "proxy"},
            ]
        )
    if cidrs:
        route_rules.append({"ip_cidr": cidrs, "action": "route", "outbound": "proxy"})

    route_cfg: dict[str, Any] = {
        "rules": route_rules,
        "final": "direct",
        "default_domain_resolver": "dns-local",
    }
    if podkop_rulesets:
        route_cfg["rule_set"] = podkop_rulesets
    if not is_openwrt:
        route_cfg["auto_detect_interface"] = True
    if use_http_client_v14:
        route_cfg["default_http_client"] = http_client_tag
    if is_android:
        route_cfg["override_android_vpn"] = True
    return dns_cfg, route_cfg


def _build_singbox_inbounds(platform: str) -> list[dict[str, Any]]:
    if platform == "openwrt":
        return [
            {
                "type": "tproxy",
                "tag": "tproxy-in",
                "listen": "0.0.0.0",
                "listen_port": 7895,
            }
        ]
    tun_inb: dict[str, Any] = {
        "type": "tun",
        "tag": "tun-in",
        "address": [
            "172.19.0.1/30",
            "fdfe:dcba:9876::1/126",
        ],
        "auto_route": True,
        "strict_route": True,
    }
    if platform != "ios":
        tun_inb["interface_name"] = (
            "throne-tun" if platform == "windows11-throne" else "sbtun0"
        )
    inbounds: list[dict[str, Any]] = [tun_inb]
    if platform in {"windows11-throne", "linux"}:
        inbounds.append(
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        )
    return inbounds


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
    routing_mode: str = "full",
    selective_domains: list[str] | None = None,
    selective_apps: list[str] | None = None,
    selective_cidrs: list[str] | None = None,
    include_podkop_rulesets: bool | None = None,
) -> dict[str, Any]:
    """Generate hardened sing-box JSON for Windows 11, Android, iOS, Linux, or OpenWrt."""
    clean_platform = (platform or "windows11-throne").strip().lower()
    if clean_platform not in SUPPORTED_SINGBOX_PLATFORMS:
        raise ValueError(
            f"Unsupported sing-box platform '{platform}': expected one of {sorted(SUPPORTED_SINGBOX_PLATFORMS)}"
        )
    clean_mode = (routing_mode or "full").strip().lower()
    if clean_mode not in {"full", "selective"}:
        raise ValueError(
            f"Unsupported routing_mode '{routing_mode}': expected 'full' or 'selective'"
        )
    if clean_platform == "openwrt" and clean_mode != "selective":
        raise ValueError(
            "OpenWrt router profile must use 'selective' mode to avoid household LAN Full Tunnel leaks onto exit-ai"
        )
    connect_host, sni = _resolve_connect_host_and_sni(domain, server_host)
    validate_short_ids([reality_short_id])
    clean_fp = validate_utls_fingerprint(fingerprint)

    strategy = "prefer_ipv4" if ipv6_egress_enabled else "ipv4_only"
    inbounds = _build_singbox_inbounds(clean_platform)

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
    if clean_mode == "selective":
        outbounds.append({"type": "direct", "tag": "direct"})

    dns_cfg, route_cfg = _build_singbox_dns_and_route(
        platform=clean_platform,
        strategy=strategy,
        ipv6_egress_enabled=ipv6_egress_enabled,
        routing_mode=clean_mode,
        selective_domains=selective_domains,
        selective_apps=selective_apps,
        selective_cidrs=selective_cidrs,
        include_podkop_rulesets=include_podkop_rulesets,
    )

    cache_cfg: dict[str, Any] = {"enabled": True}
    if clean_platform not in {"windows11-throne", "openwrt"}:
        cache_cfg["store_dns"] = True

    profile: dict[str, Any] = {
        "log": {"level": "error"},
        "dns": dns_cfg,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route_cfg,
        "experimental": {
            "cache_file": cache_cfg,
        },
    }
    if clean_mode == "selective" and clean_platform not in {
        "windows11-throne",
        "openwrt",
    }:
        profile["http_clients"] = [{"tag": "proxy-http", "detour": "proxy"}]
    return profile


def build_media_selective_profile(
    *,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    platform: str = "android",
    port: int = 443,
    server_host: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> dict[str, Any]:
    """Generate mobile-only vanilla sing-box (>= 1.14) Media-Selective JSON."""
    clean_platform = (platform or "").strip().lower()
    if clean_platform not in {"android", "ios"}:
        raise ValueError(
            f"media-consumer profiles are strictly mobile-only ('android' or 'ios', got '{platform}')"
        )
    return build_singbox_profile(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        include_xhttp_backup=False,
        platform=clean_platform,
        port=port,
        ipv6_egress_enabled=False,
        server_host=server_host,
        fingerprint=fingerprint,
        routing_mode="selective",
        selective_domains=list(MEDIA_SELECTIVE_DOMAIN_SUFFIXES),
        selective_apps=(
            list(MEDIA_SELECTIVE_ANDROID_PACKAGES)
            if clean_platform == "android"
            else []
        ),
        selective_cidrs=list(TELEGRAM_DC_CIDRS),
        include_podkop_rulesets=False,
    )


def build_openwrt_outbound_profile(
    *,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    port: int = 443,
    server_host: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
) -> dict[str, Any]:
    """Generate standalone VLESS+Reality+Vision outbound JSON for OpenWrt podkop."""
    connect_host, sni = _resolve_connect_host_and_sni(domain, server_host)
    validate_short_ids([reality_short_id])
    clean_fp = validate_utls_fingerprint(fingerprint)
    return {
        "outbounds": [
            {
                "type": "vless",
                "tag": "proxy",
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
        ]
    }


def build_singbox_selective_profile(
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
    selective_domains: list[str] | None = None,
    selective_apps: list[str] | None = None,
    selective_cidrs: list[str] | None = None,
) -> dict[str, Any]:
    """Generate whitelist-only sing-box profile: all traffic direct except selected apps/services."""
    return build_singbox_profile(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        xhttp_secret_path=xhttp_secret_path,
        include_xhttp_backup=include_xhttp_backup,
        platform=platform,
        port=port,
        ipv6_egress_enabled=ipv6_egress_enabled,
        server_host=server_host,
        fingerprint=fingerprint,
        routing_mode="selective",
        selective_domains=selective_domains,
        selective_apps=selective_apps,
        selective_cidrs=selective_cidrs,
    )


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


def _compute_bundle_manifest(
    files: dict[str, Path],
    *,
    profile_role: str,
    profile_version: str = CLIENT_PROFILE_VERSION,
    singbox_min_version: str = SINGBOX_TARGET_MIN_VERSION,
    username: str | None = None,
) -> tuple[dict[str, Any], str]:
    file_hashes: dict[str, str] = {}
    digest_acc = hashlib.sha256()
    for p in sorted(files.values(), key=lambda item: item.name):
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        file_hashes[p.name] = h
        digest_acc.update(f"{p.name}:{h}\n".encode("utf-8"))
    bundle_sha256 = digest_acc.hexdigest()
    manifest: dict[str, Any] = {
        "profile_role": profile_role,
        "profile_version": profile_version,
        "singbox_min_version": singbox_min_version,
        "bundle_sha256": bundle_sha256,
        "files": file_hashes,
    }
    if username:
        manifest["user"] = username
    if profile_role == "ai-owner":
        manifest["warning"] = (
            "Admin-only ai-owner bundle: NEVER share links.txt or exit-ai profiles with media users."
        )
    else:
        manifest["note"] = (
            "Import JSON locally via sing-box >= 1.14 (Android SFA or iOS sing-box MT -> Profiles -> + -> Local)."
        )
    return manifest, bundle_sha256


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
    profile_version: str = CLIENT_PROFILE_VERSION,
    username: str | None = None,
) -> dict[str, Path]:
    """Write ready-to-import 5-OS ai-owner suite (Windows, Android, iOS, Linux, OpenWrt, Xray, links)."""
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

    include_backup = bool(xhttp_secret_path and not server_host)
    common_sb_kwargs: dict[str, Any] = {
        "domain": domain,
        "user_uuid": user_uuid,
        "reality_public_key": reality_public_key,
        "reality_short_id": reality_short_id,
        "xhttp_secret_path": xhttp_secret_path,
        "include_xhttp_backup": include_backup,
        "port": port,
        "ipv6_egress_enabled": ipv6_egress_enabled,
        "server_host": server_host,
        "fingerprint": clean_fp,
    }
    singbox_targets = (
        ("throne", "throne-windows11.json", "windows11-throne", "full"),
        ("throne_selective", "throne-windows11-selective.json", "windows11-throne", "selective"),
        ("android", "android-singbox.json", "android", "full"),
        ("android_selective", "android-singbox-selective.json", "android", "selective"),
        ("ios", "ios-singbox.json", "ios", "full"),
        ("ios_selective", "ios-singbox-selective.json", "ios", "selective"),
        ("linux", "linux-singbox.json", "linux", "full"),
        ("linux_selective", "linux-singbox-selective.json", "linux", "selective"),
        ("openwrt_singbox", "openwrt-singbox.json", "openwrt", "selective"),
    )
    paths: dict[str, Path] = {}
    for key, filename, sb_platform, r_mode in singbox_targets:
        cfg = build_singbox_profile(
            platform=sb_platform,
            routing_mode=r_mode,
            **common_sb_kwargs,
        )
        p = out / filename
        p.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        paths[key] = p

    openwrt_ob_cfg = build_openwrt_outbound_profile(
        domain=domain,
        user_uuid=user_uuid,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        port=port,
        server_host=server_host,
        fingerprint=clean_fp,
    )
    openwrt_ob_path = out / "openwrt-outbound.json"
    openwrt_ob_path.write_text(
        json.dumps(openwrt_ob_cfg, indent=2) + "\n", encoding="utf-8"
    )
    paths["openwrt_outbound"] = openwrt_ob_path

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

    xray_path = out / "xray-client.json"
    links_path = out / "links.txt"

    xray_path.write_text(json.dumps(xray_cfg, indent=2) + "\n", encoding="utf-8")
    links_path.write_text("\n".join(uris) + "\n", encoding="utf-8")

    paths["xray"] = xray_path
    paths["links"] = links_path

    manifest, _ = _compute_bundle_manifest(
        paths,
        profile_role="ai-owner",
        profile_version=profile_version,
        username=username,
    )
    manifest_path = out / "bundle-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    paths["manifest"] = manifest_path
    return paths


def write_user_bundle(
    credentials_dir: str | Path,
    *,
    username: str,
    profile: str,
    domain: str,
    user_uuid: str,
    reality_public_key: str,
    reality_short_id: str,
    xhttp_secret_path: str = "",
    port: int = 443,
    ipv6_egress_enabled: bool = False,
    server_host: str | None = None,
    fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
    profile_version: str = CLIENT_PROFILE_VERSION,
) -> dict[str, Any]:
    """Write isolated per-user role-scoped client profiles under users/<username>/."""
    clean_profile = (profile or "").strip().lower()
    if clean_profile not in {"ai-owner", "media-selective"}:
        raise ValueError(
            f"Unsupported profile '{profile}': expected 'ai-owner' or 'media-selective'"
        )
    user_dir = Path(credentials_dir) / "users" / username
    user_dir.mkdir(parents=True, exist_ok=True)
    clean_fp = validate_utls_fingerprint(fingerprint)

    if clean_profile == "ai-owner":
        paths = write_client_bundle(
            user_dir,
            domain=domain,
            user_uuid=user_uuid,
            reality_public_key=reality_public_key,
            reality_short_id=reality_short_id,
            xhttp_secret_path=xhttp_secret_path,
            port=port,
            ipv6_egress_enabled=ipv6_egress_enabled,
            server_host=server_host,
            fingerprint=clean_fp,
            profile_version=profile_version,
            username=username,
        )
        manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
        return {
            "bundle_dir": user_dir,
            "paths": paths,
            "profile_version": manifest["profile_version"],
            "singbox_min_version": manifest["singbox_min_version"],
            "profile_sha256": manifest["bundle_sha256"],
        }

    # Strictly mobile-only Media-Selective bundle: NO links.txt, NO desktop/router files.
    for stale_file in (
        "links.txt",
        "xray-client.json",
        "throne-windows11.json",
        "throne-windows11-selective.json",
        "android-singbox.json",
        "android-singbox-selective.json",
        "ios-singbox.json",
        "ios-singbox-selective.json",
        "linux-singbox.json",
        "linux-singbox-selective.json",
        "openwrt-singbox.json",
        "openwrt-outbound.json",
    ):
        (user_dir / stale_file).unlink(missing_ok=True)

    paths: dict[str, Path] = {}
    for key, filename, mob_platform in (
        ("android_media", "android-media-selective.json", "android"),
        ("ios_media", "ios-media-selective.json", "ios"),
    ):
        cfg = build_media_selective_profile(
            domain=domain,
            user_uuid=user_uuid,
            reality_public_key=reality_public_key,
            reality_short_id=reality_short_id,
            platform=mob_platform,
            port=port,
            server_host=server_host,
            fingerprint=clean_fp,
        )
        p = user_dir / filename
        p.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        paths[key] = p

    manifest, bundle_sha256 = _compute_bundle_manifest(
        paths,
        profile_role="media-selective",
        profile_version=profile_version,
        username=username,
    )
    manifest_path = user_dir / "bundle-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    paths["manifest"] = manifest_path
    return {
        "bundle_dir": user_dir,
        "paths": paths,
        "profile_version": profile_version,
        "singbox_min_version": SINGBOX_TARGET_MIN_VERSION,
        "profile_sha256": bundle_sha256,
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
    upstream_transport: str = "vision",
    upstream_xhttp_path: str = "",
) -> str:
    """Format SSH terminal summary with VLESS URIs, UTF-8 QR code, and multi-OS instructions."""
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
        clean_up_transport = (upstream_transport or "vision").strip().lower()
        if clean_up_transport == "xhttp":
            transport_desc = "transport=xhttp+reality+xmux, mode=stream-up"
            toggle_hint = "sudo ./script.sh bridge-transport vision"
        else:
            transport_desc = "transport=vision, flow=xtls-rprx-vision"
            path_arg = upstream_xhttp_path or "<XHTTP_SECRET_PATH>"
            toggle_hint = f"sudo ./script.sh bridge-transport xhttp --path {path_arg}"
        title = (
            f" ZERO-LOOP VLESS CASCADE BRIDGE ({server_host or domain} -> {upstream_domain or upstream_ip})"
        )
        bridge_section = (
            "Cascade Bridge Topology (Zero-Emission / Fail-Closed):\n"
            f"  - Bridge Entry:     {server_host or domain}:{port} (SNI={domain})\n"
            f"  - Local Fallback:   127.0.0.1:8443 (0 external probe loops)\n"
            f"  - Frankfurt Exit:   {upstream_ip}:443 (SNI={upstream_domain}, uTLS={clean_upstream_fp}, {transport_desc})\n"
            f"  - Switch Transport: {toggle_hint}\n\n"
        )
    else:
        title = f" ZERO-SURFACE VLESS SELF-REALITY APPLIANCE ({domain})"
        exit_ip_val = server_ip or "<FRANKFURT_SERVER_IP>"
        xhttp_bridge_flags = ""
        xhttp_switch_hint = ""
        if xhttp_secret_path:
            xhttp_bridge_flags = (
                f" \\\n    --upstream-transport xhttp \\\n    --upstream-xhttp-path {xhttp_secret_path}"
            )
            xhttp_switch_hint = (
                f"  Existing Moscow Bridge Switch Command (XHTTP+Reality+xmux default):\n"
                f"    sudo ./script.sh bridge-transport xhttp --path {xhttp_secret_path} --upstream-ip {exit_ip_val} --upstream-domain {domain} --upstream-uuid {user_uuid} --upstream-pbk {reality_public_key} --upstream-sid {reality_short_id}\n"
            )
        bridge_section = (
            "Moscow Cascade Bridge Setup Command (Run on clean Ubuntu 26 RU server):\n"
            "  sudo ./script.sh --bridge \\\n"
            f"    --upstream-ip {exit_ip_val} \\\n"
            f"    --upstream-domain {domain} \\\n"
            f"    --upstream-uuid {user_uuid} \\\n"
            f"    --upstream-pbk {reality_public_key} \\\n"
            f"    --upstream-sid {reality_short_id}{xhttp_bridge_flags} \\\n"
            "    --bridge-sni <DEDICATED_BRIDGE_DOMAIN> --bridge-acme\n"
            f"{xhttp_switch_hint}"
            "  (Do NOT reuse upstream domain/AI server for general family traffic; see AGENTS.md)\n\n"
        )

    return (
        "======================================================================\n"
        f"{title}\n"
        "======================================================================\n"
        f"Primary VLESS (Reality + Vision) [ACTIVE] (admin-only — do NOT share raw URI):\n  {vision_uri}\n"
        f"{xhttp_line}\n"
        "Scan QR Code (admin-only — never distribute to media-consumer users):\n"
        f"{qr_block}\n\n"
        f"{bridge_section}"
        "Client Profile Bundle Saved To:\n"
        f"  - Windows 11 Throne (Full Tunnel):     {credentials_dir}/throne-windows11.json\n"
        f"  - Windows 11 Throne (Selective VPN):   {credentials_dir}/throne-windows11-selective.json\n"
        f"  - Android sing-box (Full Tunnel):      {credentials_dir}/android-singbox.json\n"
        f"  - Android sing-box (Selective VPN):    {credentials_dir}/android-singbox-selective.json\n"
        f"  - iOS sing-box MT (Full Tunnel):       {credentials_dir}/ios-singbox.json\n"
        f"  - iOS sing-box MT (Selective VPN):     {credentials_dir}/ios-singbox-selective.json\n"
        f"  - Linux sing-box (Full / Selective):   {credentials_dir}/linux-singbox.json\n"
        f"  - OpenWrt Router (tproxy / podkop):    {credentials_dir}/openwrt-singbox.json | openwrt-outbound.json\n"
        f"  - Xray Client JSON:                    {credentials_dir}/xray-client.json\n"
        f"  - VLESS Links (admin-only):            {credentials_dir}/links.txt\n\n"
        "Anti-Ban Checklist (Google Antigravity / Anthropic / OpenAI):\n"
        "  1. Windows 11 Throne: Import throne-windows11.json and enable TUN Mode (strict_route).\n"
        "  2. Android / iOS: Disable Location Accuracy & iCloud Private Relay; import JSON locally.\n"
        "  3. Passive Zero-Emission Self-Test: ./script.sh self-test\n"
        "======================================================================"
    )
