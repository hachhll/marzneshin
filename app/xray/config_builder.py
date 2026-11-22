import base64
import ipaddress
import os
import re
import secrets
from typing import Any

from nacl.public import PrivateKey

from app.config.env import (
    NGINX_HTTPS_FALLBACK_PORT,
    XRAY_API_ADDRESS,
    XRAY_LISTEN_PORT,
    XRAY_XHTTP_PORT,
)

PRIMARY_INBOUND_TAG = "vless-reality-vision"
BACKUP_XHTTP_INBOUND_TAG = "vless-xhttp-local"
API_INBOUND_TAG = "api"

TELEMETRY_BLACKHOLE_DOMAINS = [
    "location.googleapis.com",
    "connectivitycheck.android.com",
    "connectivitycheck.gstatic.com",
    "domain:app-measurement.com",
    "domain:firebase-settings.crashlytics.com",
]

RU_EGRESS_BLACKHOLE_DOMAINS = [
    "domain:ru",
    "domain:su",
    "domain:xn--p1ai",
]

RU_EGRESS_BLACKHOLE_GEOIPS = [
    "geoip:ru",
]

BRIDGE_XMUX_MAX_REUSABLE_SECS = "180-300"
BRIDGE_XMUX_MAX_REUSABLE_CEIL_SECS = 600

FORBIDDEN_BLACKHOLE_DOMAINS = {"gvt1.com", "domain:gvt1.com", "gvt2.com", "domain:gvt2.com"}

PRIVATE_IP_BLACKHOLE_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

SAFE_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
FORBIDDEN_OUTBOUND_PROTOCOLS = {
    "wireguard",
    "tor",
    "warp",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
}

DEFAULT_VLESS_SOCKOPT: dict[str, Any] = {
    "tcpKeepAliveIdle": 120,
    "tcpKeepAliveInterval": 30,
    "tcpNoDelay": True,
    "tcpMptcp": False,
}

# Russia's TSPU actively drops/throttles uTLS 'chrome' ClientHello signatures on mobile/ISP uplinks,
# whereas 'firefox' passes reliably while preserving full Xray/sing-box Reality compatibility.
DEFAULT_UTLS_FINGERPRINT = "firefox"
ALLOWED_REALITY_FINGERPRINTS = frozenset(
    {
        "firefox",
        "chrome",
        "edge",
        "safari",
        "ios",
        "android",
        "random",
        "randomized",
    }
)


def _validate_required_sockopt(sockopt: dict[str, Any], label: str) -> None:
    if (
        sockopt.get("tcpKeepAliveIdle") != 120
        or sockopt.get("tcpKeepAliveInterval") != 30
        or sockopt.get("tcpNoDelay") is not True
        or sockopt.get("tcpMptcp") is not False
    ):
        raise ValueError(
            f"{label} missing mandatory sockopt tcpKeepAliveIdle=120/tcpKeepAliveInterval=30/tcpNoDelay=True/tcpMptcp=False"
        )


def validate_utls_fingerprint(fingerprint: str) -> str:
    """Validate and normalize a Reality/TLS uTLS fingerprint name."""
    clean = (fingerprint or "").strip().lower()
    if clean not in ALLOWED_REALITY_FINGERPRINTS:
        allowed = ", ".join(sorted(ALLOWED_REALITY_FINGERPRINTS))
        raise ValueError(
            f"Unsupported uTLS fingerprint '{fingerprint}': expected one of [{allowed}]"
        )
    return clean


def generate_reality_keypair() -> tuple[str, str]:
    """Generate a Curve25519 keypair in Xray's RawURLEncoding base64 format."""
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    sk = PrivateKey(bytes(raw))
    priv_b64 = base64.urlsafe_b64encode(sk.encode()).decode().rstrip("=")
    pub_b64 = (
        base64.urlsafe_b64encode(sk.public_key.encode()).decode().rstrip("=")
    )
    return priv_b64, pub_b64


def generate_short_id(length_bytes: int = 8) -> str:
    """Generate a non-empty 16-char hex shortId (1..8 bytes)."""
    if length_bytes < 1 or length_bytes > 8:
        raise ValueError("shortId byte length must be between 1 and 8")
    return secrets.token_hex(length_bytes)


def validate_short_ids(short_ids: list[str]) -> list[str]:
    if not short_ids:
        raise ValueError("At least one non-empty Reality shortId is required")
    for sid in short_ids:
        if not sid or not re.fullmatch(r"[0-9a-fA-F]{1,16}", sid):
            raise ValueError(
                f"Invalid Reality shortId '{sid}': empty or non-hex shortIds are forbidden"
            )
    return short_ids


class LocalXrayConfigBuilder:
    """Builds and validates hardened single-server VLESS Self-Reality Xray configs."""

    @staticmethod
    def build_xhttp_inbound(
        xhttp_secret_path: str,
        clients: list[dict[str, Any]] | None = None,
        listen: str = "127.0.0.1",
        port: int = XRAY_XHTTP_PORT,
    ) -> dict[str, Any]:
        clean_path = "/" + xhttp_secret_path.lstrip("/")
        if clean_path == "/":
            raise ValueError("xhttp_secret_path must be a non-root secret path")
        xhttp_clients = [
            {"id": c["id"], "email": c.get("email", "owner")}
            for c in (clients or [])
        ]
        return {
            "tag": BACKUP_XHTTP_INBOUND_TAG,
            "listen": listen,
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": xhttp_clients,
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {
                    "path": clean_path,
                    "mode": "auto",
                    "xPaddingBytes": "100-1000",
                    "scMaxEachPostBytes": 1000000,
                },
                "sockopt": dict(DEFAULT_VLESS_SOCKOPT),
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        }

    @classmethod
    def build(
        cls,
        *,
        domain: str,
        reality_private_key: str,
        reality_short_ids: list[str],
        clients: list[dict[str, Any]] | None = None,
        xhttp_backup_enabled: bool = False,
        xhttp_secret_path: str = "",
        ipv6_egress_enabled: bool = False,
        listen_port: int = XRAY_LISTEN_PORT,
        fallback_port: int = NGINX_HTTPS_FALLBACK_PORT,
        api_address: str = XRAY_API_ADDRESS,
        xhttp_port: int = XRAY_XHTTP_PORT,
    ) -> dict[str, Any]:
        if not domain:
            raise ValueError("domain is required for Self-Reality SNI")
        if not reality_private_key:
            raise ValueError("reality_private_key is required")
        valid_short_ids = validate_short_ids(reality_short_ids)

        api_host, api_port_str = api_address.rsplit(":", 1)
        api_port = int(api_port_str)

        vision_clients = [
            {
                "id": c["id"],
                "flow": "xtls-rprx-vision",
                "email": c.get("email", "owner"),
            }
            for c in (clients or [])
        ]

        inbounds: list[dict[str, Any]] = [
            {
                "tag": API_INBOUND_TAG,
                "listen": api_host,
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
            {
                "tag": PRIMARY_INBOUND_TAG,
                "listen": "0.0.0.0",
                "port": listen_port,
                "protocol": "vless",
                "settings": {
                    "clients": vision_clients,
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": f"127.0.0.1:{fallback_port}",
                        "xver": 1,
                        "serverNames": [domain],
                        "privateKey": reality_private_key,
                        "shortIds": valid_short_ids,
                        "maxTimeDiff": 60000,
                    },
                    "sockopt": dict(DEFAULT_VLESS_SOCKOPT),
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
        ]

        active_vless_tags = [PRIMARY_INBOUND_TAG]
        if xhttp_backup_enabled or bool(xhttp_secret_path):
            if not xhttp_secret_path:
                raise ValueError(
                    "xhttp_secret_path is required when xhttp_backup_enabled is True"
                )
            inbounds[1]["settings"]["fallbacks"] = [
                {"dest": f"127.0.0.1:{xhttp_port}"}
            ]
            inbounds.append(
                cls.build_xhttp_inbound(
                    xhttp_secret_path=xhttp_secret_path,
                    clients=clients,
                    port=xhttp_port,
                )
            )
            active_vless_tags.append(BACKUP_XHTTP_INBOUND_TAG)

        strategy = "UseIP" if ipv6_egress_enabled else "UseIPv4"
        ip_blackholes = list(PRIVATE_IP_BLACKHOLE_CIDRS)
        if not ipv6_egress_enabled and "::/0" not in ip_blackholes:
            ip_blackholes.append("::/0")

        config: dict[str, Any] = {
            "log": {
                "access": "none",
                "error": "none",
                "loglevel": "none",
            },
            "api": {
                "tag": API_INBOUND_TAG,
                "services": ["HandlerService"],
            },
            "dns": {
                "servers": list(SAFE_DNS_SERVERS),
                "queryStrategy": strategy,
                "disableFallback": False,
            },
            "inbounds": inbounds,
            "outbounds": [
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {"domainStrategy": strategy},
                    "streamSettings": {"sockopt": dict(DEFAULT_VLESS_SOCKOPT)},
                },
                {
                    "tag": "block",
                    "protocol": "blackhole",
                    "settings": {"response": {"type": "none"}},
                },
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": [API_INBOUND_TAG],
                        "outboundTag": API_INBOUND_TAG,
                    },
                    {
                        "type": "field",
                        "domain": list(TELEMETRY_BLACKHOLE_DOMAINS),
                        "outboundTag": "block",
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
                        "ip": ip_blackholes,
                        "outboundTag": "block",
                    },
                    {
                        "type": "field",
                        "domain": list(RU_EGRESS_BLACKHOLE_DOMAINS),
                        "outboundTag": "block",
                    },
                    {
                        "type": "field",
                        "ip": list(RU_EGRESS_BLACKHOLE_GEOIPS),
                        "outboundTag": "block",
                    },
                    {
                        "type": "field",
                        "inboundTag": active_vless_tags,
                        "outboundTag": "direct",
                    },
                ],
            },
        }

        validate_xray_config(config, expected_ipv6=ipv6_egress_enabled, mode="exit")
        return config

    @staticmethod
    def _build_bridge_outbound(
        *,
        tag: str,
        upstream_ip: str,
        upstream_domain: str,
        upstream_uuid: str,
        upstream_public_key: str,
        upstream_short_id: str,
        upstream_port: int = 443,
        upstream_fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
        upstream_transport: str | None = None,
        upstream_xhttp_path: str = "",
        upstream_xhttp_mode: str = "stream-up",
        mux_enabled: bool = False,
    ) -> dict[str, Any]:
        clean_upstream_fp = validate_utls_fingerprint(upstream_fingerprint)
        default_transport = (
            "xhttp" if (upstream_xhttp_path or "").strip() else "vision"
        )
        clean_transport = (
            upstream_transport or default_transport
        ).strip().lower()
        if clean_transport not in {"vision", "xhttp"}:
            raise ValueError(
                f"Unsupported upstream_transport '{upstream_transport}': expected 'vision' or 'xhttp'"
            )
        clean_xhttp_path = ""
        if clean_transport == "xhttp":
            raw_path = (upstream_xhttp_path or "").strip().lstrip("/")
            if not raw_path or not re.fullmatch(r"[A-Za-z0-9/_-]+", raw_path):
                raise ValueError(
                    "upstream_xhttp_path is required when upstream_transport='xhttp'"
                )
            clean_xhttp_path = "/" + raw_path

        try:
            addr_obj = ipaddress.ip_address((upstream_ip or "").strip())
            if addr_obj.version != 4:
                raise ValueError("upstream_ip must be an IPv4 address")
        except ValueError as exc:
            raise ValueError(
                f"upstream_ip must be a numeric IPv4 address to avoid DNS queries on the bridge (got '{upstream_ip}')"
            ) from exc

        if not upstream_domain or "." not in upstream_domain:
            raise ValueError("upstream_domain must be a valid FQDN")
        if not upstream_uuid:
            raise ValueError("upstream_uuid is required")
        if not upstream_public_key:
            raise ValueError("upstream_public_key is required")
        validate_short_ids([upstream_short_id])

        use_xhttp = clean_transport == "xhttp"
        upstream_user: dict[str, Any] = {
            "id": upstream_uuid,
            "encryption": "none",
            "flow": (
                ""
                if (mux_enabled or use_xhttp)
                else "xtls-rprx-vision"
            ),
        }
        mux_cfg: dict[str, Any] = (
            {
                "enabled": True,
                "concurrency": 8,
                "xudpConcurrency": 16,
                "xudpProxyUDP443": "reject",
            }
            if (mux_enabled and not use_xhttp)
            else {"enabled": False}
        )
        upstream_stream_settings: dict[str, Any] = {
            "network": "xhttp" if use_xhttp else "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": upstream_domain.strip().lower(),
                "fingerprint": clean_upstream_fp,
                "publicKey": upstream_public_key,
                "shortId": upstream_short_id,
                "spiderX": "",
            },
            "sockopt": dict(DEFAULT_VLESS_SOCKOPT),
        }
        if use_xhttp:
            upstream_stream_settings["xhttpSettings"] = {
                "path": clean_xhttp_path,
                "mode": upstream_xhttp_mode,
                "xPaddingBytes": "100-1000",
                "xmux": {
                    "maxConcurrency": "16-32",
                    "maxConnections": 0,
                    "cMaxReuseTimes": 0,
                    "hMaxRequestTimes": "600-900",
                    "hMaxReusableSecs": BRIDGE_XMUX_MAX_REUSABLE_SECS,
                    "hKeepAlivePeriod": 0,
                },
            }

        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": upstream_ip.strip(),
                        "port": upstream_port,
                        "users": [upstream_user],
                    }
                ]
            },
            "streamSettings": upstream_stream_settings,
            "mux": mux_cfg,
        }

    @classmethod
    def build_bridge(
        cls,
        *,
        bridge_sni: str,
        reality_private_key: str,
        reality_short_ids: list[str],
        upstream_ip: str | None = None,
        upstream_domain: str | None = None,
        upstream_uuid: str | None = None,
        upstream_public_key: str | None = None,
        upstream_short_id: str | None = None,
        upstreams: dict[str, dict[str, Any]] | None = None,
        user_routes: dict[str, str] | None = None,
        clients: list[dict[str, Any]] | None = None,
        upstream_port: int = 443,
        upstream_fingerprint: str = DEFAULT_UTLS_FINGERPRINT,
        upstream_transport: str | None = None,
        upstream_xhttp_path: str = "",
        upstream_xhttp_mode: str = "stream-up",
        mux_enabled: bool = False,
        listen_port: int = XRAY_LISTEN_PORT,
        fallback_port: int = NGINX_HTTPS_FALLBACK_PORT,
        api_address: str = XRAY_API_ADDRESS,
    ) -> dict[str, Any]:
        """Build a fail-closed, zero-loop Russian cascade bridge config (single or multi-upstream)."""
        if not bridge_sni or "." not in bridge_sni:
            raise ValueError("bridge_sni must be a valid FQDN")
        if not reality_private_key:
            raise ValueError("reality_private_key is required")
        valid_short_ids = validate_short_ids(reality_short_ids)

        api_host, api_port_str = api_address.rsplit(":", 1)
        api_port = int(api_port_str)

        vision_clients = [
            {
                "id": c["id"],
                "flow": "xtls-rprx-vision",
                "email": c.get("email", "owner"),
            }
            for c in (clients or [])
        ]

        ip_blackholes = list(PRIVATE_IP_BLACKHOLE_CIDRS)
        if "::/0" not in ip_blackholes:
            ip_blackholes.append("::/0")

        outbounds: list[dict[str, Any]] = []
        tail_rules: list[dict[str, Any]] = []

        if upstreams is not None:
            if not isinstance(upstreams, dict) or not upstreams:
                raise ValueError("upstreams must be a non-empty mapping")
            routes_map = dict(user_routes or {})
            grouped_users: dict[str, list[str]] = {name: [] for name in upstreams}

            for up_name, up_cfg in upstreams.items():
                if not up_name or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", up_name):
                    raise ValueError(f"Invalid upstream name '{up_name}'")
                outbounds.append(
                    cls._build_bridge_outbound(
                        tag=f"proxy-{up_name}",
                        upstream_ip=str(up_cfg.get("ip", "")),
                        upstream_domain=str(up_cfg.get("domain", "")),
                        upstream_uuid=str(up_cfg.get("uuid", "")),
                        upstream_public_key=str(up_cfg.get("public_key", "")),
                        upstream_short_id=str(up_cfg.get("short_id", "")),
                        upstream_port=int(up_cfg.get("port", 443) or 443),
                        upstream_fingerprint=str(
                            up_cfg.get("fingerprint") or DEFAULT_UTLS_FINGERPRINT
                        ),
                        upstream_transport=up_cfg.get("transport"),
                        upstream_xhttp_path=str(up_cfg.get("xhttp_path", "")),
                        upstream_xhttp_mode=str(
                            up_cfg.get("xhttp_mode") or "stream-up"
                        ),
                        mux_enabled=bool(up_cfg.get("mux_enabled", False)),
                    )
                )

            for c in clients or []:
                email = str(c.get("email", "")).strip()
                target_up = routes_map.get(email) or c.get("upstream")
                if not target_up:
                    continue
                if target_up not in grouped_users:
                    raise ValueError(
                        f"Client '{email}' references unknown upstream '{target_up}'"
                    )
                if email and email not in grouped_users[target_up]:
                    grouped_users[target_up].append(email)

            for up_name, bound_emails in grouped_users.items():
                if bound_emails:
                    tail_rules.append(
                        {
                            "type": "field",
                            "inboundTag": [PRIMARY_INBOUND_TAG],
                            "user": bound_emails,
                            "outboundTag": f"proxy-{up_name}",
                        }
                    )
            tail_rules.append(
                {
                    "type": "field",
                    "inboundTag": [PRIMARY_INBOUND_TAG],
                    "outboundTag": "block",
                }
            )
        else:
            outbounds.append(
                cls._build_bridge_outbound(
                    tag="proxy",
                    upstream_ip=upstream_ip or "",
                    upstream_domain=upstream_domain or "",
                    upstream_uuid=upstream_uuid or "",
                    upstream_public_key=upstream_public_key or "",
                    upstream_short_id=upstream_short_id or "",
                    upstream_port=upstream_port,
                    upstream_fingerprint=upstream_fingerprint,
                    upstream_transport=upstream_transport,
                    upstream_xhttp_path=upstream_xhttp_path,
                    upstream_xhttp_mode=upstream_xhttp_mode,
                    mux_enabled=mux_enabled,
                )
            )
            tail_rules.append(
                {
                    "type": "field",
                    "inboundTag": [PRIMARY_INBOUND_TAG],
                    "outboundTag": "proxy",
                }
            )

        outbounds.append(
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {"response": {"type": "none"}},
            }
        )

        config: dict[str, Any] = {
            "log": {
                "access": "none",
                "error": "none",
                "loglevel": "none",
            },
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": True,
                        "statsUserDownlink": True,
                    }
                }
            },
            "api": {
                "tag": API_INBOUND_TAG,
                "services": ["HandlerService", "StatsService"],
            },
            "dns": {
                "servers": list(SAFE_DNS_SERVERS),
                "queryStrategy": "UseIPv4",
                "disableFallback": False,
            },
            "inbounds": [
                {
                    "tag": API_INBOUND_TAG,
                    "listen": api_host,
                    "port": api_port,
                    "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1"},
                },
                {
                    "tag": PRIMARY_INBOUND_TAG,
                    "listen": "0.0.0.0",
                    "port": listen_port,
                    "protocol": "vless",
                    "settings": {
                        "clients": vision_clients,
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": f"127.0.0.1:{fallback_port}",
                            "xver": 1,
                            "serverNames": [bridge_sni],
                            "privateKey": reality_private_key,
                            "shortIds": valid_short_ids,
                            "maxTimeDiff": 60000,
                        },
                        "sockopt": dict(DEFAULT_VLESS_SOCKOPT),
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": True,
                    },
                },
            ],
            "outbounds": outbounds,
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": [API_INBOUND_TAG],
                        "outboundTag": API_INBOUND_TAG,
                    },
                    {
                        "type": "field",
                        "domain": list(TELEMETRY_BLACKHOLE_DOMAINS),
                        "outboundTag": "block",
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
                        "ip": ip_blackholes,
                        "outboundTag": "block",
                    },
                    *tail_rules,
                ],
            },
        }

        validate_xray_config(config, expected_ipv6=False, mode="bridge")
        return config


def _validate_bounded_xmux_reusable_secs(raw_val: Any, label: str) -> None:
    """Require xmux.hMaxReusableSecs to rotate in bounded minute-scale intervals (1..600s)."""
    if raw_val is None or raw_val == "":
        raise ValueError(f"{label} missing xmux.hMaxReusableSecs rotation bound")
    text = str(raw_val).strip()
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", text)
    if not m:
        raise ValueError(
            f"{label} invalid xmux.hMaxReusableSecs '{raw_val}': expected N or MIN-MAX seconds"
        )
    low = int(m.group(1))
    high = int(m.group(2) or m.group(1))
    if low < 1 or high < low or high > BRIDGE_XMUX_MAX_REUSABLE_CEIL_SECS:
        raise ValueError(
            f"{label} xmux.hMaxReusableSecs '{raw_val}' must be bounded within 1-{BRIDGE_XMUX_MAX_REUSABLE_CEIL_SECS}s"
        )


def _validate_bridge_outbound(proxy_ob: dict[str, Any]) -> None:
    tag = str(proxy_ob.get("tag", "<unknown>"))
    if proxy_ob.get("protocol") != "vless":
        raise ValueError(f"Bridge '{tag}' outbound must use 'vless' protocol")
    vnext = proxy_ob.get("settings", {}).get("vnext", [])
    if len(vnext) != 1:
        raise ValueError(f"Bridge '{tag}' outbound must target a single upstream")
    up_addr = vnext[0].get("address", "")
    try:
        if ipaddress.ip_address(up_addr).version != 4:
            raise ValueError("Upstream address must be IPv4")
    except ValueError as exc:
        raise ValueError(
            "Bridge upstream address must be a numeric IPv4 address (zero DNS leakage)"
        ) from exc
    up_stream = proxy_ob.get("streamSettings", {})
    up_net = up_stream.get("network")
    if up_net not in {"tcp", "xhttp"}:
        raise ValueError("Bridge upstream network must be 'tcp' or 'xhttp'")
    if up_stream.get("security") != "reality":
        raise ValueError("Bridge upstream must use Reality security")
    if up_net == "xhttp":
        up_users = vnext[0].get("users", [{}])
        if up_users and up_users[0].get("flow"):
            raise ValueError(
                "Bridge XHTTP upstream must have empty flow (flow='')"
            )
        if proxy_ob.get("mux", {}).get("enabled") is True:
            raise ValueError("Bridge XHTTP upstream must have mux.enabled=False")
        xhttp_cfg = up_stream.get("xhttpSettings", {})
        xpath = str(xhttp_cfg.get("path", ""))
        if not xpath.startswith("/") or len(xpath) < 2:
            raise ValueError(
                "Bridge XHTTP upstream requires non-root xhttpSettings.path"
            )
        if not xhttp_cfg.get("xPaddingBytes") or not isinstance(
            xhttp_cfg.get("xmux"), dict
        ):
            raise ValueError(
                "Bridge XHTTP upstream requires xPaddingBytes and xmux configuration"
            )
        _validate_bounded_xmux_reusable_secs(
            xhttp_cfg["xmux"].get("hMaxReusableSecs"),
            f"Bridge '{tag}'",
        )
    up_reality = up_stream.get("realitySettings", {})
    if up_reality.get("fingerprint") not in ALLOWED_REALITY_FINGERPRINTS:
        raise ValueError(
            "Bridge upstream Reality must use a supported non-empty uTLS fingerprint"
        )
    if not up_reality.get("serverName") or not up_reality.get("publicKey"):
        raise ValueError("Bridge upstream Reality requires serverName and publicKey")
    validate_short_ids([up_reality.get("shortId", "")])
    _validate_required_sockopt(up_stream.get("sockopt", {}), f"Bridge upstream '{tag}'")


def _validate_bridge_routing(
    rules: list[dict[str, Any]],
    proxy_tags: set[str],
    is_multi_upstream: bool,
) -> None:
    if not is_multi_upstream:
        return
    seen_users: dict[str, str] = {}
    last_proxy_idx = -1
    catchall_block_idx = -1
    for idx, r in enumerate(rules):
        target = r.get("outboundTag")
        if target in proxy_tags:
            last_proxy_idx = idx
            users = r.get("user")
            if not isinstance(users, list) or not users:
                raise ValueError(
                    f"Multi-upstream bridge rule for '{target}' must statically bind explicit 'user' list"
                )
            for uname in users:
                if uname in seen_users:
                    raise ValueError(
                        f"Bridge user '{uname}' cannot route to multiple upstreams ('{seen_users[uname]}' and '{target}')"
                    )
                seen_users[uname] = str(target)
        elif (
            target == "block"
            and PRIMARY_INBOUND_TAG in (r.get("inboundTag") or [])
            and not r.get("user")
            and not r.get("domain")
            and not r.get("ip")
            and not r.get("network")
            and not r.get("protocol")
        ):
            catchall_block_idx = idx
    if catchall_block_idx == -1 or catchall_block_idx < last_proxy_idx:
        raise ValueError(
            "Multi-upstream bridge routing must end with a fail-closed catch-all block rule"
        )


def _validate_exit_ru_blackholes(rules: list[dict[str, Any]]) -> None:
    direct_indices = [
        idx for idx, r in enumerate(rules) if r.get("outboundTag") == "direct"
    ]
    cutoff = min(direct_indices) if direct_indices else len(rules)
    blocked_domains: set[str] = set()
    blocked_ips: set[str] = set()
    for r in rules[:cutoff]:
        if r.get("outboundTag") == "block":
            blocked_domains.update(r.get("domain", []))
            blocked_ips.update(r.get("ip", []))
    missing_domains = [
        d for d in RU_EGRESS_BLACKHOLE_DOMAINS if d not in blocked_domains
    ]
    if missing_domains:
        raise ValueError(
            f"Mandatory exit RU domain blackhole missing prior to direct: {missing_domains}"
        )
    missing_ips = [
        ip_rule for ip_rule in RU_EGRESS_BLACKHOLE_GEOIPS if ip_rule not in blocked_ips
    ]
    if missing_ips:
        raise ValueError(
            f"Mandatory exit RU IP blackhole missing prior to direct: {missing_ips}"
        )


def validate_xray_config(
    config: dict[str, Any],
    *,
    expected_ipv6: bool | None = None,
    mode: str | None = None,
) -> None:
    """Assert every anti-drift, RCA socket, and zero-log safety invariant on an Xray config."""
    log_cfg = config.get("log", {})
    if (
        log_cfg.get("access") != "none"
        or log_cfg.get("error") != "none"
        or log_cfg.get("loglevel") != "none"
    ):
        raise ValueError(
            "Xray logging must be disabled (access/error/loglevel = none)"
        )

    outbounds = config.get("outbounds", [])
    outbound_tags = {o.get("tag") for o in outbounds}
    has_bridge_proxy = any(
        isinstance(t, str) and (t == "proxy" or t.startswith("proxy-"))
        for t in outbound_tags
    )
    detected_mode = mode or (
        "bridge"
        if (has_bridge_proxy and "direct" not in outbound_tags)
        else "exit"
    )

    api_services = config.get("api", {}).get("services", [])
    has_stats_or_policy = (
        "stats" in config
        or "policy" in config
        or "StatsService" in api_services
    )
    if detected_mode != "bridge":
        if "stats" in config or "policy" in config:
            raise ValueError(
                "StatsService and traffic policy counters are prohibited"
            )
        if "StatsService" in api_services:
            raise ValueError("StatsService is prohibited")
    elif has_stats_or_policy:
        api_inb = next(
            (i for i in config.get("inbounds", []) if i.get("tag") == API_INBOUND_TAG),
            None,
        )
        if not api_inb or api_inb.get("listen") != "127.0.0.1":
            raise ValueError(
                "Bridge StatsService API inbound must bind strictly to loopback 127.0.0.1"
            )
        policy_cfg = config.get("policy", {})
        if policy_cfg:
            if set(policy_cfg.keys()) - {"levels"}:
                raise ValueError(
                    "Bridge policy may only configure per-user levels counters"
                )
            level0 = policy_cfg.get("levels", {}).get("0", {})
            allowed_level_keys = {"statsUserUplink", "statsUserDownlink"}
            if set(level0.keys()) - allowed_level_keys:
                raise ValueError(
                    "Bridge policy.levels.0 may only enable statsUserUplink/statsUserDownlink"
                )

    dns_cfg = config.get("dns", {})
    if "clientIp" in dns_cfg:
        raise ValueError("EDNS Client Subnet (dns.clientIp) is prohibited")
    if dns_cfg.get("servers") != SAFE_DNS_SERVERS:
        raise ValueError("DNS servers must be locked to 1.1.1.1 and 8.8.8.8")
    expected_strategy = "UseIP" if expected_ipv6 else "UseIPv4"
    if (
        expected_ipv6 is not None
        and dns_cfg.get("queryStrategy") != expected_strategy
    ):
        raise ValueError(f"DNS queryStrategy must be {expected_strategy}")

    proxy_tags: set[str] = set()
    is_multi_upstream = False
    if detected_mode == "bridge":
        for ob in outbounds:
            tag = ob.get("tag")
            proto = str(ob.get("protocol", "")).lower()
            if proto == "freedom" or tag == "direct":
                raise ValueError(
                    "Bridge outbounds must be fail-closed (no 'direct'/'freedom' allowed)"
                )
            if tag == "block":
                if proto != "blackhole":
                    raise ValueError("Bridge 'block' outbound must be blackhole")
                continue
            if isinstance(tag, str) and (tag == "proxy" or tag.startswith("proxy-")):
                if tag.startswith("proxy-"):
                    is_multi_upstream = True
                proxy_tags.add(tag)
                _validate_bridge_outbound(ob)
            else:
                raise ValueError(
                    f"Bridge outbounds must contain only 'proxy'/'proxy-*' and 'block' (fail-closed: got '{tag}')"
                )
        if "block" not in outbound_tags or not proxy_tags:
            raise ValueError(
                "Bridge outbounds must contain at least one proxy outbound and 'block'"
            )
        if config.get("routing", {}).get("domainStrategy") != "AsIs":
            raise ValueError(
                "Bridge routing.domainStrategy must be 'AsIs' to prevent local DNS leakage"
            )
    else:
        if outbound_tags != {"direct", "block"}:
            raise ValueError("Outbounds must contain only 'direct' and 'block'")
        for ob in outbounds:
            proto = ob.get("protocol", "").lower()
            if proto in FORBIDDEN_OUTBOUND_PROTOCOLS or proto not in {
                "freedom",
                "blackhole",
            }:
                raise ValueError(f"Forbidden outbound protocol '{proto}'")
            if proto == "freedom":
                if expected_ipv6 is not None and (
                    ob.get("settings", {}).get("domainStrategy")
                    != expected_strategy
                ):
                    raise ValueError(
                        f"Freedom domainStrategy must be {expected_strategy}"
                    )
                _validate_required_sockopt(
                    ob.get("streamSettings", {}).get("sockopt", {}),
                    f"Outbound '{ob.get('tag')}'",
                )

    inbounds = config.get("inbounds", [])
    primary = next(
        (i for i in inbounds if i.get("tag") == PRIMARY_INBOUND_TAG), None
    )
    if not primary:
        raise ValueError("Primary vless-reality-vision inbound missing")
    if primary.get("protocol") != "vless":
        raise ValueError("Primary inbound must be vless")
    reality = primary.get("streamSettings", {}).get("realitySettings", {})
    if reality.get("xver") != 1:
        raise ValueError("Reality xver must be 1 for PROXY protocol")
    if reality.get("maxTimeDiff") != 60000:
        raise ValueError("Reality maxTimeDiff must be 60000")
    if not str(reality.get("dest", "")).startswith("127.0.0.1:"):
        raise ValueError("Reality dest must target loopback Nginx")
    validate_short_ids(reality.get("shortIds", []))

    for inb in inbounds:
        if inb.get("tag") == API_INBOUND_TAG:
            continue
        if inb.get("protocol") != "vless":
            raise ValueError(
                f"Non-VLESS inbound '{inb.get('tag')}' prohibited"
            )
        _validate_required_sockopt(
            inb.get("streamSettings", {}).get("sockopt", {}),
            f"Inbound '{inb.get('tag')}'",
        )
        sniffing = inb.get("sniffing", {})
        if (
            not sniffing.get("enabled")
            or sniffing.get("routeOnly") is not True
        ):
            raise ValueError(
                f"Inbound '{inb.get('tag')}' must enable sniffing with routeOnly=True"
            )

    rules = config.get("routing", {}).get("rules", [])
    for r in rules:
        if r.get("outboundTag") == "block":
            blocked_domains = set(r.get("domain", []))
            if blocked_domains & FORBIDDEN_BLACKHOLE_DOMAINS:
                raise ValueError(
                    "gvt1.com and gvt2.com must NOT be blackholed (required for Google Antigravity updates)"
                )

    has_telemetry_block = any(
        r.get("outboundTag") == "block"
        and set(TELEMETRY_BLACKHOLE_DOMAINS).issubset(set(r.get("domain", [])))
        for r in rules
    )
    if not has_telemetry_block:
        raise ValueError(
            "Mandatory Android/Google telemetry blackhole rule missing"
        )

    has_udp_quic_stun_block = any(
        r.get("outboundTag") == "block"
        and r.get("network") == "udp"
        and "443" in str(r.get("port", ""))
        and "3478" in str(r.get("port", ""))
        and "19302" in str(r.get("port", ""))
        for r in rules
    )
    if not has_udp_quic_stun_block:
        raise ValueError("Mandatory UDP QUIC/STUN (443,3478,19302) blackhole rule missing")

    has_bittorrent_block = any(
        r.get("outboundTag") == "block"
        and "bittorrent" in r.get("protocol", [])
        for r in rules
    )
    if not has_bittorrent_block:
        raise ValueError("Mandatory bittorrent blackhole rule missing")

    has_private_block = any(
        r.get("outboundTag") == "block"
        and "127.0.0.0/8" in r.get("ip", [])
        and "10.0.0.0/8" in r.get("ip", [])
        and (expected_ipv6 is not False or "::/0" in r.get("ip", []))
        for r in rules
    )
    if not has_private_block:
        raise ValueError(
            "Mandatory private-IP (and ::/0 when IPv6 disabled) blackhole rule missing"
        )

    if detected_mode == "bridge":
        _validate_bridge_routing(rules, proxy_tags, is_multi_upstream)
    else:
        _validate_exit_ru_blackholes(rules)
