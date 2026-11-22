import base64
import copy
import pytest

from app.xray import (
    BACKUP_XHTTP_INBOUND_TAG,
    PRIMARY_INBOUND_TAG,
    TELEMETRY_BLACKHOLE_DOMAINS,
    LocalXrayConfigBuilder,
    generate_reality_keypair,
    generate_short_id,
    validate_xray_config,
)
from app.xray.proto import (
    build_add_vless_user_request,
    build_remove_inbound_request,
    build_remove_user_request,
)


def test_reality_keypair_and_short_id_format():
    priv, pub = generate_reality_keypair()
    assert priv != pub
    assert "=" not in priv and "=" not in pub
    assert len(base64.urlsafe_b64decode(priv + "==")) == 32
    assert len(base64.urlsafe_b64decode(pub + "==")) == 32

    sid = generate_short_id()
    assert len(sid) == 16
    int(sid, 16)


def test_xray_config_safety_invariants_default_no_xhttp():
    priv, _ = generate_reality_keypair()
    sid = generate_short_id()

    cfg = LocalXrayConfigBuilder.build(
        domain="vpn.example.com",
        reality_private_key=priv,
        reality_short_ids=[sid],
        clients=[{"id": "11111111-1111-1111-1111-111111111111", "email": "owner"}],
        xhttp_backup_enabled=False,
        ipv6_egress_enabled=False,
    )

    assert cfg["log"] == {"access": "none", "error": "none", "loglevel": "none"}
    assert cfg["api"]["services"] == ["HandlerService"]
    assert "StatsService" not in cfg["api"]["services"]
    assert "stats" not in cfg
    assert cfg["dns"]["servers"] == ["1.1.1.1", "8.8.8.8"]
    assert cfg["dns"]["queryStrategy"] == "UseIPv4"
    assert "clientIp" not in cfg["dns"]

    outbounds = cfg["outbounds"]
    assert [o["protocol"] for o in outbounds] == ["freedom", "blackhole"]
    assert outbounds[0]["settings"]["domainStrategy"] == "UseIPv4"

    tags = [i["tag"] for i in cfg["inbounds"]]
    assert PRIMARY_INBOUND_TAG in tags
    assert BACKUP_XHTTP_INBOUND_TAG not in tags

    primary = next(i for i in cfg["inbounds"] if i["tag"] == PRIMARY_INBOUND_TAG)
    rs = primary["streamSettings"]["realitySettings"]
    assert rs["xver"] == 1
    assert rs["maxTimeDiff"] == 60000
    assert rs["dest"] == "127.0.0.1:8443"
    assert rs["shortIds"] == [sid]
    assert rs["serverNames"] == ["vpn.example.com"]

    # RCA Cause #5: sockopt keepalive + sniffing.routeOnly + MPTCP hardening
    assert primary["streamSettings"]["sockopt"] == {
        "tcpKeepAliveIdle": 120,
        "tcpKeepAliveInterval": 30,
        "tcpNoDelay": True,
        "tcpMptcp": False,
    }
    assert primary["sniffing"]["routeOnly"] is True

    # Antigravity gvt1/gvt2 unblocked, geolocation telemetry blocked
    assert "domain:gvt1.com" not in TELEMETRY_BLACKHOLE_DOMAINS
    assert "domain:gvt2.com" not in TELEMETRY_BLACKHOLE_DOMAINS
    telemetry_rules = [
        r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "block" and r.get("domain")
    ]
    assert telemetry_rules
    for domain in TELEMETRY_BLACKHOLE_DOMAINS:
        assert domain in telemetry_rules[0]["domain"]

    # RCA Cause #6: QUIC, STUN, BitTorrent, and ::/0 blocked
    ip_rules = [
        r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "block" and r.get("ip")
    ]
    assert "::/0" in ip_rules[0]["ip"]


def test_xray_config_with_xhttp_and_ipv6_opt_in():
    priv, _ = generate_reality_keypair()
    sid = generate_short_id()

    cfg = LocalXrayConfigBuilder.build(
        domain="vpn.example.com",
        reality_private_key=priv,
        reality_short_ids=[sid],
        clients=[{"id": "11111111-1111-1111-1111-111111111111", "email": "owner"}],
        xhttp_backup_enabled=True,
        xhttp_secret_path="/secret-xhttp-path-1234",
        ipv6_egress_enabled=True,
    )

    assert cfg["dns"]["queryStrategy"] == "UseIP"
    assert cfg["outbounds"][0]["settings"]["domainStrategy"] == "UseIP"

    primary = next(
        i for i in cfg["inbounds"] if i["tag"] == PRIMARY_INBOUND_TAG
    )
    assert primary["settings"]["fallbacks"] == [{"dest": "127.0.0.1:10086"}]

    xhttp_inb = next(
        i for i in cfg["inbounds"] if i["tag"] == BACKUP_XHTTP_INBOUND_TAG
    )
    assert xhttp_inb["listen"] == "127.0.0.1"
    assert xhttp_inb["port"] == 10086
    assert xhttp_inb["streamSettings"]["network"] == "xhttp"
    assert xhttp_inb["streamSettings"]["security"] == "none"
    assert (
        xhttp_inb["streamSettings"]["xhttpSettings"]["path"]
        == "/secret-xhttp-path-1234"
    )
    assert xhttp_inb["streamSettings"]["xhttpSettings"]["mode"] == "auto"
    assert (
        xhttp_inb["streamSettings"]["xhttpSettings"]["xPaddingBytes"]
        == "100-1000"
    )
    assert (
        xhttp_inb["streamSettings"]["xhttpSettings"]["scMaxEachPostBytes"]
        == 1000000
    )
    assert xhttp_inb["streamSettings"]["sockopt"] == {
        "tcpKeepAliveIdle": 120,
        "tcpKeepAliveInterval": 30,
        "tcpNoDelay": True,
        "tcpMptcp": False,
    }
    assert xhttp_inb["sniffing"]["routeOnly"] is True


def test_xray_builder_forbids_empty_short_id():
    priv, _ = generate_reality_keypair()
    with pytest.raises(ValueError, match="shortId"):
        LocalXrayConfigBuilder.build(
            domain="vpn.example.com",
            reality_private_key=priv,
            reality_short_ids=[""],
        )


def test_validate_xray_config_rejects_tampered_safety_invariants():
    priv, _ = generate_reality_keypair()
    sid = generate_short_id()
    base = LocalXrayConfigBuilder.build(
        domain="vpn.example.com",
        reality_private_key=priv,
        reality_short_ids=[sid],
    )

    bad_stats = copy.deepcopy(base)
    bad_stats["api"]["services"].append("StatsService")
    with pytest.raises(ValueError, match="StatsService"):
        validate_xray_config(bad_stats)

    bad_wg = copy.deepcopy(base)
    bad_wg["outbounds"].append({"tag": "warp", "protocol": "wireguard"})
    with pytest.raises(ValueError):
        validate_xray_config(bad_wg)

    bad_ecs = copy.deepcopy(base)
    bad_ecs["dns"]["clientIp"] = "1.2.3.4"
    with pytest.raises(ValueError, match="clientIp"):
        validate_xray_config(bad_ecs)

    bad_gvt = copy.deepcopy(base)
    bad_gvt["routing"]["rules"][1]["domain"].append("domain:gvt1.com")
    with pytest.raises(ValueError, match="gvt1.com"):
        validate_xray_config(bad_gvt)

    bad_sockopt = copy.deepcopy(base)
    del bad_sockopt["inbounds"][1]["streamSettings"]["sockopt"]
    with pytest.raises(ValueError, match="sockopt"):
        validate_xray_config(bad_sockopt)

    bad_out_sockopt = copy.deepcopy(base)
    del bad_out_sockopt["outbounds"][0]["streamSettings"]["sockopt"]
    with pytest.raises(ValueError, match="sockopt"):
        validate_xray_config(bad_out_sockopt)


def test_xray_grpc_protobuf_payloads_serialize():
    add_bytes = build_add_vless_user_request(
        PRIMARY_INBOUND_TAG,
        "owner",
        "11111111-1111-1111-1111-111111111111",
        flow="xtls-rprx-vision",
    )
    assert b"vless-reality-vision" in add_bytes
    assert b"11111111-1111-1111-1111-111111111111" in add_bytes

    rm_bytes = build_remove_user_request(PRIMARY_INBOUND_TAG, "owner")
    assert b"owner" in rm_bytes

    rm_inb_bytes = build_remove_inbound_request(BACKUP_XHTTP_INBOUND_TAG)
    assert b"vless-xhttp-local" in rm_inb_bytes


def test_xray_bridge_config_zero_loop_and_fail_closed():
    priv_bridge, _ = generate_reality_keypair()
    _, pub_exit = generate_reality_keypair()
    sid_bridge = generate_short_id()
    sid_exit = generate_short_id()

    bridge_cfg = LocalXrayConfigBuilder.build_bridge(
        bridge_sni="exit.example.com",
        reality_private_key=priv_bridge,
        reality_short_ids=[sid_bridge],
        upstream_ip="203.0.113.20",
        upstream_domain="exit.example.com",
        upstream_uuid="22222222-2222-2222-2222-222222222222",
        upstream_public_key=pub_exit,
        upstream_short_id=sid_exit,
        clients=[{"id": "11111111-1111-1111-1111-111111111111", "email": "owner"}],
        mux_enabled=True,
    )

    # 1. Zero-loop local fallback (never dials external vk.com/etc. on TSPU probe)
    primary = next(
        i for i in bridge_cfg["inbounds"] if i["tag"] == PRIMARY_INBOUND_TAG
    )
    assert (
        primary["streamSettings"]["realitySettings"]["dest"] == "127.0.0.1:8443"
    )

    # 2. Fail-closed outbounds: only 'proxy' and 'block', zero 'direct'/'freedom'
    out_tags = [o["tag"] for o in bridge_cfg["outbounds"]]
    assert out_tags == ["proxy", "block"]
    assert all(o["protocol"] != "freedom" for o in bridge_cfg["outbounds"])

    # 3. Numeric IPv4 upstream with Firefox uTLS (TSPU-resilient default) and zero RU DNS queries
    proxy_ob = bridge_cfg["outbounds"][0]
    assert proxy_ob["settings"]["vnext"][0]["address"] == "203.0.113.20"
    assert (
        proxy_ob["streamSettings"]["realitySettings"]["serverName"]
        == "exit.example.com"
    )
    assert (
        proxy_ob["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"
    )
    assert proxy_ob["streamSettings"]["sockopt"]["tcpMptcp"] is False
    assert proxy_ob["mux"]["enabled"] is True
    assert proxy_ob["mux"]["xudpProxyUDP443"] == "reject"
    assert bridge_cfg["routing"]["domainStrategy"] == "AsIs"

    # Rejects local DNS resolution on bridge (IPIfNonMatch leaks DNS queries in RU)
    bad_dns_bridge = copy.deepcopy(bridge_cfg)
    bad_dns_bridge["routing"]["domainStrategy"] = "IPIfNonMatch"
    with pytest.raises(ValueError, match="AsIs"):
        validate_xray_config(bad_dns_bridge, mode="bridge")

    # 4. Rejects non-IP upstream address (which would leak DNS queries in Russia)
    with pytest.raises(ValueError, match="numeric IPv4"):
        LocalXrayConfigBuilder.build_bridge(
            bridge_sni="exit.example.com",
            reality_private_key=priv_bridge,
            reality_short_ids=[sid_bridge],
            upstream_ip="exit.example.com",
            upstream_domain="exit.example.com",
            upstream_uuid="22222222-2222-2222-2222-222222222222",
            upstream_public_key=pub_exit,
            upstream_short_id=sid_exit,
        )

    # 5. Rejects adding a 'direct' freedom outbound or invalid uTLS fingerprint to a bridge config
    tampered = copy.deepcopy(bridge_cfg)
    tampered["outbounds"].append({"tag": "direct", "protocol": "freedom"})
    with pytest.raises(ValueError, match="fail-closed"):
        validate_xray_config(tampered, mode="bridge")

    # 6. Bridge XHTTP + Reality + xmux upstream mode
    bridge_xhttp = LocalXrayConfigBuilder.build_bridge(
        bridge_sni="bridge.example.com",
        reality_private_key=priv_bridge,
        reality_short_ids=[sid_bridge],
        upstream_ip="203.0.113.20",
        upstream_domain="exit.example.com",
        upstream_uuid="22222222-2222-2222-2222-222222222222",
        upstream_public_key=pub_exit,
        upstream_short_id=sid_exit,
        upstream_transport="xhttp",
        upstream_xhttp_path="a" * 64,
        clients=[{"id": "11111111-1111-1111-1111-111111111111", "email": "owner"}],
    )
    xhttp_ob = bridge_xhttp["outbounds"][0]
    assert xhttp_ob["settings"]["vnext"][0]["users"][0]["flow"] == ""
    assert xhttp_ob["streamSettings"]["network"] == "xhttp"
    assert xhttp_ob["streamSettings"]["security"] == "reality"
    assert (
        xhttp_ob["streamSettings"]["xhttpSettings"]["path"]
        == "/" + ("a" * 64)
    )
    assert xhttp_ob["streamSettings"]["xhttpSettings"]["mode"] == "stream-up"
    assert (
        xhttp_ob["streamSettings"]["xhttpSettings"]["xPaddingBytes"]
        == "100-1000"
    )
    assert xhttp_ob["streamSettings"]["xhttpSettings"]["xmux"] == {
        "maxConcurrency": "16-32",
        "maxConnections": 0,
        "cMaxReuseTimes": 0,
        "hMaxRequestTimes": "600-900",
        "hMaxReusableSecs": "180-300",
        "hKeepAlivePeriod": 0,
    }
    assert xhttp_ob["mux"]["enabled"] is False

    with pytest.raises(ValueError, match="upstream_xhttp_path"):
        LocalXrayConfigBuilder.build_bridge(
            bridge_sni="bridge.example.com",
            reality_private_key=priv_bridge,
            reality_short_ids=[sid_bridge],
            upstream_ip="203.0.113.20",
            upstream_domain="exit.example.com",
            upstream_uuid="22222222-2222-2222-2222-222222222222",
            upstream_public_key=pub_exit,
            upstream_short_id=sid_exit,
            upstream_transport="xhttp",
            upstream_xhttp_path="",
        )

    bad_fp = copy.deepcopy(bridge_cfg)
    bad_fp["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] = "bogus"
    with pytest.raises(ValueError, match="uTLS fingerprint"):
        validate_xray_config(bad_fp, mode="bridge")


def test_exit_ru_egress_blackhole_and_validation():
    priv, _ = generate_reality_keypair()
    sid = generate_short_id()
    cfg = LocalXrayConfigBuilder.build(
        domain="exit-ai.example.com",
        reality_private_key=priv,
        reality_short_ids=[sid],
        clients=[{"id": "11111111-1111-4111-8111-111111111111", "email": "owner"}],
    )

    rules = cfg["routing"]["rules"]
    direct_idx = next(i for i, r in enumerate(rules) if r.get("outboundTag") == "direct")
    ru_dom_idx = next(
        i
        for i, r in enumerate(rules)
        if r.get("outboundTag") == "block" and "domain:ru" in r.get("domain", [])
    )
    ru_ip_idx = next(
        i
        for i, r in enumerate(rules)
        if r.get("outboundTag") == "block" and "geoip:ru" in r.get("ip", [])
    )
    assert ru_dom_idx < direct_idx
    assert ru_ip_idx < direct_idx
    assert {"domain:ru", "domain:su", "domain:xn--p1ai"}.issubset(
        set(rules[ru_dom_idx]["domain"])
    )
    assert all(o["protocol"] in {"freedom", "blackhole"} for o in cfg["outbounds"])

    no_ru_dom = copy.deepcopy(cfg)
    no_ru_dom["routing"]["rules"].pop(ru_dom_idx)
    with pytest.raises(ValueError, match="RU domain blackhole"):
        validate_xray_config(no_ru_dom, expected_ipv6=False, mode="exit")

    no_ru_ip = copy.deepcopy(cfg)
    no_ru_ip["routing"]["rules"].pop(ru_ip_idx)
    with pytest.raises(ValueError, match="RU IP blackhole"):
        validate_xray_config(no_ru_ip, expected_ipv6=False, mode="exit")


def test_multi_upstream_bridge_static_routing_and_xmux_bounds():
    priv_bridge, _ = generate_reality_keypair()
    _, pub_ai = generate_reality_keypair()
    _, pub_media = generate_reality_keypair()

    cfg = LocalXrayConfigBuilder.build_bridge(
        bridge_sni="mos.bridge-edge.net",
        reality_private_key=priv_bridge,
        reality_short_ids=[generate_short_id()],
        upstreams={
            "exit-ai": {
                "ip": "203.0.113.10",
                "domain": "de-ai.only-ai.org",
                "uuid": "aaaaaaaa-1111-4111-8111-111111111111",
                "public_key": pub_ai,
                "short_id": generate_short_id(),
                "transport": "xhttp",
                "xhttp_path": "a" * 64,
            },
            "exit-media-1": {
                "ip": "198.51.100.20",
                "domain": "de-media.stream-cdn.net",
                "uuid": "bbbbbbbb-2222-4222-8222-222222222222",
                "public_key": pub_media,
                "short_id": generate_short_id(),
                "transport": "xhttp",
                "xhttp_path": "b" * 64,
            },
        },
        clients=[
            {"id": "11111111-1111-4111-8111-111111111111", "email": "owner"},
            {"id": "22222222-2222-4222-8222-222222222222", "email": "alice"},
        ],
        user_routes={
            "owner": "exit-ai",
            "alice": "exit-media-1",
        },
    )

    validate_xray_config(cfg, expected_ipv6=False)
    assert cfg["routing"]["domainStrategy"] == "AsIs"
    out_tags = [o["tag"] for o in cfg["outbounds"]]
    assert out_tags == ["proxy-exit-ai", "proxy-exit-media-1", "block"]
    assert all(o["protocol"] != "freedom" for o in cfg["outbounds"])

    for ob in cfg["outbounds"][:2]:
        assert ob["streamSettings"]["network"] == "xhttp"
        assert ob["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"
        assert ob["streamSettings"]["sockopt"]["tcpMptcp"] is False
        assert ob["mux"]["enabled"] is False
        assert ob["streamSettings"]["xhttpSettings"]["xmux"]["hMaxReusableSecs"] == "180-300"

    primary_clients = cfg["inbounds"][1]["settings"]["clients"]
    assert [(c["email"], c["flow"]) for c in primary_clients] == [
        ("owner", "xtls-rprx-vision"),
        ("alice", "xtls-rprx-vision"),
    ]

    rules = cfg["routing"]["rules"]
    assert rules[-3] == {
        "type": "field",
        "inboundTag": [PRIMARY_INBOUND_TAG],
        "user": ["owner"],
        "outboundTag": "proxy-exit-ai",
    }
    assert rules[-2] == {
        "type": "field",
        "inboundTag": [PRIMARY_INBOUND_TAG],
        "user": ["alice"],
        "outboundTag": "proxy-exit-media-1",
    }
    assert rules[-1] == {
        "type": "field",
        "inboundTag": [PRIMARY_INBOUND_TAG],
        "outboundTag": "block",
    }

    # Rejects unbounded/excessive xmux rotation (>600s)
    bad_xmux = copy.deepcopy(cfg)
    bad_xmux["outbounds"][0]["streamSettings"]["xhttpSettings"]["xmux"]["hMaxReusableSecs"] = "1800-3000"
    with pytest.raises(ValueError, match="hMaxReusableSecs"):
        validate_xray_config(bad_xmux, mode="bridge")

    # Rejects missing fail-closed catch-all block rule
    bad_tail = copy.deepcopy(cfg)
    bad_tail["routing"]["rules"].pop()
    with pytest.raises(ValueError, match="catch-all block"):
        validate_xray_config(bad_tail, mode="bridge")

    # Rejects user routed to multiple upstreams
    bad_dup = copy.deepcopy(cfg)
    bad_dup["routing"]["rules"][-2]["user"].append("owner")
    with pytest.raises(ValueError, match="multiple upstreams"):
        validate_xray_config(bad_dup, mode="bridge")
