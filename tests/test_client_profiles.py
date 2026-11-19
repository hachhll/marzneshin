import json
from pathlib import Path

import pytest

from app.client import (
    PODKOP_COMMUNITY_RULESET_NAMES,
    PODKOP_DNS_DOMAIN_RULESET_NAMES,
    SELECTIVE_ANDROID_DIRECT_PACKAGES,
    SELECTIVE_ANDROID_PACKAGES,
    SELECTIVE_DIRECT_BYPASS_DOMAINS,
    SELECTIVE_VPN_DOMAIN_SUFFIXES,
    SELECTIVE_WINDOWS_PROCESSES,
    TELEGRAM_DC_CIDRS,
    build_singbox_profile,
    build_singbox_selective_profile,
    build_vless_vision_uri,
    build_vless_xhttp_uri,
    build_xray_client_profile,
    format_terminal_credentials,
    render_qr_utf8,
    write_client_bundle,
)
from app.xray.config_builder import generate_reality_keypair, generate_short_id


def test_vless_uris_and_terminal_qr_generation():
    _, pub = generate_reality_keypair()
    sid = generate_short_id()
    uid = "11111111-1111-1111-1111-111111111111"

    vision_uri = build_vless_vision_uri(
        domain="vpn.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
    )
    assert vision_uri.startswith(f"vless://{uid}@vpn.example.com:443?")
    assert "flow=xtls-rprx-vision" in vision_uri
    assert "security=reality" in vision_uri
    assert "fp=firefox" in vision_uri
    assert "packetEncoding=xudp" in vision_uri
    assert f"pbk={pub}" in vision_uri
    assert f"sid={sid}" in vision_uri

    xhttp_uri = build_vless_xhttp_uri(
        domain="vpn.example.com",
        user_uuid=uid,
        xhttp_secret_path="a" * 64,
    )
    assert xhttp_uri.startswith(f"vless://{uid}@vpn.example.com:443?")
    assert "security=tls" in xhttp_uri
    assert "type=xhttp" in xhttp_uri
    assert "alpn=h2" in xhttp_uri
    assert "packetEncoding=xudp" in xhttp_uri

    qr = render_qr_utf8(vision_uri)
    assert len(qr.splitlines()) >= 15
    assert any(ch in qr for ch in ("█", "▀", "▄"))

    # RCA Cause #2: Reject raw IP in client URI host
    with pytest.raises(ValueError, match="RCA Cause #2"):
        build_vless_vision_uri(
            domain="198.51.100.30",
            user_uuid=uid,
            reality_public_key=pub,
            reality_short_id=sid,
        )


def test_throne_windows11_and_android_singbox_profiles_anti_ban_invariants():
    _, pub = generate_reality_keypair()
    sid = generate_short_id()
    uid = "11111111-1111-1111-1111-111111111111"

    cfg = build_singbox_profile(
        domain="vpn.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        xhttp_secret_path="b" * 64,
        include_xhttp_backup=True,
        platform="windows11-throne",
    )

    # Remote DNS only via proxy with ipv4_only
    server_tags = [s["tag"] for s in cfg["dns"]["servers"]]
    assert "dns-local" not in server_tags
    for srv in cfg["dns"]["servers"]:
        assert srv["detour"] == "proxy"
    assert cfg["dns"]["strategy"] == "ipv4_only"

    # TUN strict_route + mixed inbound for Throne
    tun_in = next(i for i in cfg["inbounds"] if i["type"] == "tun")
    assert tun_in["interface_name"] == "throne-tun"
    assert tun_in["auto_route"] is True
    assert tun_in["strict_route"] is True

    # RCA Cause #3 & #4: Manual selector only, NO urltest background probing
    outbound_types = [o["type"] for o in cfg["outbounds"]]
    assert "urltest" not in outbound_types
    selector = next(o for o in cfg["outbounds"] if o["type"] == "selector")
    assert selector["default"] == "vless-vision"
    assert selector["outbounds"] == ["vless-vision", "vless-xhttp-backup"]

    vless_outs = [o for o in cfg["outbounds"] if o["type"] == "vless"]
    assert len(vless_outs) == 2
    for vo in vless_outs:
        assert vo["server"] == "vpn.example.com"
        assert vo["packet_encoding"] == "xudp"
        assert vo["tls"]["utls"]["fingerprint"] == "firefox"
        assert vo["connect_timeout"] == "5s"
        assert vo["tcp_keep_alive"] == "2m"
        assert vo["tcp_keep_alive_interval"] == "30s"

    with pytest.raises(ValueError, match="Unsupported uTLS fingerprint"):
        build_vless_vision_uri(
            domain="vpn.example.com",
            user_uuid=uid,
            reality_public_key=pub,
            reality_short_id=sid,
            fingerprint="invalidfp",
        )

    # Route rules: no direct bypasses, QUIC/STUN/BitTorrent/::/0 blocked, gvt1/gvt2 allowed
    rules = cfg["route"]["rules"]
    assert not any(r.get("outbound") == "direct" for r in rules)
    serialized = json.dumps(rules)
    assert "gvt1.com" not in serialized
    assert "gvt2.com" not in serialized
    assert "location.googleapis.com" in serialized
    assert "quic" in serialized
    assert "stun" in serialized
    assert "::/0" in serialized


def test_xray_client_profile_and_bundle_writer(tmp_path: Path):
    _, pub = generate_reality_keypair()
    sid = generate_short_id()
    uid = "11111111-1111-1111-1111-111111111111"

    xray_cfg = build_xray_client_profile(
        domain="vpn.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
    )
    assert xray_cfg["outbounds"][0]["streamSettings"]["sockopt"] == {
        "tcpKeepAliveIdle": 120,
        "tcpKeepAliveInterval": 30,
        "tcpNoDelay": True,
        "tcpMptcp": False,
    }
    rules = xray_cfg["routing"]["rules"]
    assert rules[0] == {
        "type": "field",
        "inboundTag": ["dns_out"],
        "outboundTag": "proxy",
    }
    serialized = json.dumps(rules)
    assert "gvt1.com" not in serialized
    assert "gvt2.com" not in serialized
    assert "443,3478,19302" in serialized
    assert "::/0" in serialized

    paths = write_client_bundle(
        tmp_path,
        domain="vpn.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        xhttp_secret_path="c" * 64,
        xhttp_backup_enabled=False,
    )
    assert paths["throne"].exists()
    assert paths["android"].exists()
    assert paths["xray"].exists()
    assert paths["links"].exists()

    summary = format_terminal_credentials(
        domain="vpn.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        xhttp_secret_path="c" * 64,
        xhttp_backup_enabled=False,
        credentials_dir=str(tmp_path),
    )
    assert "throne-windows11.json" in summary
    assert "vless://" in summary
    assert "--bridge" in summary
    assert "--upstream-domain vpn.example.com" in summary
    assert f"bridge-transport xhttp --path {'c' * 64}" in summary

    bridge_summary = format_terminal_credentials(
        domain="bridge.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        mode="bridge",
        server_host="198.51.100.20",
        upstream_ip="203.0.113.20",
        upstream_domain="vpn.example.com",
        upstream_transport="xhttp",
        upstream_xhttp_path="c" * 64,
    )
    assert "transport=xhttp+reality+xmux, mode=stream-up" in bridge_summary
    assert "sudo ./script.sh bridge-transport vision" in bridge_summary

    # Bridge-mode client bundle uses server_host IP while keeping FQDN SNI
    bridge_paths = write_client_bundle(
        tmp_path / "bridge",
        domain="vpn.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        server_host="198.51.100.20",
    )
    bridge_throne = json.loads(bridge_paths["throne"].read_text())
    vless_vo = next(
        o for o in bridge_throne["outbounds"] if o["type"] == "vless"
    )
    assert vless_vo["server"] == "198.51.100.20"
    assert vless_vo["tls"]["server_name"] == "vpn.example.com"
    bridge_uri = bridge_paths["links"].read_text().strip()
    assert f"vless://{uid}@198.51.100.20:443?" in bridge_uri
    assert "sni=vpn.example.com" in bridge_uri
    assert "override_android_vpn" not in bridge_throne["route"]
    android_cfg = json.loads(bridge_paths["android"].read_text())
    assert android_cfg["route"].get("override_android_vpn") is True


def test_selective_whitelist_singbox_profiles_for_windows_and_android(tmp_path: Path):
    _, pub = generate_reality_keypair()
    sid = generate_short_id()
    uid = "11111111-1111-1111-1111-111111111111"

    with pytest.raises(ValueError, match="Unsupported routing_mode"):
        build_singbox_profile(
            domain="bridge.example.com",
            user_uuid=uid,
            reality_public_key=pub,
            reality_short_id=sid,
            server_host="198.51.100.20",
            routing_mode="badmode",
        )

    paths = write_client_bundle(
        tmp_path,
        domain="bridge.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        server_host="198.51.100.20",
    )
    assert paths["throne_selective"].exists()
    assert paths["android_selective"].exists()

    win_sel = json.loads(paths["throne_selective"].read_text())
    and_sel = json.loads(paths["android_selective"].read_text())

    expected_podkop_tags = [f"podkop-{name}" for name in PODKOP_COMMUNITY_RULESET_NAMES]
    expected_podkop_dns_tags = [f"podkop-{name}" for name in PODKOP_DNS_DOMAIN_RULESET_NAMES]

    for cfg, app_field, expected_apps, is_android in (
        (win_sel, "process_name", SELECTIVE_WINDOWS_PROCESSES, False),
        (and_sel, "package_name", SELECTIVE_ANDROID_PACKAGES, True),
    ):
        assert cfg["route"]["final"] == "direct"
        assert cfg["route"]["default_domain_resolver"] == "dns-local"
        assert cfg["dns"]["final"] == "dns-local"
        assert cfg["dns"]["strategy"] == "ipv4_only"
        tun_in = next(i for i in cfg["inbounds"] if i["type"] == "tun")
        assert "stack" not in tun_in
        assert "store_rdrc" not in cfg["experimental"]["cache_file"]
        assert cfg["experimental"]["cache_file"]["enabled"] is True

        out_tags = {o["tag"] for o in cfg["outbounds"]}
        assert {"proxy", "vless-vision", "direct"}.issubset(out_tags)
        assert "urltest" not in [o["type"] for o in cfg["outbounds"]]

        vless_out = next(o for o in cfg["outbounds"] if o["type"] == "vless")
        assert vless_out["server"] == "198.51.100.20"
        assert vless_out["tls"]["server_name"] == "bridge.example.com"
        assert vless_out["tls"]["utls"]["fingerprint"] == "firefox"

        dns_servers = {s["tag"]: s for s in cfg["dns"]["servers"]}
        assert dns_servers["dns-remote"]["detour"] == "proxy"
        assert dns_servers["dns-local"]["type"] == "local"
        assert "223.5.5.5" not in json.dumps(cfg)

        dns_rules = cfg["dns"]["rules"]
        # HTTPS type-65 rejected, then app/process -> remote, SMS/mtalk/reminders & .ru -> local, then domain-only Podkop & custom domains -> remote
        assert dns_rules[0] == {"query_type": "HTTPS", "action": "reject"}
        assert dns_rules[1][app_field] == expected_apps
        assert dns_rules[1]["server"] == "dns-remote"
        assert dns_rules[1]["action"] == "route"
        idx = 2
        if is_android:
            assert dns_rules[idx]["package_name"] == SELECTIVE_ANDROID_DIRECT_PACKAGES
            assert dns_rules[idx]["server"] == "dns-local"
            idx += 1
        assert dns_rules[idx]["domain"] == SELECTIVE_DIRECT_BYPASS_DOMAINS
        assert dns_rules[idx]["server"] == "dns-local"
        assert dns_rules[idx + 1]["domain_suffix"] == [".ru", ".su", ".xn--p1ai"]
        assert dns_rules[idx + 1]["server"] == "dns-local"
        assert dns_rules[idx + 2]["rule_set"] == expected_podkop_dns_tags
        assert dns_rules[idx + 2]["server"] == "dns-remote"
        assert dns_rules[idx + 3]["domain_suffix"] == SELECTIVE_VPN_DOMAIN_SUFFIXES
        assert dns_rules[idx + 3]["server"] == "dns-remote"

        rule_sets = cfg["route"]["rule_set"]
        assert [rs["tag"] for rs in rule_sets] == expected_podkop_tags
        if is_android:
            assert cfg["http_clients"] == [{"tag": "proxy-http", "detour": "proxy"}]
            assert cfg["route"]["default_http_client"] == "proxy-http"
            assert cfg["experimental"]["cache_file"].get("store_dns") is True
        else:
            assert "http_clients" not in cfg
        for rs in rule_sets:
            assert rs["type"] == "remote"
            assert rs["format"] == "binary"
            if is_android:
                assert rs["http_client"] == "proxy-http"
                assert "download_detour" not in rs
            else:
                assert rs["download_detour"] == "proxy"
            assert rs["update_interval"] == "1d"
            assert rs["url"].startswith("https://github.com/itdoginfo/allow-domains/releases/latest/download/")

        rules = cfg["route"]["rules"]
        # Private IPs direct (IDE local IPC), telemetry & IPv6 rejected above proxy rules
        idx_private = next(i for i, r in enumerate(rules) if r.get("ip_is_private") is True)
        idx_telem = next(i for i, r in enumerate(rules) if "location.googleapis.com" in r.get("domain", []))
        idx_ipv6 = next(i for i, r in enumerate(rules) if r.get("ip_cidr") == ["::/0"])
        idx_app_proxy = next(i for i, r in enumerate(rules) if r.get(app_field) == expected_apps and r.get("outbound") == "proxy")
        idx_direct_dom = next(i for i, r in enumerate(rules) if r.get("domain") == SELECTIVE_DIRECT_BYPASS_DOMAINS and r.get("outbound") == "direct")
        idx_rs_proxy = next(i for i, r in enumerate(rules) if r.get("rule_set") == expected_podkop_tags and r.get("outbound") == "proxy")
        idx_dom_proxy = next(i for i, r in enumerate(rules) if r.get("domain_suffix") == SELECTIVE_VPN_DOMAIN_SUFFIXES and r.get("outbound") == "proxy")
        idx_tg_cidr = next(i for i, r in enumerate(rules) if r.get("ip_cidr") == TELEGRAM_DC_CIDRS and r.get("outbound") == "proxy")

        assert rules[idx_private]["outbound"] == "direct"
        assert rules[idx_telem]["action"] == "reject"
        assert "firebaselogging.googleapis.com" in rules[idx_telem]["domain"]
        assert rules[idx_ipv6]["action"] == "reject"
        assert idx_telem < idx_app_proxy < idx_direct_dom < idx_rs_proxy < idx_dom_proxy < idx_tg_cidr
        if is_android:
            idx_direct_pkg = next(i for i, r in enumerate(rules) if r.get("package_name") == SELECTIVE_ANDROID_DIRECT_PACKAGES and r.get("outbound") == "direct")
            assert idx_app_proxy < idx_direct_pkg < idx_direct_dom

    assert "Antigravity.exe" in win_sel["dns"]["rules"][1]["process_name"]
    assert "com.google.android.youtube" in and_sel["dns"]["rules"][1]["package_name"]
    assert {"netflix.com", "claude.ai", "databricks.com", "okta.com", "antigravity.google"}.issubset(
        set(SELECTIVE_VPN_DOMAIN_SUFFIXES)
    )
    assert "override_android_vpn" not in win_sel["route"]
    assert and_sel["route"]["override_android_vpn"] is True

    custom_sel = build_singbox_selective_profile(
        domain="vpn.example.com",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        platform="android",
        selective_apps=["com.example.work"],
        selective_domains=["example.org"],
    )
    assert custom_sel["dns"]["rules"][1]["package_name"] == ["com.example.work"]
    assert custom_sel["route"]["final"] == "direct"
