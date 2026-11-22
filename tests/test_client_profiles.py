import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.client import (
    CLIENT_PROFILE_VERSION,
    MEDIA_SELECTIVE_ANDROID_PACKAGES,
    MEDIA_SELECTIVE_DOMAIN_SUFFIXES,
    PODKOP_COMMUNITY_RULESET_NAMES,
    PODKOP_DNS_DOMAIN_RULESET_NAMES,
    SELECTIVE_ANDROID_DIRECT_PACKAGES,
    SELECTIVE_ANDROID_PACKAGES,
    SELECTIVE_DIRECT_BYPASS_DOMAINS,
    SELECTIVE_VPN_DOMAIN_SUFFIXES,
    SELECTIVE_WINDOWS_PROCESSES,
    SINGBOX_TARGET_MIN_VERSION,
    TELEGRAM_DC_CIDRS,
    build_media_selective_profile,
    build_openwrt_outbound_profile,
    build_singbox_profile,
    build_singbox_selective_profile,
    build_vless_vision_uri,
    build_vless_xhttp_uri,
    build_xray_client_profile,
    format_terminal_credentials,
    render_qr_utf8,
    write_client_bundle,
    write_user_bundle,
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


def test_media_consumer_mobile_only_profiles_and_no_raw_links(tmp_path: Path):
    _, pub = generate_reality_keypair()
    sid = generate_short_id()
    uid = "33333333-3333-4333-8333-333333333333"

    # Media-consumer profiles reject desktop/router platforms
    for bad_plat in ("windows11-throne", "linux", "openwrt"):
        with pytest.raises(ValueError, match="mobile-only"):
            build_media_selective_profile(
                domain="mos.bridge.net",
                user_uuid=uid,
                reality_public_key=pub,
                reality_short_id=sid,
                platform=bad_plat,
                server_host="192.0.2.10",
            )

    res = write_user_bundle(
        tmp_path,
        username="alice-phone",
        profile="media-selective",
        domain="mos.bridge.net",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        server_host="192.0.2.10",
    )
    user_dir = res["bundle_dir"]
    assert user_dir == tmp_path / "users" / "alice-phone"
    created_names = sorted(p.name for p in user_dir.iterdir())
    assert created_names == [
        "android-media-selective.json",
        "bundle-manifest.json",
        "ios-media-selective.json",
    ]
    assert not (user_dir / "links.txt").exists()
    assert res["profile_version"] == CLIENT_PROFILE_VERSION
    assert res["singbox_min_version"] == SINGBOX_TARGET_MIN_VERSION
    assert len(res["profile_sha256"]) == 64

    and_cfg = json.loads((user_dir / "android-media-selective.json").read_text())
    ios_cfg = json.loads((user_dir / "ios-media-selective.json").read_text())

    for cfg in (and_cfg, ios_cfg):
        assert cfg["route"]["final"] == "direct"
        assert cfg["dns"]["final"] == "dns-local"
        assert {"query_type": "HTTPS", "action": "reject"} in cfg["dns"]["rules"]
        assert "urltest" not in [o["type"] for o in cfg["outbounds"]]
        vless_out = next(o for o in cfg["outbounds"] if o["type"] == "vless")
        assert vless_out["server"] == "192.0.2.10"
        assert vless_out["tls"]["server_name"] == "mos.bridge.net"
        assert vless_out["tls"]["utls"]["fingerprint"] == "firefox"
        assert cfg["http_clients"] == [{"tag": "proxy-http", "detour": "proxy"}]
        assert cfg["route"]["default_http_client"] == "proxy-http"
        assert cfg["experimental"]["cache_file"].get("store_dns") is True
        serialized = json.dumps(cfg)
        assert "download_detour" not in serialized
        assert "store_rdrc" not in serialized
        assert "stack" not in json.dumps(cfg["inbounds"])
        # Only 5 target media services (no AI/IDE domains leaked into media-consumer profile)
        for ai_dom in ("openai.com", "claude.ai", "anthropic.com", "antigravity.google"):
            assert ai_dom not in serialized
        for media_dom in (
            "youtube.com",
            "instagram.com",
            "telegram.org",
            "tiktok.com",
            "tiktokv.eu",
            "bytedance.com",
            "bytegecko.com",
            "whatsapp.com",
            "yazio.com",
        ):
            assert media_dom in serialized
        # Unconditional blocking of QUIC, STUN, BitTorrent, ::/0, telemetry
        rules = cfg["route"]["rules"]
        assert {"protocol": ["quic", "stun", "bittorrent"], "action": "reject"} in rules
        assert {"network": "udp", "port": [443, 3478, 19302], "action": "reject"} in rules
        assert {"ip_cidr": ["::/0"], "action": "reject"} in rules
        assert any("location.googleapis.com" in r.get("domain", []) and r.get("action") == "reject" for r in rules)

    # Android-specific fields present on Android, strictly omitted on iOS
    assert and_cfg["route"].get("override_android_vpn") is True
    assert and_cfg["inbounds"][0]["interface_name"] == "sbtun0"
    assert "com.yazio.android" in MEDIA_SELECTIVE_ANDROID_PACKAGES
    assert any(r.get("package_name") == MEDIA_SELECTIVE_ANDROID_PACKAGES for r in and_cfg["route"]["rules"])

    ios_serialized = json.dumps(ios_cfg)
    assert "package_name" not in ios_serialized
    assert "process_name" not in ios_serialized
    assert "override_android_vpn" not in ios_serialized
    assert "interface_name" not in ios_serialized
    assert "rule_set" not in ios_cfg["route"]
    assert "russia_inside" not in ios_serialized
    assert set(MEDIA_SELECTIVE_DOMAIN_SUFFIXES).issubset(
        set(next(r["domain_suffix"] for r in ios_cfg["route"]["rules"] if r.get("outbound") == "proxy" and "domain_suffix" in r))
    )


def test_ai_owner_five_os_admin_suite_and_https_dns_block(tmp_path: Path):
    _, pub = generate_reality_keypair()
    sid = generate_short_id()
    uid = "44444444-4444-4444-8444-444444444444"

    res = write_user_bundle(
        tmp_path,
        username="owner",
        profile="ai-owner",
        domain="mos.bridge.net",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        server_host="192.0.2.10",
    )
    user_dir = res["bundle_dir"]
    expected_files = {
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
        "xray-client.json",
        "links.txt",
        "bundle-manifest.json",
    }
    assert expected_files.issubset({p.name for p in user_dir.iterdir()})
    manifest = json.loads((user_dir / "bundle-manifest.json").read_text())
    assert manifest["profile_role"] == "ai-owner"
    assert manifest["bundle_sha256"] == res["profile_sha256"]
    assert "throne-windows11.json" in manifest["files"]
    assert f"vless://{uid}@192.0.2.10:443?" in (user_dir / "links.txt").read_text()

    # Full-tunnel profiles on all OSes MUST reject query_type HTTPS in dns.rules
    for full_name in (
        "throne-windows11.json",
        "android-singbox.json",
        "ios-singbox.json",
        "linux-singbox.json",
    ):
        full_cfg = json.loads((user_dir / full_name).read_text())
        assert {"query_type": "HTTPS", "action": "reject"} in full_cfg["dns"]["rules"], full_name
        assert "urltest" not in [o["type"] for o in full_cfg["outbounds"]]

    # iOS profiles omit package_name, process_name, override_android_vpn, interface_name, heavy .srs
    for ios_name in ("ios-singbox.json", "ios-singbox-selective.json"):
        ios_raw = (user_dir / ios_name).read_text()
        assert "package_name" not in ios_raw
        assert "process_name" not in ios_raw
        assert "override_android_vpn" not in ios_raw
        assert "interface_name" not in ios_raw
        assert "russia_inside" not in ios_raw

    # Linux profiles omit override_android_vpn and expose tun + mixed-in
    lin_cfg = json.loads((user_dir / "linux-singbox-selective.json").read_text())
    assert "override_android_vpn" not in lin_cfg["route"]
    assert {i["type"] for i in lin_cfg["inbounds"]} == {"tun", "mixed"}

    # OpenWrt router-safe tproxy + standalone podkop outbound
    owrt_sb = json.loads((user_dir / "openwrt-singbox.json").read_text())
    assert owrt_sb["inbounds"] == [
        {"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 7895}
    ]
    assert owrt_sb["route"]["final"] == "direct"
    assert {"query_type": "HTTPS", "action": "reject"} in owrt_sb["dns"]["rules"]
    assert "auto_route" not in json.dumps(owrt_sb)
    assert "rule_set" not in owrt_sb["route"]

    owrt_ob = build_openwrt_outbound_profile(
        domain="mos.bridge.net",
        user_uuid=uid,
        reality_public_key=pub,
        reality_short_id=sid,
        server_host="192.0.2.10",
    )
    assert owrt_ob == json.loads((user_dir / "openwrt-outbound.json").read_text())
    ob0 = owrt_ob["outbounds"][0]
    assert ob0["type"] == "vless"
    assert ob0["server"] == "192.0.2.10"
    assert ob0["tls"]["utls"]["fingerprint"] == "firefox"
    assert ob0["packet_encoding"] == "xudp"

    # OpenWrt Full Tunnel is explicitly rejected to protect exit-ai from LAN leaks
    with pytest.raises(ValueError, match="OpenWrt"):
        build_singbox_profile(
            domain="mos.bridge.net",
            user_uuid=uid,
            reality_public_key=pub,
            reality_short_id=sid,
            platform="openwrt",
            routing_mode="full",
            server_host="192.0.2.10",
        )

    if shutil.which("sing-box"):
        for check_file in ("throne-windows11.json", "openwrt-singbox.json"):
            proc = subprocess.run(
                ["sing-box", "check", "-c", str(user_dir / check_file)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert proc.returncode == 0, f"{check_file}: {proc.stderr}"
