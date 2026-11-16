import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.client import (
    build_singbox_profile,
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

    if shutil.which("sing-box"):
        res = subprocess.run(
            ["sing-box", "check", "-c", str(bridge_paths["throne"])],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert res.returncode == 0, res.stderr + res.stdout
