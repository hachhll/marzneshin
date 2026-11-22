"""Isolated 127.0.0.1 regression tests for Xray <-> sing-box Reality compatibility and cascade forwarding."""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from app.cli import main as cli_main
from app.client.profile_generator import build_singbox_profile
from app.nginx.manager import NginxManager
from app.xray.config_builder import (
    LocalXrayConfigBuilder,
    generate_reality_keypair,
    generate_short_id,
    validate_xray_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _e2e_deps_available() -> bool:
    if not shutil.which("docker") or not shutil.which("sing-box"):
        return False
    res = subprocess.run(
        ["docker", "image", "inspect", "jc21/nginx-proxy-manager:latest"],
        capture_output=True,
        text=True,
    )
    return res.returncode == 0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_tcp(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"Timed out waiting for {host}:{port}")


@pytest.mark.skipif(
    not _e2e_deps_available(),
    reason="Requires local docker, nginx-proxy-manager image, and sing-box binary",
)
def test_singbox_reality_handshake_and_bridge_cascade_compatibility():
    """Verify Dockerfile Xray binary completes Reality handshake with sing-box across Bridge->Exit on 127.0.0.1."""
    image_tag = "marzneshin-xray-compat:test"
    build = subprocess.run(
        ["docker", "build", "-q", "-t", image_tag, str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert build.returncode == 0, build.stderr

    domain = "compat.example.test"
    uid_exit = "11111111-1111-1111-1111-111111111111"
    priv_exit, pub_exit = generate_reality_keypair()
    sid_exit = generate_short_id()

    uid_br = "22222222-2222-2222-2222-222222222222"
    priv_br, pub_br = generate_reality_keypair()
    sid_br = generate_short_id()

    nx_http_port = _free_port()
    nx_fallback_port = _free_port()
    exit_port = _free_port()
    exit_xhttp_port = _free_port()
    bridge_port = _free_port()
    bridge_xhttp_port = _free_port()
    exit_api_port = _free_port()
    bridge_api_port = _free_port()
    bridge_xhttp_api_port = _free_port()
    socks_port = _free_port()
    socks_xhttp_port = _free_port()
    xhttp_secret = "e" * 64

    cname_nx = f"compat-nx-{os.getpid()}"
    cname_exit = f"compat-exit-{os.getpid()}"
    cname_br = f"compat-br-{os.getpid()}"
    cname_br_xh = f"compat-br-xh-{os.getpid()}"

    with tempfile.TemporaryDirectory(prefix="marzneshin-compat-") as td:
        tmp = Path(td)
        os.chmod(tmp, 0o755)
        rt = tmp / "nginx"
        mgr = NginxManager(
            runtime_dir=str(rt),
            cert_path=str(tmp / "fullchain.pem"),
            key_path=str(tmp / "privkey.pem"),
            dummy_cert_path=str(tmp / "dummy-fullchain.pem"),
            dummy_key_path=str(tmp / "dummy-privkey.pem"),
            webroot_dir=str(tmp / "webroot"),
            http_port=nx_http_port,
            fallback_port=nx_fallback_port,
        )
        mgr.apply(domain=domain, validate_binary=False, enable_http=False)
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                str(tmp / "privkey.pem"),
                "-out",
                str(tmp / "fullchain.pem"),
                "-days",
                "5",
                "-nodes",
                "-subj",
                f"/CN={domain}",
                "-addext",
                f"subjectAltName=DNS:{domain}",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(tmp / "privkey.pem", 0o644)
        os.chmod(tmp / "fullchain.pem", 0o644)

        # Validate generated client profile schema via sing-box check
        throne_cfg = build_singbox_profile(
            domain=domain,
            user_uuid=uid_br,
            reality_public_key=pub_br,
            reality_short_id=sid_br,
            include_xhttp_backup=False,
            platform="windows11-throne",
            port=bridge_port,
            server_host="127.0.0.1",
        )
        (tmp / "throne.json").write_text(json.dumps(throne_cfg))
        chk = subprocess.run(
            ["sing-box", "check", "-c", str(tmp / "throne.json")],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert chk.returncode == 0, chk.stderr

        exit_cfg = LocalXrayConfigBuilder.build(
            domain=domain,
            reality_private_key=priv_exit,
            reality_short_ids=[sid_exit],
            clients=[{"id": uid_exit, "email": "owner"}],
            xhttp_backup_enabled=True,
            xhttp_secret_path=xhttp_secret,
            listen_port=exit_port,
            fallback_port=nx_fallback_port,
            api_address=f"127.0.0.1:{exit_api_port}",
            xhttp_port=exit_xhttp_port,
        )
        exit_cfg["log"] = {"loglevel": "debug"}
        exit_cfg["inbounds"][1]["listen"] = "127.0.0.1"
        exit_cfg["inbounds"][1]["streamSettings"]["realitySettings"]["show"] = True
        (tmp / "exit.json").write_text(json.dumps(exit_cfg))

        br_cfg = LocalXrayConfigBuilder.build_bridge(
            bridge_sni=domain,
            reality_private_key=priv_br,
            reality_short_ids=[sid_br],
            clients=[{"id": uid_br, "email": "owner"}],
            upstream_ip="127.0.0.1",
            upstream_domain=domain,
            upstream_uuid=uid_exit,
            upstream_public_key=pub_exit,
            upstream_short_id=sid_exit,
            upstream_port=exit_port,
            upstream_transport="vision",
            listen_port=bridge_port,
            fallback_port=nx_fallback_port,
            api_address=f"127.0.0.1:{bridge_api_port}",
        )
        br_cfg["log"] = {"loglevel": "debug"}
        br_cfg["inbounds"][1]["listen"] = "127.0.0.1"
        br_cfg["inbounds"][1]["streamSettings"]["realitySettings"]["show"] = True
        (tmp / "bridge.json").write_text(json.dumps(br_cfg))

        br_xh_cfg = LocalXrayConfigBuilder.build_bridge(
            bridge_sni=domain,
            reality_private_key=priv_br,
            reality_short_ids=[sid_br],
            clients=[{"id": uid_br, "email": "owner"}],
            upstream_ip="127.0.0.1",
            upstream_domain=domain,
            upstream_uuid=uid_exit,
            upstream_public_key=pub_exit,
            upstream_short_id=sid_exit,
            upstream_port=exit_port,
            upstream_transport="xhttp",
            upstream_xhttp_path=xhttp_secret,
            listen_port=bridge_xhttp_port,
            fallback_port=nx_fallback_port,
            api_address=f"127.0.0.1:{bridge_xhttp_api_port}",
        )
        br_xh_cfg["log"] = {"loglevel": "debug"}
        br_xh_cfg["inbounds"][1]["listen"] = "127.0.0.1"
        br_xh_cfg["inbounds"][1]["streamSettings"]["realitySettings"]["show"] = True
        (tmp / "bridge_xhttp.json").write_text(json.dumps(br_xh_cfg))

        nx_proc = None
        exit_proc = None
        br_proc = None
        br_xh_proc = None
        sb_proc = None
        try:
            nx_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_nx,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:rw",
                    "--entrypoint",
                    "/bin/sh",
                    "jc21/nginx-proxy-manager:latest",
                    "-c",
                    f'exec nginx -g "user root; daemon off;" -e /dev/null -c "{rt}/nginx.conf"',
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            exit_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_exit,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:ro",
                    "--entrypoint",
                    "xray",
                    image_tag,
                    "run",
                    "-c",
                    str(tmp / "exit.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            br_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_br,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:ro",
                    "--entrypoint",
                    "xray",
                    image_tag,
                    "run",
                    "-c",
                    str(tmp / "bridge.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            br_xh_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_br_xh,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:ro",
                    "--entrypoint",
                    "xray",
                    image_tag,
                    "run",
                    "-c",
                    str(tmp / "bridge_xhttp.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            _wait_tcp("127.0.0.1", nx_fallback_port, timeout=10.0)
            _wait_tcp("127.0.0.1", exit_port, timeout=10.0)
            _wait_tcp("127.0.0.1", bridge_port, timeout=10.0)
            _wait_tcp("127.0.0.1", bridge_xhttp_port, timeout=10.0)

            sb_cfg = {
                "log": {"level": "debug"},
                "inbounds": [
                    {
                        "type": "socks",
                        "tag": "socks-in",
                        "listen": "127.0.0.1",
                        "listen_port": socks_port,
                    },
                    {
                        "type": "socks",
                        "tag": "socks-xhttp-in",
                        "listen": "127.0.0.1",
                        "listen_port": socks_xhttp_port,
                    },
                ],
                "outbounds": [
                    {
                        "type": "vless",
                        "tag": "proxy",
                        "server": "127.0.0.1",
                        "server_port": bridge_port,
                        "uuid": uid_br,
                        "flow": "xtls-rprx-vision",
                        "tls": {
                            "enabled": True,
                            "server_name": domain,
                            "utls": {"enabled": True, "fingerprint": "firefox"},
                            "reality": {
                                "enabled": True,
                                "public_key": pub_br,
                                "short_id": sid_br,
                            },
                        },
                    },
                    {
                        "type": "vless",
                        "tag": "proxy-via-xhttp-bridge",
                        "server": "127.0.0.1",
                        "server_port": bridge_xhttp_port,
                        "uuid": uid_br,
                        "flow": "xtls-rprx-vision",
                        "tls": {
                            "enabled": True,
                            "server_name": domain,
                            "utls": {"enabled": True, "fingerprint": "firefox"},
                            "reality": {
                                "enabled": True,
                                "public_key": pub_br,
                                "short_id": sid_br,
                            },
                        },
                    },
                ],
                "route": {
                    "rules": [
                        {
                            "inbound": ["socks-xhttp-in"],
                            "outbound": "proxy-via-xhttp-bridge",
                        }
                    ],
                    "final": "proxy",
                },
            }
            (tmp / "sb.json").write_text(json.dumps(sb_cfg))
            sb_proc = subprocess.Popen(
                ["sing-box", "run", "-c", str(tmp / "sb.json")],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _wait_tcp("127.0.0.1", socks_port, timeout=5.0)
            _wait_tcp("127.0.0.1", socks_xhttp_port, timeout=5.0)

            # Trigger SOCKS5 connection through sing-box -> Bridge (Vision) -> Exit AND sing-box -> Bridge (XHTTP+Reality+xmux) -> Exit
            env = os.environ.copy()
            env.pop("NO_PROXY", None)
            env.pop("no_proxy", None)
            for sp in (socks_port, socks_xhttp_port):
                subprocess.run(
                    [
                        "curl",
                        "--noproxy",
                        "",
                        "-sS",
                        "-m",
                        "2",
                        "--socks5-hostname",
                        f"127.0.0.1:{sp}",
                        "http://198.18.0.1/",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                )

            # Terminate clients/servers cleanly and verify Reality handshake completed on Vision Bridge, XHTTP Bridge, and Dual-Mode Exit
            sb_proc.terminate()
            sb_out, _ = sb_proc.communicate(timeout=3)
            subprocess.run(
                ["docker", "rm", "-f", cname_br, cname_br_xh, cname_exit, cname_nx],
                capture_output=True,
            )
            br_out, _ = br_proc.communicate(timeout=3)
            br_xh_out, _ = br_xh_proc.communicate(timeout=3)
            exit_out, _ = exit_proc.communicate(timeout=3)

            assert "reality verification failed" not in sb_out
            assert "x509:" not in sb_out
            assert "hs.c.isHandshakeComplete.Load(): true" in br_out, br_out
            assert "authentication failed" not in br_out
            assert "hs.c.isHandshakeComplete.Load(): true" in br_xh_out, br_xh_out
            assert "authentication failed" not in br_xh_out
            assert "XHTTP is dialing" in br_xh_out, br_xh_out
            assert "hs.c.isHandshakeComplete.Load(): true" in exit_out, exit_out
            assert "fallback starts" in exit_out, exit_out
            assert "authentication failed" not in exit_out
            assert "taking detour [proxy]" in br_out
            assert "taking detour [proxy]" in br_xh_out
        finally:
            if sb_proc and sb_proc.poll() is None:
                sb_proc.terminate()
            subprocess.run(
                ["docker", "rm", "-f", cname_br, cname_br_xh, cname_exit, cname_nx],
                capture_output=True,
            )
            for p in (nx_proc, exit_proc, br_proc, br_xh_proc):
                if p and p.poll() is None:
                    p.terminate()


@pytest.mark.skipif(
    not _e2e_deps_available(),
    reason="Requires local docker, nginx-proxy-manager image, and sing-box binary",
)
def test_multi_exit_bridge_routing_ru_blackhole_and_migrate():
    """Verify 1 bridge statically routes 2 UUIDs to 2 XHTTP exits, Exit blackholes .ru, and upstream migrate keeps client UUID/bundle intact."""
    image_tag = "marzneshin-xray-compat:test"
    build = subprocess.run(
        ["docker", "build", "-q", "-t", image_tag, str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert build.returncode == 0, build.stderr

    domain_bridge = "mos.bridge-e2e.test"
    domain_ai = "ai.only-ai-e2e.org"
    domain_m1 = "m1.media-e2e.net"

    uid_exit_ai = "11111111-1111-4111-8111-111111111111"
    uid_exit_m1 = "22222222-2222-4222-8222-222222222222"
    priv_ai, pub_ai = generate_reality_keypair()
    priv_m1, pub_m1 = generate_reality_keypair()
    sid_ai = generate_short_id()
    sid_m1 = generate_short_id()
    xhttp_ai = "a" * 64
    xhttp_m1 = "b" * 64

    uid_owner = "33333333-3333-4333-8333-333333333333"
    uid_alice = "44444444-4444-4444-8444-444444444444"
    priv_br, pub_br = generate_reality_keypair()
    sid_br = generate_short_id()

    nx_http_port = _free_port()
    nx_fallback_port = _free_port()
    exit_ai_port = _free_port()
    exit_ai_xhttp_port = _free_port()
    exit_ai_api_port = _free_port()
    exit_m1_port = _free_port()
    exit_m1_xhttp_port = _free_port()
    exit_m1_api_port = _free_port()
    bridge_port = _free_port()
    bridge_api_port = _free_port()
    socks_owner_port = _free_port()
    socks_alice_port = _free_port()

    cname_nx = f"multi-nx-{os.getpid()}"
    cname_ai = f"multi-ai-{os.getpid()}"
    cname_m1 = f"multi-m1-{os.getpid()}"
    cname_br = f"multi-br-{os.getpid()}"

    with tempfile.TemporaryDirectory(prefix="marzneshin-multi-e2e-") as td:
        tmp = Path(td)
        os.chmod(tmp, 0o755)
        rt = tmp / "nginx"
        mgr = NginxManager(
            runtime_dir=str(rt),
            cert_path=str(tmp / "fullchain.pem"),
            key_path=str(tmp / "privkey.pem"),
            dummy_cert_path=str(tmp / "dummy-fullchain.pem"),
            dummy_key_path=str(tmp / "dummy-privkey.pem"),
            webroot_dir=str(tmp / "webroot"),
            http_port=nx_http_port,
            fallback_port=nx_fallback_port,
        )
        mgr.apply(domain=domain_bridge, validate_binary=False, enable_http=False)
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                str(tmp / "privkey.pem"),
                "-out",
                str(tmp / "fullchain.pem"),
                "-days",
                "5",
                "-nodes",
                "-subj",
                f"/CN={domain_bridge}",
                "-addext",
                f"subjectAltName=DNS:{domain_bridge}",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(tmp / "privkey.pem", 0o644)
        os.chmod(tmp / "fullchain.pem", 0o644)

        exit_ai_cfg = LocalXrayConfigBuilder.build(
            domain=domain_ai,
            reality_private_key=priv_ai,
            reality_short_ids=[sid_ai],
            clients=[{"id": uid_exit_ai, "email": "bridge-ai"}],
            xhttp_backup_enabled=True,
            xhttp_secret_path=xhttp_ai,
            listen_port=exit_ai_port,
            fallback_port=nx_fallback_port,
            api_address=f"127.0.0.1:{exit_ai_api_port}",
            xhttp_port=exit_ai_xhttp_port,
        )
        validate_xray_config(exit_ai_cfg, expected_ipv6=False, mode="exit")
        exit_ai_cfg["log"] = {"loglevel": "debug"}
        exit_ai_cfg["inbounds"][1]["listen"] = "127.0.0.1"
        exit_ai_cfg["inbounds"][1]["streamSettings"]["realitySettings"]["show"] = True
        (tmp / "exit_ai.json").write_text(json.dumps(exit_ai_cfg))

        # Verify real Xray binary validates Exit config with geoip:ru + domain:ru rules
        xray_test = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp}:{tmp}:ro",
                "--entrypoint",
                "xray",
                image_tag,
                "run",
                "-test",
                "-config",
                str(tmp / "exit_ai.json"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert xray_test.returncode == 0, xray_test.stderr

        exit_m1_cfg = LocalXrayConfigBuilder.build(
            domain=domain_m1,
            reality_private_key=priv_m1,
            reality_short_ids=[sid_m1],
            clients=[{"id": uid_exit_m1, "email": "bridge-m1"}],
            xhttp_backup_enabled=True,
            xhttp_secret_path=xhttp_m1,
            listen_port=exit_m1_port,
            fallback_port=nx_fallback_port,
            api_address=f"127.0.0.1:{exit_m1_api_port}",
            xhttp_port=exit_m1_xhttp_port,
        )
        exit_m1_cfg["log"] = {"loglevel": "debug"}
        exit_m1_cfg["inbounds"][1]["listen"] = "127.0.0.1"
        exit_m1_cfg["inbounds"][1]["streamSettings"]["realitySettings"]["show"] = True
        (tmp / "exit_m1.json").write_text(json.dumps(exit_m1_cfg))

        upstreams_live = {
            "exit-ai": {
                "ip": "127.0.0.1",
                "port": exit_ai_port,
                "domain": domain_ai,
                "uuid": uid_exit_ai,
                "public_key": pub_ai,
                "short_id": sid_ai,
                "transport": "xhttp",
                "xhttp_path": xhttp_ai,
            },
            "exit-media-1": {
                "ip": "127.0.0.1",
                "port": exit_m1_port,
                "domain": domain_m1,
                "uuid": uid_exit_m1,
                "public_key": pub_m1,
                "short_id": sid_m1,
                "transport": "xhttp",
                "xhttp_path": xhttp_m1,
            },
        }
        bridge_cfg = LocalXrayConfigBuilder.build_bridge(
            bridge_sni=domain_bridge,
            reality_private_key=priv_br,
            reality_short_ids=[sid_br],
            upstreams=upstreams_live,
            clients=[
                {"id": uid_owner, "email": "owner"},
                {"id": uid_alice, "email": "alice"},
            ],
            user_routes={"owner": "exit-ai", "alice": "exit-media-1"},
            listen_port=bridge_port,
            fallback_port=nx_fallback_port,
            api_address=f"127.0.0.1:{bridge_api_port}",
        )
        for ob in bridge_cfg["outbounds"][:2]:
            assert ob["streamSettings"]["xhttpSettings"]["xmux"]["hMaxReusableSecs"] == "180-300"

        bridge_cfg["log"] = {"loglevel": "debug"}
        bridge_cfg["inbounds"][1]["listen"] = "127.0.0.1"
        bridge_cfg["inbounds"][1]["streamSettings"]["realitySettings"]["show"] = True
        (tmp / "bridge.json").write_text(json.dumps(bridge_cfg))

        nx_proc = None
        ai_proc = None
        m1_proc = None
        br_proc = None
        sb_proc = None
        try:
            nx_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_nx,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:rw",
                    "--entrypoint",
                    "/bin/sh",
                    "jc21/nginx-proxy-manager:latest",
                    "-c",
                    f'exec nginx -g "user root; daemon off;" -e /dev/null -c "{rt}/nginx.conf"',
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            ai_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_ai,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:ro",
                    "--entrypoint",
                    "xray",
                    image_tag,
                    "run",
                    "-c",
                    str(tmp / "exit_ai.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            m1_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_m1,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:ro",
                    "--entrypoint",
                    "xray",
                    image_tag,
                    "run",
                    "-c",
                    str(tmp / "exit_m1.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            br_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    cname_br,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:ro",
                    "--entrypoint",
                    "xray",
                    image_tag,
                    "run",
                    "-c",
                    str(tmp / "bridge.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _wait_tcp("127.0.0.1", nx_fallback_port, timeout=10.0)
            _wait_tcp("127.0.0.1", exit_ai_port, timeout=10.0)
            _wait_tcp("127.0.0.1", exit_m1_port, timeout=10.0)
            _wait_tcp("127.0.0.1", bridge_port, timeout=10.0)

            sb_cfg = {
                "log": {"level": "debug"},
                "inbounds": [
                    {
                        "type": "socks",
                        "tag": "socks-owner",
                        "listen": "127.0.0.1",
                        "listen_port": socks_owner_port,
                    },
                    {
                        "type": "socks",
                        "tag": "socks-alice",
                        "listen": "127.0.0.1",
                        "listen_port": socks_alice_port,
                    },
                ],
                "outbounds": [
                    {
                        "type": "vless",
                        "tag": "proxy-owner",
                        "server": "127.0.0.1",
                        "server_port": bridge_port,
                        "uuid": uid_owner,
                        "flow": "xtls-rprx-vision",
                        "tls": {
                            "enabled": True,
                            "server_name": domain_bridge,
                            "utls": {"enabled": True, "fingerprint": "firefox"},
                            "reality": {
                                "enabled": True,
                                "public_key": pub_br,
                                "short_id": sid_br,
                            },
                        },
                    },
                    {
                        "type": "vless",
                        "tag": "proxy-alice",
                        "server": "127.0.0.1",
                        "server_port": bridge_port,
                        "uuid": uid_alice,
                        "flow": "xtls-rprx-vision",
                        "tls": {
                            "enabled": True,
                            "server_name": domain_bridge,
                            "utls": {"enabled": True, "fingerprint": "firefox"},
                            "reality": {
                                "enabled": True,
                                "public_key": pub_br,
                                "short_id": sid_br,
                            },
                        },
                    },
                ],
                "route": {
                    "rules": [
                        {"inbound": ["socks-owner"], "outbound": "proxy-owner"},
                        {"inbound": ["socks-alice"], "outbound": "proxy-alice"},
                    ],
                    "final": "proxy-owner",
                },
            }
            (tmp / "sb.json").write_text(json.dumps(sb_cfg))
            sb_proc = subprocess.Popen(
                ["sing-box", "run", "-c", str(tmp / "sb.json")],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _wait_tcp("127.0.0.1", socks_owner_port, timeout=5.0)
            _wait_tcp("127.0.0.1", socks_alice_port, timeout=5.0)

            env = os.environ.copy()
            env.pop("NO_PROXY", None)
            env.pop("no_proxy", None)
            for sp, url in (
                (socks_owner_port, "http://198.18.0.1/"),
                (socks_alice_port, "http://198.18.0.2/"),
                (socks_owner_port, "http://blocked-snitch.ru/"),
            ):
                subprocess.run(
                    [
                        "curl",
                        "--noproxy",
                        "",
                        "-sS",
                        "-m",
                        "2",
                        "--socks5-hostname",
                        f"127.0.0.1:{sp}",
                        url,
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                )

            sb_proc.terminate()
            sb_out, _ = sb_proc.communicate(timeout=3)
            subprocess.run(
                ["docker", "rm", "-f", cname_br, cname_ai, cname_m1, cname_nx],
                capture_output=True,
            )
            br_out, _ = br_proc.communicate(timeout=3)
            ai_out, _ = ai_proc.communicate(timeout=3)
            m1_out, _ = m1_proc.communicate(timeout=3)

            assert "reality verification failed" not in sb_out
            assert "taking detour [proxy-exit-ai]" in br_out, br_out
            assert "taking detour [proxy-exit-media-1]" in br_out, br_out
            # Static isolation: owner (198.18.0.1) only on exit-ai, alice (198.18.0.2) only on exit-media-1
            assert "198.18.0.1" in ai_out and "198.18.0.2" not in ai_out, ai_out
            assert "198.18.0.2" in m1_out and "198.18.0.1" not in m1_out, m1_out
            # Exit RU blackhole rule enforced on exit-ai
            assert "blocked-snitch.ru" in ai_out and "taking detour [block]" in ai_out, ai_out
        finally:
            if sb_proc and sb_proc.poll() is None:
                sb_proc.terminate()
            subprocess.run(
                ["docker", "rm", "-f", cname_br, cname_ai, cname_m1, cname_nx],
                capture_output=True,
            )
            for p in (nx_proc, ai_proc, m1_proc, br_proc):
                if p and p.poll() is None:
                    p.terminate()

        # Verify CLI upstream migrate without changing client UUIDs or mobile JSON profiles
        cli_data = tmp / "cli_data"
        cli_creds = tmp / "cli_creds"
        assert (
            cli_main(
                [
                    "--data-dir",
                    str(cli_data),
                    "--credentials-dir",
                    str(cli_creds),
                    "init-bridge",
                    "--upstream-ip",
                    "198.51.100.10",
                    "--upstream-domain",
                    domain_m1,
                    "--upstream-uuid",
                    uid_exit_m1,
                    "--upstream-pbk",
                    pub_m1,
                    "--upstream-sid",
                    sid_m1,
                    "--bridge-sni",
                    domain_bridge,
                    "--bridge-ip",
                    "192.0.2.50",
                    "--upstream-transport",
                    "xhttp",
                    "--upstream-xhttp-path",
                    xhttp_m1,
                ]
            )
            == 0
        )
        assert (
            cli_main(
                [
                    "--data-dir",
                    str(cli_data),
                    "--credentials-dir",
                    str(cli_creds),
                    "upstream",
                    "add",
                    "exit-media-2",
                    "--role",
                    "media",
                    "--ip",
                    "198.18.20.20",
                    "--domain",
                    "m2.media-backup.org",
                    "--uuid",
                    uid_exit_ai,
                    "--pbk",
                    pub_ai,
                    "--sid",
                    sid_ai,
                    "--transport",
                    "xhttp",
                    "--xhttp-path",
                    xhttp_ai,
                ]
            )
            == 0
        )
        assert (
            cli_main(
                [
                    "--data-dir",
                    str(cli_data),
                    "--credentials-dir",
                    str(cli_creds),
                    "user",
                    "add",
                    "alice",
                    "--upstream",
                    "default",
                    "--uuid",
                    uid_alice,
                ]
            )
            == 0
        )
        before_and_json = (
            cli_creds / "users" / "alice" / "android-media-selective.json"
        ).read_bytes()
        before_ios_json = (
            cli_creds / "users" / "alice" / "ios-media-selective.json"
        ).read_bytes()

        assert (
            cli_main(
                [
                    "--data-dir",
                    str(cli_data),
                    "--credentials-dir",
                    str(cli_creds),
                    "upstream",
                    "migrate",
                    "default",
                    "exit-media-2",
                ]
            )
            == 0
        )
        assert (
            cli_creds / "users" / "alice" / "android-media-selective.json"
        ).read_bytes() == before_and_json
        assert (
            cli_creds / "users" / "alice" / "ios-media-selective.json"
        ).read_bytes() == before_ios_json
        migrated_xray = json.loads((cli_data / "xray" / "config.json").read_text())
        assert any(
            "alice" in r.get("user", [])
            and r.get("outboundTag") == "proxy-exit-media-2"
            for r in migrated_xray["routing"]["rules"]
        )
