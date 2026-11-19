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

from app.client.profile_generator import build_singbox_profile
from app.nginx.manager import NginxManager
from app.xray.config_builder import (
    LocalXrayConfigBuilder,
    generate_reality_keypair,
    generate_short_id,
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
