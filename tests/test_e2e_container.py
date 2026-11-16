import asyncio
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from cryptography import x509

from app.cli import main as cli_main
from app.utils.self_test import run_self_test


def _docker_available() -> bool:
    if not shutil.which("docker"):
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
    raise RuntimeError(f"Timed out waiting for TCP {host}:{port}")


class ProxyProtocolRelayThread(threading.Thread):
    """Simulates Xray Reality TCP :443 forwarding non-Reality traffic to Nginx :8443 with PROXY v1."""

    def __init__(self, listen_port: int, target_port: int) -> None:
        super().__init__(daemon=True)
        self.listen_port = listen_port
        self.target_port = target_port
        self._stop_event: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self.ready = threading.Event()

    async def _pipe(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        peer = client_writer.get_extra_info("peername") or ("127.0.0.1", 12345)
        sport = (
            int(peer[1])
            if isinstance(peer, tuple) and len(peer) >= 2
            else 12345
        )
        try:
            up_reader, up_writer = await asyncio.open_connection(
                "127.0.0.1", self.target_port
            )
        except Exception:
            client_writer.close()
            return
        up_writer.write(
            f"PROXY TCP4 127.0.0.1 127.0.0.1 {sport} 443\r\n".encode("ascii")
        )
        await up_writer.drain()
        await asyncio.gather(
            self._pipe(client_reader, up_writer),
            self._pipe(up_reader, client_writer),
            return_exceptions=True,
        )

    async def _serve(self) -> None:
        self._stop_event = asyncio.Event()
        server = await asyncio.start_server(
            self._handle, "127.0.0.1", self.listen_port
        )
        self.ready.set()
        async with server:
            await self._stop_event.wait()

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        finally:
            self._loop.close()

    def stop(self) -> None:
        if self._loop and self._stop_event:
            self._loop.call_soon_threadsafe(self._stop_event.set)


def _https_request(
    port: int,
    method: str,
    path: str,
    host_header: str,
    sni_hostname: str | None = None,
) -> tuple[int, dict[str, str], bytes, str]:
    """Perform a raw HTTP/1.1 request over TLSv1.3 and return (status, headers, body, cert_subject)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")

    with socket.create_connection(("127.0.0.1", port), timeout=10.0) as tcp:
        with ctx.wrap_socket(
            tcp, server_hostname=sni_hostname or host_header
        ) as tls_sock:
            assert tls_sock.version() == "TLSv1.3"
            der_cert = tls_sock.getpeercert(binary_form=True)
            cert_subject = (
                x509.load_der_x509_certificate(
                    der_cert
                ).subject.rfc4514_string()
                if der_cert
                else ""
            )
            tls_sock.sendall(req)
            chunks: list[bytes] = []
            while True:
                buf = tls_sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)

    raw_resp = b"".join(chunks)
    if not raw_resp:
        return 444, {}, b"", cert_subject

    head, _, payload = raw_resp.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", errors="replace").split("\r\n")
    status_code = int(lines[0].split(" ", 2)[1])
    resp_headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()
    return status_code, resp_headers, payload, cert_subject


@pytest.mark.skipif(
    not _docker_available(), reason="Docker nginx image unavailable"
)
def test_e2e_zero_surface_probe_isolation_xhttp_and_selftest():
    """End-to-end containerized verification of the Zero-Surface VLESS Self-Reality Appliance."""
    repo_root = Path(__file__).resolve().parent.parent
    domain = "e2e.example.test"

    nginx_http_port = _free_port()
    nginx_fallback_port = _free_port()
    reality_port = _free_port()
    xhttp_port = _free_port()

    with tempfile.TemporaryDirectory(prefix="marzneshin-e2e-") as td:
        tmp = Path(td)
        runtime_dir = tmp / "nginx-runtime"
        webroot_dir = tmp / "acme-webroot"
        certs_dir = tmp / "certs"
        xray_dir = tmp / "xray"
        creds_dir = tmp / "creds"
        for d in (
            runtime_dir / "conf.d",
            runtime_dir / "decoy",
            webroot_dir,
            certs_dir,
            xray_dir,
            creds_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
        os.chmod(tmp, 0o755)

        cert_path = certs_dir / "fullchain.pem"
        key_path = certs_dir / "privkey.pem"
        ec_param = certs_dir / "ec.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-out", str(ec_param)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                f"ec:{ec_param}",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "30",
                "-nodes",
                "-subj",
                f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(key_path, 0o644)
        os.chmod(cert_path, 0o644)

        env = os.environ.copy()
        env.update(
            {
                "APPLIANCE_MODE": "true",
                "APPLIANCE_DOMAIN": domain,
                "MARZNESHIN_DATA_DIR": str(tmp),
                "VPN_CREDENTIALS_DIR": str(creds_dir),
                "NGINX_RUNTIME_DIR": str(runtime_dir),
                "NGINX_HTTP_PORT": str(nginx_http_port),
                "NGINX_HTTPS_FALLBACK_PORT": str(nginx_fallback_port),
                "NGINX_ACME_CERT_PATH": str(cert_path),
                "NGINX_ACME_KEY_PATH": str(key_path),
                "NGINX_DUMMY_CERT_PATH": str(certs_dir / "dummy-fullchain.pem"),
                "NGINX_DUMMY_KEY_PATH": str(certs_dir / "dummy-privkey.pem"),
                "NGINX_WEBROOT_DIR": str(webroot_dir),
                "XRAY_CONFIG_PATH": str(xray_dir / "config.json"),
                "XRAY_LISTEN_PORT": str(reality_port),
                "XRAY_XHTTP_PORT": str(xhttp_port),
            }
        )

        # Initialize Zero-Surface state via CLI
        import importlib
        import app.config.env as app_env
        import app.cli as app_cli

        with patch.dict(os.environ, env, clear=False):
            importlib.reload(app_env)
            importlib.reload(app_cli)
            assert (
                app_cli.main(
                    [
                        "--data-dir",
                        str(tmp),
                        "--credentials-dir",
                        str(creds_dir),
                        "init",
                        "--domain",
                        domain,
                    ]
                )
                == 0
            )
        importlib.reload(app_env)
        importlib.reload(app_cli)

        nginx_cname = f"marzneshin-e2e-nginx-{os.getpid()}"
        nginx_proc = None
        relay = ProxyProtocolRelayThread(reality_port, nginx_fallback_port)
        try:
            watcher_script = tmp / "run_nginx.sh"
            watcher_script.write_text(
                f"""#!/bin/sh
set -eu
LAST_TRIG=""
(
  while true; do
    if [ -f "{runtime_dir}/reload.trigger" ]; then
      CUR="$(cat "{runtime_dir}/reload.trigger" 2>/dev/null || true)"
      if [ -n "$CUR" ] && [ "$CUR" != "$LAST_TRIG" ]; then
        LAST_TRIG="$CUR"
        nginx -g "user root;" -e /dev/null -c "{runtime_dir}/nginx.conf" -s reload >/dev/null 2>&1 || true
      fi
    fi
    sleep 0.2
  done
) &
exec nginx -g "user root; daemon off;" -e /dev/null -c "{runtime_dir}/nginx.conf"
""",
                encoding="utf-8",
            )
            os.chmod(watcher_script, 0o755)

            nginx_proc = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    nginx_cname,
                    "--network",
                    "host",
                    "-v",
                    f"{tmp}:{tmp}:rw",
                    "--entrypoint",
                    "/bin/sh",
                    "jc21/nginx-proxy-manager:latest",
                    str(watcher_script),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            _wait_tcp("127.0.0.1", nginx_http_port, timeout=15.0)
            _wait_tcp("127.0.0.1", nginx_fallback_port, timeout=15.0)

            relay.start()
            assert relay.ready.wait(timeout=5.0)
            _wait_tcp("127.0.0.1", reality_port, timeout=5.0)

            # 1. RCA Cause #2: Raw-IP HTTP probe on port :80 must close with 444 (0 bytes), NOT 301!
            with socket.create_connection(
                ("127.0.0.1", nginx_http_port), timeout=5.0
            ) as s80:
                s80.sendall(
                    b"GET / HTTP/1.1\r\nHost: 198.51.100.30\r\nConnection: close\r\n\r\n"
                )
                raw_ip_resp = s80.recv(1024)
            assert raw_ip_resp == b"", (
                f"Expected 444 empty close on raw IP :80 probe, got: {raw_ip_resp!r}"
            )

            # Domain HTTP request on :80 redirects to HTTPS
            with socket.create_connection(
                ("127.0.0.1", nginx_http_port), timeout=5.0
            ) as s80_dom:
                s80_dom.sendall(
                    f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
                )
                dom_80_resp = s80_dom.recv(1024).decode("utf-8", errors="ignore")
            assert "301 Moved Permanently" in dom_80_resp
            assert f"Location: https://{domain}/" in dom_80_resp

            # 2. RCA Cause #2: Foreign/no-SNI probe on :443 gets neutral CN=localhost cert + 444 close
            st_probe, _, body_probe, cert_subj_probe = _https_request(
                reality_port,
                "GET",
                "/",
                host_header="198.51.100.30",
                sni_hostname="scanner.invalid",
            )
            assert st_probe == 444
            assert body_probe == b""
            assert "CN=localhost" in cert_subj_probe
            assert domain not in cert_subj_probe

            # 3. RCA Cause #1: Matching SNI=<domain> serves decoy HTML over TLS 1.3 without ETag
            st_root, hdr_root, body_root, cert_subj_dom = _https_request(
                reality_port, "GET", "/", host_header=domain
            )
            assert st_root == 200
            assert f"CN={domain}" in cert_subj_dom
            assert b"Nordic Systems" in body_root
            assert "etag" not in hdr_root
            assert hdr_root.get("last-modified", "") == ""

            # 4. Zero-Surface: All legacy panel/API/sub paths return static decoy 404
            for forbidden_path in (
                "/api/status",
                "/sub/alice/key",
                "/setup",
                "/dashboard/",
                "/admin",
            ):
                st_404, _, body_404, _ = _https_request(
                    reality_port, "GET", forbidden_path, host_header=domain
                )
                assert st_404 == 404, f"{forbidden_path} did not return 404"
                assert b"404" in body_404

            # 5. SSH CLI subcommands: status, xhttp on, xhttp off
            st_cli = subprocess.run(
                ["bash", str(repo_root / "script.sh"), "status"],
                cwd=str(repo_root),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert st_cli.returncode == 0, st_cli.stderr
            assert f"vless://" in st_cli.stdout
            assert (creds_dir / "throne-windows11.json").exists()

            state = json.loads((tmp / "state.json").read_text())
            xhttp_secret = state["xhttp_secret_path"]

            # While xhttp is off, secret path returns 404
            st_xoff, _, _, _ = _https_request(
                reality_port, "GET", f"/{xhttp_secret}", host_header=domain
            )
            assert st_xoff == 404

            # Enable xhttp via script.sh xhttp on -> Nginx reloads and proxies to 127.0.0.1:xhttp_port (502 since no XHTTP listener on xhttp_port)
            xon_cli = subprocess.run(
                ["bash", str(repo_root / "script.sh"), "xhttp", "on"],
                cwd=str(repo_root),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert xon_cli.returncode == 0, xon_cli.stderr

            deadline = time.monotonic() + 8.0
            st_xon = 404
            while time.monotonic() < deadline:
                st_xon, _, _, _ = _https_request(
                    reality_port, "GET", f"/{xhttp_secret}", host_header=domain
                )
                if st_xon == 502:
                    break
                time.sleep(0.25)
            assert st_xon == 502

            # 6. Run full self_test suite (with mocked external AI HTTP responses)
            def _mock_ai_handler(request: httpx.Request) -> httpx.Response:
                url = str(request.url)
                if "youtube.com" in url:
                    return httpx.Response(
                        200,
                        text='<html><script>var ytcfg={"INNERTUBE_CONTEXT_GL":"DE"};</script></html>',
                    )
                if "chatgpt.com/cdn-cgi/trace" in url:
                    return httpx.Response(200, text="fl=1\nloc=DE\nwarp=off\n")
                return httpx.Response(404, text='{"type":"error"}')

            mock_tcp_lines = [
                "0: 00000000:0050 00000000:0000 0A",
                "1: 00000000:01BB 00000000:0000 0A",
                "2: 00000000:0016 00000000:0000 0A",
                "3: 0100007F:20FB 00000000:0000 0A",
            ]
            from app.utils import self_test as st_mod

            orig_ports = st_mod.check_exposed_ports
            orig_ai = st_mod.check_triple_ai_egress

            async def _patched_ai():
                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(_mock_ai_handler)
                ) as c:
                    return await orig_ai(http_client=c)

            with (
                patch.object(
                    st_mod,
                    "check_exposed_ports",
                    lambda: orig_ports(
                        proc_tcp_lines=mock_tcp_lines, proc_tcp6_lines=[]
                    ),
                ),
                patch.object(st_mod, "check_triple_ai_egress", _patched_ai),
            ):
                report = asyncio.run(
                    run_self_test(
                        domain=domain,
                        xray_config_path=str(xray_dir / "config.json"),
                        nginx_runtime_dir=str(runtime_dir),
                        reality_port=reality_port,
                        nginx_fallback_port=nginx_fallback_port,
                        include_network_probes=True,
                    )
                )
            failed = [c for c in report.checks if not c.passed]
            assert report.passed is True, f"Self-test failed: {failed}"
        finally:
            relay.stop()
            subprocess.run(
                ["docker", "rm", "-f", nginx_cname],
                capture_output=True,
                text=True,
            )
            if nginx_proc and nginx_proc.poll() is None:
                nginx_proc.terminate()
