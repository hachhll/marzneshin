import shutil
import subprocess
from pathlib import Path

import pytest

from app.nginx.decoys import DecoyMode, get_decoy_html
from app.nginx.manager import NginxManager


def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _docker_nginx_available() -> bool:
    if shutil.which("nginx"):
        return True
    if not shutil.which("docker"):
        return False
    res = subprocess.run(
        ["docker", "image", "inspect", "jc21/nginx-proxy-manager:latest"],
        capture_output=True,
        text=True,
    )
    return res.returncode == 0


def _run_nginx_t(runtime_dir: Path, main_conf: Path) -> subprocess.CompletedProcess:
    if shutil.which("nginx"):
        return subprocess.run(
            ["nginx", "-t", "-c", str(main_conf)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{runtime_dir}:{runtime_dir}:rw",
            "--entrypoint",
            "nginx",
            "jc21/nginx-proxy-manager:latest",
            "-t",
            "-e",
            "/dev/null",
            "-g",
            "user root;",
            "-c",
            str(main_conf),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_nginx_manager_zero_surface_and_probe_isolation(tmp_path: Path):
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    _generate_self_signed_cert(cert, key)

    mgr = NginxManager(
        runtime_dir=str(tmp_path),
        cert_path=str(cert),
        key_path=str(key),
        webroot_dir=str(tmp_path / "webroot"),
    )

    conf_disabled = mgr.apply(
        domain="vpn.example.com",
        decoy_mode=DecoyMode.preset,
        decoy_target="corporate",
        xhttp_backup_enabled=False,
        xhttp_secret_path="secret_xhttp_path_1",
        validate_binary=False,
    )
    text_disabled = conf_disabled.read_text()

    # RCA Cause #2: Raw-IP port 80 and no-SNI port 8443 default_server isolation with 444
    assert "listen 80 default_server;" in text_disabled
    assert "listen 127.0.0.1:8443 ssl default_server proxy_protocol;" in text_disabled
    assert "server_name _;" in text_disabled
    assert "return 444;" in text_disabled
    assert (tmp_path / "certs" / "dummy-fullchain.pem").exists()
    assert (tmp_path / "certs" / "dummy-privkey.pem").exists()

    # Domain server blocks
    assert "server_name vpn.example.com;" in text_disabled
    assert "/.well-known/acme-challenge/" in text_disabled
    assert "return 301 https://$host$request_uri;" in text_disabled
    assert "listen 127.0.0.1:8443 ssl proxy_protocol;" in text_disabled
    assert "http2 on;" in text_disabled
    assert "ssl_protocols TLSv1.3;" in text_disabled
    assert "access_log off;" in text_disabled
    assert "error_log /dev/null crit;" in text_disabled

    # RCA Cause #1 & #3: Zero ETag/Last-Modified and zero /sub/, /api/, or panel paths
    assert "etag off;" in text_disabled
    assert "if_modified_since off;" in text_disabled
    assert 'add_header Last-Modified "";' in text_disabled
    assert "Strict-Transport-Security" in text_disabled
    assert "/sub/" not in text_disabled
    assert "/api/" not in text_disabled
    assert "/dashboard/" not in text_disabled
    assert "panel_auth" not in text_disabled
    assert "/secret_xhttp_path_1" not in text_disabled
    assert (tmp_path / "decoy" / "index.html").exists()
    assert "ArmenyTravel" in (tmp_path / "decoy" / "index.html").read_text()
    assert (tmp_path / "decoy" / "ru" / "index.html").exists()
    assert (tmp_path / "decoy" / "de" / "index.html").exists()
    assert (tmp_path / "decoy" / "tours.html").exists()
    assert (tmp_path / "decoy" / "guide.html").exists()
    assert (tmp_path / "decoy" / "assets" / "style.css").exists()
    assert (tmp_path / "decoy" / "assets" / "app.js").exists()
    assert (tmp_path / "decoy" / "assets" / "ararat.svg").exists()
    assert (tmp_path / "decoy" / "assets" / "sevan.svg").exists()
    assert (tmp_path / "decoy" / "assets" / "tatev.svg").exists()
    assert (tmp_path / "decoy" / "404.html").exists()
    assert (tmp_path / "decoy" / "robots.txt").exists()
    assert (tmp_path / "decoy" / "sitemap.xml").exists()
    assert (tmp_path / "decoy" / "favicon.ico").exists()
    assert (tmp_path / "reload.trigger").exists()

    # Polymorphic decoy HTML produces distinct output across installs
    html_a = get_decoy_html("corporate")
    html_b = get_decoy_html("corporate")
    assert html_a != html_b

    conf_enabled = mgr.apply(
        domain="vpn.example.com",
        decoy_mode=DecoyMode.custom_html,
        decoy_target="corporate",
        decoy_html="<html><head></head><body><h1>Custom Site</h1></body></html>",
        xhttp_backup_enabled=True,
        xhttp_secret_path="secret_xhttp_path_1",
        validate_binary=False,
    )
    text_enabled = conf_enabled.read_text()
    assert "location /secret_xhttp_path_1 {" in text_enabled
    assert "client_max_body_size 0;" in text_enabled
    assert "proxy_pass http://127.0.0.1:10086;" in text_enabled
    assert "proxy_buffering off;" in text_enabled
    assert "proxy_request_buffering off;" in text_enabled
    assert "Custom Site" in (tmp_path / "decoy" / "index.html").read_text()


def test_nginx_manager_rejects_invalid_inputs_without_overwriting(tmp_path: Path):
    mgr = NginxManager(runtime_dir=str(tmp_path), webroot_dir=str(tmp_path / "webroot"))
    mgr.apply(
        domain="vpn.example.com",
        validate_binary=False,
    )
    # Bootstrap cert pair should be auto-created even before ACME runs
    assert (tmp_path / "certs" / "fullchain.pem").exists()
    assert (tmp_path / "certs" / "privkey.pem").exists()
    assert (tmp_path / "certs" / "dummy-fullchain.pem").exists()
    assert (tmp_path / "certs" / "dummy-privkey.pem").exists()

    before = (tmp_path / "conf.d" / "appliance.conf").read_text()

    with pytest.raises(ValueError):
        mgr.apply(
            domain="../bad",
            validate_binary=False,
        )

    assert (tmp_path / "conf.d" / "appliance.conf").read_text() == before


@pytest.mark.skipif(
    not _docker_nginx_available(),
    reason="Neither local nginx nor nginx docker image is available",
)
@pytest.mark.parametrize("xhttp_enabled", [False, True])
@pytest.mark.parametrize("decoy_mode", [DecoyMode.preset, DecoyMode.reverse_proxy])
def test_generated_configs_pass_nginx_t(
    tmp_path: Path, xhttp_enabled: bool, decoy_mode: DecoyMode
):
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    _generate_self_signed_cert(cert, key)

    mgr = NginxManager(
        runtime_dir=str(tmp_path),
        cert_path=str(cert),
        key_path=str(key),
        webroot_dir=str(tmp_path / "webroot"),
    )
    mgr.apply(
        domain="vpn.example.com",
        decoy_mode=decoy_mode,
        decoy_target="https://example.com"
        if decoy_mode == DecoyMode.reverse_proxy
        else "corporate",
        xhttp_backup_enabled=xhttp_enabled,
        xhttp_secret_path="secret_xhttp_path_1",
        validate_binary=False,
    )
    res = _run_nginx_t(tmp_path, tmp_path / "nginx.conf")
    assert res.returncode == 0, f"nginx -t failed:\nSTDOUT:{res.stdout}\nSTDERR:{res.stderr}"
