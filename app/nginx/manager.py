import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.config.env import (
    NGINX_ACME_CERT_PATH,
    NGINX_ACME_KEY_PATH,
    NGINX_DUMMY_CERT_PATH,
    NGINX_DUMMY_KEY_PATH,
    NGINX_HTTP_PORT,
    NGINX_HTTPS_FALLBACK_PORT,
    NGINX_RUNTIME_DIR,
    NGINX_WEBROOT_DIR,
    XRAY_XHTTP_PORT,
)
from app.nginx.decoys import (
    DECOY_404_HTML,
    DECOY_FAVICON_ICO,
    DecoyMode,
    get_decoy_404_html,
    get_decoy_Auxiliary_pages,
    get_decoy_html,
    get_decoy_robots_txt,
    get_decoy_sitemap_xml,
)

PATH_RE = re.compile(r"^[a-zA-Z0-9/_-]{8,128}$")
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


def validate_xhttp_path(path: str) -> str:
    clean = path.strip("/")
    if not clean or not PATH_RE.fullmatch(clean) or ".." in clean:
        raise ValueError(
            "xhttp_secret_path must be 8-128 safe URL path characters"
        )
    return clean


def validate_domain(domain: str) -> str:
    clean = domain.strip().lower()
    if (
        not clean
        or not DOMAIN_RE.fullmatch(clean)
        or ".." in clean
        or "." not in clean
    ):
        raise ValueError(f"Invalid domain '{domain}'")
    return clean


def validate_reverse_proxy_target(target: str) -> str:
    parsed = urlparse(target.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Reverse proxy decoy target must be an http(s) URL")
    if any(ch in target for ch in (";", "{", "}", "\n", "\r", "'", '"')):
        raise ValueError("Invalid characters in reverse proxy decoy target")
    return target.strip()


def ensure_dummy_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    """Create a neutral CN=localhost EC-256 cert for no-SNI/foreign-SNI probes."""
    if cert_path.exists() and key_path.exists():
        return
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
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


class NginxManager:
    """Renders, validates, and signals reload for the Zero-Surface Self-Reality Nginx gateway."""

    def __init__(
        self,
        runtime_dir: str = NGINX_RUNTIME_DIR,
        cert_path: str | None = None,
        key_path: str | None = None,
        dummy_cert_path: str | None = None,
        dummy_key_path: str | None = None,
        webroot_dir: str = NGINX_WEBROOT_DIR,
        http_port: int = NGINX_HTTP_PORT,
        fallback_port: int = NGINX_HTTPS_FALLBACK_PORT,
        xhttp_port: int = XRAY_XHTTP_PORT,
    ):
        self.runtime_dir = Path(runtime_dir)
        self.conf_dir = self.runtime_dir / "conf.d"
        self.decoy_dir = self.runtime_dir / "decoy"
        self.cert_path = cert_path or str(
            self.runtime_dir / "certs" / "fullchain.pem"
            if runtime_dir != NGINX_RUNTIME_DIR
            else NGINX_ACME_CERT_PATH
        )
        self.key_path = key_path or str(
            self.runtime_dir / "certs" / "privkey.pem"
            if runtime_dir != NGINX_RUNTIME_DIR
            else NGINX_ACME_KEY_PATH
        )
        self.dummy_cert_path = dummy_cert_path or str(
            self.runtime_dir / "certs" / "dummy-fullchain.pem"
            if runtime_dir != NGINX_RUNTIME_DIR
            else NGINX_DUMMY_CERT_PATH
        )
        self.dummy_key_path = dummy_key_path or str(
            self.runtime_dir / "certs" / "dummy-privkey.pem"
            if runtime_dir != NGINX_RUNTIME_DIR
            else NGINX_DUMMY_KEY_PATH
        )
        self.webroot_dir = webroot_dir
        self.http_port = http_port
        self.fallback_port = fallback_port
        self.xhttp_port = xhttp_port

    def render_server_snippet(
        self,
        *,
        domain: str,
        decoy_mode: DecoyMode = DecoyMode.preset,
        decoy_target: str = "corporate",
        xhttp_backup_enabled: bool = False,
        xhttp_secret_path: str = "",
        decoy_root: str | None = None,
        enable_http: bool = True,
    ) -> str:
        clean_domain = validate_domain(domain)
        decoy_root_path = decoy_root or str(self.decoy_dir)

        xhttp_block = ""
        if xhttp_backup_enabled:
            clean_xhttp = validate_xhttp_path(xhttp_secret_path)
            xhttp_block = f"""
    location /{clean_xhttp} {{
        client_max_body_size 0;
        proxy_pass http://127.0.0.1:{self.xhttp_port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}"""

        if decoy_mode == DecoyMode.reverse_proxy:
            target = validate_reverse_proxy_target(decoy_target)
            target_host = urlparse(target).netloc
            root_block = f"""
    location / {{
        proxy_pass {target};
        proxy_ssl_server_name on;
        proxy_set_header Host {target_host};
        proxy_set_header Accept-Encoding "";
        proxy_intercept_errors on;
    }}"""
        else:
            root_block = f"""
    location / {{
        root {decoy_root_path};
        index index.html;
        try_files $uri $uri/ =404;
    }}"""

        http_blocks = ""
        if enable_http:
            http_blocks = f"""server {{
    listen {self.http_port} default_server;
    listen [::]:{self.http_port} default_server;
    server_name _;

    access_log off;
    error_log /dev/null crit;
    server_tokens off;

    return 444;
}}

server {{
    listen {self.http_port};
    listen [::]:{self.http_port};
    server_name {clean_domain};

    access_log off;
    error_log /dev/null crit;
    server_tokens off;

    location /.well-known/acme-challenge/ {{
        root {self.webroot_dir};
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

"""

        return f"""{http_blocks}server {{
    listen 127.0.0.1:{self.fallback_port} ssl default_server proxy_protocol;
    http2 on;
    server_name _;

    ssl_certificate {self.dummy_cert_path};
    ssl_certificate_key {self.dummy_key_path};
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    access_log off;
    error_log /dev/null crit;
    server_tokens off;

    return 444;
}}

server {{
    listen 127.0.0.1:{self.fallback_port} ssl proxy_protocol;
    http2 on;
    server_name {clean_domain};

    ssl_certificate {self.cert_path};
    ssl_certificate_key {self.key_path};
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    access_log off;
    error_log /dev/null crit;
    server_tokens off;
    etag off;
    if_modified_since off;
    add_header Last-Modified "";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    proxy_hide_header Server;
    proxy_hide_header X-Powered-By;

    error_page 404 /404.html;
    location = /404.html {{
        root {decoy_root_path};
        internal;
    }}
{xhttp_block}
{root_block}
}}
"""

    def render_main_nginx_conf(self, conf_d_path: str | None = None) -> str:
        include_dir = conf_d_path or str(self.conf_dir)
        return f"""worker_processes auto;
pid /tmp/nginx.pid;
error_log /dev/null crit;

events {{
    worker_connections 1024;
}}

http {{
    types {{
        text/html                             html htm;
        text/css                              css;
        application/javascript                js;
        image/svg+xml                         svg svgz;
        image/x-icon                          ico;
        text/plain                            txt;
        application/xml                       xml;
    }}
    default_type application/octet-stream;
    client_body_temp_path /tmp/nginx_client_temp;
    proxy_temp_path /tmp/nginx_proxy_temp;
    fastcgi_temp_path /tmp/nginx_fastcgi_temp;
    uwsgi_temp_path /tmp/nginx_uwsgi_temp;
    scgi_temp_path /tmp/nginx_scgi_temp;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    server_tokens off;
    etag off;
    access_log off;

    include {include_dir}/*.conf;
}}
"""

    def apply(
        self,
        *,
        domain: str,
        decoy_mode: DecoyMode = DecoyMode.preset,
        decoy_target: str = "corporate",
        decoy_html: str | None = None,
        xhttp_backup_enabled: bool = False,
        xhttp_secret_path: str = "",
        entropy_seed: str | None = None,
        validate_binary: bool = True,
        enable_http: bool = True,
    ) -> Path:
        self.conf_dir.mkdir(parents=True, exist_ok=True)
        self.decoy_dir.mkdir(parents=True, exist_ok=True)
        Path(self.webroot_dir).mkdir(parents=True, exist_ok=True)
        ensure_dummy_self_signed_cert(
            Path(self.dummy_cert_path), Path(self.dummy_key_path)
        )
        ensure_dummy_self_signed_cert(
            Path(self.cert_path), Path(self.key_path)
        )

        snippet = self.render_server_snippet(
            domain=domain,
            decoy_mode=decoy_mode,
            decoy_target=decoy_target,
            xhttp_backup_enabled=xhttp_backup_enabled,
            xhttp_secret_path=xhttp_secret_path,
            enable_http=enable_http,
        )
        main_conf = self.render_main_nginx_conf()

        conf_file = self.conf_dir / "appliance.conf"
        main_file = self.runtime_dir / "nginx.conf"
        index_file = self.decoy_dir / "index.html"
        not_found_file = self.decoy_dir / "404.html"

        prev_conf = conf_file.read_text() if conf_file.exists() else None
        prev_main = main_file.read_text() if main_file.exists() else None

        try:
            self._atomic_write(conf_file, snippet)
            self._atomic_write(main_file, main_conf)
            if decoy_mode != DecoyMode.reverse_proxy:
                html_content = get_decoy_html(
                    decoy_target,
                    decoy_html
                    if decoy_mode == DecoyMode.custom_html
                    else None,
                    entropy_seed=entropy_seed,
                )
                self._atomic_write(index_file, html_content)
                clean_dom = validate_domain(domain)
                self._atomic_write(
                    self.decoy_dir / "robots.txt",
                    get_decoy_robots_txt(clean_dom),
                )
                self._atomic_write(
                    self.decoy_dir / "sitemap.xml",
                    get_decoy_sitemap_xml(clean_dom),
                )
                self._atomic_write_bytes(
                    self.decoy_dir / "favicon.ico",
                    DECOY_FAVICON_ICO,
                )
                for rel_path, page_content in get_decoy_Auxiliary_pages(
                    entropy_seed=entropy_seed
                ).items():
                    self._atomic_write(self.decoy_dir / rel_path, page_content)
            self._atomic_write(
                not_found_file,
                get_decoy_404_html(entropy_seed=entropy_seed)
                if entropy_seed
                else DECOY_404_HTML,
            )

            if (
                validate_binary
                and shutil.which("nginx")
                and Path(self.cert_path).exists()
                and Path(self.key_path).exists()
            ):
                res = subprocess.run(
                    ["nginx", "-t", "-e", "/dev/null", "-c", str(main_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode != 0:
                    raise RuntimeError(
                        f"nginx -t validation failed: {res.stderr.strip()}"
                    )
        except Exception:
            if prev_conf is not None:
                self._atomic_write(conf_file, prev_conf)
            if prev_main is not None:
                self._atomic_write(main_file, prev_main)
            raise

        self.signal_reload()
        return conf_file

    def signal_reload(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        trigger_file = self.runtime_dir / "reload.trigger"
        self._atomic_write(trigger_file, f"{time.time_ns()}\n")

    @staticmethod
    def _atomic_write(target: Path, content: str) -> None:
        NginxManager._atomic_write_bytes(target, content.encode("utf-8"))

    @staticmethod
    def _atomic_write_bytes(target: Path, content: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(target.parent), prefix=f".{target.name}-"
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(content)
            os.chmod(tmp_path, 0o644)
            os.replace(tmp_path, target)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise


nginx_manager = NginxManager()
