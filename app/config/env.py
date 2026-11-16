import os

APPLIANCE_MODE: bool = os.environ.get("APPLIANCE_MODE", "true").lower() in (
    "1",
    "true",
    "yes",
)
APPLIANCE_DOMAIN: str = os.environ.get("APPLIANCE_DOMAIN", "")

XRAY_API_ADDRESS: str = os.environ.get("XRAY_API_ADDRESS", "127.0.0.1:10085")
XRAY_LISTEN_PORT: int = int(os.environ.get("XRAY_LISTEN_PORT", "443"))
XRAY_XHTTP_PORT: int = int(os.environ.get("XRAY_XHTTP_PORT", "10086"))
XRAY_CONFIG_PATH: str = os.environ.get(
    "XRAY_CONFIG_PATH", "/var/lib/marzneshin/xray/config.json"
)
XRAY_BINARY_PATH: str = os.environ.get(
    "XRAY_BINARY_PATH", "/usr/local/bin/xray"
)

NGINX_RUNTIME_DIR: str = os.environ.get(
    "NGINX_RUNTIME_DIR", "/var/lib/marzneshin/nginx-runtime"
)
NGINX_HTTP_PORT: int = int(os.environ.get("NGINX_HTTP_PORT", "80"))
NGINX_HTTPS_FALLBACK_PORT: int = int(
    os.environ.get("NGINX_HTTPS_FALLBACK_PORT", "8443")
)
NGINX_ACME_CERT_PATH: str = os.environ.get(
    "NGINX_ACME_CERT_PATH", "/var/lib/marzneshin/certs/fullchain.pem"
)
NGINX_ACME_KEY_PATH: str = os.environ.get(
    "NGINX_ACME_KEY_PATH", "/var/lib/marzneshin/certs/privkey.pem"
)
NGINX_DUMMY_CERT_PATH: str = os.environ.get(
    "NGINX_DUMMY_CERT_PATH", "/var/lib/marzneshin/certs/dummy-fullchain.pem"
)
NGINX_DUMMY_KEY_PATH: str = os.environ.get(
    "NGINX_DUMMY_KEY_PATH", "/var/lib/marzneshin/certs/dummy-privkey.pem"
)
NGINX_WEBROOT_DIR: str = os.environ.get(
    "NGINX_WEBROOT_DIR", "/var/lib/marzneshin/acme-webroot"
)
