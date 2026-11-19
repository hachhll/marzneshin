"""SSH CLI backend for the Zero-Surface Single-User VLESS Self-Reality Appliance."""

import argparse
import json
import os
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any

from app.client.profile_generator import (
    format_terminal_credentials,
    write_client_bundle,
)
from app.config.env import (
    NGINX_ACME_CERT_PATH,
    NGINX_ACME_KEY_PATH,
    NGINX_DUMMY_CERT_PATH,
    NGINX_DUMMY_KEY_PATH,
    NGINX_HTTP_PORT,
    NGINX_HTTPS_FALLBACK_PORT,
    NGINX_RUNTIME_DIR,
    NGINX_WEBROOT_DIR,
    XRAY_API_ADDRESS,
    XRAY_CONFIG_PATH,
    XRAY_LISTEN_PORT,
    XRAY_XHTTP_PORT,
)
from app.nginx.decoys import DecoyMode
from app.nginx.manager import NginxManager, validate_domain
from app.xray.config_builder import (
    LocalXrayConfigBuilder,
    generate_reality_keypair,
    generate_short_id,
)


def _default_data_dir() -> Path:
    return Path(os.environ.get("MARZNESHIN_DATA_DIR", "/var/lib/marzneshin"))


def _default_credentials_dir() -> Path:
    return Path(
        os.environ.get("VPN_CREDENTIALS_DIR", "/root/vpn-credentials")
    )


def load_or_init_state(
    state_path: Path,
    *,
    domain: str | None = None,
    decoy_target: str | None = None,
    server_ip: str | None = None,
) -> dict[str, Any]:
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        changed = False
        if domain:
            clean_dom = validate_domain(domain)
            if state.get("domain") != clean_dom:
                state["domain"] = clean_dom
                changed = True
        if decoy_target:
            state["decoy_target"] = decoy_target
            state["decoy_mode"] = (
                DecoyMode.reverse_proxy.value
                if decoy_target.startswith(("http://", "https://"))
                else DecoyMode.preset.value
            )
            changed = True
        if server_ip and state.get("server_ip") != server_ip:
            state["server_ip"] = server_ip
            changed = True
        if changed:
            save_state(state_path, state)
        return state

    if not domain:
        raise ValueError(
            "Appliance is not initialized yet. Run: sudo ./script.sh --domain <fqdn>"
        )

    effective_decoy = decoy_target or "corporate"
    clean_domain = validate_domain(domain)
    priv_key, pub_key = generate_reality_keypair()
    short_id = generate_short_id()
    user_uuid = str(uuid.uuid4())
    xhttp_secret = secrets.token_hex(32)  # 64 hex chars
    entropy_seed = secrets.token_hex(24)

    decoy_mode = (
        DecoyMode.reverse_proxy.value
        if effective_decoy.startswith(("http://", "https://"))
        else DecoyMode.preset.value
    )

    state = {
        "mode": "exit",
        "domain": clean_domain,
        "server_ip": server_ip or "",
        "user_uuid": user_uuid,
        "reality_private_key": priv_key,
        "reality_public_key": pub_key,
        "reality_short_id": short_id,
        "xhttp_secret_path": xhttp_secret,
        "xhttp_backup_enabled": False,
        "decoy_mode": decoy_mode,
        "decoy_target": effective_decoy,
        "entropy_seed": entropy_seed,
        "ipv6_egress_enabled": False,
    }
    save_state(state_path, state)
    return state


def load_or_init_bridge_state(
    state_path: Path,
    *,
    upstream_ip: str,
    upstream_domain: str,
    upstream_uuid: str,
    upstream_public_key: str,
    upstream_short_id: str,
    bridge_sni: str | None = None,
    bridge_ip: str = "",
    bridge_acme_enabled: bool = False,
    upstream_transport: str | None = None,
    upstream_xhttp_path: str | None = None,
) -> dict[str, Any]:
    clean_up_domain = validate_domain(upstream_domain)
    effective_sni = validate_domain(bridge_sni or clean_up_domain)

    if state_path.exists():
        existing = json.loads(state_path.read_text(encoding="utf-8"))
        if existing.get("mode") == "bridge":
            resolved_xhttp_path = (
                upstream_xhttp_path
                if upstream_xhttp_path is not None
                else existing.get("upstream_xhttp_path", "")
            ).strip().strip("/")
            default_tr = "xhttp" if resolved_xhttp_path else "vision"
            resolved_transport = (
                upstream_transport
                or existing.get("upstream_transport")
                or default_tr
            ).strip().lower()
            existing.update(
                {
                    "mode": "bridge",
                    "domain": effective_sni,
                    "bridge_sni": effective_sni,
                    "bridge_ip": bridge_ip or existing.get("bridge_ip", ""),
                    "bridge_acme_enabled": bool(
                        bridge_acme_enabled
                        or existing.get("bridge_acme_enabled", False)
                    ),
                    "upstream_ip": upstream_ip.strip(),
                    "upstream_domain": clean_up_domain,
                    "upstream_uuid": upstream_uuid.strip(),
                    "upstream_public_key": upstream_public_key.strip(),
                    "upstream_short_id": upstream_short_id.strip(),
                    "upstream_transport": resolved_transport,
                    "upstream_xhttp_path": resolved_xhttp_path,
                }
            )
            save_state(state_path, existing)
            return existing

    priv_key, pub_key = generate_reality_keypair()
    short_id = generate_short_id()
    user_uuid = str(uuid.uuid4())
    xhttp_secret = secrets.token_hex(32)
    entropy_seed = secrets.token_hex(24)

    clean_xhttp_path = (upstream_xhttp_path or "").strip().strip("/")
    default_tr = "xhttp" if clean_xhttp_path else "vision"
    state = {
        "mode": "bridge",
        "domain": effective_sni,
        "bridge_sni": effective_sni,
        "bridge_ip": bridge_ip.strip(),
        "bridge_acme_enabled": bool(bridge_acme_enabled),
        "upstream_ip": upstream_ip.strip(),
        "upstream_domain": clean_up_domain,
        "upstream_uuid": upstream_uuid.strip(),
        "upstream_public_key": upstream_public_key.strip(),
        "upstream_short_id": upstream_short_id.strip(),
        "upstream_transport": (upstream_transport or default_tr).strip().lower(),
        "upstream_xhttp_path": clean_xhttp_path,
        "user_uuid": user_uuid,
        "reality_private_key": priv_key,
        "reality_public_key": pub_key,
        "reality_short_id": short_id,
        "xhttp_secret_path": xhttp_secret,
        "xhttp_backup_enabled": False,
        "decoy_mode": DecoyMode.preset.value,
        "decoy_target": "corporate",
        "entropy_seed": entropy_seed,
        "ipv6_egress_enabled": False,
    }
    save_state(state_path, state)
    return state


def save_state(state_path: Path, state: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(state_path, 0o600)
    except OSError:
        pass


def apply_state(
    state: dict[str, Any],
    *,
    data_dir: Path,
    credentials_dir: Path,
    validate_nginx_binary: bool = False,
    enable_bridge_http: bool = False,
) -> None:
    xray_cfg_path = Path(
        os.environ.get("XRAY_CONFIG_PATH", str(data_dir / "xray" / "config.json"))
    )
    nginx_runtime_dir = os.environ.get(
        "NGINX_RUNTIME_DIR", str(data_dir / "nginx-runtime")
    )
    cert_path = os.environ.get(
        "NGINX_ACME_CERT_PATH", str(data_dir / "certs" / "fullchain.pem")
    )
    key_path = os.environ.get(
        "NGINX_ACME_KEY_PATH", str(data_dir / "certs" / "privkey.pem")
    )
    dummy_cert_path = os.environ.get(
        "NGINX_DUMMY_CERT_PATH",
        str(data_dir / "certs" / "dummy-fullchain.pem"),
    )
    dummy_key_path = os.environ.get(
        "NGINX_DUMMY_KEY_PATH", str(data_dir / "certs" / "dummy-privkey.pem")
    )
    webroot_dir = os.environ.get(
        "NGINX_WEBROOT_DIR", str(data_dir / "acme-webroot")
    )

    is_bridge = state.get("mode") == "bridge"
    if is_bridge:
        xray_cfg = LocalXrayConfigBuilder.build_bridge(
            bridge_sni=state.get("bridge_sni") or state["domain"],
            reality_private_key=state["reality_private_key"],
            reality_short_ids=[state["reality_short_id"]],
            clients=[{"id": state["user_uuid"], "email": "owner"}],
            upstream_ip=state["upstream_ip"],
            upstream_domain=state["upstream_domain"],
            upstream_uuid=state["upstream_uuid"],
            upstream_public_key=state["upstream_public_key"],
            upstream_short_id=state["upstream_short_id"],
            upstream_transport=state.get("upstream_transport", "vision"),
            upstream_xhttp_path=state.get("upstream_xhttp_path", ""),
            listen_port=XRAY_LISTEN_PORT,
            fallback_port=NGINX_HTTPS_FALLBACK_PORT,
            api_address=XRAY_API_ADDRESS,
        )
    else:
        xray_cfg = LocalXrayConfigBuilder.build(
            domain=state["domain"],
            reality_private_key=state["reality_private_key"],
            reality_short_ids=[state["reality_short_id"]],
            clients=[{"id": state["user_uuid"], "email": "owner"}],
            xhttp_backup_enabled=bool(state.get("xhttp_backup_enabled", False)),
            xhttp_secret_path=state["xhttp_secret_path"],
            ipv6_egress_enabled=bool(state.get("ipv6_egress_enabled", False)),
            listen_port=XRAY_LISTEN_PORT,
            fallback_port=NGINX_HTTPS_FALLBACK_PORT,
            api_address=XRAY_API_ADDRESS,
            xhttp_port=XRAY_XHTTP_PORT,
        )
    xray_cfg_path.parent.mkdir(parents=True, exist_ok=True)
    xray_cfg_path.write_text(
        json.dumps(xray_cfg, indent=2) + "\n", encoding="utf-8"
    )

    mgr = NginxManager(
        runtime_dir=nginx_runtime_dir,
        cert_path=cert_path,
        key_path=key_path,
        dummy_cert_path=dummy_cert_path,
        dummy_key_path=dummy_key_path,
        webroot_dir=webroot_dir,
        http_port=NGINX_HTTP_PORT,
        fallback_port=NGINX_HTTPS_FALLBACK_PORT,
        xhttp_port=XRAY_XHTTP_PORT,
    )
    mgr.apply(
        domain=state["domain"],
        decoy_mode=DecoyMode(state.get("decoy_mode", "preset")),
        decoy_target=state.get("decoy_target", "corporate"),
        xhttp_backup_enabled=False
        if is_bridge
        else bool(state.get("xhttp_backup_enabled", False)),
        xhttp_secret_path=state["xhttp_secret_path"],
        entropy_seed=state.get("entropy_seed"),
        validate_binary=validate_nginx_binary,
        enable_http=(not is_bridge) or enable_bridge_http,
    )

    write_client_bundle(
        credentials_dir,
        domain=state["domain"],
        user_uuid=state["user_uuid"],
        reality_public_key=state["reality_public_key"],
        reality_short_id=state["reality_short_id"],
        xhttp_secret_path=state["xhttp_secret_path"],
        xhttp_backup_enabled=False
        if is_bridge
        else bool(state.get("xhttp_backup_enabled", False)),
        port=XRAY_LISTEN_PORT,
        ipv6_egress_enabled=False
        if is_bridge
        else bool(state.get("ipv6_egress_enabled", False)),
        server_host=state.get("bridge_ip") if is_bridge else None,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zero-Surface VLESS Self-Reality CLI state manager"
    )
    parser.add_argument(
        "--data-dir",
        default=str(_default_data_dir()),
        help="Path to appliance state directory",
    )
    parser.add_argument(
        "--credentials-dir",
        default=str(_default_credentials_dir()),
        help="Path to generated client profile directory",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Initialize or update appliance state")
    p_init.add_argument("--domain", required=True)
    p_init.add_argument("--decoy", default=None)
    p_init.add_argument("--server-ip", default=None)

    p_bridge = sub.add_parser(
        "init-bridge",
        help="Initialize or update Cascade Bridge (Moscow -> Frankfurt) state",
    )
    p_bridge.add_argument("--upstream-ip", required=True)
    p_bridge.add_argument("--upstream-domain", required=True)
    p_bridge.add_argument("--upstream-uuid", required=True)
    p_bridge.add_argument("--upstream-pbk", required=True)
    p_bridge.add_argument("--upstream-sid", required=True)
    p_bridge.add_argument("--bridge-sni", default=None)
    p_bridge.add_argument("--bridge-ip", default="")
    p_bridge.add_argument("--bridge-acme", action="store_true")
    p_bridge.add_argument("--acme-http-challenge", action="store_true")
    p_bridge.add_argument(
        "--upstream-transport", choices=["vision", "xhttp"], default=None
    )
    p_bridge.add_argument("--upstream-xhttp-path", default=None)

    p_bt = sub.add_parser(
        "bridge-transport",
        help="Switch Cascade Bridge upstream transport between vision and xhttp",
    )
    p_bt.add_argument("transport", choices=["vision", "xhttp"])
    p_bt.add_argument("--path", default=None)
    p_bt.add_argument("--upstream-ip", default=None)
    p_bt.add_argument("--upstream-domain", default=None)
    p_bt.add_argument("--upstream-uuid", default=None)
    p_bt.add_argument("--upstream-pbk", default=None)
    p_bt.add_argument("--upstream-sid", default=None)

    sub.add_parser("status", help="Print VLESS URIs, QR code, and profile paths")

    p_xhttp = sub.add_parser("xhttp", help="Toggle backup XHTTP channel")
    p_xhttp.add_argument("mode", choices=["on", "off"])

    sub.add_parser("rotate", help="Rotate UUID, Reality keys, shortId, and XHTTP path")

    p_decoy = sub.add_parser("decoy", help="Switch decoy preset or reverse-proxy URL")
    p_decoy.add_argument("target")

    args = parser.parse_args(argv)
    data_dir = Path(args.data_dir)
    credentials_dir = Path(args.credentials_dir)
    state_path = data_dir / "state.json"

    if args.cmd == "init":
        state = load_or_init_state(
            state_path,
            domain=args.domain,
            decoy_target=args.decoy,
            server_ip=args.server_ip,
        )
        apply_state(state, data_dir=data_dir, credentials_dir=credentials_dir)
    elif args.cmd == "init-bridge":
        state = load_or_init_bridge_state(
            state_path,
            upstream_ip=args.upstream_ip,
            upstream_domain=args.upstream_domain,
            upstream_uuid=args.upstream_uuid,
            upstream_public_key=args.upstream_pbk,
            upstream_short_id=args.upstream_sid,
            bridge_sni=args.bridge_sni,
            bridge_ip=args.bridge_ip,
            bridge_acme_enabled=bool(args.bridge_acme),
            upstream_transport=args.upstream_transport,
            upstream_xhttp_path=args.upstream_xhttp_path,
        )
        apply_state(
            state,
            data_dir=data_dir,
            credentials_dir=credentials_dir,
            enable_bridge_http=bool(args.acme_http_challenge),
        )
    elif args.cmd == "bridge-transport":
        state = load_or_init_state(state_path)
        if state.get("mode") != "bridge":
            raise ValueError(
                "bridge-transport is only supported on Cascade Bridge nodes (mode='bridge')"
            )
        if args.path is not None:
            state["upstream_xhttp_path"] = args.path.strip().strip("/")
        if args.upstream_ip:
            state["upstream_ip"] = args.upstream_ip.strip()
        if args.upstream_domain:
            state["upstream_domain"] = validate_domain(args.upstream_domain)
        if args.upstream_uuid:
            state["upstream_uuid"] = args.upstream_uuid.strip()
        if args.upstream_pbk:
            state["upstream_public_key"] = args.upstream_pbk.strip()
        if args.upstream_sid:
            state["upstream_short_id"] = args.upstream_sid.strip()
        if args.transport == "xhttp" and not state.get("upstream_xhttp_path"):
            raise ValueError(
                "Switching bridge to 'xhttp' requires --path <64-hex-xhttp-secret-path> (from 'sudo ./script.sh xhttp on' on Exit node)"
            )
        state["upstream_transport"] = args.transport
        apply_state(state, data_dir=data_dir, credentials_dir=credentials_dir)
        save_state(state_path, state)
    elif args.cmd == "status":
        state = load_or_init_state(state_path)
        is_bridge = state.get("mode") == "bridge"
        if not (credentials_dir / "throne-windows11.json").exists():
            write_client_bundle(
                credentials_dir,
                domain=state["domain"],
                user_uuid=state["user_uuid"],
                reality_public_key=state["reality_public_key"],
                reality_short_id=state["reality_short_id"],
                xhttp_secret_path=state["xhttp_secret_path"],
                xhttp_backup_enabled=False
                if is_bridge
                else bool(state.get("xhttp_backup_enabled", False)),
                port=XRAY_LISTEN_PORT,
                ipv6_egress_enabled=False
                if is_bridge
                else bool(state.get("ipv6_egress_enabled", False)),
                server_host=state.get("bridge_ip") if is_bridge else None,
            )
    elif args.cmd == "xhttp":
        state = load_or_init_state(state_path)
        if args.mode == "off":
            sys.stderr.write(
                "[WARN] Ensure any downstream Cascade Bridge is switched to "
                "'sudo ./script.sh bridge-transport vision' before disabling XHTTP on the Exit node.\n"
            )
        state["xhttp_backup_enabled"] = args.mode == "on"
        save_state(state_path, state)
        apply_state(state, data_dir=data_dir, credentials_dir=credentials_dir)
    elif args.cmd == "rotate":
        state = load_or_init_state(state_path)
        priv_key, pub_key = generate_reality_keypair()
        state["user_uuid"] = str(uuid.uuid4())
        state["reality_private_key"] = priv_key
        state["reality_public_key"] = pub_key
        state["reality_short_id"] = generate_short_id()
        state["xhttp_secret_path"] = secrets.token_hex(32)
        state["entropy_seed"] = secrets.token_hex(24)
        save_state(state_path, state)
        apply_state(state, data_dir=data_dir, credentials_dir=credentials_dir)
    elif args.cmd == "decoy":
        state = load_or_init_state(state_path)
        state["decoy_target"] = args.target
        state["decoy_mode"] = (
            DecoyMode.reverse_proxy.value
            if args.target.startswith(("http://", "https://"))
            else DecoyMode.preset.value
        )
        state["entropy_seed"] = secrets.token_hex(24)
        save_state(state_path, state)
        apply_state(state, data_dir=data_dir, credentials_dir=credentials_dir)
    else:
        return 1

    is_bridge = state.get("mode") == "bridge"
    print(
        format_terminal_credentials(
            domain=state["domain"],
            user_uuid=state["user_uuid"],
            reality_public_key=state["reality_public_key"],
            reality_short_id=state["reality_short_id"],
            xhttp_secret_path=state["xhttp_secret_path"],
            xhttp_backup_enabled=False
            if is_bridge
            else bool(state.get("xhttp_backup_enabled", False)),
            credentials_dir=str(credentials_dir),
            port=XRAY_LISTEN_PORT,
            server_host=state.get("bridge_ip") if is_bridge else None,
            mode=state.get("mode", "exit"),
            server_ip=state.get("server_ip", ""),
            upstream_ip=state.get("upstream_ip", ""),
            upstream_domain=state.get("upstream_domain", ""),
            upstream_transport=state.get("upstream_transport", "vision"),
            upstream_xhttp_path=state.get("upstream_xhttp_path", ""),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
