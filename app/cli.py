"""SSH CLI backend for the Zero-Surface Single-User VLESS Self-Reality Appliance."""

import argparse
import copy
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

from app.bridge_state import (
    BRIDGE_STATE_SCHEMA_VERSION,
    atomic_write_json,
    atomic_write_text,
    default_platforms_for_profile,
    migrate_bridge_state_v1_to_v2,
    normalize_upstream_entry,
    sync_legacy_bridge_fields,
    validate_bridge_isolation,
    validate_upstream_name,
    validate_user_name,
    validate_uuid_str,
)
from app.client.profile_generator import (
    format_terminal_credentials,
    write_client_bundle,
    write_user_bundle,
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
        raw_text = state_path.read_text(encoding="utf-8")
        state = json.loads(raw_text)
        changed = False
        if state.get("mode") == "bridge":
            had_schema = "schema_version" in state
            state, migrated = migrate_bridge_state_v1_to_v2(state)
            if migrated:
                if not had_schema:
                    v1_bak = state_path.with_suffix(".json.v1.bak")
                    if not v1_bak.exists():
                        atomic_write_text(v1_bak, raw_text, mode=0o600)
                changed = True
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
    upstream_role: str = "media",
    upstream_name: str = "default",
) -> dict[str, Any]:
    clean_up_domain = validate_domain(upstream_domain)
    effective_sni = validate_domain(bridge_sni or clean_up_domain)

    if state_path.exists():
        existing = json.loads(state_path.read_text(encoding="utf-8"))
        if existing.get("mode") == "bridge":
            existing, _ = migrate_bridge_state_v1_to_v2(existing)
            target_name = (
                upstream_name
                if upstream_name in existing["upstreams"]
                else (
                    next(iter(existing["upstreams"]))
                    if len(existing["upstreams"]) == 1
                    else upstream_name
                )
            )
            prev_up = existing["upstreams"].get(target_name, {})
            resolved_xhttp_path = (
                upstream_xhttp_path
                if upstream_xhttp_path is not None
                else prev_up.get("xhttp_path", existing.get("upstream_xhttp_path", ""))
            ).strip().strip("/")
            default_tr = "xhttp" if resolved_xhttp_path else "vision"
            resolved_transport = (
                upstream_transport
                or prev_up.get("transport")
                or existing.get("upstream_transport")
                or default_tr
            ).strip().lower()
            existing["upstreams"][target_name] = normalize_upstream_entry(
                {
                    "role": prev_up.get("role", upstream_role),
                    "ip": upstream_ip.strip(),
                    "domain": clean_up_domain,
                    "uuid": upstream_uuid.strip(),
                    "public_key": upstream_public_key.strip(),
                    "short_id": upstream_short_id.strip(),
                    "transport": resolved_transport,
                    "xhttp_path": resolved_xhttp_path,
                    "xhttp_mode": prev_up.get("xhttp_mode", "stream-up"),
                    "port": prev_up.get("port", 443),
                    "fingerprint": prev_up.get("fingerprint", "firefox"),
                    "allow_same_subnet": prev_up.get("allow_same_subnet", False),
                }
            )
            existing.update(
                {
                    "schema_version": BRIDGE_STATE_SCHEMA_VERSION,
                    "mode": "bridge",
                    "domain": effective_sni,
                    "bridge_sni": effective_sni,
                    "bridge_ip": bridge_ip or existing.get("bridge_ip", ""),
                    "bridge_acme_enabled": bool(
                        bridge_acme_enabled
                        or existing.get("bridge_acme_enabled", False)
                    ),
                }
            )
            sync_legacy_bridge_fields(existing)
            validate_bridge_isolation(existing)
            save_state(state_path, existing)
            return existing

    priv_key, pub_key = generate_reality_keypair()
    short_id = generate_short_id()
    user_uuid = str(uuid.uuid4())
    xhttp_secret = secrets.token_hex(32)
    entropy_seed = secrets.token_hex(24)

    clean_xhttp_path = (upstream_xhttp_path or "").strip().strip("/")
    default_tr = "xhttp" if clean_xhttp_path else "vision"
    resolved_tr = (upstream_transport or default_tr).strip().lower()
    up_entry = normalize_upstream_entry(
        {
            "role": upstream_role,
            "ip": upstream_ip.strip(),
            "domain": clean_up_domain,
            "uuid": upstream_uuid.strip(),
            "public_key": upstream_public_key.strip(),
            "short_id": upstream_short_id.strip(),
            "transport": resolved_tr,
            "xhttp_path": clean_xhttp_path,
            "xhttp_mode": "stream-up",
            "port": 443,
            "fingerprint": "firefox",
            "allow_same_subnet": False,
        }
    )
    state = {
        "schema_version": BRIDGE_STATE_SCHEMA_VERSION,
        "mode": "bridge",
        "domain": effective_sni,
        "bridge_sni": effective_sni,
        "bridge_ip": bridge_ip.strip(),
        "bridge_acme_enabled": bool(bridge_acme_enabled),
        "upstreams": {upstream_name: up_entry},
        "users": {
            "owner": {
                "uuid": user_uuid,
                "upstream": upstream_name,
                "profile": "ai-owner",
                "platforms": default_platforms_for_profile("ai-owner"),
                "note": "",
                "disabled": False,
                "profile_version": "v1",
                "singbox_min_version": "1.14",
                "profile_sha256": "",
            }
        },
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
    sync_legacy_bridge_fields(state)
    validate_bridge_isolation(state)
    save_state(state_path, state)
    return state


def save_state(state_path: Path, state: dict[str, Any]) -> None:
    atomic_write_json(state_path, state, mode=0o600)


def query_xray_user_stats(
    *,
    server: str = XRAY_API_ADDRESS,
    reset: bool = False,
    timeout_sec: float = 3.0,
    container: str = "marzneshin-xray",
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    """Query loopback Xray StatsService in RAM with hard fail-fast timeout (zero disk logs)."""
    cmd = [
        "docker",
        "exec",
        container,
        "/usr/local/bin/xray",
        "api",
        "statsquery",
        f"--server={server}",
        "-pattern",
        "user>>>",
    ]
    if reset:
        cmd.append("-reset=true")

    exec_fn = runner or subprocess.run
    try:
        proc = exec_fn(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "reset": reset,
            "users": {},
            "detail": f"xray statsquery timed out after {timeout_sec}s",
        }
    except OSError as exc:
        return {
            "status": "unavailable",
            "reset": reset,
            "users": {},
            "detail": str(exc),
        }

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() or f"exit={proc.returncode}"
        return {
            "status": "unavailable",
            "reset": reset,
            "users": {},
            "detail": detail,
        }

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        return {
            "status": "unavailable",
            "reset": reset,
            "users": {},
            "detail": f"invalid statsquery JSON: {exc}",
        }

    users: dict[str, dict[str, int]] = {}
    for item in payload.get("stat", []) or []:
        name = str(item.get("name", ""))
        parts = name.split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            user_name = parts[1]
            direction = parts[3]
            if direction in ("uplink", "downlink"):
                entry = users.setdefault(user_name, {"uplink": 0, "downlink": 0})
                try:
                    entry[direction] = int(item.get("value", 0))
                except (TypeError, ValueError):
                    pass

    return {
        "status": "ok",
        "reset": reset,
        "users": users,
        "detail": f"{len(users)} user counter(s) read",
    }


def _active_bridge_clients(state: dict[str, Any]) -> list[dict[str, str]]:
    """Build active client list from v1 or v2 bridge state, omitting disabled users."""
    users_map = state.get("users")
    if isinstance(users_map, dict):
        clients: list[dict[str, str]] = []
        for uname, uinfo in users_map.items():
            if not isinstance(uinfo, dict) or uinfo.get("disabled", False):
                continue
            uid = str(uinfo.get("uuid", "")).strip()
            if uid:
                clients.append({"id": uid, "email": uname})
        return clients

    disabled_set = set(state.get("disabled_users", []) or [])
    if "owner" in disabled_set:
        return []
    return [{"id": state["user_uuid"], "email": "owner"}]


def _build_bridge_xray_from_state(state: dict[str, Any]) -> dict[str, Any]:
    """Render validated multi-upstream Xray config from v1 or v2 bridge state."""
    norm_state, _ = migrate_bridge_state_v1_to_v2(state)
    validate_bridge_isolation(norm_state)
    clients = _active_bridge_clients(norm_state)
    user_routes: dict[str, str] = {}
    users_map = norm_state.get("users") or {}
    for c in clients:
        uname = c["email"]
        uinfo = users_map.get(uname, {})
        if uinfo.get("upstream"):
            user_routes[uname] = str(uinfo["upstream"])

    return LocalXrayConfigBuilder.build_bridge(
        bridge_sni=norm_state.get("bridge_sni") or norm_state["domain"],
        reality_private_key=norm_state["reality_private_key"],
        reality_short_ids=[norm_state["reality_short_id"]],
        upstreams=norm_state["upstreams"],
        user_routes=user_routes,
        clients=clients,
        listen_port=XRAY_LISTEN_PORT,
        fallback_port=NGINX_HTTPS_FALLBACK_PORT,
        api_address=XRAY_API_ADDRESS,
    )


def _default_xray_config_test(candidate_path: Path) -> tuple[bool, str]:
    """Run xray run -test inside marzneshin-xray if the container is running."""
    try:
        ps = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except OSError:
        return True, "docker unavailable (local test mode)"
    if "marzneshin-xray" not in (ps.stdout or "").splitlines():
        return True, "marzneshin-xray not running"
    try:
        res = subprocess.run(
            [
                "docker",
                "exec",
                "marzneshin-xray",
                "/usr/local/bin/xray",
                "run",
                "-test",
                "-config",
                str(candidate_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "xray -test timed out after 10s"
    if res.returncode != 0:
        return False, (res.stderr or res.stdout or f"exit={res.returncode}").strip()
    return True, (res.stdout or "Configuration OK").strip()


def _atomic_apply_bridge_xray_and_save(
    state_path: Path,
    candidate_state: dict[str, Any],
    *,
    data_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Validate isolation, test candidate Xray config, replace atomically, and save state."""
    norm_state, _ = migrate_bridge_state_v1_to_v2(candidate_state)
    warnings = validate_bridge_isolation(norm_state)
    sync_legacy_bridge_fields(norm_state)
    xray_cfg = _build_bridge_xray_from_state(norm_state)

    xray_cfg_path = Path(
        os.environ.get("XRAY_CONFIG_PATH", str(data_dir / "xray" / "config.json"))
    )
    xray_cfg_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = xray_cfg_path.with_suffix(".json.bak")
    candidate_path = xray_cfg_path.with_name(f"{xray_cfg_path.stem}.candidate.json")
    if xray_cfg_path.exists():
        shutil.copy2(xray_cfg_path, backup_path)

    atomic_write_json(candidate_path, xray_cfg, mode=0o644)

    test_fn = xray_test_fn or _default_xray_config_test
    ok, detail = test_fn(candidate_path)
    if not ok:
        try:
            candidate_path.unlink(missing_ok=True)
        except OSError:
            pass
        if backup_path.exists():
            shutil.copy2(backup_path, xray_cfg_path)
        raise RuntimeError(
            f"xray -test failed; rolled back live config untouched: {detail}"
        )

    os.replace(candidate_path, xray_cfg_path)
    save_state(state_path, norm_state)
    return norm_state, warnings


def _require_bridge_state(state_path: Path) -> dict[str, Any]:
    state = load_or_init_state(state_path)
    if state.get("mode") != "bridge":
        raise ValueError(
            "This operation is only supported on Cascade Bridge nodes (mode='bridge')"
        )
    return state


def set_user_disabled(
    state_path: Path,
    *,
    name: str,
    disabled: bool,
    automated: bool = False,
    data_dir: Path,
    credentials_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> dict[str, Any]:
    """Toggle a bridge user's disabled flag with ai-owner protection and xray -test pre-flight."""
    state = _require_bridge_state(state_path)
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValueError("User name is required")

    candidate_state = copy.deepcopy(state)
    users_map = candidate_state.get("users")
    if isinstance(users_map, dict) and users_map:
        if clean_name not in users_map:
            raise ValueError(f"Unknown user '{clean_name}'")
        uinfo = users_map[clean_name]
        profile = str(uinfo.get("profile", "")).strip().lower()
        if disabled and automated and (profile == "ai-owner" or clean_name == "owner"):
            raise ValueError(
                f"Refusing automated disable of protected ai-owner user '{clean_name}'"
            )
        uinfo["disabled"] = bool(disabled)
    else:
        if clean_name != "owner":
            raise ValueError(f"Unknown user '{clean_name}' (v1 state only has 'owner')")
        if disabled and automated:
            raise ValueError(
                "Refusing automated disable of protected ai-owner user 'owner'"
            )
        disabled_list = set(candidate_state.get("disabled_users", []) or [])
        if disabled:
            disabled_list.add("owner")
        else:
            disabled_list.discard("owner")
        candidate_state["disabled_users"] = sorted(disabled_list)

    saved_state, _ = _atomic_apply_bridge_xray_and_save(
        state_path,
        candidate_state,
        data_dir=data_dir,
        xray_test_fn=xray_test_fn,
    )
    return saved_state


def upstream_add(
    state_path: Path,
    *,
    name: str,
    role: str,
    ip: str,
    domain: str,
    upstream_uuid: str,
    public_key: str,
    short_id: str,
    transport: str | None = None,
    xhttp_path: str = "",
    xhttp_mode: str = "stream-up",
    port: int = 443,
    fingerprint: str = "firefox",
    allow_same_subnet: bool = False,
    data_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Register a new named upstream on the Cascade Bridge with strict isolation guards."""
    state = _require_bridge_state(state_path)
    clean_name = validate_upstream_name(name)
    if clean_name in state.get("upstreams", {}):
        raise ValueError(f"Upstream '{clean_name}' already exists")

    candidate_state = copy.deepcopy(state)
    candidate_state.setdefault("upstreams", {})[clean_name] = normalize_upstream_entry(
        {
            "role": role,
            "ip": ip,
            "domain": domain,
            "uuid": upstream_uuid,
            "public_key": public_key,
            "short_id": short_id,
            "transport": transport,
            "xhttp_path": xhttp_path,
            "xhttp_mode": xhttp_mode,
            "port": port,
            "fingerprint": fingerprint,
            "allow_same_subnet": allow_same_subnet,
        }
    )
    return _atomic_apply_bridge_xray_and_save(
        state_path,
        candidate_state,
        data_dir=data_dir,
        xray_test_fn=xray_test_fn,
    )


def upstream_list(state_path: Path) -> dict[str, Any]:
    state = _require_bridge_state(state_path)
    users = state.get("users", {})
    result: dict[str, Any] = {}
    for uname, ucfg in state.get("upstreams", {}).items():
        bound = [u for u, info in users.items() if info.get("upstream") == uname]
        result[uname] = {**ucfg, "bound_users": bound}
    return result


def upstream_remove(
    state_path: Path,
    *,
    name: str,
    data_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> dict[str, Any]:
    """Delete an unused upstream; refuses if any user is still bound."""
    state = _require_bridge_state(state_path)
    clean_name = validate_upstream_name(name)
    upstreams = state.get("upstreams", {})
    if clean_name not in upstreams:
        raise ValueError(f"Unknown upstream '{clean_name}'")

    bound = [
        uname
        for uname, uinfo in state.get("users", {}).items()
        if uinfo.get("upstream") == clean_name
    ]
    if bound:
        raise ValueError(
            f"Refusing to remove upstream '{clean_name}': bound users exist ({', '.join(bound)}); "
            "migrate or remove them first"
        )
    if len(upstreams) <= 1:
        raise ValueError(
            f"Refusing to remove '{clean_name}': at least one upstream must remain on the bridge"
        )

    candidate_state = copy.deepcopy(state)
    del candidate_state["upstreams"][clean_name]
    saved_state, _ = _atomic_apply_bridge_xray_and_save(
        state_path,
        candidate_state,
        data_dir=data_dir,
        xray_test_fn=xray_test_fn,
    )
    return saved_state


def upstream_migrate(
    state_path: Path,
    *,
    source: str,
    target: str,
    data_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Rebind all users from source upstream to target upstream without altering client UUIDs/profiles."""
    state = _require_bridge_state(state_path)
    src = validate_upstream_name(source)
    dst = validate_upstream_name(target)
    upstreams = state.get("upstreams", {})
    if src not in upstreams:
        raise ValueError(f"Unknown source upstream '{src}'")
    if dst not in upstreams:
        raise ValueError(f"Unknown target upstream '{dst}'")
    if src == dst:
        raise ValueError("Source and target upstreams must differ")

    candidate_state = copy.deepcopy(state)
    migrated_users: list[str] = []
    for uname, uinfo in candidate_state.get("users", {}).items():
        if uinfo.get("upstream") == src:
            uinfo["upstream"] = dst
            migrated_users.append(uname)

    saved_state, _ = _atomic_apply_bridge_xray_and_save(
        state_path,
        candidate_state,
        data_dir=data_dir,
        xray_test_fn=xray_test_fn,
    )
    return saved_state, migrated_users


def _render_user_bundle_for_state(
    state: dict[str, Any],
    *,
    username: str,
    credentials_dir: Path,
    fingerprint: str = "firefox",
) -> dict[str, Any]:
    uinfo = state["users"][username]
    return write_user_bundle(
        credentials_dir,
        username=username,
        profile=uinfo["profile"],
        domain=state["domain"],
        user_uuid=uinfo["uuid"],
        reality_public_key=state["reality_public_key"],
        reality_short_id=state["reality_short_id"],
        xhttp_secret_path=state.get("xhttp_secret_path", ""),
        port=XRAY_LISTEN_PORT,
        ipv6_egress_enabled=False,
        server_host=state.get("bridge_ip") or None,
        fingerprint=fingerprint,
    )


def user_add(
    state_path: Path,
    *,
    name: str,
    upstream: str,
    profile: str | None = None,
    user_uuid: str | None = None,
    note: str = "",
    fingerprint: str = "firefox",
    data_dir: Path,
    credentials_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create a bridge user bound statically to an upstream and generate role-scoped profiles."""
    state = _require_bridge_state(state_path)
    clean_name = validate_user_name(name)
    clean_up = validate_upstream_name(upstream)
    upstreams = state.get("upstreams", {})
    if clean_up not in upstreams:
        raise ValueError(f"Unknown upstream '{clean_up}'")
    if clean_name in state.get("users", {}):
        raise ValueError(f"User '{clean_name}' already exists")

    up_role = upstreams[clean_up]["role"]
    resolved_profile = (
        profile.strip().lower()
        if profile
        else ("ai-owner" if up_role == "ai-isolated" else "media-selective")
    )
    uid = validate_uuid_str(user_uuid) if user_uuid else str(uuid.uuid4())

    candidate_state = copy.deepcopy(state)
    candidate_state.setdefault("users", {})[clean_name] = {
        "uuid": uid,
        "upstream": clean_up,
        "profile": resolved_profile,
        "platforms": default_platforms_for_profile(resolved_profile),
        "note": note,
        "disabled": False,
        "profile_version": "v1",
        "singbox_min_version": "1.14",
        "profile_sha256": "",
    }
    validate_bridge_isolation(candidate_state)

    if resolved_profile in {"ai-owner", "ai-user"} and up_role == "media":
        sys.stderr.write(
            f"[WARN] Binding {resolved_profile} user '{clean_name}' to media upstream '{clean_up}'; "
            "prefer an 'ai-isolated' exit for AI account isolation.\n"
        )

    bundle_meta = _render_user_bundle_for_state(
        candidate_state,
        username=clean_name,
        credentials_dir=credentials_dir,
        fingerprint=fingerprint,
    )
    candidate_state["users"][clean_name]["profile_version"] = bundle_meta[
        "profile_version"
    ]
    candidate_state["users"][clean_name]["singbox_min_version"] = bundle_meta[
        "singbox_min_version"
    ]
    candidate_state["users"][clean_name]["profile_sha256"] = bundle_meta[
        "profile_sha256"
    ]

    try:
        saved_state, _ = _atomic_apply_bridge_xray_and_save(
            state_path,
            candidate_state,
            data_dir=data_dir,
            xray_test_fn=xray_test_fn,
        )
    except Exception:
        shutil.rmtree(bundle_meta["bundle_dir"], ignore_errors=True)
        raise

    return saved_state, bundle_meta


def user_assign(
    state_path: Path,
    *,
    name: str,
    upstream: str,
    data_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> dict[str, Any]:
    """Reassign an existing bridge user to another upstream while preserving UUID/profile."""
    state = _require_bridge_state(state_path)
    clean_name = validate_user_name(name)
    clean_up = validate_upstream_name(upstream)
    if clean_name not in state.get("users", {}):
        raise ValueError(f"Unknown user '{clean_name}'")
    if clean_up not in state.get("upstreams", {}):
        raise ValueError(f"Unknown upstream '{clean_up}'")

    candidate_state = copy.deepcopy(state)
    candidate_state["users"][clean_name]["upstream"] = clean_up
    saved_state, _ = _atomic_apply_bridge_xray_and_save(
        state_path,
        candidate_state,
        data_dir=data_dir,
        xray_test_fn=xray_test_fn,
    )
    return saved_state


def user_remove(
    state_path: Path,
    *,
    name: str,
    data_dir: Path,
    credentials_dir: Path,
    xray_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
) -> dict[str, Any]:
    """Revoke a bridge user atomically and remove their isolated credential bundle."""
    state = _require_bridge_state(state_path)
    clean_name = validate_user_name(name)
    if clean_name not in state.get("users", {}):
        raise ValueError(f"Unknown user '{clean_name}'")

    candidate_state = copy.deepcopy(state)
    del candidate_state["users"][clean_name]
    saved_state, _ = _atomic_apply_bridge_xray_and_save(
        state_path,
        candidate_state,
        data_dir=data_dir,
        xray_test_fn=xray_test_fn,
    )
    shutil.rmtree(Path(credentials_dir) / "users" / clean_name, ignore_errors=True)
    return saved_state


def user_list(state_path: Path) -> dict[str, Any]:
    state = _require_bridge_state(state_path)
    return copy.deepcopy(state.get("users", {}))


def user_show(
    state_path: Path, *, name: str, credentials_dir: Path
) -> dict[str, Any]:
    state = _require_bridge_state(state_path)
    clean_name = validate_user_name(name)
    users = state.get("users", {})
    if clean_name not in users:
        raise ValueError(f"Unknown user '{clean_name}'")
    uinfo = copy.deepcopy(users[clean_name])
    user_dir = Path(credentials_dir) / "users" / clean_name
    files = (
        sorted(p.name for p in user_dir.iterdir() if p.is_file())
        if user_dir.exists()
        else []
    )
    return {
        "user": clean_name,
        **uinfo,
        "bundle_dir": str(user_dir),
        "files": files,
    }


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
        xray_cfg = _build_bridge_xray_from_state(state)
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
    atomic_write_json(xray_cfg_path, xray_cfg, mode=0o644)

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

    if not is_bridge:
        write_client_bundle(
            credentials_dir,
            domain=state["domain"],
            user_uuid=state["user_uuid"],
            reality_public_key=state["reality_public_key"],
            reality_short_id=state["reality_short_id"],
            xhttp_secret_path=state["xhttp_secret_path"],
            xhttp_backup_enabled=bool(state.get("xhttp_backup_enabled", False)),
            port=XRAY_LISTEN_PORT,
            ipv6_egress_enabled=bool(state.get("ipv6_egress_enabled", False)),
            server_host=None,
        )
        return

    norm_state, _ = migrate_bridge_state_v1_to_v2(state)
    users_map = norm_state.get("users", {})
    for uname, uinfo in users_map.items():
        meta = _render_user_bundle_for_state(
            norm_state,
            username=uname,
            credentials_dir=credentials_dir,
        )
        uinfo["profile_version"] = meta["profile_version"]
        uinfo["singbox_min_version"] = meta["singbox_min_version"]
        uinfo["profile_sha256"] = meta["profile_sha256"]

    ai_owner_entry = next(
        (u for u in users_map.values() if u.get("profile") == "ai-owner"),
        None,
    )
    if ai_owner_entry or norm_state.get("user_uuid"):
        owner_uuid = (
            ai_owner_entry["uuid"] if ai_owner_entry else norm_state["user_uuid"]
        )
        write_client_bundle(
            credentials_dir,
            domain=norm_state["domain"],
            user_uuid=owner_uuid,
            reality_public_key=norm_state["reality_public_key"],
            reality_short_id=norm_state["reality_short_id"],
            xhttp_secret_path=norm_state["xhttp_secret_path"],
            xhttp_backup_enabled=False,
            port=XRAY_LISTEN_PORT,
            ipv6_egress_enabled=False,
            server_host=norm_state.get("bridge_ip") or None,
        )


def _register_upstream_subparser(sub: argparse._SubParsersAction) -> None:
    p_up = sub.add_parser(
        "upstream",
        help="Manage named German exit upstreams on the Cascade Bridge",
    )
    up_sub = p_up.add_subparsers(dest="up_action", required=True)

    p_add = up_sub.add_parser("add", help="Add a named exit upstream")
    p_add.add_argument("name")
    p_add.add_argument("--role", choices=["ai-isolated", "media"], required=True)
    p_add.add_argument("--ip", required=True)
    p_add.add_argument("--domain", required=True)
    p_add.add_argument("--uuid", required=True)
    p_add.add_argument("--pbk", required=True)
    p_add.add_argument("--sid", required=True)
    p_add.add_argument("--transport", choices=["xhttp", "vision"], default=None)
    p_add.add_argument("--xhttp-path", default="")
    p_add.add_argument("--xhttp-mode", default="stream-up")
    p_add.add_argument("--port", type=int, default=443)
    p_add.add_argument("--fp", default="firefox")
    p_add.add_argument("--allow-same-subnet", action="store_true")

    p_list = up_sub.add_parser("list", help="List configured bridge upstreams")
    p_list.add_argument("--json", action="store_true", dest="as_json")

    p_rm = up_sub.add_parser("remove", help="Remove an unused bridge upstream")
    p_rm.add_argument("name")

    p_mig = up_sub.add_parser(
        "migrate",
        help="Migrate all users from one upstream to another without changing client UUIDs",
    )
    p_mig.add_argument("source")
    p_mig.add_argument("target")


def _register_user_subparser(sub: argparse._SubParsersAction) -> None:
    p_user = sub.add_parser(
        "user",
        help="Manage bridge users, upstream bindings, and quarantine state",
    )
    u_sub = p_user.add_subparsers(dest="user_action", required=True)

    p_add = u_sub.add_parser("add", help="Create a user and generate role-scoped profiles")
    p_add.add_argument("name")
    p_add.add_argument("--upstream", required=True)
    p_add.add_argument(
        "--profile", choices=["ai-owner", "ai-user", "media-selective"], default=None
    )
    p_add.add_argument("--uuid", default=None)
    p_add.add_argument("--note", default="")
    p_add.add_argument("--fp", default="firefox")

    p_list = u_sub.add_parser("list", help="List configured bridge users")
    p_list.add_argument("--json", action="store_true", dest="as_json")

    p_show = u_sub.add_parser("show", help="Show user binding and credential bundle info")
    p_show.add_argument("name")
    p_show.add_argument("--json", action="store_true", dest="as_json")

    p_assign = u_sub.add_parser(
        "assign", help="Reassign a user to another upstream without rotating UUID"
    )
    p_assign.add_argument("name")
    p_assign.add_argument("upstream")

    p_rm = u_sub.add_parser("remove", help="Remove user and delete credential bundle")
    p_rm.add_argument("name")

    for act in ("disable", "enable"):
        p_toggle = u_sub.add_parser(
            act, help=f"{act.capitalize()} user access with xray -test pre-flight"
        )
        p_toggle.add_argument("name")
        p_toggle.add_argument(
            "--automated",
            action="store_true",
            help="Enforce hard ai-owner whitelist protection for automated callers",
        )


def _handle_upstream_command(
    args: argparse.Namespace, *, state_path: Path, data_dir: Path
) -> int:
    try:
        if args.up_action == "add":
            _, warnings = upstream_add(
                state_path,
                name=args.name,
                role=args.role,
                ip=args.ip,
                domain=args.domain,
                upstream_uuid=args.uuid,
                public_key=args.pbk,
                short_id=args.sid,
                transport=args.transport,
                xhttp_path=args.xhttp_path,
                xhttp_mode=args.xhttp_mode,
                port=args.port,
                fingerprint=args.fp,
                allow_same_subnet=bool(args.allow_same_subnet),
                data_dir=data_dir,
            )
            for w in warnings:
                sys.stderr.write(f"[WARN] {w}\n")
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": "upstream-add",
                        "upstream": args.name,
                        "role": args.role,
                        "warnings": warnings,
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        if args.up_action == "list":
            data = upstream_list(state_path)
            if args.as_json:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            else:
                for uname, uinfo in data.items():
                    bound = ", ".join(uinfo["bound_users"]) or "none"
                    print(
                        f"{uname}: role={uinfo['role']} ip={uinfo['ip']}:{uinfo['port']} "
                        f"domain={uinfo['domain']} transport={uinfo['transport']} users=[{bound}]"
                    )
            return 0
        if args.up_action == "remove":
            upstream_remove(state_path, name=args.name, data_dir=data_dir)
            print(
                json.dumps(
                    {"status": "ok", "action": "upstream-remove", "upstream": args.name},
                    ensure_ascii=False,
                )
            )
            return 0
        if args.up_action == "migrate":
            _, migrated = upstream_migrate(
                state_path,
                source=args.source,
                target=args.target,
                data_dir=data_dir,
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": "upstream-migrate",
                        "source": args.source,
                        "target": args.target,
                        "migrated_users": migrated,
                    },
                    ensure_ascii=False,
                )
            )
            return 0
    except (ValueError, RuntimeError) as exc:
        sys.stderr.write(f"[ERROR] {exc}\n")
        return 1
    return 1


def _handle_user_command(
    args: argparse.Namespace,
    *,
    state_path: Path,
    data_dir: Path,
    credentials_dir: Path,
) -> int:
    try:
        if args.user_action == "add":
            _, meta = user_add(
                state_path,
                name=args.name,
                upstream=args.upstream,
                profile=args.profile,
                user_uuid=args.uuid,
                note=args.note,
                fingerprint=args.fp,
                data_dir=data_dir,
                credentials_dir=credentials_dir,
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": "user-add",
                        "user": args.name,
                        "upstream": args.upstream,
                        "bundle_dir": str(meta["bundle_dir"]),
                        "profile_version": meta["profile_version"],
                        "profile_sha256": meta["profile_sha256"],
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        if args.user_action == "list":
            users = user_list(state_path)
            if args.as_json:
                print(json.dumps(users, indent=2, ensure_ascii=False))
            else:
                for uname, uinfo in users.items():
                    status = "disabled" if uinfo.get("disabled") else "active"
                    print(
                        f"{uname}: profile={uinfo['profile']} upstream={uinfo['upstream']} "
                        f"status={status} version={uinfo.get('profile_version', 'v1')}"
                    )
            return 0
        if args.user_action == "show":
            info = user_show(
                state_path, name=args.name, credentials_dir=credentials_dir
            )
            if args.as_json:
                print(json.dumps(info, indent=2, ensure_ascii=False))
            else:
                print(
                    f"User: {info['user']}\n"
                    f"  Profile:   {info['profile']} (v={info.get('profile_version', 'v1')}, "
                    f"sing-box>={info.get('singbox_min_version', '1.14')})\n"
                    f"  Upstream:  {info['upstream']}\n"
                    f"  UUID:      {info['uuid']}\n"
                    f"  Disabled:  {info.get('disabled', False)}\n"
                    f"  SHA-256:   {info.get('profile_sha256', '')}\n"
                    f"  Bundle:    {info['bundle_dir']}\n"
                    f"  Files:     {', '.join(info['files']) or 'none'}"
                )
                if info["profile"] == "media-selective":
                    print("  Raw VLESS: omitted (mobile-only Media-Selective JSON distribution)")
                elif info["profile"] == "ai-user":
                    print("  Raw VLESS: omitted (Linux Selective + mixed-in JSON distribution)")
            return 0
        if args.user_action == "assign":
            user_assign(
                state_path,
                name=args.name,
                upstream=args.upstream,
                data_dir=data_dir,
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": "user-assign",
                        "user": args.name,
                        "upstream": args.upstream,
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        if args.user_action == "remove":
            user_remove(
                state_path,
                name=args.name,
                data_dir=data_dir,
                credentials_dir=credentials_dir,
            )
            print(
                json.dumps(
                    {"status": "ok", "action": "user-remove", "user": args.name},
                    ensure_ascii=False,
                )
            )
            return 0
        if args.user_action in ("disable", "enable"):
            set_user_disabled(
                state_path,
                name=args.name,
                disabled=(args.user_action == "disable"),
                automated=bool(args.automated),
                data_dir=data_dir,
                credentials_dir=credentials_dir,
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "action": args.user_action,
                        "user": args.name,
                    },
                    ensure_ascii=False,
                )
            )
            return 0
    except (ValueError, RuntimeError) as exc:
        sys.stderr.write(f"[ERROR] {exc}\n")
        return 1
    return 1


def _normalize_leading_dash_values(argv: list[str] | None) -> list[str] | None:
    """Prevent base64url Reality public keys starting with '-' from being parsed as options."""
    if argv is None:
        return None
    value_flags = {"--pbk", "--upstream-pbk", "--sid", "--upstream-sid"}
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in value_flags and i + 1 < len(argv) and argv[i + 1].startswith("-"):
            out.append(f"{tok}={argv[i + 1]}")
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


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
    p_bt.add_argument("--upstream", default=None)
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

    p_stats = sub.add_parser(
        "stats",
        help="Query loopback in-memory Xray per-user byte counters (bridge mode, 0 disk logs)",
    )
    p_stats.add_argument("--reset", action="store_true", help="Reset counters after read")
    p_stats.add_argument("--timeout", type=float, default=3.0)
    p_stats.add_argument("--server", default=XRAY_API_ADDRESS)
    p_stats.add_argument("--container", default="marzneshin-xray")

    _register_upstream_subparser(sub)
    _register_user_subparser(sub)

    effective_argv = _normalize_leading_dash_values(
        sys.argv[1:] if argv is None else argv
    )
    args = parser.parse_args(effective_argv)
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
        save_state(state_path, state)
    elif args.cmd == "bridge-transport":
        state = load_or_init_state(state_path)
        if state.get("mode") != "bridge":
            raise ValueError(
                "bridge-transport is only supported on Cascade Bridge nodes (mode='bridge')"
            )
        upstreams = state.setdefault("upstreams", {})
        target_up = args.upstream or (
            "default"
            if "default" in upstreams
            else (next(iter(upstreams)) if len(upstreams) == 1 else "")
        )
        if not target_up or target_up not in upstreams:
            raise ValueError(
                "Specify --upstream <name> when multiple upstreams exist on the bridge"
            )
        up_entry = dict(upstreams[target_up])
        if args.path is not None:
            up_entry["xhttp_path"] = args.path.strip().strip("/")
        if args.upstream_ip:
            up_entry["ip"] = args.upstream_ip.strip()
        if args.upstream_domain:
            up_entry["domain"] = validate_domain(args.upstream_domain)
        if args.upstream_uuid:
            up_entry["uuid"] = args.upstream_uuid.strip()
        if args.upstream_pbk:
            up_entry["public_key"] = args.upstream_pbk.strip()
        if args.upstream_sid:
            up_entry["short_id"] = args.upstream_sid.strip()
        if args.transport == "xhttp" and not up_entry.get("xhttp_path"):
            raise ValueError(
                "Switching bridge to 'xhttp' requires --path <64-hex-xhttp-secret-path> (from 'sudo ./script.sh xhttp on' on Exit node)"
            )
        up_entry["transport"] = args.transport
        upstreams[target_up] = normalize_upstream_entry(up_entry)
        sync_legacy_bridge_fields(state)
        validate_bridge_isolation(state)
        apply_state(state, data_dir=data_dir, credentials_dir=credentials_dir)
        save_state(state_path, state)
    elif args.cmd == "status":
        state = load_or_init_state(state_path)
        is_bridge = state.get("mode") == "bridge"
        if not (credentials_dir / "throne-windows11.json").exists() or not (
            credentials_dir / "ios-singbox.json"
        ).exists():
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
        new_uuid = str(uuid.uuid4())
        state["user_uuid"] = new_uuid
        state["reality_private_key"] = priv_key
        state["reality_public_key"] = pub_key
        state["reality_short_id"] = generate_short_id()
        state["xhttp_secret_path"] = secrets.token_hex(32)
        state["entropy_seed"] = secrets.token_hex(24)
        if state.get("mode") == "bridge" and "owner" in state.get("users", {}):
            state["users"]["owner"]["uuid"] = new_uuid
            sync_legacy_bridge_fields(state)
        apply_state(state, data_dir=data_dir, credentials_dir=credentials_dir)
        save_state(state_path, state)
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
    elif args.cmd == "stats":
        result = query_xray_user_stats(
            server=args.server,
            reset=bool(args.reset),
            timeout_sec=args.timeout,
            container=args.container,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    elif args.cmd == "upstream":
        return _handle_upstream_command(
            args, state_path=state_path, data_dir=data_dir
        )
    elif args.cmd == "user":
        return _handle_user_command(
            args,
            state_path=state_path,
            data_dir=data_dir,
            credentials_dir=credentials_dir,
        )
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
