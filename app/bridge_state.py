"""Bridge v2 state schema, v1-to-v2 migration, atomic I/O, and ai-isolated guards."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any

from app.nginx.manager import validate_domain
from app.xray.config_builder import (
    DEFAULT_UTLS_FINGERPRINT,
    validate_short_ids,
    validate_utls_fingerprint,
)

BRIDGE_STATE_SCHEMA_VERSION = 2
UPSTREAM_ROLES = frozenset({"ai-isolated", "media"})
USER_PROFILES = frozenset({"ai-owner", "ai-user", "media-selective"})

UPSTREAM_SLUG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
USER_SLUG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

# Common multi-label public suffixes for dependency-free registrable root-domain (eTLD+1) checks.
MULTI_LABEL_PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "me.uk",
        "net.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "com.ru",
        "org.ru",
        "net.ru",
        "msk.ru",
        "spb.ru",
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "com.br",
        "net.br",
        "org.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "edu.cn",
        "gov.cn",
        "co.in",
        "net.in",
        "org.in",
        "com.tr",
        "org.tr",
        "com.ua",
        "org.ua",
        "kiev.ua",
        "co.za",
        "com.mx",
        "co.kr",
        "com.tw",
        "co.il",
        "com.sg",
        "com.hk",
        "co.nz",
        "org.nz",
    }
)


def atomic_write_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Atomically write text content via same-directory temp file + fsync + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, mode)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, payload: Any, *, mode: int = 0o600) -> None:
    """Atomically serialize JSON to disk with trailing newline."""
    atomic_write_text(path, json.dumps(payload, indent=2) + "\n", mode=mode)


def validate_upstream_name(name: str) -> str:
    clean = (name or "").strip()
    if not clean or not UPSTREAM_SLUG_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid upstream name '{name}': use 1-64 alphanumeric, '-' or '_' characters"
        )
    return clean


def validate_user_name(name: str) -> str:
    clean = (name or "").strip()
    if not clean or not USER_SLUG_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid user name '{name}': use 1-64 alphanumeric, '.', '-' or '_' characters"
        )
    return clean


def validate_ipv4(ip: str, label: str = "IP address") -> str:
    clean = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(clean)
        if addr.version != 4:
            raise ValueError(f"{label} must be IPv4")
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv4 address (got '{ip}')") from exc
    return str(addr)


def validate_uuid_str(value: str, label: str = "UUID") -> str:
    clean = (value or "").strip()
    try:
        parsed = uuid.UUID(clean)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label} must be a valid UUID (got '{value}')") from exc
    return str(parsed)


def extract_root_domain(domain: str) -> str:
    """Extract lowercase registrable root domain (eTLD+1) from an FQDN."""
    clean = validate_domain(domain).rstrip(".")
    labels = [lbl for lbl in clean.split(".") if lbl]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def ipv4_slash24(ip: str) -> str:
    """Return canonical IPv4 /24 network CIDR string for subnet isolation checks."""
    clean_ip = validate_ipv4(ip)
    return str(ipaddress.ip_network(f"{clean_ip}/24", strict=False))


def default_platforms_for_profile(profile: str) -> list[str]:
    clean = (profile or "").strip().lower()
    if clean == "ai-owner":
        return ["android", "ios", "windows", "linux", "openwrt"]
    if clean == "ai-user":
        return ["linux"]
    if clean == "media-selective":
        return ["android", "ios"]
    raise ValueError(
        f"Unsupported user profile '{profile}': expected 'ai-owner', 'ai-user', or 'media-selective'"
    )


def normalize_upstream_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a single bridge upstream dictionary."""
    role = str(entry.get("role", "media")).strip().lower()
    if role not in UPSTREAM_ROLES:
        raise ValueError(
            f"Unsupported upstream role '{role}': expected 'ai-isolated' or 'media'"
        )
    ip = validate_ipv4(str(entry.get("ip", "")), "upstream ip")
    domain = validate_domain(str(entry.get("domain", "")))
    up_uuid = str(entry.get("uuid", "")).strip()
    if not up_uuid:
        raise ValueError("upstream uuid is required")
    public_key = str(entry.get("public_key", "")).strip()
    if not public_key:
        raise ValueError("upstream public_key is required")
    short_id = str(entry.get("short_id", "")).strip()
    validate_short_ids([short_id])

    xhttp_path = str(entry.get("xhttp_path", "")).strip().strip("/")
    default_tr = "xhttp" if xhttp_path else "vision"
    transport = str(entry.get("transport") or default_tr).strip().lower()
    if transport not in {"vision", "xhttp"}:
        raise ValueError(
            f"Unsupported upstream transport '{transport}': expected 'vision' or 'xhttp'"
        )
    if transport == "xhttp" and not xhttp_path:
        raise ValueError("xhttp_path is required when upstream transport is 'xhttp'")

    port = int(entry.get("port", 443) or 443)
    if port < 1 or port > 65535:
        raise ValueError(f"Invalid upstream port {port}")

    fp = validate_utls_fingerprint(
        str(entry.get("fingerprint") or DEFAULT_UTLS_FINGERPRINT)
    )
    xhttp_mode = str(entry.get("xhttp_mode") or "stream-up").strip() or "stream-up"

    return {
        "role": role,
        "ip": ip,
        "domain": domain,
        "uuid": up_uuid,
        "public_key": public_key,
        "short_id": short_id,
        "transport": transport,
        "xhttp_path": xhttp_path,
        "xhttp_mode": xhttp_mode,
        "port": port,
        "fingerprint": fp,
        "allow_same_subnet": bool(entry.get("allow_same_subnet", False)),
    }


def sync_legacy_bridge_fields(state: dict[str, Any]) -> None:
    """Keep legacy mirror keys aligned with primary upstream/user for backward compatibility."""
    upstreams = state.get("upstreams") or {}
    primary_up_name = (
        "default"
        if "default" in upstreams
        else (next(iter(upstreams)) if upstreams else None)
    )
    if primary_up_name:
        up = upstreams[primary_up_name]
        state["upstream_ip"] = up["ip"]
        state["upstream_domain"] = up["domain"]
        state["upstream_uuid"] = up["uuid"]
        state["upstream_public_key"] = up["public_key"]
        state["upstream_short_id"] = up["short_id"]
        state["upstream_transport"] = up["transport"]
        state["upstream_xhttp_path"] = up["xhttp_path"]

    users = state.get("users") or {}
    primary_user: dict[str, Any] | None = None
    if "owner" in users and isinstance(users["owner"], dict):
        primary_user = users["owner"]
    else:
        for uinfo in users.values():
            if isinstance(uinfo, dict) and uinfo.get("profile") == "ai-owner":
                primary_user = uinfo
                break
        if primary_user is None and users:
            first_val = next(iter(users.values()))
            if isinstance(first_val, dict):
                primary_user = first_val
    if primary_user and primary_user.get("uuid"):
        state["user_uuid"] = primary_user["uuid"]


def migrate_bridge_state_v1_to_v2(
    state: dict[str, Any],
    *,
    default_upstream_role: str = "media",
) -> tuple[dict[str, Any], bool]:
    """Migrate a v1 (or partially populated) bridge state to schema_version=2 in-place-safe copy."""
    if state.get("mode") != "bridge":
        return copy.deepcopy(state), False

    if default_upstream_role not in UPSTREAM_ROLES:
        raise ValueError(
            f"Invalid default_upstream_role '{default_upstream_role}'"
        )

    out = copy.deepcopy(state)
    changed = out.get("schema_version") != BRIDGE_STATE_SCHEMA_VERSION

    upstreams = out.get("upstreams")
    if not isinstance(upstreams, dict) or not upstreams:
        xhttp_path = str(out.get("upstream_xhttp_path", "")).strip().strip("/")
        default_tr = "xhttp" if xhttp_path else "vision"
        transport = str(out.get("upstream_transport") or default_tr).strip().lower()
        upstreams = {
            "default": normalize_upstream_entry(
                {
                    "role": default_upstream_role,
                    "ip": out.get("upstream_ip", ""),
                    "domain": out.get("upstream_domain", ""),
                    "uuid": out.get("upstream_uuid", ""),
                    "public_key": out.get("upstream_public_key", ""),
                    "short_id": out.get("upstream_short_id", ""),
                    "transport": transport,
                    "xhttp_path": xhttp_path,
                    "xhttp_mode": "stream-up",
                    "port": int(out.get("upstream_port", 443) or 443),
                    "fingerprint": out.get(
                        "upstream_fingerprint", DEFAULT_UTLS_FINGERPRINT
                    ),
                    "allow_same_subnet": False,
                }
            )
        }
        out["upstreams"] = upstreams
        changed = True
    else:
        normalized_upstreams: dict[str, dict[str, Any]] = {}
        for uname, uentry in upstreams.items():
            clean_uname = validate_upstream_name(uname)
            norm = normalize_upstream_entry(uentry)
            if norm != uentry or clean_uname != uname:
                changed = True
            normalized_upstreams[clean_uname] = norm
        out["upstreams"] = normalized_upstreams

    default_up_name = (
        "default"
        if "default" in out["upstreams"]
        else next(iter(out["upstreams"]))
    )

    users = out.get("users")
    disabled_legacy = set(out.get("disabled_users", []) or [])
    if not isinstance(users, dict) or (
        not users and out.get("user_uuid") and "users" not in state
    ):
        user_uuid = str(out.get("user_uuid", "")).strip()
        if user_uuid:
            out["users"] = {
                "owner": {
                    "uuid": user_uuid,
                    "upstream": default_up_name,
                    "profile": "ai-owner",
                    "platforms": default_platforms_for_profile("ai-owner"),
                    "note": "",
                    "disabled": "owner" in disabled_legacy,
                    "profile_version": "v1",
                    "singbox_min_version": "1.14",
                    "profile_sha256": "",
                }
            }
            changed = True
        else:
            out["users"] = {}
            changed = True
    else:
        normalized_users: dict[str, dict[str, Any]] = {}
        for uname, uinfo in users.items():
            clean_user = validate_user_name(uname)
            if not isinstance(uinfo, dict):
                raise ValueError(f"Invalid user entry for '{uname}'")
            u_copy = copy.deepcopy(uinfo)
            profile = str(u_copy.get("profile") or "media-selective").strip().lower()
            if profile not in USER_PROFILES:
                raise ValueError(f"Invalid profile '{profile}' for user '{uname}'")
            u_copy["profile"] = profile
            if not u_copy.get("upstream") and len(out["upstreams"]) == 1:
                u_copy["upstream"] = default_up_name
                changed = True
            if not u_copy.get("platforms"):
                u_copy["platforms"] = default_platforms_for_profile(profile)
                changed = True
            if "disabled" not in u_copy:
                u_copy["disabled"] = clean_user in disabled_legacy
                changed = True
            else:
                u_copy["disabled"] = bool(u_copy["disabled"])
            if "note" not in u_copy:
                u_copy["note"] = ""
            if "profile_version" not in u_copy:
                u_copy["profile_version"] = "v1"
            if "singbox_min_version" not in u_copy:
                u_copy["singbox_min_version"] = "1.14"
            if "profile_sha256" not in u_copy:
                u_copy["profile_sha256"] = ""
            if u_copy != uinfo or clean_user != uname:
                changed = True
            normalized_users[clean_user] = u_copy
        out["users"] = normalized_users

    out["schema_version"] = BRIDGE_STATE_SCHEMA_VERSION
    sync_legacy_bridge_fields(out)
    return out, changed


def validate_bridge_isolation(state: dict[str, Any]) -> list[str]:
    """Enforce ai-isolated single-owner, profile, and /24 subnet guards.

    Returns non-fatal operational warnings (e.g. shared root domain or overridden /24
    overlap) and raises ValueError on any hard isolation violation.
    """
    if state.get("mode") != "bridge":
        return []

    upstreams = state.get("upstreams")
    if not isinstance(upstreams, dict) or not upstreams:
        raise ValueError("Bridge state must define at least one upstream")

    normalized_upstreams: dict[str, dict[str, Any]] = {}
    for uname, uentry in upstreams.items():
        clean_uname = validate_upstream_name(uname)
        normalized_upstreams[clean_uname] = normalize_upstream_entry(uentry)

    users = state.get("users")
    if users is None:
        users = {}
    if not isinstance(users, dict):
        raise ValueError("Bridge state 'users' must be a mapping")

    seen_uuids: dict[str, str] = {}
    bound_by_upstream: dict[str, list[tuple[str, dict[str, Any]]]] = {
        uname: [] for uname in normalized_upstreams
    }

    for uname, uinfo in users.items():
        clean_user = validate_user_name(uname)
        if not isinstance(uinfo, dict):
            raise ValueError(f"User '{uname}' entry must be an object")
        uid = str(uinfo.get("uuid", "")).strip()
        if not uid:
            raise ValueError(f"User '{clean_user}' missing uuid")
        if uid in seen_uuids:
            raise ValueError(
                f"Duplicate UUID '{uid}' shared by '{seen_uuids[uid]}' and '{clean_user}'"
            )
        seen_uuids[uid] = clean_user

        profile = str(uinfo.get("profile", "")).strip().lower()
        if profile not in USER_PROFILES:
            raise ValueError(
                f"User '{clean_user}' has unsupported profile '{profile}'"
            )

        up_name = str(uinfo.get("upstream", "")).strip()
        if up_name not in normalized_upstreams:
            raise ValueError(
                f"User '{clean_user}' references unknown upstream '{up_name}'"
            )
        bound_by_upstream[up_name].append((clean_user, uinfo))

    # 1. Hard ai-isolated upstream guards (at most 1 ai-owner + ai-user users; reject media-selective)
    ai_upstreams: list[tuple[str, dict[str, Any]]] = []
    media_upstreams: list[tuple[str, dict[str, Any]]] = []

    for up_name, up_cfg in normalized_upstreams.items():
        if up_cfg["role"] == "ai-isolated":
            ai_upstreams.append((up_name, up_cfg))
            bound = bound_by_upstream[up_name]
            ai_owners: list[str] = []
            for bound_user, uinfo in bound:
                prof = str(uinfo.get("profile", "")).strip().lower()
                if prof not in {"ai-owner", "ai-user"}:
                    raise ValueError(
                        f"ai-isolated upstream '{up_name}' rejects '{prof}' user '{bound_user}'; "
                        "only 'ai-owner' and 'ai-user' are allowed"
                    )
                if prof == "ai-owner":
                    ai_owners.append(bound_user)
            if len(ai_owners) > 1:
                names = ", ".join(ai_owners)
                raise ValueError(
                    f"ai-isolated upstream '{up_name}' accepts at most 1 'ai-owner' user "
                    f"(got {len(ai_owners)}: {names})"
                )
        else:
            media_upstreams.append((up_name, up_cfg))

    # 2. Root-domain and /24 subnet isolation between ai-isolated and media upstreams
    warnings: list[str] = []
    for ai_name, ai_cfg in ai_upstreams:
        ai_root = extract_root_domain(ai_cfg["domain"])
        ai_net24 = ipv4_slash24(ai_cfg["ip"])
        for media_name, media_cfg in media_upstreams:
            media_root = extract_root_domain(media_cfg["domain"])
            if ai_root == media_root:
                warnings.append(
                    f"Shared root domain '{ai_root}' between ai-isolated upstream '{ai_name}' "
                    f"({ai_cfg['domain']}) and media upstream '{media_name}' ({media_cfg['domain']})"
                )
            media_net24 = ipv4_slash24(media_cfg["ip"])
            if ai_net24 == media_net24:
                overridden = bool(ai_cfg.get("allow_same_subnet")) or bool(
                    media_cfg.get("allow_same_subnet")
                )
                if not overridden:
                    raise ValueError(
                        f"/24 IPv4 subnet collision: ai-isolated upstream '{ai_name}' ({ai_cfg['ip']}) "
                        f"and media upstream '{media_name}' ({media_cfg['ip']}) share {ai_net24}; "
                        "use an exit in a distinct /24 subnet (or pass --allow-same-subnet to override)"
                    )
                warnings.append(
                    f"/24 subnet overlap overridden between '{ai_name}' and '{media_name}' ({ai_net24})"
                )

    return warnings
