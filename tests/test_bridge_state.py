import json
from pathlib import Path

import pytest

from app.bridge_state import (
    BRIDGE_STATE_SCHEMA_VERSION,
    atomic_write_json,
    extract_root_domain,
    ipv4_slash24,
    migrate_bridge_state_v1_to_v2,
    validate_bridge_isolation,
)
from app.cli import load_or_init_state, save_state
from app.xray.config_builder import generate_reality_keypair, generate_short_id


def _make_v1_bridge_state(tmp_path: Path) -> dict:
    priv, pub = generate_reality_keypair()
    _, up_pub = generate_reality_keypair()
    return {
        "mode": "bridge",
        "domain": "mos.example.net",
        "bridge_sni": "mos.example.net",
        "bridge_ip": "192.0.2.10",
        "bridge_acme_enabled": False,
        "upstream_ip": "203.0.113.10",
        "upstream_domain": "de1.exit-media.org",
        "upstream_uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "upstream_public_key": up_pub,
        "upstream_short_id": generate_short_id(),
        "upstream_transport": "xhttp",
        "upstream_xhttp_path": "a" * 64,
        "user_uuid": "11111111-1111-4111-8111-111111111111",
        "reality_private_key": priv,
        "reality_public_key": pub,
        "reality_short_id": generate_short_id(),
        "xhttp_secret_path": "f" * 64,
        "xhttp_backup_enabled": False,
        "decoy_mode": "preset",
        "decoy_target": "corporate",
        "entropy_seed": "0" * 48,
        "ipv6_egress_enabled": False,
    }


def test_v1_bridge_state_migration_and_atomic_save_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state_path = tmp_path / "state.json"
    v1 = _make_v1_bridge_state(tmp_path)
    state_path.write_text(json.dumps(v1, indent=2), encoding="utf-8")

    loaded = load_or_init_state(state_path)
    assert loaded["schema_version"] == BRIDGE_STATE_SCHEMA_VERSION
    assert loaded["reality_private_key"] == v1["reality_private_key"]
    assert loaded["reality_public_key"] == v1["reality_public_key"]
    assert loaded["reality_short_id"] == v1["reality_short_id"]
    assert loaded["bridge_sni"] == "mos.example.net"
    assert "default" in loaded["upstreams"]
    assert loaded["upstreams"]["default"]["ip"] == "203.0.113.10"
    assert loaded["upstreams"]["default"]["domain"] == "de1.exit-media.org"
    assert loaded["upstreams"]["default"]["transport"] == "xhttp"
    assert loaded["upstreams"]["default"]["xhttp_path"] == "a" * 64
    assert loaded["upstreams"]["default"]["role"] == "media"
    assert loaded["users"]["owner"]["uuid"] == v1["user_uuid"]
    assert loaded["users"]["owner"]["upstream"] == "default"
    assert loaded["users"]["owner"]["profile"] == "ai-owner"
    assert (tmp_path / "state.json.v1.bak").exists()

    # Subsequent load is idempotent
    loaded2, changed = migrate_bridge_state_v1_to_v2(loaded)
    assert changed is False
    assert loaded2 == loaded

    # Atomic write preserves original file intact if replace fails mid-save
    original_bytes = state_path.read_bytes()

    def _boom(src, dst):
        raise OSError("disk full simulated")

    monkeypatch.setattr("app.bridge_state.os.replace", _boom)
    with pytest.raises(OSError, match="disk full"):
        save_state(state_path, {"broken": True})
    assert state_path.read_bytes() == original_bytes
    # Temp file cleaned up on failure
    assert not list(tmp_path.glob(".state.json.*.tmp"))

    monkeypatch.undo()
    atomic_write_json(state_path, loaded)
    assert (state_path.stat().st_mode & 0o777) == 0o600


def test_bridge_isolation_guards_reject_violations_cleanly():
    _, pub_ai = generate_reality_keypair()
    _, pub_media = generate_reality_keypair()
    sid_ai = generate_short_id()
    sid_media = generate_short_id()

    base = {
        "mode": "bridge",
        "schema_version": 2,
        "upstreams": {
            "exit-ai": {
                "role": "ai-isolated",
                "ip": "203.0.113.10",
                "domain": "edge.ai-only.org",
                "uuid": "aaaaaaaa-1111-4111-8111-111111111111",
                "public_key": pub_ai,
                "short_id": sid_ai,
                "transport": "xhttp",
                "xhttp_path": "a" * 64,
            },
            "exit-media-1": {
                "role": "media",
                "ip": "198.51.100.20",
                "domain": "cdn.media-stream.net",
                "uuid": "bbbbbbbb-2222-4222-8222-222222222222",
                "public_key": pub_media,
                "short_id": sid_media,
                "transport": "xhttp",
                "xhttp_path": "b" * 64,
            },
        },
        "users": {
            "owner": {
                "uuid": "11111111-1111-4111-8111-111111111111",
                "upstream": "exit-ai",
                "profile": "ai-owner",
            },
            "alice": {
                "uuid": "22222222-2222-4222-8222-222222222222",
                "upstream": "exit-media-1",
                "profile": "media-selective",
            },
        },
    }
    assert validate_bridge_isolation(base) == []

    # 1. >1 user on ai-isolated
    too_many = json.loads(json.dumps(base))
    too_many["users"]["second-admin"] = {
        "uuid": "33333333-3333-4333-8333-333333333333",
        "upstream": "exit-ai",
        "profile": "ai-owner",
    }
    with pytest.raises(ValueError, match="at most 1 user"):
        validate_bridge_isolation(too_many)

    # 2. media-selective bound to ai-isolated
    wrong_profile = json.loads(json.dumps(base))
    wrong_profile["users"]["owner"]["profile"] = "media-selective"
    with pytest.raises(ValueError, match="only 'ai-owner'"):
        validate_bridge_isolation(wrong_profile)

    # 3. Root-domain collision (even across subdomains or multi-label TLDs)
    assert extract_root_domain("sub1.shared.co.uk") == "shared.co.uk"
    assert extract_root_domain("sub2.shared.co.uk") == "shared.co.uk"
    same_root = json.loads(json.dumps(base))
    same_root["upstreams"]["exit-media-1"]["domain"] = "media.ai-only.org"
    with pytest.raises(ValueError, match="Root-domain collision"):
        validate_bridge_isolation(same_root)

    # 4. /24 IPv4 subnet collision unless explicitly overridden
    assert ipv4_slash24("203.0.113.10") == "203.0.113.0/24"
    same_subnet = json.loads(json.dumps(base))
    same_subnet["upstreams"]["exit-media-1"]["ip"] = "203.0.113.99"
    with pytest.raises(ValueError, match="/24 IPv4 subnet collision"):
        validate_bridge_isolation(same_subnet)

    same_subnet["upstreams"]["exit-media-1"]["allow_same_subnet"] = True
    warnings = validate_bridge_isolation(same_subnet)
    assert len(warnings) == 1
    assert "203.0.113.0/24" in warnings[0]
