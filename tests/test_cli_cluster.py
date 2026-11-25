"""Unit tests for Zero-Surface SSH CLI upstream and user lifecycle management."""

import json
import os
import subprocess
from pathlib import Path

from app.cli import main as cli_main
from app.xray.config_builder import (
    generate_reality_keypair,
    generate_short_id,
    validate_xray_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _init_sample_bridge(data_dir: Path, creds_dir: Path) -> dict:
    _, pub1 = generate_reality_keypair()
    sid1 = generate_short_id()
    rc = cli_main(
        [
            "--data-dir",
            str(data_dir),
            "--credentials-dir",
            str(creds_dir),
            "init-bridge",
            "--upstream-ip",
            "198.51.100.10",
            "--upstream-domain",
            "de1.media-edge.net",
            "--upstream-uuid",
            "aaaaaaaa-1111-4111-8111-111111111111",
            "--upstream-pbk",
            pub1,
            "--upstream-sid",
            sid1,
            "--bridge-sni",
            "mos.bridge-gateway.org",
            "--bridge-ip",
            "192.0.2.50",
            "--upstream-transport",
            "xhttp",
            "--upstream-xhttp-path",
            "a" * 64,
        ]
    )
    assert rc == 0
    return json.loads((data_dir / "state.json").read_text(encoding="utf-8"))


def test_cli_upstream_lifecycle_isolation_and_migrate(
    tmp_path: Path, capsys
):
    data_dir = tmp_path / "data"
    creds_dir = tmp_path / "creds"
    _init_sample_bridge(data_dir, creds_dir)
    capsys.readouterr()

    state_path = data_dir / "state.json"
    xray_cfg_path = data_dir / "xray" / "config.json"

    _, pub_ai = generate_reality_keypair()
    sid_ai = generate_short_id()

    # 1. Shared root domain between ai-isolated and default media upstream -> allowed with warning
    rc_shared_dom = cli_main(
        [
            "--data-dir",
            str(data_dir),
            "--credentials-dir",
            str(creds_dir),
            "upstream",
            "add",
            "exit-ai-shared",
            "--role",
            "ai-isolated",
            "--ip",
            "203.0.113.10",
            "--domain",
            "ai.media-edge.net",
            "--uuid",
            "bbbbbbbb-2222-4222-8222-222222222222",
            "--pbk",
            pub_ai,
            "--sid",
            sid_ai,
            "--transport",
            "xhttp",
            "--xhttp-path",
            "b" * 64,
        ]
    )
    assert rc_shared_dom == 0
    out_shared = capsys.readouterr()
    assert "Shared root domain" in out_shared.err
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "upstream",
                "remove",
                "exit-ai-shared",
            ]
        )
        == 0
    )
    capsys.readouterr()

    # 2. Negative: /24 subnet overlap with default media upstream -> non-zero & unchanged state
    snap_state = state_path.read_text(encoding="utf-8")
    snap_xray = xray_cfg_path.read_text(encoding="utf-8")
    rc_bad_sub = cli_main(
        [
            "--data-dir",
            str(data_dir),
            "--credentials-dir",
            str(creds_dir),
            "upstream",
            "add",
            "exit-ai",
            "--role",
            "ai-isolated",
            "--ip",
            "198.51.100.99",
            "--domain",
            "node.ai-dedicated.org",
            "--uuid",
            "bbbbbbbb-2222-4222-8222-222222222222",
            "--pbk",
            pub_ai,
            "--sid",
            sid_ai,
            "--transport",
            "xhttp",
            "--xhttp-path",
            "b" * 64,
        ]
    )
    assert rc_bad_sub == 1
    assert state_path.read_text(encoding="utf-8") == snap_state
    assert xray_cfg_path.read_text(encoding="utf-8") == snap_xray
    capsys.readouterr()

    # 3. Positive: add clean exit-ai (distinct domain + distinct /24) and exit-media-2
    rc_ai = cli_main(
        [
            "--data-dir",
            str(data_dir),
            "--credentials-dir",
            str(creds_dir),
            "upstream",
            "add",
            "exit-ai",
            "--role",
            "ai-isolated",
            "--ip",
            "203.0.113.10",
            "--domain",
            "node.ai-dedicated.org",
            "--uuid",
            "bbbbbbbb-2222-4222-8222-222222222222",
            "--pbk",
            pub_ai,
            "--sid",
            sid_ai,
            "--transport",
            "xhttp",
            "--xhttp-path",
            "b" * 64,
        ]
    )
    assert rc_ai == 0
    capsys.readouterr()

    _, pub_m2 = generate_reality_keypair()
    rc_m2 = cli_main(
        [
            "--data-dir",
            str(data_dir),
            "--credentials-dir",
            str(creds_dir),
            "upstream",
            "add",
            "exit-media-2",
            "--role",
            "media",
            "--ip",
            "198.18.10.20",
            "--domain",
            "edge2.media-backup.net",
            "--uuid",
            "cccccccc-3333-4333-8333-333333333333",
            "--pbk",
            pub_m2,
            "--sid",
            generate_short_id(),
            "--transport",
            "xhttp",
            "--xhttp-path",
            "c" * 64,
        ]
    )
    assert rc_m2 == 0
    capsys.readouterr()

    # upstream list reports all 3 upstreams
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "upstream",
                "list",
                "--json",
            ]
        )
        == 0
    )
    listed = json.loads(capsys.readouterr().out)
    assert set(listed.keys()) == {"default", "exit-ai", "exit-media-2"}
    assert listed["default"]["bound_users"] == ["owner"]

    # 4. upstream remove default MUST refuse while 'owner' is still bound
    rc_rm_busy = cli_main(
        [
            "--data-dir",
            str(data_dir),
            "--credentials-dir",
            str(creds_dir),
            "upstream",
            "remove",
            "default",
        ]
    )
    assert rc_rm_busy == 1
    assert "bound users exist" in capsys.readouterr().err

    # 5. upstream migrate default -> exit-media-2 preserves UUID and re-renders Xray atomically
    before_owner_uuid = json.loads(state_path.read_text())["users"]["owner"]["uuid"]
    rc_mig = cli_main(
        [
            "--data-dir",
            str(data_dir),
            "--credentials-dir",
            str(creds_dir),
            "upstream",
            "migrate",
            "default",
            "exit-media-2",
        ]
    )
    assert rc_mig == 0
    mig_out = json.loads(capsys.readouterr().out)
    assert mig_out["migrated_users"] == ["owner"]
    state_after_mig = json.loads(state_path.read_text())
    assert state_after_mig["users"]["owner"]["uuid"] == before_owner_uuid
    assert state_after_mig["users"]["owner"]["upstream"] == "exit-media-2"
    xray_cfg = json.loads(xray_cfg_path.read_text())
    validate_xray_config(xray_cfg, mode="bridge")
    assert any(
        r.get("user") == ["owner"] and r.get("outboundTag") == "proxy-exit-media-2"
        for r in xray_cfg["routing"]["rules"]
    )

    # 6. Now 'default' has 0 bound users -> upstream remove default succeeds
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "upstream",
                "remove",
                "default",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert "default" not in json.loads(state_path.read_text())["upstreams"]


def test_cli_user_add_show_assign_remove_and_script_sh(tmp_path: Path, capsys):
    data_dir = tmp_path / "data"
    creds_dir = tmp_path / "creds"
    _init_sample_bridge(data_dir, creds_dir)
    capsys.readouterr()

    state_path = data_dir / "state.json"
    xray_cfg_path = data_dir / "xray" / "config.json"

    _, pub_ai = generate_reality_keypair()
    _, pub_m2 = generate_reality_keypair()
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "upstream",
                "add",
                "exit-ai",
                "--role",
                "ai-isolated",
                "--ip",
                "203.0.113.10",
                "--domain",
                "node.ai-dedicated.org",
                "--uuid",
                "bbbbbbbb-2222-4222-8222-222222222222",
                "--pbk",
                pub_ai,
                "--sid",
                generate_short_id(),
                "--transport",
                "xhttp",
                "--xhttp-path",
                "b" * 64,
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "upstream",
                "add",
                "exit-media-2",
                "--role",
                "media",
                "--ip",
                "198.18.10.20",
                "--domain",
                "edge2.media-backup.net",
                "--uuid",
                "cccccccc-3333-4333-8333-333333333333",
                "--pbk",
                pub_m2,
                "--sid",
                generate_short_id(),
                "--transport",
                "xhttp",
                "--xhttp-path",
                "c" * 64,
            ]
        )
        == 0
    )
    capsys.readouterr()

    # 1. user add admin-ai -> exit-ai (auto-infers ai-owner)
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "add",
                "admin-ai",
                "--upstream",
                "exit-ai",
            ]
        )
        == 0
    )
    add_ai_out = json.loads(capsys.readouterr().out)
    assert len(add_ai_out["profile_sha256"]) == 64
    ai_bundle = creds_dir / "users" / "admin-ai"
    assert (ai_bundle / "ios-singbox.json").exists()
    assert (ai_bundle / "openwrt-outbound.json").exists()
    assert (ai_bundle / "links.txt").exists()

    # 2. Negative: adding second ai-owner OR media-selective user to exit-ai -> rejected with state unchanged
    snap_state = state_path.read_text(encoding="utf-8")
    snap_xray = xray_cfg_path.read_text(encoding="utf-8")
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "add",
                "bob",
                "--upstream",
                "exit-ai",
            ]
        )
        == 1
    )
    assert state_path.read_text(encoding="utf-8") == snap_state
    assert xray_cfg_path.read_text(encoding="utf-8") == snap_xray
    assert not (creds_dir / "users" / "bob").exists()
    capsys.readouterr()

    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "add",
                "bob-media",
                "--upstream",
                "exit-ai",
                "--profile",
                "media-selective",
            ]
        )
        == 1
    )
    assert state_path.read_text(encoding="utf-8") == snap_state
    assert xray_cfg_path.read_text(encoding="utf-8") == snap_xray
    assert not (creds_dir / "users" / "bob-media").exists()
    capsys.readouterr()

    # 2b. Positive: adding ai-user ('worknode') alongside ai-owner ('admin-ai') on exit-ai succeeds
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "add",
                "worknode",
                "--upstream",
                "exit-ai",
                "--profile",
                "ai-user",
            ]
        )
        == 0
    )
    worknode_out = json.loads(capsys.readouterr().out)
    assert worknode_out["user"] == "worknode"
    assert len(worknode_out["profile_sha256"]) == 64
    worknode_dir = creds_dir / "users" / "worknode"
    assert sorted(p.name for p in worknode_dir.iterdir()) == [
        "bundle-manifest.json",
        "linux-ai-user.json",
    ]
    assert not (worknode_dir / "links.txt").exists()
    xray_with_worknode = json.loads(xray_cfg_path.read_text(encoding="utf-8"))
    validate_xray_config(xray_with_worknode, mode="bridge")
    assert xray_with_worknode["routing"]["domainStrategy"] == "AsIs"
    assert any(
        "worknode" in r.get("user", [])
        and "admin-ai" in r.get("user", [])
        and r.get("outboundTag") == "proxy-exit-ai"
        for r in xray_with_worknode["routing"]["rules"]
    )
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "show",
                "worknode",
            ]
        )
        == 0
    )
    worknode_show = capsys.readouterr().out
    assert "ai-user" in worknode_show
    assert "Raw VLESS: omitted" in worknode_show

    # 3. user add alice -> default (media-selective, mobile-only, NO links.txt)
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "add",
                "alice",
                "--upstream",
                "default",
            ]
        )
        == 0
    )
    capsys.readouterr()
    alice_dir = creds_dir / "users" / "alice"
    assert (alice_dir / "android-media-selective.json").exists()
    assert (alice_dir / "ios-media-selective.json").exists()
    assert not (alice_dir / "links.txt").exists()

    # user show & user list
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "show",
                "alice",
            ]
        )
        == 0
    )
    show_out = capsys.readouterr().out
    assert "media-selective" in show_out
    assert "Raw VLESS: omitted" in show_out

    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "list",
            ]
        )
        == 0
    )
    list_out = capsys.readouterr().out
    assert "admin-ai:" in list_out
    assert "alice:" in list_out

    # 4. Negative: user assign alice -> exit-ai MUST reject and leave state/xray untouched
    snap_state2 = state_path.read_text(encoding="utf-8")
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "assign",
                "alice",
                "exit-ai",
            ]
        )
        == 1
    )
    assert state_path.read_text(encoding="utf-8") == snap_state2
    capsys.readouterr()

    # 5. Positive: user assign alice -> exit-media-2 preserves alice UUID
    alice_uuid_before = json.loads(state_path.read_text())["users"]["alice"]["uuid"]
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "assign",
                "alice",
                "exit-media-2",
            ]
        )
        == 0
    )
    capsys.readouterr()
    state_after_assign = json.loads(state_path.read_text())
    assert state_after_assign["users"]["alice"]["uuid"] == alice_uuid_before
    assert state_after_assign["users"]["alice"]["upstream"] == "exit-media-2"

    # 6. script.sh wrapper works for read-only 'upstream list' & 'user show', and 'user remove alice' cleans up bundle
    env = os.environ.copy()
    env.update(
        {
            "MARZNESHIN_DATA_DIR": str(data_dir),
            "VPN_CREDENTIALS_DIR": str(creds_dir),
            "XRAY_CONFIG_PATH": str(xray_cfg_path),
            "NGINX_RUNTIME_DIR": str(data_dir / "nginx-runtime"),
        }
    )
    sh_list = subprocess.run(
        ["bash", str(REPO_ROOT / "script.sh"), "upstream", "list"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert sh_list.returncode == 0, sh_list.stderr
    assert "exit-ai:" in sh_list.stdout

    sh_rm = subprocess.run(
        ["bash", str(REPO_ROOT / "script.sh"), "user", "remove", "alice"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert sh_rm.returncode == 0, sh_rm.stderr
    assert not alice_dir.exists()
    final_state = json.loads(state_path.read_text())
    assert "alice" not in final_state["users"]
    assert "admin-ai" in final_state["users"]
    assert "owner" in final_state["users"]


def test_cli_user_refresh_preserves_uuid_and_updates_stale_bundles(tmp_path: Path, capsys):
    data_dir = tmp_path / "data"
    creds_dir = tmp_path / "creds"
    _init_sample_bridge(data_dir, creds_dir)
    capsys.readouterr()

    state_path = data_dir / "state.json"
    xray_cfg_path = data_dir / "xray" / "config.json"

    _, pub_m = generate_reality_keypair()
    sid_m = generate_short_id()
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "upstream",
                "add",
                "exit-media-1",
                "--role",
                "media",
                "--ip",
                "203.0.113.20",
                "--domain",
                "media1.example.net",
                "--uuid",
                "bbbbbbbb-2222-4222-8222-222222222222",
                "--pbk",
                pub_m,
                "--sid",
                sid_m,
                "--transport",
                "xhttp",
                "--xhttp-path",
                "b" * 64,
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "add",
                "alice",
                "--upstream",
                "exit-media-1",
            ]
        )
        == 0
    )
    capsys.readouterr()

    state_before = json.loads(state_path.read_text(encoding="utf-8"))
    alice_uuid = state_before["users"]["alice"]["uuid"]
    alice_sha = state_before["users"]["alice"]["profile_sha256"]
    owner_sha = state_before["users"]["owner"]["profile_sha256"]
    xray_before = xray_cfg_path.read_text(encoding="utf-8")

    # Simulate outdated on-disk bundles & sha256 metadata prior to refresh
    alice_ios = creds_dir / "users" / "alice" / "ios-media-selective.json"
    alice_ios.write_text('{"stale": true}\n', encoding="utf-8")
    owner_ios = creds_dir / "users" / "owner" / "ios-singbox-selective.json"
    owner_ios.write_text('{"stale": true}\n', encoding="utf-8")
    state_before["users"]["alice"]["profile_sha256"] = "0" * 64
    state_before["users"]["owner"]["profile_sha256"] = "0" * 64
    state_path.write_text(json.dumps(state_before, indent=2) + "\n", encoding="utf-8")

    # 1. Single-user refresh updates only alice without touching owner or xray/config.json
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "refresh",
                "alice",
                "--json",
            ]
        )
        == 0
    )
    ref_single = json.loads(capsys.readouterr().out)
    assert ref_single["action"] == "user-refresh"
    assert [r["user"] for r in ref_single["refreshed"]] == ["alice"]
    state_mid = json.loads(state_path.read_text(encoding="utf-8"))
    assert state_mid["users"]["alice"]["uuid"] == alice_uuid
    assert state_mid["users"]["alice"]["upstream"] == "exit-media-1"
    assert state_mid["users"]["alice"]["profile_sha256"] == alice_sha
    assert state_mid["users"]["owner"]["profile_sha256"] == "0" * 64
    assert "antigravity.google" in alice_ios.read_text(encoding="utf-8")
    assert owner_ios.read_text(encoding="utf-8") == '{"stale": true}\n'
    assert xray_cfg_path.read_text(encoding="utf-8") == xray_before

    # 2. --all via script.sh refreshes remaining users too without touching UUIDs or Xray
    env = os.environ.copy()
    env.update(
        {
            "MARZNESHIN_DATA_DIR": str(data_dir),
            "VPN_CREDENTIALS_DIR": str(creds_dir),
            "XRAY_CONFIG_PATH": str(xray_cfg_path),
            "NGINX_RUNTIME_DIR": str(data_dir / "nginx-runtime"),
        }
    )
    sh_ref = subprocess.run(
        ["bash", str(REPO_ROOT / "script.sh"), "user", "refresh", "--all"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert sh_ref.returncode == 0, sh_ref.stderr
    assert "alice:" in sh_ref.stdout
    assert "owner:" in sh_ref.stdout
    state_after = json.loads(state_path.read_text(encoding="utf-8"))
    owner_manifest = json.loads(
        (creds_dir / "users" / "owner" / "bundle-manifest.json").read_text(encoding="utf-8")
    )
    assert len(state_after["users"]["owner"]["profile_sha256"]) == 64
    assert state_after["users"]["owner"]["profile_sha256"] == owner_manifest["bundle_sha256"]
    assert "groq.com" in owner_ios.read_text(encoding="utf-8")
    assert xray_cfg_path.read_text(encoding="utf-8") == xray_before

    # 3. Negative cases: unknown user or invalid flag combination
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "refresh",
                "nonexistent-user",
            ]
        )
        == 1
    )
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "user",
                "refresh",
            ]
        )
        == 1
    )
    capsys.readouterr()
