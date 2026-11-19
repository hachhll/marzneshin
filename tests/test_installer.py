import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "script.sh"


def _write_exec(directory: Path, name: str, body: str) -> None:
    p = directory / name
    p.write_text("#!/usr/bin/env bash\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def _setup_mock_bin(
    tmp_path: Path,
    *,
    uid: str = "0",
    ntp_synced: str = "yes",
    ss_out: str = "",
    resolved_ip: str = "203.0.113.10",
    public_ip: str = "203.0.113.10",
    youtube_gl: str = "DE",
    openai_loc: str = "DE",
    openai_warp: str = "off",
) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    curl_log = tmp_path / "curl.log"

    _write_exec(
        bin_dir,
        "id",
        f'if [ "${{1:-}}" = "-u" ]; then echo "{uid}"; else /usr/bin/id "$@"; fi\n',
    )
    _write_exec(bin_dir, "timedatectl", f'echo "{ntp_synced}"\n')
    _write_exec(bin_dir, "ss", f"cat <<'EOF'\n{ss_out}\nEOF\n")
    _write_exec(bin_dir, "dig", f'echo "{resolved_ip}"\n')
    _write_exec(bin_dir, "docker", 'echo "Docker Compose version v2.27.0"\n')
    _write_exec(bin_dir, "ufw", 'echo "Status: inactive"\n')
    _write_exec(
        bin_dir,
        "curl",
        f'''
echo "$@" >> "{curl_log}"
case "$*" in
  *api.ipify.org*)
    echo "{public_ip}"
    ;;
  *youtube.com*)
    echo '{{"INNERTUBE_CONTEXT_GL":"{youtube_gl}"}}'
    ;;
  *chatgpt.com/cdn-cgi/trace*)
    printf "fl=1\\nloc={openai_loc}\\nwarp={openai_warp}\\n"
    ;;
  *api.anthropic.com*)
    echo '{{"type":"error","error":{{"type":"not_found_error"}}}}'
    ;;
esac
''',
    )
    return bin_dir, curl_log


def _run_installer(
    bin_dir: Path, args: list[str], extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:/usr/bin:/bin"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(SCRIPT_PATH), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_installer_bash_syntax_and_optional_shellcheck():
    res = subprocess.run(
        ["bash", "-n", str(SCRIPT_PATH)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stderr
    if shutil.which("shellcheck"):
        sc = subprocess.run(
            ["shellcheck", str(SCRIPT_PATH)], capture_output=True, text=True
        )
        assert sc.returncode == 0, sc.stdout + sc.stderr


def test_installer_dry_run_succeeds_and_omits_ru_headers(tmp_path: Path):
    bin_dir, curl_log = _setup_mock_bin(tmp_path, youtube_gl="NL")
    res = _run_installer(
        bin_dir,
        ["--domain", "vpn.example.com", "--dry-run"],
        extra_env={"SSH_CONNECTION": "198.51.100.1 54321 203.0.113.10 2222"},
    )
    assert res.returncode == 0, res.stderr
    assert "Zero-Surface SSH mode" in res.stdout
    assert "2222" in res.stdout
    assert "SSH hardening would create sudo user 'stealth', move SSH to port 22222/tcp" in res.stdout
    assert "/setup?token=" not in res.stdout
    logged_headers = curl_log.read_text().lower()
    assert "ru-ru" not in logged_headers
    assert "yandex" not in logged_headers


def test_installer_blocks_risky_xyz_tld_by_default(tmp_path: Path):
    bin_dir, _ = _setup_mock_bin(tmp_path, youtube_gl="DE")
    res = _run_installer(
        bin_dir, ["--domain", "risky-test.example.xyz", "--dry-run"]
    )
    assert res.returncode != 0
    assert "high-risk abused TLD '.xyz'" in res.stderr

    # Overrides with --allow-risky-tld
    res_allow = _run_installer(
        bin_dir,
        [
            "--domain",
            "risky-test.example.xyz",
            "--allow-risky-tld",
            "--dry-run",
        ],
    )
    assert res_allow.returncode == 0, res_allow.stderr


def test_installer_aborts_on_gl_ru_or_openai_warp(tmp_path: Path):
    bin_dir, _ = _setup_mock_bin(tmp_path, youtube_gl="RU")
    res = _run_installer(bin_dir, ["--domain", "vpn.example.com", "--dry-run"])
    assert res.returncode != 0
    assert "INNERTUBE_CONTEXT_GL=RU" in res.stderr

    bin_dir2, _ = _setup_mock_bin(
        tmp_path / "w", youtube_gl="DE", openai_warp="on"
    )
    res2 = _run_installer(
        bin_dir2, ["--domain", "vpn.example.com", "--dry-run"]
    )
    assert res2.returncode != 0
    assert "warp=on" in res2.stderr


def test_installer_aborts_on_port_conflict(tmp_path: Path):
    bin_dir, _ = _setup_mock_bin(
        tmp_path,
        ss_out='tcp   LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=123,fd=6))',
    )
    res = _run_installer(bin_dir, ["--domain", "vpn.example.com", "--dry-run"])
    assert res.returncode != 0
    assert "Ports 80 and 443 must be free" in res.stderr

    # When marzneshin-xray / marzneshin-nginx are already running, re-running script.sh succeeds idempotently
    _write_exec(
        bin_dir,
        "docker",
        '''if [ "${1:-}" = "ps" ]; then
  echo "marzneshin-xray"
  echo "marzneshin-nginx"
else
  echo "Docker Compose version v2.27.0"
fi
''',
    )
    res_rerun = _run_installer(
        bin_dir, ["--domain", "vpn.example.com", "--dry-run"]
    )
    assert res_rerun.returncode == 0, res_rerun.stderr


@pytest.mark.parametrize(
    "bad_ip,expected_msg",
    [
        ("198.51.100.99", "expected server public IP"),
        ("104.16.10.5", "CDN proxy IP"),
    ],
)
def test_installer_aborts_on_mismatched_or_cdn_dns(
    tmp_path: Path, bad_ip: str, expected_msg: str
):
    bin_dir, _ = _setup_mock_bin(
        tmp_path, public_ip="203.0.113.10", resolved_ip=bad_ip
    )
    res = _run_installer(bin_dir, ["--domain", "vpn.example.com", "--dry-run"])
    assert res.returncode != 0
    assert expected_msg in res.stderr


def test_ssh_cli_subcommands_status_xhttp_rotate_decoy(tmp_path: Path):
    data_dir = tmp_path / "data"
    creds_dir = tmp_path / "creds"
    bin_dir, _ = _setup_mock_bin(tmp_path)
    extra = {
        "MARZNESHIN_DATA_DIR": str(data_dir),
        "VPN_CREDENTIALS_DIR": str(creds_dir),
        "XRAY_CONFIG_PATH": str(data_dir / "xray" / "config.json"),
        "NGINX_RUNTIME_DIR": str(data_dir / "nginx-runtime"),
    }

    # Initialize via Python CLI
    from app.cli import main as cli_main

    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "init",
                "--domain",
                "vpn.example.com",
            ]
        )
        == 0
    )

    # 1. script.sh status (does not recreate reload.trigger if unlinked)
    trigger_file = data_dir / "nginx-runtime" / "reload.trigger"
    if trigger_file.exists():
        trigger_file.unlink()
    st = _run_installer(bin_dir, ["status"], extra_env=extra)
    assert st.returncode == 0, st.stderr
    assert "vless://" in st.stdout
    assert "throne-windows11.json" in st.stdout
    assert (creds_dir / "throne-windows11.json").exists()
    assert (creds_dir / "android-singbox.json").exists()
    assert not trigger_file.exists()

    # 1b. script.sh decoy blog + re-running init without --decoy preserves 'blog'
    dec = _run_installer(bin_dir, ["decoy", "blog"], extra_env=extra)
    assert dec.returncode == 0, dec.stderr
    assert json.loads((data_dir / "state.json").read_text())["decoy_target"] == "blog"
    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "init",
                "--domain",
                "vpn.example.com",
            ]
        )
        == 0
    )
    assert json.loads((data_dir / "state.json").read_text())["decoy_target"] == "blog"

    # 2. script.sh xhttp on / off preserves secret path
    state_before = json.loads((data_dir / "state.json").read_text())
    x_on = _run_installer(bin_dir, ["xhttp", "on"], extra_env=extra)
    assert x_on.returncode == 0, x_on.stderr
    assert "Backup VLESS (XHTTP + TLS) [ENABLED]" in x_on.stdout
    app_conf_on = (
        data_dir / "nginx-runtime" / "conf.d" / "appliance.conf"
    ).read_text()
    assert f"location /{state_before['xhttp_secret_path']}" in app_conf_on

    x_off = _run_installer(bin_dir, ["xhttp", "off"], extra_env=extra)
    assert x_off.returncode == 0, x_off.stderr
    state_after_toggle = json.loads((data_dir / "state.json").read_text())
    assert (
        state_after_toggle["xhttp_secret_path"]
        == state_before["xhttp_secret_path"]
    )

    # 3. script.sh rotate generates new UUID, shortId, and XHTTP path
    rot = _run_installer(bin_dir, ["rotate"], extra_env=extra)
    assert rot.returncode == 0, rot.stderr
    state_rot = json.loads((data_dir / "state.json").read_text())
    assert state_rot["user_uuid"] != state_before["user_uuid"]
    assert state_rot["reality_short_id"] != state_before["reality_short_id"]
    assert state_rot["xhttp_secret_path"] != state_before["xhttp_secret_path"]


def test_bridge_mode_zero_emission_installer_and_cli(tmp_path: Path):
    bin_dir, curl_log = _setup_mock_bin(tmp_path, youtube_gl="RU")
    # Mock local kernel routing table lookup (`ip -4 route get 1.1.1.1`)
    _write_exec(
        bin_dir,
        "ip",
        'echo "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.20 uid 0"\n',
    )

    # 1. Dry-run in --bridge mode on a Russian server (where youtube_gl="RU" would abort exit mode)
    # MUST succeed and emit ZERO curl calls!
    res = _run_installer(
        bin_dir,
        [
            "--bridge",
            "--upstream-ip",
            "203.0.113.20",
            "--upstream-domain",
            "exit.example.com",
            "--upstream-uuid",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "--upstream-pbk",
            "PubKeyExitExample1234567890",
            "--upstream-sid",
            "0123456789abcdef",
            "--dry-run",
        ],
    )
    assert res.returncode == 0, res.stderr
    assert "Cascade Bridge (192.0.2.20 -> 203.0.113.20:443, SNI=exit.example.com, Zero-Emission mode)" in res.stdout
    assert not curl_log.exists(), "Zero-Emission violated: curl was invoked during --bridge setup!"

    # 2. Initialize Bridge state via CLI and verify fail-closed Xray config + client profiles
    data_dir = tmp_path / "bridge_data"
    creds_dir = tmp_path / "bridge_creds"
    extra = {
        "MARZNESHIN_DATA_DIR": str(data_dir),
        "VPN_CREDENTIALS_DIR": str(creds_dir),
        "XRAY_CONFIG_PATH": str(data_dir / "xray" / "config.json"),
        "NGINX_RUNTIME_DIR": str(data_dir / "nginx-runtime"),
    }
    from app.cli import main as cli_main
    from app.xray.config_builder import validate_xray_config

    assert (
        cli_main(
            [
                "--data-dir",
                str(data_dir),
                "--credentials-dir",
                str(creds_dir),
                "init-bridge",
                "--upstream-ip",
                "203.0.113.20",
                "--upstream-domain",
                "exit.example.com",
                "--upstream-uuid",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "--upstream-pbk",
                "PubKeyExitExample1234567890",
                "--upstream-sid",
                "0123456789abcdef",
                "--bridge-sni",
                "exit.example.com",
                "--bridge-ip",
                "192.0.2.20",
            ]
        )
        == 0
    )

    xray_cfg = json.loads((data_dir / "xray" / "config.json").read_text())
    validate_xray_config(xray_cfg, mode="bridge")
    out_tags = {o["tag"] for o in xray_cfg["outbounds"]}
    assert out_tags == {"proxy", "block"}
    assert "direct" not in out_tags

    st = _run_installer(bin_dir, ["status"], extra_env=extra)
    assert st.returncode == 0, st.stderr
    assert "@192.0.2.20:443?" in st.stdout
    assert "sni=exit.example.com" in st.stdout
    assert "ZERO-LOOP VLESS CASCADE BRIDGE (192.0.2.20 -> exit.example.com)" in st.stdout
    assert "Frankfurt Exit:   203.0.113.20:443" in st.stdout
    assert "transport=vision" in st.stdout
    assert not curl_log.exists()

    # Switch bridge transport to xhttp and roll back to vision via script.sh bridge-transport
    bt_xhttp = _run_installer(
        bin_dir,
        ["bridge-transport", "xhttp", "--path", "d" * 64],
        extra_env=extra,
    )
    assert bt_xhttp.returncode == 0, bt_xhttp.stderr
    assert "transport=xhttp+reality+xmux" in bt_xhttp.stdout
    xray_cfg_xhttp = json.loads((data_dir / "xray" / "config.json").read_text())
    validate_xray_config(xray_cfg_xhttp, mode="bridge")
    assert xray_cfg_xhttp["outbounds"][0]["streamSettings"]["network"] == "xhttp"
    assert (
        xray_cfg_xhttp["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"]
        == "/" + ("d" * 64)
    )

    bt_vision = _run_installer(
        bin_dir,
        ["bridge-transport", "vision"],
        extra_env=extra,
    )
    assert bt_vision.returncode == 0, bt_vision.stderr
    assert "transport=vision" in bt_vision.stdout
    xray_cfg_vision = json.loads((data_dir / "xray" / "config.json").read_text())
    validate_xray_config(xray_cfg_vision, mode="bridge")
    assert xray_cfg_vision["outbounds"][0]["streamSettings"]["network"] == "tcp"

    # 3. --bridge-acme rejects reusing upstream domain as bridge SNI and accepts independent FQDN
    res_bad_acme = _run_installer(
        bin_dir,
        [
            "--bridge",
            "--upstream-ip",
            "203.0.113.20",
            "--upstream-domain",
            "exit.example.com",
            "--upstream-uuid",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "--upstream-pbk",
            "PubKeyExitExample1234567890",
            "--upstream-sid",
            "0123456789abcdef",
            "--bridge-acme",
            "--dry-run",
        ],
    )
    assert res_bad_acme.returncode != 0
    assert "independent --bridge-sni" in res_bad_acme.stderr

    bin_acme, _ = _setup_mock_bin(tmp_path / "acme_case", resolved_ip="192.0.2.20")
    _write_exec(
        bin_acme,
        "ip",
        'echo "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.20 uid 0"\n',
    )
    res_ok_acme = _run_installer(
        bin_acme,
        [
            "--bridge",
            "--upstream-ip",
            "203.0.113.20",
            "--upstream-domain",
            "exit.example.com",
            "--upstream-uuid",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "--upstream-pbk",
            "PubKeyExitExample1234567890",
            "--upstream-sid",
            "0123456789abcdef",
            "--bridge-sni",
            "edge.bridge-example.net",
            "--bridge-acme",
            "--dry-run",
        ],
    )
    assert res_ok_acme.returncode == 0, res_ok_acme.stderr
    assert "SNI=edge.bridge-example.net, ACME TLS mode" in res_ok_acme.stdout

