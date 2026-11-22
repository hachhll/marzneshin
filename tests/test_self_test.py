import json
from pathlib import Path

import httpx
import pytest

from app.nginx.manager import NginxManager
from app.utils import self_test
from app.xray.config_builder import (
    LocalXrayConfigBuilder,
    generate_reality_keypair,
    generate_short_id,
)


def test_xray_config_safety_pass_and_fail(tmp_path: Path):
    priv, _ = generate_reality_keypair()
    cfg = LocalXrayConfigBuilder.build(
        domain="vpn.example.com",
        reality_private_key=priv,
        reality_short_ids=[generate_short_id()],
        clients=[],
    )
    cfg_path = tmp_path / "xray.json"
    cfg_path.write_text(json.dumps(cfg))

    ok = self_test.check_xray_config_safety(str(cfg_path))
    assert ok.passed is True

    # Mutate loglevel to warning -> fails
    bad = json.loads(cfg_path.read_text())
    bad["log"]["loglevel"] = "warning"
    bad_path = tmp_path / "bad_xray.json"
    bad_path.write_text(json.dumps(bad))
    fail = self_test.check_xray_config_safety(str(bad_path))
    assert fail.passed is False


def test_nginx_logging_and_tls_pass_and_fail(tmp_path: Path):
    mgr = NginxManager(runtime_dir=str(tmp_path), webroot_dir=str(tmp_path / "webroot"))
    mgr.apply(
        domain="vpn.example.com",
        validate_binary=False,
    )
    ok = self_test.check_nginx_logging_and_tls_conf(str(tmp_path))
    assert ok.passed is True

    # Replace access_log off -> fails
    app_conf = tmp_path / "conf.d" / "appliance.conf"
    app_conf.write_text(app_conf.read_text().replace("access_log off;", "access_log /tmp/a.log;"))
    (tmp_path / "nginx.conf").write_text(
        (tmp_path / "nginx.conf").read_text().replace("access_log off;", "")
    )
    fail = self_test.check_nginx_logging_and_tls_conf(str(tmp_path))
    assert fail.passed is False
    assert "access_log off" in fail.detail


def test_forbidden_processes_pass_and_fail():
    clean = [["/usr/local/bin/xray", "run"], ["nginx", "-g", "daemon off;"]]
    assert self_test.scan_forbidden_processes(clean).passed is True

    for proc in (["wg-quick", "up", "wg0"], ["/usr/bin/warp-svc"], ["/usr/bin/tor"]):
        res = self_test.scan_forbidden_processes(clean + [proc])
        assert res.passed is False
        assert "Forbidden overlay/tunnel process" in res.detail


def test_exposed_ports_pass_and_fail(monkeypatch: pytest.MonkeyPatch):
    # Loopback 10085, 8443 + external 80, 443, 22 -> PASS
    tcp_ok = [
        "0: 00000000:0050 00000000:0000 0A",  # 0.0.0.0:80
        "1: 00000000:01BB 00000000:0000 0A",  # 0.0.0.0:443
        "2: 00000000:0016 00000000:0000 0A",  # 0.0.0.0:22
        "3: 0100007F:20FB 00000000:0000 0A",  # 127.0.0.1:8443
        "4: 0100007F:2765 00000000:0000 0A",  # 127.0.0.1:10085
    ]
    assert self_test.check_exposed_ports(proc_tcp_lines=tcp_ok, proc_tcp6_lines=[]).passed is True

    # Multi-port SSH_PORT="22 2222" allows custom SSH port 2222 (0x08AE)
    monkeypatch.setenv("SSH_PORT", "22 2222")
    tcp_custom_ssh = tcp_ok + ["5: 00000000:08AE 00000000:0000 0A"]
    assert self_test.check_exposed_ports(proc_tcp_lines=tcp_custom_ssh, proc_tcp6_lines=[]).passed is True
    monkeypatch.delenv("SSH_PORT", raising=False)

    # Exposed external 0.0.0.0:8443 -> FAIL (RCA Cause #4)
    tcp_bad = tcp_ok + ["5: 00000000:20FB 00000000:0000 0A"]
    fail = self_test.check_exposed_ports(proc_tcp_lines=tcp_bad, proc_tcp6_lines=[])
    assert fail.passed is False
    assert "0.0.0.0:8443" in fail.detail


def test_client_templates_safety_passes():
    res = self_test.check_client_templates_safety()
    assert res.passed is True, res.detail


@pytest.mark.asyncio
async def test_triple_ai_egress_checks_pass_and_fail():
    captured_headers = {}

    def _make_client(gl_code: str, loc: str = "DE", warp: str = "off", anthropic_status: int = 404) -> httpx.AsyncClient:
        def handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            url = str(request.url)
            if "youtube.com" in url:
                return httpx.Response(
                    200,
                    text=f'<html><script>var ytcfg={{"INNERTUBE_CONTEXT_GL":"{gl_code}"}};</script></html>',
                )
            if "chatgpt.com/cdn-cgi/trace" in url:
                return httpx.Response(200, text=f"fl=1\nloc={loc}\nwarp={warp}\n")
            if "api.anthropic.com" in url:
                body = "Attention Required! Cloudflare" if anthropic_status == 403 else '{"type":"error"}'
                return httpx.Response(anthropic_status, text=body)
            return httpx.Response(200, text="ok")

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async with _make_client("DE", "DE", "off", 404) as client_ok:
        checks = await self_test.check_triple_ai_egress(http_client=client_ok)
        assert len(checks) == 3
        assert all(c.passed for c in checks)
        assert "ru" not in captured_headers.get("accept-language", "").lower()

    async with _make_client("RU", "RU", "on", 403) as client_bad:
        checks_bad = await self_test.check_triple_ai_egress(http_client=client_bad)
        assert len(checks_bad) == 3
        assert not any(c.passed for c in checks_bad)


@pytest.mark.asyncio
async def test_bridge_mode_self_test_zero_emission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    priv, _ = generate_reality_keypair()
    _, up_pub = generate_reality_keypair()
    bridge_cfg = LocalXrayConfigBuilder.build_bridge(
        bridge_sni="exit.example.com",
        reality_private_key=priv,
        reality_short_ids=[generate_short_id()],
        clients=[{"id": "11111111-2222-3333-4444-555555555555", "email": "b@local"}],
        upstream_ip="203.0.113.20",
        upstream_domain="exit.example.com",
        upstream_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        upstream_public_key=up_pub,
        upstream_short_id="0123456789abcdef",
    )
    xray_dir = tmp_path / "xray"
    xray_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = xray_dir / "config.json"
    cfg_path.write_text(json.dumps(bridge_cfg), encoding="utf-8")

    # Auto-detects bridge mode, validates fail-closed config, and warns on shared SNI
    chk = self_test.check_xray_config_safety(str(cfg_path))
    assert chk.passed is True, chk.detail
    assert "mode=bridge" in chk.detail
    assert "upstream=tcp" in chk.detail
    assert "shared bridge/upstream SNI" in chk.detail

    bridge_xhttp_cfg = LocalXrayConfigBuilder.build_bridge(
        bridge_sni="bridge.example.com",
        reality_private_key=priv,
        reality_short_ids=[generate_short_id()],
        clients=[{"id": "11111111-2222-3333-4444-555555555555", "email": "b@local"}],
        upstream_ip="203.0.113.20",
        upstream_domain="exit.example.com",
        upstream_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        upstream_public_key=up_pub,
        upstream_short_id="0123456789abcdef",
        upstream_transport="xhttp",
        upstream_xhttp_path="b" * 64,
    )
    cfg_xhttp_path = xray_dir / "config_xhttp.json"
    cfg_xhttp_path.write_text(json.dumps(bridge_xhttp_cfg), encoding="utf-8")
    chk_xhttp = self_test.check_xray_config_safety(str(cfg_xhttp_path))
    assert chk_xhttp.passed is True, chk_xhttp.detail
    assert "upstream=xhttp" in chk_xhttp.detail

    # Port 80 exposed externally on bridge node -> fails minimal_port_exposure in bridge mode
    tcp_bridge_with_80 = [
        "0: 00000000:0050 00000000:0000 0A",  # 0.0.0.0:80 (forbidden on bridge)
        "1: 00000000:01BB 00000000:0000 0A",  # 0.0.0.0:443
        "2: 00000000:0016 00000000:0000 0A",  # 0.0.0.0:22
    ]
    assert (
        self_test.check_exposed_ports(
            proc_tcp_lines=tcp_bridge_with_80, proc_tcp6_lines=[], mode="bridge"
        ).passed
        is False
    )

    tcp_bridge_ok = [
        "0: 0100007F:0050 00000000:0000 0A",  # 127.0.0.1:80 (loopback ok)
        "1: 00000000:01BB 00000000:0000 0A",  # 0.0.0.0:443
        "2: 00000000:0016 00000000:0000 0A",  # 0.0.0.0:22
        "3: 0100007F:20FB 00000000:0000 0A",  # 127.0.0.1:8443
    ]
    assert (
        self_test.check_exposed_ports(
            proc_tcp_lines=tcp_bridge_ok, proc_tcp6_lines=[], mode="bridge"
        ).passed
        is True
    )

    nginx_dir = tmp_path / "nginx-runtime"
    mgr = NginxManager(runtime_dir=str(nginx_dir), webroot_dir=str(tmp_path / "webroot"))
    mgr.apply(domain="exit.example.com", validate_binary=False)

    monkeypatch.setattr(
        self_test,
        "check_exposed_ports",
        lambda mode="exit": self_test.SelfTestCheck(
            name="minimal_port_exposure", passed=True, detail=f"ok ({mode})"
        ),
    )
    monkeypatch.setattr(
        self_test,
        "scan_forbidden_processes",
        lambda: self_test.SelfTestCheck(
            name="zero_tunnel_stacking", passed=True, detail="ok"
        ),
    )

    def _forbid_network(*args, **kwargs):
        raise AssertionError("Zero-Emission violated: network probe was called!")

    monkeypatch.setattr(self_test, "probe_reality_and_nginx_tls13", _forbid_network)
    monkeypatch.setattr(self_test, "check_triple_ai_egress", _forbid_network)

    # Default run_self_test() is 100% passive (include_network_probes=False)
    report = await self_test.run_self_test(
        domain="exit.example.com",
        xray_config_path=str(cfg_path),
        nginx_runtime_dir=str(nginx_dir),
    )
    assert report.passed is True
    assert len(report.checks) == 5


def test_multi_upstream_bridge_and_exit_ru_selftest_with_meminfo(tmp_path: Path):
    priv, _ = generate_reality_keypair()
    _, pub_ai = generate_reality_keypair()
    _, pub_media = generate_reality_keypair()
    sid_ai = generate_short_id()
    sid_media = generate_short_id()

    bridge_dir = tmp_path / "bridge"
    (bridge_dir / "xray").mkdir(parents=True, exist_ok=True)
    state_path = bridge_dir / "state.json"
    cfg_path = bridge_dir / "xray" / "config.json"

    upstreams = {
        "exit-ai": {
            "role": "ai-isolated",
            "ip": "203.0.113.10",
            "domain": "de-ai.only-ai.org",
            "uuid": "aaaaaaaa-1111-4111-8111-111111111111",
            "public_key": pub_ai,
            "short_id": sid_ai,
            "transport": "xhttp",
            "xhttp_path": "a" * 64,
        },
        "exit-media-1": {
            "role": "media",
            "ip": "198.51.100.20",
            "domain": "de-media.stream-cdn.net",
            "uuid": "bbbbbbbb-2222-4222-8222-222222222222",
            "public_key": pub_media,
            "short_id": sid_media,
            "transport": "xhttp",
            "xhttp_path": "b" * 64,
        },
    }
    state = {
        "schema_version": 2,
        "mode": "bridge",
        "domain": "mos.bridge-edge.net",
        "bridge_sni": "mos.bridge-edge.net",
        "upstreams": upstreams,
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
    state_path.write_text(json.dumps(state), encoding="utf-8")

    multi_cfg = LocalXrayConfigBuilder.build_bridge(
        bridge_sni="mos.bridge-edge.net",
        reality_private_key=priv,
        reality_short_ids=[generate_short_id()],
        upstreams=upstreams,
        clients=[
            {"id": "11111111-1111-4111-8111-111111111111", "email": "owner"},
            {"id": "22222222-2222-4222-8222-222222222222", "email": "alice"},
        ],
        user_routes={"owner": "exit-ai", "alice": "exit-media-1"},
    )
    cfg_path.write_text(json.dumps(multi_cfg), encoding="utf-8")

    # 1. Adequate RAM (2048 MB) and Swap (1024 MB) -> PASS without capacity WARN
    mem_ok = tmp_path / "meminfo_ok"
    mem_ok.write_text(
        f"MemTotal:        {2048 * 1024} kB\nSwapTotal:       {1024 * 1024} kB\n",
        encoding="utf-8",
    )
    res_ok = self_test.check_xray_config_safety(
        str(cfg_path), state_path=state_path, meminfo_path=mem_ok
    )
    assert res_ok.passed is True, res_ok.detail
    assert "upstreams=2" in res_ok.detail
    assert "WARN:" not in res_ok.detail

    # 2. Low RAM (< 1800 MB) -> PASS with non-fatal WARN:
    mem_low_ram = tmp_path / "meminfo_low"
    mem_low_ram.write_text(
        f"MemTotal:        {955 * 1024} kB\nSwapTotal:       {1024 * 1024} kB\n",
        encoding="utf-8",
    )
    res_low = self_test.check_xray_config_safety(
        str(cfg_path), state_path=state_path, meminfo_path=mem_low_ram
    )
    assert res_low.passed is True
    assert "WARN:" in res_low.detail
    assert "memory headroom below baseline" in res_low.detail

    # 3. 0 swap even with 2048 MB RAM -> PASS with non-fatal WARN:
    mem_no_swap = tmp_path / "meminfo_noswap"
    mem_no_swap.write_text(
        f"MemTotal:        {2048 * 1024} kB\nSwapTotal:       0 kB\n",
        encoding="utf-8",
    )
    res_noswap = self_test.check_xray_config_safety(
        str(cfg_path), state_path=state_path, meminfo_path=mem_no_swap
    )
    assert res_noswap.passed is True
    assert "WARN:" in res_noswap.detail
    assert "Swap=0 MB" in res_noswap.detail

    # 4. Violation of ai-isolated /24 subnet separation in state.json -> FAIL
    bad_state = json.loads(json.dumps(state))
    bad_state["upstreams"]["exit-media-1"]["ip"] = "203.0.113.55"
    state_path.write_text(json.dumps(bad_state), encoding="utf-8")
    res_bad_iso = self_test.check_xray_config_safety(
        str(cfg_path), state_path=state_path, meminfo_path=mem_ok
    )
    assert res_bad_iso.passed is False
    assert "/24 IPv4 subnet collision" in res_bad_iso.detail

    # 5. Exit config missing RU egress blackhole -> FAIL
    exit_cfg = LocalXrayConfigBuilder.build(
        domain="de-ai.only-ai.org",
        reality_private_key=priv,
        reality_short_ids=[generate_short_id()],
        clients=[],
    )
    exit_cfg["routing"]["rules"] = [
        r for r in exit_cfg["routing"]["rules"] if "domain:ru" not in r.get("domain", [])
    ]
    bad_exit_path = tmp_path / "exit_missing_ru.json"
    bad_exit_path.write_text(json.dumps(exit_cfg), encoding="utf-8")
    res_exit = self_test.check_xray_config_safety(str(bad_exit_path), mode="exit")
    assert res_exit.passed is False
    assert "RU domain blackhole" in res_exit.detail

