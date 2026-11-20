import fcntl
import json
import subprocess
from pathlib import Path

import pytest

from app.cli import (
    load_or_init_bridge_state,
    query_xray_user_stats,
    set_user_disabled,
)
from app.utils.self_test import check_xray_config_safety
from app.xray.config_builder import (
    LocalXrayConfigBuilder,
    generate_reality_keypair,
    generate_short_id,
    validate_xray_config,
)
from tools.cluster_watch import (
    NodeAssessment,
    NodeMetrics,
    WatchThresholds,
    assess_node,
    collect_node,
    dispatch_alert_if_needed,
    evaluate_quarantine_candidates,
    parse_node_output,
    run_watch,
    sanitize_alert_text,
)


def _sample_bridge_cfg():
    priv, _ = generate_reality_keypair()
    _, up_pub = generate_reality_keypair()
    return LocalXrayConfigBuilder.build_bridge(
        bridge_sni="mos.example.com",
        reality_private_key=priv,
        reality_short_ids=[generate_short_id()],
        clients=[{"id": "11111111-1111-4111-8111-111111111111", "email": "owner"}],
        upstream_ip="203.0.113.10",
        upstream_domain="de.example.com",
        upstream_uuid="22222222-2222-4222-8222-222222222222",
        upstream_public_key=up_pub,
        upstream_short_id=generate_short_id(),
        upstream_transport="xhttp",
        upstream_xhttp_path="a" * 64,
    )


def _sample_exit_cfg():
    priv, _ = generate_reality_keypair()
    return LocalXrayConfigBuilder.build(
        domain="de.example.com",
        reality_private_key=priv,
        reality_short_ids=[generate_short_id()],
        clients=[{"id": "22222222-2222-4222-8222-222222222222", "email": "owner"}],
    )


def test_bridge_enables_loopback_stats_while_exit_forbids_it():
    bcfg = _sample_bridge_cfg()
    assert "StatsService" in bcfg["api"]["services"]
    assert bcfg["stats"] == {}
    assert bcfg["policy"]["levels"]["0"] == {
        "statsUserUplink": True,
        "statsUserDownlink": True,
    }
    assert bcfg["log"] == {"access": "none", "error": "none", "loglevel": "none"}

    # Non-loopback API listen must be rejected even on bridge
    bad_bridge = json.loads(json.dumps(bcfg))
    bad_bridge["inbounds"][0]["listen"] = "0.0.0.0"
    with pytest.raises(ValueError, match="loopback 127.0.0.1"):
        validate_xray_config(bad_bridge, expected_ipv6=False, mode="bridge")

    # Exit mode must remain strictly stats-free
    ecfg = _sample_exit_cfg()
    assert "stats" not in ecfg
    assert "policy" not in ecfg
    assert "StatsService" not in ecfg["api"]["services"]

    bad_exit = json.loads(json.dumps(ecfg))
    bad_exit["stats"] = {}
    with pytest.raises(ValueError, match="prohibited"):
        validate_xray_config(bad_exit, expected_ipv6=False, mode="exit")


def test_self_test_allows_bridge_loopback_stats_and_rejects_exit_stats(tmp_path: Path):
    bpath = tmp_path / "bridge.json"
    bpath.write_text(json.dumps(_sample_bridge_cfg()), encoding="utf-8")
    res_b = check_xray_config_safety(str(bpath), expected_ipv6=False, mode="bridge")
    assert res_b.passed is True
    assert "stats=in-memory(127.0.0.1)" in res_b.detail

    ecfg = _sample_exit_cfg()
    ecfg["api"]["services"].append("StatsService")
    epath = tmp_path / "exit.json"
    epath.write_text(json.dumps(ecfg), encoding="utf-8")
    res_e = check_xray_config_safety(str(epath), expected_ipv6=False, mode="exit")
    assert res_e.passed is False


def test_query_xray_user_stats_ok_and_timeout():
    captured_cmds = []

    def fake_ok(cmd, **kwargs):
        captured_cmds.append((cmd, kwargs))
        out = json.dumps(
            {
                "stat": [
                    {"name": "user>>>owner>>>traffic>>>uplink", "value": "1024"},
                    {"name": "user>>>owner>>>traffic>>>downlink", "value": "2048"},
                    {"name": "user>>>alice>>>traffic>>>downlink", "value": "4096"},
                ]
            }
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    res = query_xray_user_stats(reset=True, timeout_sec=3.0, runner=fake_ok)
    assert res["status"] == "ok"
    assert res["users"]["owner"] == {"uplink": 1024, "downlink": 2048}
    assert res["users"]["alice"] == {"uplink": 0, "downlink": 4096}
    assert "-reset=true" in captured_cmds[0][0]
    assert captured_cmds[0][1]["timeout"] == 3.0

    def fake_timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 3.0))

    res_to = query_xray_user_stats(timeout_sec=3.0, runner=fake_timeout)
    assert res_to["status"] == "timeout"
    assert res_to["users"] == {}


def test_set_user_disabled_protects_ai_owner_and_rolls_back_on_xray_test_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    data_dir = tmp_path / "data"
    creds_dir = tmp_path / "creds"
    state_path = data_dir / "state.json"
    xray_cfg_path = data_dir / "xray" / "config.json"
    monkeypatch.setenv("XRAY_CONFIG_PATH", str(xray_cfg_path))

    _, up_pub = generate_reality_keypair()
    state = load_or_init_bridge_state(
        state_path,
        upstream_ip="203.0.113.10",
        upstream_domain="de.example.com",
        upstream_uuid="22222222-2222-4222-8222-222222222222",
        upstream_public_key=up_pub,
        upstream_short_id=generate_short_id(),
        bridge_sni="mos.example.com",
        bridge_ip="198.51.100.10",
        upstream_transport="xhttp",
        upstream_xhttp_path="b" * 64,
    )
    state["users"] = {
        "owner": {
            "uuid": state["user_uuid"],
            "profile": "ai-owner",
            "disabled": False,
        },
        "alice": {
            "uuid": "33333333-3333-4333-8333-333333333333",
            "profile": "media-selective",
            "disabled": False,
        },
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")
    xray_cfg_path.parent.mkdir(parents=True, exist_ok=True)
    original_live = '{"marker": "untouched-live-config"}\n'
    xray_cfg_path.write_text(original_live, encoding="utf-8")

    # 1. Automated disable of ai-owner MUST be rejected
    with pytest.raises(ValueError, match="protected ai-owner"):
        set_user_disabled(
            state_path,
            name="owner",
            disabled=True,
            automated=True,
            data_dir=data_dir,
            credentials_dir=creds_dir,
            xray_test_fn=lambda p: (True, "ok"),
        )

    # 2. Failed xray -test MUST roll back and leave live config & state untouched
    with pytest.raises(RuntimeError, match="rolled back"):
        set_user_disabled(
            state_path,
            name="alice",
            disabled=True,
            automated=True,
            data_dir=data_dir,
            credentials_dir=creds_dir,
            xray_test_fn=lambda p: (False, "simulated xray syntax error"),
        )
    assert xray_cfg_path.read_text(encoding="utf-8") == original_live
    assert json.loads(state_path.read_text(encoding="utf-8"))["users"]["alice"]["disabled"] is False

    # 3. Passing xray -test disables alice cleanly (candidate path must end with .json for Xray), and enable restores her
    seen_candidates = []

    def _assert_json_and_ok(p: Path):
        seen_candidates.append(p.name)
        assert p.suffix == ".json"
        return True, "Configuration OK"

    st_dis = set_user_disabled(
        state_path,
        name="alice",
        disabled=True,
        automated=True,
        data_dir=data_dir,
        credentials_dir=creds_dir,
        xray_test_fn=_assert_json_and_ok,
    )
    assert seen_candidates == ["config.candidate.json"]
    assert st_dis["users"]["alice"]["disabled"] is True
    rendered = json.loads(xray_cfg_path.read_text(encoding="utf-8"))
    emails = [c["email"] for c in rendered["inbounds"][1]["settings"]["clients"]]
    assert emails == ["owner"]

    st_en = set_user_disabled(
        state_path,
        name="alice",
        disabled=False,
        data_dir=data_dir,
        credentials_dir=creds_dir,
        xray_test_fn=lambda p: (True, "Configuration OK"),
    )
    assert st_en["users"]["alice"]["disabled"] is False
    rendered2 = json.loads(xray_cfg_path.read_text(encoding="utf-8"))
    emails2 = [c["email"] for c in rendered2["inbounds"][1]["settings"]["clients"]]
    assert set(emails2) == {"owner", "alice"}


def _sample_ssh_output(syn=100, to=200, rst=50, started="2026-11-18T18:00:00Z", stats_json=None):
    base = f"""1795150000
---NSTAT---
#kernel
TcpExtEmbryonicRsts {rst} 0.0
TcpExtTCPTimeouts {to} 0.0
TcpExtTCPSynRetrans {syn} 0.0
TcpExtTCPAbortOnTimeout 5 0.0
---SS---
TCP:   18 (estab 10, closed 2, orphaned 0, timewait 2)
---DOCKER---
/marzneshin-xray|running|0|false|{started}
/marzneshin-nginx|running|0|false|{started}
---MEM---
MEM 955 640
SWAP 511 480
---DISK---
42%
---NTP---
System clock synchronized: yes
---TCPMSS---
2
"""
    if stats_json is not None:
        base += f"---USERSTATS---\n{stats_json}\n"
    return base


def test_cluster_watch_deltas_restart_unreachable_and_flock(tmp_path: Path):
    snap = tmp_path / "snapshot.json"
    lock = tmp_path / "watch.lock"
    calls = []

    def runner_run1(cmd, **kwargs):
        calls.append(cmd)
        if "mos" in cmd:
            out = _sample_ssh_output(
                syn=100,
                to=200,
                rst=50,
                stats_json=json.dumps(
                    {"stat": [{"name": "user>>>owner>>>traffic>>>downlink", "value": "1073741824"}]}
                ),
            )
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
        return subprocess.CompletedProcess(cmd, 255, stdout="", stderr="Connection timed out")

    code1, rep1 = run_watch(
        ["mos:bridge", "server-de:exit"],
        snapshot_path=snap,
        lock_path=lock,
        runner=runner_run1,
    )
    assert code1 == 2  # server-de unreachable
    assert len(calls) == 2  # strictly 1 attempt per node, zero retries
    assert "[UNREACHABLE]" in rep1
    assert "owner" in rep1
    assert snap.exists()

    # Second run: normal delta + restart detection on mos
    def runner_run2(cmd, **kwargs):
        if "mos" in cmd:
            out = _sample_ssh_output(syn=125, to=250, rst=55, started="2026-11-20T01:00:00Z")
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout=_sample_ssh_output(syn=10, to=20, rst=5), stderr="")

    code2, rep2 = run_watch(
        ["mos:bridge", "server-de:exit"],
        snapshot_path=snap,
        lock_path=lock,
        runner=runner_run2,
    )
    assert code2 == 0
    assert "[RESTARTED ]" in rep2

    # Held flock skips immediately without SSH calls
    ssh_called = []
    with open(lock, "w", encoding="utf-8") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        code3, rep3 = run_watch(
            ["mos:bridge"],
            snapshot_path=snap,
            lock_path=lock,
            runner=lambda *a, **kw: ssh_called.append(a),
        )
        fcntl.flock(held.fileno(), fcntl.LOCK_UN)
    assert code3 == 0
    assert "[SKIP]" in rep3
    assert ssh_called == []


def test_alert_dispatcher_silent_on_ok_sanitized_and_forbidden_on_bridge(tmp_path: Path):
    sent = []

    def fake_alert(cmd, **kwargs):
        sent.append(kwargs.get("input", ""))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    ok_list = [NodeAssessment(alias="mos", role="bridge", status="OK")]
    assert (
        dispatch_alert_if_needed(
            ok_list,
            "all good",
            alert_cmd="/bin/true",
            bridge_state_path=tmp_path / "missing.json",
            runner=fake_alert,
        )
        is False
    )
    assert sent == []

    warn_list = [NodeAssessment(alias="mos", role="bridge", status="WARN")]
    raw_msg = "WARN on 151.248.126.10 uuid 11111111-1111-4111-8111-111111111111"
    assert (
        dispatch_alert_if_needed(
            warn_list,
            raw_msg,
            alert_cmd="/bin/true",
            bridge_state_path=tmp_path / "missing.json",
            runner=fake_alert,
        )
        is True
    )
    assert "151.248.126.10" not in sent[0]
    assert "11111111-1111-4111-8111-111111111111" not in sent[0]
    assert "<REDACTED_IP>" in sent[0]
    assert "<REDACTED_UUID>" in sent[0]

    # Running alert dispatch on a bridge node MUST raise
    bstate = tmp_path / "state.json"
    bstate.write_text(json.dumps({"mode": "bridge"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="Zero-Emission"):
        dispatch_alert_if_needed(
            warn_list,
            raw_msg,
            alert_cmd="/bin/true",
            bridge_state_path=bstate,
            runner=fake_alert,
        )


def test_quarantine_circuit_breaker_branches():
    th = WatchThresholds(user_quarantine_gb=25.0)
    gb30 = int(30 * (1024**3))
    gb40 = int(40 * (1024**3))

    ok_nodes = [
        NodeAssessment(alias="mos", role="bridge", status="OK"),
        NodeAssessment(alias="server-de", role="exit", status="OK"),
    ]

    # 1. ai-owner is permanently whitelisted
    bm_owner = NodeMetrics(
        alias="mos",
        role="bridge",
        user_stats_status="ok",
        user_bytes={"owner": {"uplink": 0, "downlink": gb40}},
    )
    target, notes = evaluate_quarantine_candidates(ok_nodes, bm_owner, th)
    assert target is None
    assert any("whitelisted" in n for n in notes)

    # 2. Blast-radius cap: max 1 media user disabled per run (picks worst)
    bm_two = NodeMetrics(
        alias="mos",
        role="bridge",
        user_stats_status="ok",
        user_bytes={
            "user-01": {"uplink": 0, "downlink": gb30},
            "user-07": {"uplink": 0, "downlink": gb40},
        },
    )
    target2, notes2 = evaluate_quarantine_candidates(ok_nodes, bm_two, th)
    assert target2 == "user-07"
    assert any("max 1/run" in n for n in notes2)

    # 3. Outage guard: CRIT / UNREACHABLE node aborts quarantine completely
    crit_nodes = [
        NodeAssessment(alias="mos", role="bridge", status="CRIT"),
        NodeAssessment(alias="server-de", role="exit", status="OK"),
    ]
    target3, notes3 = evaluate_quarantine_candidates(crit_nodes, bm_two, th)
    assert target3 is None
    assert any("aborted by circuit breaker" in n for n in notes3)
