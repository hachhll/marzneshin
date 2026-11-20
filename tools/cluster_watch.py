#!/usr/bin/env python3
"""Passive, zero-emission SSH cluster watchdog for marzneshin (mos + exit-*).

Phase 1 (default): Strictly manual, read-only inspection from the admin workstation.
- Zero outbound packets from the Russian bridge (mos).
- Zero disk writes on any server (single bounded snapshot JSON on workstation).
- Zero retry loops (1 SSH attempt per node, 8s connect / 15s total timeout).
- Single-instance flock prevents overlapping runs.
- Phase 2 (opt-in alerts) and Phase 3 (opt-in --auto-quarantine with circuit breaker)
  are disabled by default until thresholds are calibrated manually.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "marzneshin-watch"
DEFAULT_SNAPSHOT_PATH = DEFAULT_CACHE_DIR / "snapshot.json"
DEFAULT_LOCK_PATH = DEFAULT_CACHE_DIR / "watch.lock"
DEFAULT_SSH_CONNECT_TIMEOUT = 8
DEFAULT_HOST_CMD_TIMEOUT = 15
DEFAULT_BRIDGE_STATE_PATH = Path("/var/lib/marzneshin/state.json")

PASSIVE_NODE_CMD = r"""
set -u
date -u +%s
echo "---NSTAT---"
nstat -az TcpExtEmbryonicRsts TcpExtTCPTimeouts TcpExtTCPSynRetrans TcpExtTCPAbortOnTimeout 2>/dev/null || true
echo "---SS---"
ss -s 2>/dev/null | grep -m1 '^TCP:' || true
echo "---DOCKER---"
sudo docker inspect --format '{{.Name}}|{{.State.Status}}|{{.RestartCount}}|{{.State.OOMKilled}}|{{.State.StartedAt}}' marzneshin-xray marzneshin-nginx 2>/dev/null || true
echo "---MEM---"
free -m 2>/dev/null | awk '/^Mem:/ {print "MEM",$2,$7} /^Swap:/ {print "SWAP",$2,$4}'
echo "---DISK---"
df -P / 2>/dev/null | awk 'NR==2 {print $5}'
echo "---NTP---"
timedatectl status 2>/dev/null | grep -i 'synchronized:' || true
echo "---TCPMSS---"
sudo iptables -t mangle -S 2>/dev/null | grep -c 'TCPMSS' || true
"""

BRIDGE_STATS_SNIPPET = r"""
echo "---USERSTATS---"
timeout 3 sudo docker exec marzneshin-xray /usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -pattern "user>>>" {reset_flag} 2>&1 || echo "__STATS_UNAVAILABLE__"
"""

SYSTEMD_TIMER_EXAMPLE = """# Optional Phase 2 systemd --user timer (disabled by default in Phase 1).
# Place in ~/.config/systemd/user/marzneshin-watch.service and .timer on the ADMIN WORKSTATION ONLY
# (NEVER on the Moscow bridge mos).
#
# [Unit]
# Description=Passive Marzneshin Cluster Watchdog (Phase 2)
#
# [Service]
# Type=oneshot
# ExecStart=/usr/bin/python3 /path/to/marzneshin/tools/cluster_watch.py --nodes mos:bridge server-de:exit --reset-stats --alert-cmd /path/to/alert.sh
#
# [Timer]
# OnBootSec=15m
# OnUnitActiveSec=3h30m
# RandomizedDelaySec=15m
# Persistent=true
#
# [Install]
# WantedBy=timers.target
"""


@dataclass
class NodeMetrics:
    alias: str
    role: str
    reachable: bool = True
    timestamp: int = 0
    syn_retrans: int = 0
    tcp_timeouts: int = 0
    embryonic_rsts: int = 0
    abort_on_timeout: int = 0
    estab: int = 0
    orphaned: int = 0
    timewait: int = 0
    xray_status: str = "unknown"
    xray_restarts: int = 0
    xray_oom: bool = False
    xray_started_at: str = ""
    nginx_status: str = "unknown"
    nginx_restarts: int = 0
    nginx_oom: bool = False
    mem_total_mb: int = 0
    mem_avail_mb: int = 0
    swap_total_mb: int = 0
    disk_use_pct: int = 0
    ntp_synced: bool = True
    tcpmss_rules: int = 0
    user_stats_status: str = "skipped"
    user_bytes: dict[str, dict[str, int]] = field(default_factory=dict)
    error: str = ""


@dataclass
class NodeAssessment:
    alias: str
    role: str
    status: str  # OK | WARN | CRIT | UNREACHABLE | RESTARTED
    delta_syn_retrans: int | None = None
    delta_timeouts: int | None = None
    delta_rsts: int | None = None
    delta_abort: int | None = None
    reasons: list[str] = field(default_factory=list)
    metrics: NodeMetrics | None = None


@dataclass
class WatchThresholds:
    syn_retrans_warn: int = 300
    syn_retrans_crit: int = 1000
    rsts_warn: int = 200
    rsts_crit: int = 800
    timeouts_warn: int = 5000
    mem_avail_warn_mb: int = 150
    disk_warn_pct: int = 85
    user_warn_gb: float = 15.0
    user_quarantine_gb: float = 25.0


def parse_node_spec(spec: str) -> tuple[str, str]:
    if ":" in spec:
        alias, role = spec.split(":", 1)
    else:
        alias, role = spec, ("bridge" if spec == "mos" else "exit")
    alias = alias.strip()
    role = role.strip().lower()
    if role not in ("bridge", "exit"):
        raise ValueError(f"Unsupported node role '{role}' in '{spec}' (expected bridge or exit)")
    if not alias:
        raise ValueError(f"Empty SSH alias in '{spec}'")
    return alias, role


def parse_user_stats_output(raw: str) -> tuple[str, dict[str, dict[str, int]]]:
    text = (raw or "").strip()
    if not text or "__STATS_UNAVAILABLE__" in text:
        if "StatsService" in text or "Unimplemented" in text or "not found" in text:
            return "not-enabled", {}
        if "timed out" in text.lower():
            return "timeout", {}
        return "unavailable", {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        if "Unimplemented" in text or "StatsService" in text:
            return "not-enabled", {}
        return "unavailable", {}
    users: dict[str, dict[str, int]] = {}
    for item in payload.get("stat", []) or []:
        name = str(item.get("name", ""))
        parts = name.split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            uname, direction = parts[1], parts[3]
            if direction in ("uplink", "downlink"):
                entry = users.setdefault(uname, {"uplink": 0, "downlink": 0})
                try:
                    entry[direction] = int(item.get("value", 0))
                except (TypeError, ValueError):
                    pass
    return "ok", users


def parse_node_output(alias: str, role: str, stdout: str) -> NodeMetrics:
    m = NodeMetrics(alias=alias, role=role, reachable=True)
    sections: dict[str, list[str]] = {"HEADER": []}
    current = "HEADER"
    for line in (stdout or "").splitlines():
        tag = re.fullmatch(r"---([A-Z]+)---", line.strip())
        if tag:
            current = tag.group(1)
            sections.setdefault(current, [])
        else:
            sections.setdefault(current, []).append(line)

    for line in sections.get("HEADER", []):
        if line.strip().isdigit():
            m.timestamp = int(line.strip())
            break
    if not m.timestamp:
        m.timestamp = int(time.time())

    for line in sections.get("NSTAT", []):
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            val = int(parts[1])
            if parts[0] == "TcpExtTCPSynRetrans":
                m.syn_retrans = val
            elif parts[0] == "TcpExtTCPTimeouts":
                m.tcp_timeouts = val
            elif parts[0] == "TcpExtEmbryonicRsts":
                m.embryonic_rsts = val
            elif parts[0] == "TcpExtTCPAbortOnTimeout":
                m.abort_on_timeout = val

    ss_text = " ".join(sections.get("SS", []))
    for key, attr in (
        ("estab", "estab"),
        ("orphaned", "orphaned"),
        ("timewait", "timewait"),
    ):
        match = re.search(rf"{key}\s+(\d+)", ss_text)
        if match:
            setattr(m, attr, int(match.group(1)))

    for line in sections.get("DOCKER", []):
        parts = line.strip().split("|")
        if len(parts) >= 5:
            cname = parts[0].lstrip("/")
            status = parts[1]
            restarts = int(parts[2]) if parts[2].isdigit() else 0
            oom = parts[3].lower() == "true"
            started_at = parts[4]
            if cname == "marzneshin-xray":
                m.xray_status = status
                m.xray_restarts = restarts
                m.xray_oom = oom
                m.xray_started_at = started_at
            elif cname == "marzneshin-nginx":
                m.nginx_status = status
                m.nginx_restarts = restarts
                m.nginx_oom = oom

    for line in sections.get("MEM", []):
        parts = line.split()
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            if parts[0] == "MEM":
                m.mem_total_mb = int(parts[1])
                m.mem_avail_mb = int(parts[2])
            elif parts[0] == "SWAP":
                m.swap_total_mb = int(parts[1])

    for line in sections.get("DISK", []):
        match = re.search(r"(\d+)%", line)
        if match:
            m.disk_use_pct = int(match.group(1))
            break

    ntp_text = " ".join(sections.get("NTP", [])).lower()
    if ntp_text:
        m.ntp_synced = "yes" in ntp_text

    for line in sections.get("TCPMSS", []):
        if line.strip().isdigit():
            m.tcpmss_rules = int(line.strip())
            break

    if "USERSTATS" in sections:
        st, ubytes = parse_user_stats_output("\n".join(sections["USERSTATS"]))
        m.user_stats_status = st
        m.user_bytes = ubytes

    return m


def collect_node(
    alias: str,
    role: str,
    *,
    reset_stats: bool = False,
    connect_timeout: int = DEFAULT_SSH_CONNECT_TIMEOUT,
    cmd_timeout: int = DEFAULT_HOST_CMD_TIMEOUT,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> NodeMetrics:
    """Single-attempt passive SSH collection (zero retries, fail-fast)."""
    remote_script = PASSIVE_NODE_CMD
    if role == "bridge":
        remote_script += BRIDGE_STATS_SNIPPET.format(
            reset_flag="-reset=true" if reset_stats else ""
        )

    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        alias,
        remote_script,
    ]
    exec_fn = runner or subprocess.run
    try:
        proc = exec_fn(
            cmd,
            capture_output=True,
            text=True,
            timeout=cmd_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return NodeMetrics(
            alias=alias,
            role=role,
            reachable=False,
            timestamp=int(time.time()),
            error=f"SSH command timed out after {cmd_timeout}s",
        )
    except OSError as exc:
        return NodeMetrics(
            alias=alias,
            role=role,
            reachable=False,
            timestamp=int(time.time()),
            error=str(exc),
        )

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or f"ssh exit={proc.returncode}").strip()
        return NodeMetrics(
            alias=alias,
            role=role,
            reachable=False,
            timestamp=int(time.time()),
            error=err.splitlines()[-1] if err else f"ssh exit={proc.returncode}",
        )

    return parse_node_output(alias, role, proc.stdout)


def load_snapshot(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"nodes": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("nodes"), dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"nodes": {}}


def save_snapshot_atomic(path: Path, snapshot: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".snapshot-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def assess_node(
    current: NodeMetrics,
    previous: dict[str, Any] | None,
    thresholds: WatchThresholds,
) -> NodeAssessment:
    if not current.reachable:
        return NodeAssessment(
            alias=current.alias,
            role=current.role,
            status="UNREACHABLE",
            reasons=[current.error or "SSH unreachable"],
            metrics=current,
        )

    reasons: list[str] = []
    severity = "OK"

    def bump(level: str, msg: str) -> None:
        nonlocal severity
        order = {"OK": 0, "RESTARTED": 1, "WARN": 2, "CRIT": 3}
        if order[level] > order[severity]:
            severity = level
        reasons.append(msg)

    restarted = False
    d_syn: int | None = None
    d_to: int | None = None
    d_rst: int | None = None
    d_ab: int | None = None

    if previous:
        prev_started = str(previous.get("xray_started_at", ""))
        if prev_started and current.xray_started_at and prev_started != current.xray_started_at:
            restarted = True
            bump("RESTARTED", "marzneshin-xray restarted since previous snapshot")
        else:
            d_syn = current.syn_retrans - int(previous.get("syn_retrans", 0))
            d_to = current.tcp_timeouts - int(previous.get("tcp_timeouts", 0))
            d_rst = current.embryonic_rsts - int(previous.get("embryonic_rsts", 0))
            d_ab = current.abort_on_timeout - int(previous.get("abort_on_timeout", 0))
            if min(d_syn, d_to, d_rst, d_ab) < 0:
                restarted = True
                d_syn = d_to = d_rst = d_ab = None
                bump("RESTARTED", "kernel counters reset (host rebooted)")

    if not restarted and d_syn is not None:
        if d_syn >= thresholds.syn_retrans_crit:
            bump("CRIT", f"TCPSynRetrans +{d_syn} (>= {thresholds.syn_retrans_crit})")
        elif d_syn >= thresholds.syn_retrans_warn:
            bump("WARN", f"TCPSynRetrans +{d_syn} (>= {thresholds.syn_retrans_warn})")
    if not restarted and d_rst is not None:
        if d_rst >= thresholds.rsts_crit:
            bump("CRIT", f"EmbryonicRsts +{d_rst} (>= {thresholds.rsts_crit})")
        elif d_rst >= thresholds.rsts_warn:
            bump("WARN", f"EmbryonicRsts +{d_rst} (>= {thresholds.rsts_warn})")
    if not restarted and d_to is not None and d_to >= thresholds.timeouts_warn:
        bump("WARN", f"TCPTimeouts +{d_to} (>= {thresholds.timeouts_warn})")

    if current.xray_status != "running":
        bump("CRIT", f"marzneshin-xray status={current.xray_status}")
    if current.nginx_status != "running":
        bump("CRIT", f"marzneshin-nginx status={current.nginx_status}")
    if current.xray_oom or current.nginx_oom:
        bump("CRIT", "container OOMKilled=true")
    if current.mem_avail_mb and current.mem_avail_mb < thresholds.mem_avail_warn_mb:
        bump("WARN", f"low RAM available ({current.mem_avail_mb} MB)")
    if current.disk_use_pct >= thresholds.disk_warn_pct:
        bump("WARN", f"disk usage {current.disk_use_pct}%")
    if not current.ntp_synced:
        bump("WARN", "NTP not synchronized")
    if current.tcpmss_rules == 0:
        bump("WARN", "TCPMSS mangle rule missing")

    return NodeAssessment(
        alias=current.alias,
        role=current.role,
        status=severity,
        delta_syn_retrans=d_syn,
        delta_timeouts=d_to,
        delta_rsts=d_rst,
        delta_abort=d_ab,
        reasons=reasons,
        metrics=current,
    )


def evaluate_quarantine_candidates(
    assessments: list[NodeAssessment],
    bridge_metrics: NodeMetrics | None,
    thresholds: WatchThresholds,
    protected_users: set[str] | None = None,
) -> tuple[str | None, list[str]]:
    """Circuit-breaker evaluation for Phase 3 opt-in auto-quarantine.

    Returns (user_to_disable_or_None, notes).
    - Permanent whitelist: 'owner' and any protected ai-owner users are never disabled.
    - Outage guard: if any node is UNREACHABLE/CRIT/OOMKilled, abort quarantine.
    - Blast-radius cap: disable at most 1 media-consumer user per run.
    """
    notes: list[str] = []
    whitelist = {"owner"} | {u.strip() for u in (protected_users or set()) if u.strip()}

    for a in assessments:
        if a.status in ("UNREACHABLE", "CRIT"):
            notes.append(
                f"Quarantine aborted by circuit breaker: node '{a.alias}' status={a.status}"
            )
            return None, notes
        if a.metrics and (a.metrics.xray_oom or a.metrics.nginx_oom):
            notes.append(
                f"Quarantine aborted by circuit breaker: node '{a.alias}' OOMKilled"
            )
            return None, notes

    if not bridge_metrics or bridge_metrics.user_stats_status != "ok":
        return None, notes

    threshold_bytes = int(thresholds.user_quarantine_gb * (1024**3))
    offenders: list[tuple[int, str]] = []
    for uname, counters in bridge_metrics.user_bytes.items():
        total_b = int(counters.get("uplink", 0)) + int(counters.get("downlink", 0))
        if total_b >= threshold_bytes:
            if uname in whitelist or uname.startswith("ai-"):
                notes.append(
                    f"Protected ai-owner user '{uname}' exceeded {thresholds.user_quarantine_gb:.1f} GB (whitelisted; never auto-disabled)"
                )
            else:
                offenders.append((total_b, uname))

    if not offenders:
        return None, notes

    offenders.sort(reverse=True)
    _, worst_user = offenders[0]
    if len(offenders) > 1:
        notes.append(
            f"Blast-radius cap active: {len(offenders)} media users exceeded threshold; selecting only '{worst_user}' (max 1/run)"
        )
    return worst_user, notes


def format_report(
    assessments: list[NodeAssessment],
    bridge_metrics: NodeMetrics | None,
    thresholds: WatchThresholds,
    quarantine_notes: list[str] | None = None,
) -> str:
    lines: list[str] = []
    lines.append("=== MARZNESHIN PASSIVE CLUSTER STATUS ===")
    lines.append(
        f"{'NODE':<14} {'ROLE':<7} {'STATUS':<12} {'SYN_RETR':<10} {'TIMEOUTS':<10} {'RSTS':<8} {'ESTAB':<6} {'RAM_AVAIL':<10} {'XRAY/NGINX'}"
    )
    for a in assessments:
        m = a.metrics
        syn_s = f"+{a.delta_syn_retrans}" if a.delta_syn_retrans is not None else "n/a"
        to_s = f"+{a.delta_timeouts}" if a.delta_timeouts is not None else "n/a"
        rst_s = f"+{a.delta_rsts}" if a.delta_rsts is not None else "n/a"
        if m and m.reachable:
            ram_s = f"{m.mem_avail_mb}/{m.mem_total_mb}M"
            ctr_s = f"{m.xray_status}(r={m.xray_restarts})/{m.nginx_status}(r={m.nginx_restarts})"
            estab_s = str(m.estab)
        else:
            ram_s = "-"
            ctr_s = "-"
            estab_s = "-"
        lines.append(
            f"{a.alias:<14} {a.role:<7} [{a.status:<10}] {syn_s:<10} {to_s:<10} {rst_s:<8} {estab_s:<6} {ram_s:<10} {ctr_s}"
        )
        for r in a.reasons:
            lines.append(f"  -> {r}")

    if bridge_metrics and bridge_metrics.reachable:
        lines.append("")
        lines.append(f"=== BRIDGE IN-MEMORY USER STATS ({bridge_metrics.alias}) ===")
        if bridge_metrics.user_stats_status == "ok":
            if not bridge_metrics.user_bytes:
                lines.append("  (0 active user counters in current window)")
            else:
                lines.append(f"{'USER':<18} {'UPLINK_GB':<11} {'DOWNLINK_GB':<13} {'TOTAL_GB':<10} {'STATUS'}")
                for uname, c in sorted(bridge_metrics.user_bytes.items()):
                    up_gb = c.get("uplink", 0) / (1024**3)
                    dn_gb = c.get("downlink", 0) / (1024**3)
                    tot_gb = up_gb + dn_gb
                    st = "WARN" if tot_gb >= thresholds.user_warn_gb else "OK"
                    if uname == "owner" or uname.startswith("ai-"):
                        st += " (protected)"
                    lines.append(
                        f"{uname:<18} {up_gb:<11.3f} {dn_gb:<13.3f} {tot_gb:<10.3f} [{st}]"
                    )
        else:
            lines.append(f"  status={bridge_metrics.user_stats_status} (passive OS checks unaffected)")

    if quarantine_notes:
        lines.append("")
        lines.append("=== QUARANTINE / CIRCUIT BREAKER ===")
        for n in quarantine_notes:
            lines.append(f"  - {n}")

    return "\n".join(lines)


def sanitize_alert_text(text: str) -> str:
    """Strip any accidental IPv4 addresses or UUIDs before sending an external alert."""
    cleaned = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<REDACTED_IP>", text)
    cleaned = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "<REDACTED_UUID>",
        cleaned,
    )
    return cleaned


def is_running_on_bridge(state_path: Path = DEFAULT_BRIDGE_STATE_PATH) -> bool:
    if not state_path.exists():
        return False
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        return data.get("mode") == "bridge"
    except (OSError, json.JSONDecodeError):
        return False


def dispatch_alert_if_needed(
    assessments: list[NodeAssessment],
    report_text: str,
    *,
    alert_cmd: str | None = None,
    bridge_state_path: Path = DEFAULT_BRIDGE_STATE_PATH,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> bool:
    """Phase 2 silent-on-OK alert dispatcher (strictly forbidden on mos bridge)."""
    if not alert_cmd:
        return False
    if is_running_on_bridge(bridge_state_path):
        raise RuntimeError(
            "Zero-Emission violation: external alert dispatch is strictly prohibited on a domestic bridge node"
        )
    has_issue = any(a.status in ("WARN", "CRIT", "UNREACHABLE") for a in assessments)
    if not has_issue:
        return False
    safe_payload = sanitize_alert_text(report_text)
    exec_fn = runner or subprocess.run
    exec_fn(
        [alert_cmd],
        input=safe_payload,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    return True


def execute_quarantine(
    bridge_alias: str,
    user_name: str,
    *,
    connect_timeout: int = DEFAULT_SSH_CONNECT_TIMEOUT,
    cmd_timeout: int = DEFAULT_HOST_CMD_TIMEOUT,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> tuple[bool, str]:
    """Execute reversible user disable on mos with --automated whitelist enforcement."""
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        bridge_alias,
        f"cd /opt/marzneshin && sudo ./script.sh user disable {user_name} --automated",
    ]
    exec_fn = runner or subprocess.run
    try:
        proc = exec_fn(
            cmd,
            capture_output=True,
            text=True,
            timeout=cmd_timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or f"exit={proc.returncode}").strip()
    return True, (proc.stdout or "disabled").strip()


def run_watch(
    node_specs: list[str],
    *,
    snapshot_path: Path = DEFAULT_SNAPSHOT_PATH,
    lock_path: Path = DEFAULT_LOCK_PATH,
    reset_stats: bool = False,
    auto_quarantine: bool = False,
    protected_users: set[str] | None = None,
    alert_cmd: str | None = None,
    thresholds: WatchThresholds | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> tuple[int, str]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fh = open(lock_path, "w", encoding="utf-8")
    try:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0, "[SKIP] Another cluster_watch instance is already running (flock held)."

        cfg_thresholds = thresholds or WatchThresholds()
        prev_snapshot = load_snapshot(snapshot_path)
        prev_nodes = prev_snapshot.get("nodes", {})

        parsed_nodes = [parse_node_spec(s) for s in node_specs]
        assessments: list[NodeAssessment] = []
        new_nodes: dict[str, Any] = dict(prev_nodes)
        bridge_metrics: NodeMetrics | None = None

        for alias, role in parsed_nodes:
            metrics = collect_node(
                alias,
                role,
                reset_stats=reset_stats,
                runner=runner,
            )
            if role == "bridge":
                bridge_metrics = metrics
            assessment = assess_node(metrics, prev_nodes.get(alias), cfg_thresholds)
            assessments.append(assessment)
            if metrics.reachable:
                new_nodes[alias] = asdict(metrics)

        save_snapshot_atomic(
            snapshot_path,
            {"updated_at": int(time.time()), "nodes": new_nodes},
        )

        q_notes: list[str] = []
        if auto_quarantine:
            target_user, q_notes = evaluate_quarantine_candidates(
                assessments,
                bridge_metrics,
                cfg_thresholds,
                protected_users=protected_users,
            )
            if target_user and bridge_metrics:
                ok, detail = execute_quarantine(
                    bridge_metrics.alias, target_user, runner=runner
                )
                if ok:
                    q_notes.append(
                        f"Quarantined '{target_user}' on '{bridge_metrics.alias}'. "
                        f"Restore: ssh {bridge_metrics.alias} 'cd /opt/marzneshin && sudo ./script.sh user enable {target_user}'"
                    )
                else:
                    q_notes.append(
                        f"Quarantine failed for '{target_user}' (live config untouched): {detail}"
                    )

        report = format_report(assessments, bridge_metrics, cfg_thresholds, q_notes)
        if alert_cmd:
            dispatch_alert_if_needed(
                assessments, report, alert_cmd=alert_cmd, runner=runner
            )

        exit_code = 0
        if any(a.status in ("CRIT", "UNREACHABLE") for a in assessments):
            exit_code = 2
        elif any(a.status == "WARN" for a in assessments):
            exit_code = 1
        return exit_code, report
    finally:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fh.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Passive, zero-emission SSH cluster watchdog (Phase 1: manual read-only by default)."
    )
    parser.add_argument(
        "--nodes",
        nargs="+",
        default=["mos:bridge", "server-de:exit"],
        help="SSH aliases with optional :bridge or :exit role (default: mos:bridge server-de:exit)",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=DEFAULT_SNAPSHOT_PATH,
        help=f"Local bounded snapshot JSON path (default: {DEFAULT_SNAPSHOT_PATH})",
    )
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=DEFAULT_LOCK_PATH,
        help=f"Single-instance flock path (default: {DEFAULT_LOCK_PATH})",
    )
    parser.add_argument(
        "--reset-stats",
        action="store_true",
        help="Pass -reset=true to bridge in-memory StatsService query",
    )
    parser.add_argument(
        "--alert-cmd",
        default=None,
        help="Phase 2 opt-in executable receiving anonymized alert on stdin (silent on OK; forbidden on mos)",
    )
    parser.add_argument(
        "--auto-quarantine",
        action="store_true",
        help="Phase 3 opt-in guarded quarantine for media-consumer users (disabled by default)",
    )
    parser.add_argument(
        "--protect-user",
        action="append",
        default=[],
        help="Additional user name to permanently whitelist from auto-quarantine (ai-owner is always protected)",
    )
    parser.add_argument(
        "--print-systemd-example",
        action="store_true",
        help="Print example Phase 2 systemd --user timer and exit",
    )
    args = parser.parse_args(argv)

    if args.print_systemd_example:
        print(SYSTEMD_TIMER_EXAMPLE)
        return 0

    code, report = run_watch(
        args.nodes,
        snapshot_path=args.snapshot,
        lock_path=args.lock_file,
        reset_stats=bool(args.reset_stats),
        auto_quarantine=bool(args.auto_quarantine),
        protected_users=set(args.protect_user or []),
        alert_cmd=args.alert_cmd,
    )
    print(report)
    return code


if __name__ == "__main__":
    sys.exit(main())
