## Why

While rolling out `multi-exit-bridge-cluster` across `mos` and `oblako-fam1`, two gaps were left behind for follow-up:
1. `server-de` (`exit-ai`) is still running the pre-cluster codebase and Xray configuration without the mandatory server-side domestic RU egress blackhole (`domain:ru`, `domain:su`, `domain:xn--p1ai`, `geoip:ru` -> `block`).
2. The recently archived main OpenSpec specs (`anti-drift-safety-policy` and `multi-exit-cluster-routing`) and `openspec/config.yaml` still state that `ai-isolated` and `media` upstreams MUST reject shared registrable root domains, whereas the requirement was relaxed in code (`app/bridge_state.py`) and `AGENTS.md` to a non-fatal warning (`WARN`) so both exits can safely share a root domain while keeping `/24` IPv4 subnet and user-isolation guards strict.

## What Changes

- Sync the updated repository code and container image to `server-de` and atomically re-render its `exit` Xray configuration with the server-side RU egress blackhole while preserving existing Reality keys, UUID, `shortId`, and XHTTP secret path so the live `mos -> server-de` cascade remains uninterrupted.
- Verify `server-de` and the 3-node cluster (`mos`, `server-de`, `oblako-fam1`) via passive `./script.sh self-test` and `python3 tools/cluster_watch.py`.
- Reconcile `openspec/specs/anti-drift-safety-policy/spec.md`, `openspec/specs/multi-exit-cluster-routing/spec.md`, and `openspec/config.yaml` so shared root domains between `ai-isolated` and `media` upstreams are explicitly specified as allowed with a non-fatal warning (preserving strict `/24` subnet and `ai-isolated` single-owner guards), and commit the clean repository state to Git.

## Capabilities

### Modified Capabilities
- `anti-drift-safety-policy`: Align passive `self-test` requirement so shared root domain between `ai-isolated` and `media` exits emits a non-fatal warning rather than failing validation, while enforcing RU egress blackholes on all foreign exit nodes including `server-de`.
- `multi-exit-cluster-routing`: Align upstream isolation specification so shared root domains emit a warning instead of hard rejection, while keeping `/24` IPv4 subnet and single-`ai-owner` isolation mandatory.

## Impact

- Live host: `server-de` (`/opt/marzneshin`, `/var/lib/marzneshin/xray/config.json`, `marzneshin-xray` container).
- OpenSpec documentation/context: `openspec/specs/anti-drift-safety-policy/spec.md`, `openspec/specs/multi-exit-cluster-routing/spec.md`, `openspec/config.yaml`.
- Git hygiene: clean commit of repository code/spec updates with zero live IPs, UUIDs, or Reality keys committed.
