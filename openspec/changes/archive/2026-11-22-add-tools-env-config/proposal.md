# Proposal: Add Gitignored `tools/.env` Configuration for Workstation Tools

## Why

`tools/cluster_watch.py` currently hardcodes a two-node default (`mos:bridge server-de:exit`) and protected user defaults in tracked Python code, forcing manual `--nodes` arguments on every invocation as new exit servers are added to the cluster. Moving workstation node aliases, protected account aliases, and optional alert settings into a separate gitignored `tools/.env` file keeps live infrastructure topology out of Git while making `tools/` work seamlessly across the entire cluster as new servers are provisioned.

## What Changes

- Add a tracked placeholder template `tools/.env.example` documenting workstation-only variables (`MARZNESHIN_WATCH_NODES`, `MARZNESHIN_PROTECT_USERS`, `MARZNESHIN_ALERT_CMD`) without real aliases, IPs, or secrets.
- Add explicit ignore rules for `tools/.env` and `!tools/.env.example` in `.gitignore` alongside existing `.env` protections.
- Add a stdlib-only `.env` loader in `tools/cluster_watch.py` with strict precedence (`CLI flags > os.environ > tools/.env > fallback defaults`) and explicit `env_file` override/isolation for tests.
- Add unit tests covering `tools/.env` parsing, precedence, quote/comment handling, and isolation of `pytest` from a real local `tools/.env`.

## Capabilities

### New Capabilities
- *(none)*

### Modified Capabilities
- `passive-cluster-watchdog`: Support loading cluster node aliases (`--nodes`), protected user aliases (`--protect-user`), and optional alert command (`--alert-cmd`) from a gitignored `tools/.env` file on the admin workstation while preserving CLI overrides and test isolation.

## Impact

- `tools/cluster_watch.py` (stdlib `.env` loading and CLI/env precedence)
- `tools/.env.example` (new tracked template file)
- `.gitignore` (explicit `tools/.env` / `!tools/.env.example` rules)
- `tests/test_passive_cluster_watchdog.py` (unit tests for `.env` loading and isolation)
- Zero impact on server-side `/opt/marzneshin/.env`, `docker-compose.yml`, `mos` bridge Zero-Emission, or Xray/Nginx runtime behavior.
