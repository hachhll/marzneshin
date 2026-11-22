# Design: Workstation `tools/.env` Configuration

## Context

See `proposal.md` for motivation. Currently `tools/cluster_watch.py` is pure Python stdlib (no third-party dependencies such as `python-dotenv`) and defaults `--nodes` to `["mos:bridge", "server-de:exit"]`, while server runtime `.env` (`/opt/marzneshin/.env`) is strictly scoped to single-node Docker Compose deployment via `script.sh`.

## Goals / Non-Goals

**Goals:**
- Provide a dedicated workstation-only `tools/.env` configuration file (plus tracked `tools/.env.example`) for logical server aliases (`<ssh_alias>:<role>`) and protected user aliases.
- Keep `tools/cluster_watch.py` zero-dependency (stdlib-only `.env` parser).
- Enforce strict precedence: `CLI flags > os.environ > tools/.env > built-in defaults`.
- Ensure `pytest` and library callers remain completely isolated from any real `tools/.env` on the developer workstation.

**Non-Goals:**
- Replacing `~/.ssh/config` or storing IPs, ports, SSH keys, VPN UUIDs, or `vless://` links in `tools/.env`.
- Modifying server-side `/opt/marzneshin/.env`, `docker-compose.yml`, or `mos` Zero-Emission behavior.
- Adding multi-bridge `bridge_metrics` aggregation in this change (current topology is 1 bridge + N exits).

## Decisions

1. **Separate `tools/.env` from root `.env`:**
   - *Rationale:* Root `.env` holds single-server container parameters (`APPLIANCE_DOMAIN`, `XRAY_*`, `NGINX_*`). Mixing workstation SSH/cluster inventory into root `.env` would create confusion between server and admin-workstation scopes.
   - *Alternative considered:* `~/.config/marzneshin-watch/nodes.txt`. Keeping `tools/.env` inside `tools/` matches the user's request, reuses `.env` conventions (`tools/.env.example`), and works for future scripts in `tools/`.

2. **Stdlib-only `.env` parser (`load_tools_env`):**
   - *Rationale:* `tools/cluster_watch.py` runs directly with system `python3` without requiring `.venv` or `python-dotenv`. A small stdlib parser handling blank lines, `#` comments, `export KEY=VALUE`, and single/double-quoted values is trivial to test and has zero supply-chain surface.
   - *Variables:*
     - `MARZNESHIN_WATCH_NODES`: whitespace- or comma-separated `<alias>:<role>` entries (e.g. `"bridge-1:bridge exit-1:exit exit-2:exit"`).
     - `MARZNESHIN_PROTECT_USERS`: whitespace- or comma-separated user aliases merged with built-in `"owner"` protection.
     - `MARZNESHIN_ALERT_CMD`: optional Phase 2 alert executable path.

3. **Precedence and Test Isolation:**
   - *Rationale:* `argparse` defaults `--nodes`, `--protect-user`, and `--alert-cmd` to `None` before resolution in `main()` so explicit CLI flags can be distinguished from omitted flags.
   - `main(argv=None, *, env_file: Path | None = DEFAULT_TOOLS_ENV_PATH, environ: Mapping[str, str] | None = None)` allows unit tests to pass `env_file=tmp_path / ".env"` or `env_file=None`, guaranteeing deterministic test execution regardless of whether the workstation has a live `tools/.env`.

4. **`.gitignore` Hygiene:**
   - `.gitignore` already ignores `.env` and `.env.*` while whitelisting `!.env.example`; adding explicit `tools/.env`, `tools/.env.*`, and `!tools/.env.example` rules makes the protection obvious to future maintainers.

## Risks / Trade-offs

- **Accidental world-readable `tools/.env`** -> Document `chmod 600 tools/.env` in `tools/.env.example` and emit a stderr warning (non-fatal) if `tools/.env` has group/other permissions on POSIX.
- **Whitespace vs comma separation in `MARZNESHIN_WATCH_NODES`** -> Accept both whitespace and commas (`re.split(r"[\s,]+", raw.strip())`) so users cannot trip over delimiter formatting.
