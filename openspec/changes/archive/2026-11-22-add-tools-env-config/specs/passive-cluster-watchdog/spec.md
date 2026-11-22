## ADDED Requirements

### Requirement: Gitignored workstation `tools/.env` configuration for cluster aliases
The workstation watchdog (`tools/cluster_watch.py`) SHALL support loading cluster node aliases (`MARZNESHIN_WATCH_NODES`), protected user aliases (`MARZNESHIN_PROTECT_USERS`), and optional alert command (`MARZNESHIN_ALERT_CMD`) from a local gitignored `tools/.env` file using stdlib parsing only, with precedence `CLI flags > process environment > tools/.env > fallback defaults`.

#### Scenario: `tools/.env` configures multi-exit node list without CLI flags
- **WHEN** `tools/.env` defines `MARZNESHIN_WATCH_NODES` with a bridge alias and multiple exit aliases and the administrator runs `tools/cluster_watch.py` without `--nodes`
- **THEN** the watchdog inspects all nodes listed in `tools/.env` instead of only the two-node fallback

#### Scenario: CLI flags and process environment override `tools/.env`
- **WHEN** `tools/.env` defines `MARZNESHIN_WATCH_NODES` or `MARZNESHIN_PROTECT_USERS` and the caller passes `--nodes`, `--protect-user`, or process environment variables
- **THEN** CLI flags take highest precedence over process environment variables, which take precedence over `tools/.env`

#### Scenario: Missing `tools/.env` falls back safely and unit tests stay isolated
- **WHEN** `tools/.env` does not exist or tests invoke the watchdog with an isolated `env_file` path
- **THEN** the watchdog falls back to default parameters without error and tests never read the workstation's live `tools/.env`

### Requirement: Repository hygiene for workstation `.env` templates
The repository SHALL ignore `tools/.env` in `.gitignore` while tracking a placeholder-only `tools/.env.example` template that contains no real server aliases, user names, IP addresses, domains, or credentials.

#### Scenario: Local `tools/.env` stays untracked while `tools/.env.example` is tracked
- **WHEN** `tools/.env` is created on the admin workstation alongside `tools/.env.example`
- **THEN** `git check-ignore` ignores `tools/.env` and allows `tools/.env.example` to remain tracked in Git
