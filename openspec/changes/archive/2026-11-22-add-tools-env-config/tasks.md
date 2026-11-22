# Tasks

## 1. Repository Ignore Rules & Placeholder Template

- [x] 1.1 Update `.gitignore` with explicit `tools/.env`, `tools/.env.*`, and `!tools/.env.example` rules and verify via `git check-ignore -v tools/.env tools/.env.example` that `tools/.env` is ignored while `tools/.env.example` is tracked.
- [x] 1.2 Create `tools/.env.example` containing only placeholder aliases (`MARZNESHIN_WATCH_NODES`, `MARZNESHIN_PROTECT_USERS`, commented `MARZNESHIN_ALERT_CMD`) and `chmod 600` usage guidance, and verify no live aliases, IPs, domains, or credentials are present.

## 2. Stdlib `.env` Loader & Precedence in `tools/cluster_watch.py`

- [x] 2.1 Implement stdlib-only `.env` parsing (`load_tools_env`, supporting `#` comments, blank lines, optional `export`, and single/double quotes) plus non-fatal stderr warning when `tools/.env` is readable by group/others, and verify with unit tests in `tests/test_passive_cluster_watchdog.py`.
- [x] 2.2 Wire `MARZNESHIN_WATCH_NODES`, `MARZNESHIN_PROTECT_USERS`, and `MARZNESHIN_ALERT_CMD` resolution into `tools/cluster_watch.py` `main()` with precedence `CLI flags > os.environ > tools/.env > built-in defaults` and injectable `env_file` / `environ` parameters for test isolation; verify via unit tests covering precedence, missing `tools/.env`, and isolation from real workstation files.

## 3. End-to-End Verification

- [x] 3.1 Run `.venv/bin/python -m pytest tests/test_passive_cluster_watchdog.py tests/ -v` and verify all tests pass with zero failures, and verify `python3 tools/cluster_watch.py --help` documents `tools/.env` behavior cleanly.
