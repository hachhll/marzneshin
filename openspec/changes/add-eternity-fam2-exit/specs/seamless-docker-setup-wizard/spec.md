## ADDED Requirements

### Requirement: Mandatory UFW and iptables availability before firewall and TCPMSS hardening
During non-dry-run installation, `script.sh` SHALL verify that `ufw` and `iptables` are available (installing missing packages via `apt-get` on exit nodes or aborting with an explicit error if unavailable) before applying firewall and `TCPMSS=1360` rules, rather than silently skipping UFW or `*mangle` clamping on minimal Ubuntu images. In `--dry-run`, `script.sh` SHALL emit an explicit warning or error if `ufw` or `iptables` is missing.

#### Scenario: Minimal Ubuntu 26.04 exit host missing ufw and iptables installs them before hardening
- **WHEN** the owner runs `sudo ./script.sh --domain vpn.example.com` on a minimal Ubuntu 26.04 host without `ufw` or `iptables` pre-installed
- **THEN** `script.sh` installs `ufw` and `iptables` before configuring firewall rules, applies `ufw limit 22222/tcp`, opens `80/tcp` and `443/tcp`, and writes persistent `*mangle` `TCPMSS --set-mss 1360` rules

#### Scenario: Dry-run reports missing firewall or iptables prerequisites explicitly
- **WHEN** `script.sh --dry-run` runs on a host missing `ufw` or `iptables`
- **THEN** `script.sh` reports the missing prerequisite explicitly instead of silently omitting firewall and `TCPMSS=1360` checks

### Requirement: Zero-Emission CLI execution on already-running Cascade Bridges
When executing routine CLI subcommands (`status`, `upstream`, `user`, `stats`, `xhttp`, `bridge-transport`, `rotate`, `decoy`) on a host without a local `.venv` or host `nacl`/`cryptography` packages, `script.sh` SHALL execute `app.cli` inside the already-running `marzneshin-xray` container (or via `--no-build` when an image already exists) before falling back to `docker compose run --build`, ensuring zero outbound Docker registry requests on the Cascade Bridge.

#### Scenario: Running upstream or user management on mos emits zero outbound registry traffic
- **WHEN** the owner runs `./script.sh upstream ...` or `./script.sh user ...` on `mos` while `marzneshin-xray` is already running without a host `.venv`
- **THEN** `script.sh` runs `python3 -m app.cli` via `docker exec` against `marzneshin-xray` without invoking `docker compose run --build` or contacting external container registries
