# Proposal

## Why

To add spare `media` exit capacity behind the `mos` Cascade Bridge without concentrating family traffic on `oblako-fam1` or `eternity-fam2`, two new German VPS nodes (`server-de-fam1` and `server-de-fam2`) need to be provisioned and registered as `media` upstreams on `mos` with zero users assigned initially.

## What Changes

- **Provision `server-de-fam1` (`de-fam1.armenytravel.com`) and `server-de-fam2` (`de-fam2.armenytravel.com`) as `media` exit nodes:**
  - Sync `/opt/marzneshin`, deploy via `script.sh --domain <fqdn>` (Docker, Xray `v26.6.27`, Nginx `>= 1.30.7-alpine` + ACME TLS 1.3, RU egress blackhole, UFW, `TCPMSS=1360`, SSH hardened to `stealth:22222`), and update workstation `~/.ssh/config`.
  - Verify both nodes with `sudo /opt/marzneshin/script.sh self-test`.
- **Register both exits on `mos` (no users assigned):**
  - Run `upstream add server-de-fam1 --role media --transport xhttp ...` and `upstream add server-de-fam2 --role media --transport xhttp ...` on `mos`.
  - Verify `upstream list` and `self-test` on `mos`.
- **Update cluster monitoring:**
  - Add `server-de-fam1:exit` and `server-de-fam2:exit` to workstation `tools/.env` (`MARZNESHIN_WATCH_NODES`) and verify all 6 nodes via `python3 tools/cluster_watch.py`.

## Capabilities

### New Capabilities
- *(none)*

### Modified Capabilities
- *(none — pure operational provisioning using existing multi-exit cluster capabilities)*

## Impact

- **Repository code:** None.
- **Live infrastructure:** `server-de-fam1`, `server-de-fam2`, `mos` (`state.json`, `xray/config.json`), workstation `~/.ssh/config` and `tools/.env` (gitignored).
