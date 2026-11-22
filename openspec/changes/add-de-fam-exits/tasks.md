# Tasks

## 1. Provision `server-de-fam1` (`de-fam1.armenytravel.com`)

- [x] 1.1 Sync the repository to `server-de-fam1:/opt/marzneshin` and verify `/opt/marzneshin/script.sh` is executable.
- [x] 1.2 Run `sudo /opt/marzneshin/script.sh --domain de-fam1.armenytravel.com` on `server-de-fam1`, update workstation `~/.ssh/config` (`User stealth`, `Port 22222`), and verify `ssh server-de-fam1 'whoami'` returns `stealth`.
- [x] 1.3 Run `sudo /opt/marzneshin/script.sh self-test` on `server-de-fam1` and confirm all passive safety checks report `[PASS]`.

## 2. Provision `server-de-fam2` (`de-fam2.armenytravel.com`)

- [x] 2.1 Sync the repository to `server-de-fam2:/opt/marzneshin` and verify `/opt/marzneshin/script.sh` is executable.
- [x] 2.2 Run `sudo /opt/marzneshin/script.sh --domain de-fam2.armenytravel.com` on `server-de-fam2`, update workstation `~/.ssh/config` (`User stealth`, `Port 22222`), and verify `ssh server-de-fam2 'whoami'` returns `stealth`.
- [x] 2.3 Run `sudo /opt/marzneshin/script.sh self-test` on `server-de-fam2` and confirm all passive safety checks report `[PASS]`.

## 3. Register Exits on `mos` & Verify Cluster

- [x] 3.1 Register `server-de-fam1` and `server-de-fam2` on `mos` (`upstream add ... --role media --transport xhttp`) with zero users assigned, and verify `upstream list` on `mos` shows all 5 upstreams with zero `/24` subnet errors.
- [x] 3.2 Update workstation `tools/.env` (`MARZNESHIN_WATCH_NODES`) to include `server-de-fam1:exit` and `server-de-fam2:exit`, run `sudo /opt/marzneshin/script.sh self-test` on `mos`, and verify `python3 tools/cluster_watch.py` reports all 6 nodes healthy.
