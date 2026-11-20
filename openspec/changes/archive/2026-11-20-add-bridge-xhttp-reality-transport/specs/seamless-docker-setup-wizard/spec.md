# Spec Delta

## MODIFIED Requirements

### Requirement: Complete SSH CLI subcommands without a web wizard
`script.sh` SHALL support subcommands `status`, `xhttp on|off`, `bridge-transport xhttp [--path <64-hex>]|vision`, `rotate`, `decoy <preset_or_url>`, and `self-test` over SSH (plus optional `--upstream-transport vision|xhttp` and `--upstream-xhttp-path <64-hex>` installer flags on Cascade Bridges), SHALL NOT expose any browser `/setup` wizard or HTTP admin endpoints, SHALL keep `status` side-effect-free with respect to daemon reload triggers, SHALL validate updated Xray configurations before restarting services, and SHALL execute `self-test` reliably in 100% passive local mode by default on hosts without local Python virtualenvs while passing detected custom SSH ports.

#### Scenario: Owner manages appliance state entirely via SSH subcommands
- **WHEN** the owner runs `./script.sh status`, `./script.sh xhttp on`, `./script.sh xhttp off`, `./script.sh bridge-transport xhttp --path <64-hex>`, `./script.sh bridge-transport vision`, `./script.sh rotate`, `./script.sh decoy <target>`, or `./script.sh self-test`
- **THEN** mutating subcommands update the local Xray/Nginx configuration, validate and reload cleanly, and print the updated links and terminal QR codes, whereas `status` displays current credentials without triggering a daemon reload and `self-test` runs passively without emitting network probes by default

#### Scenario: Owner switches and rolls back Cascade Bridge upstream transport between Vision and XHTTP without downtime
- **WHEN** the owner first enables `./script.sh xhttp on` on the exit node, then runs `./script.sh bridge-transport xhttp --path <64-hex>` on the bridge node, and later runs `./script.sh bridge-transport vision` on the bridge node
- **THEN** the bridge persists `<64-hex>` in local state, switches the `Bridge -> Exit` outbound to `VLESS + XHTTP + Reality + xmux` after config validation without modifying end-user client credentials, and rolls back to `VLESS + TCP + Reality + Vision` in a single command on the bridge while the exit node accepts both transports on `:443`
