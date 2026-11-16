#!/usr/bin/env bash
set -euo pipefail

APP_NAME="marzneshin"
DATA_DIR="${MARZNESHIN_DATA_DIR:-/var/lib/$APP_NAME}"
CREDENTIALS_DIR="${VPN_CREDENTIALS_DIR:-/root/vpn-credentials}"
COMPOSE_PROJECT_DIR="${MARZNESHIN_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
DOMAIN=""
ACME_EMAIL=""
DECOY_TARGET=""
ALLOW_RISKY_TLD=0
DRY_RUN=0
BRIDGE_MODE=0
UPSTREAM_IP=""
UPSTREAM_DOMAIN=""
UPSTREAM_UUID=""
UPSTREAM_PBK=""
UPSTREAM_SID=""
BRIDGE_SNI=""
BRIDGE_IP=""
BRIDGE_ACME=0
SERVER_IP=""

usage() {
    cat <<'EOF'
Usage:
  script.sh --domain <fqdn> [--email <email>] [--decoy <preset|url>] [--allow-risky-tld] [--dry-run]
  script.sh --bridge --upstream-ip <ip> --upstream-domain <fqdn> --upstream-uuid <uuid> \
            --upstream-pbk <pubkey> --upstream-sid <shortid> [--bridge-sni <sni>] [--bridge-ip <ip>] [--bridge-acme] [--email <email>] [--dry-run]
  script.sh status
  script.sh xhttp <on|off>
  script.sh rotate
  script.sh decoy <corporate|blog|coming_soon|https://...>
  script.sh self-test [--active-probe]

Zero-Surface Single-User VLESS Self-Reality Appliance & Cascade Bridge Installer.
EOF
}

log_info() {
    printf '[INFO] %s\n' "$1"
}

log_warn() {
    printf '[WARN] %s\n' "$1" >&2
}

log_err() {
    printf '[ERROR] %s\n' "$1" >&2
}

run_python_cli() {
    if [ -x "${COMPOSE_PROJECT_DIR}/.venv/bin/python" ]; then
        PYTHONPATH="$COMPOSE_PROJECT_DIR" "${COMPOSE_PROJECT_DIR}/.venv/bin/python" -m app.cli \
            --data-dir "$DATA_DIR" --credentials-dir "$CREDENTIALS_DIR" "$@"
    elif command -v python3 >/dev/null 2>&1 && PYTHONPATH="$COMPOSE_PROJECT_DIR" python3 -c "import nacl, cryptography" >/dev/null 2>&1; then
        PYTHONPATH="$COMPOSE_PROJECT_DIR" python3 -m app.cli \
            --data-dir "$DATA_DIR" --credentials-dir "$CREDENTIALS_DIR" "$@"
    else
        docker compose -f "${COMPOSE_PROJECT_DIR}/docker-compose.yml" run --build --rm \
            -v "${DATA_DIR}:${DATA_DIR}" \
            -v "${CREDENTIALS_DIR}:${CREDENTIALS_DIR}" \
            --entrypoint python3 xray \
            -m app.cli --data-dir "$DATA_DIR" --credentials-dir "$CREDENTIALS_DIR" "$@"
    fi
}

detect_ssh_ports() {
    local ports="22 22222"
    if [ -n "${SSH_CONNECTION:-}" ]; then
        local conn_port
        conn_port="$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')"
        if printf '%s' "$conn_port" | grep -Eq '^[0-9]+$'; then
            ports="$ports $conn_port"
        fi
    fi
    local cfg_file cfg_ports
    for cfg_file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        if [ -f "$cfg_file" ]; then
            cfg_ports="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2}' "$cfg_file" 2>/dev/null || true)"
            if [ -n "$cfg_ports" ]; then
                ports="$ports $cfg_ports"
            fi
        fi
    done
    printf '%s\n' "$ports" | tr ' ' '\n' | awk 'NF && !seen[$0]++'
}

reload_services_if_running() {
    if command -v docker >/dev/null 2>&1; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^marzneshin-xray$'; then
            docker restart marzneshin-xray >/dev/null 2>&1 || true
        fi
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^marzneshin-nginx$'; then
            docker exec marzneshin-nginx nginx -s reload -e /dev/null -c "${DATA_DIR}/nginx-runtime/nginx.conf" >/dev/null 2>&1 || true
        fi
    fi
}

handle_subcommand() {
    local subcmd="${1:-}"
    case "$subcmd" in
        status)
            run_python_cli status
            exit 0
            ;;
        xhttp)
            shift
            local mode="${1:-}"
            if [ "$mode" != "on" ] && [ "$mode" != "off" ]; then
                log_err "Usage: script.sh xhttp <on|off>"
                exit 1
            fi
            run_python_cli xhttp "$mode"
            reload_services_if_running
            exit 0
            ;;
        rotate)
            run_python_cli rotate
            reload_services_if_running
            exit 0
            ;;
        decoy)
            shift
            local target="${1:-}"
            if [ -z "$target" ]; then
                log_err "Usage: script.sh decoy <corporate|blog|coming_soon|https://...>"
                exit 1
            fi
            run_python_cli decoy "$target"
            reload_services_if_running
            exit 0
            ;;
        self-test)
            shift
            local domain_val="" ssh_ports_val=""
            ssh_ports_val="$(detect_ssh_ports | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
            if [ -f "${DATA_DIR}/state.json" ] && command -v python3 >/dev/null 2>&1; then
                domain_val="$(python3 - "${DATA_DIR}/state.json" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1]))["domain"])
except Exception:
    pass
PY
)"
            fi
            APPLIANCE_DOMAIN="$domain_val" \
                XRAY_CONFIG_PATH="${DATA_DIR}/xray/config.json" \
                NGINX_RUNTIME_DIR="${DATA_DIR}/nginx-runtime" \
                SSH_PORT="${SSH_PORT:-$ssh_ports_val}" \
                "${COMPOSE_PROJECT_DIR}/scripts/self_test.sh" "$@"
            exit $?
            ;;
    esac
}

detect_local_ipv4() {
    local ip=""
    if command -v ip >/dev/null 2>&1; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
    fi
    if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
    printf '%s' "$ip"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --domain)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--domain requires a value"
                    exit 1
                fi
                DOMAIN="$1"
                ;;
            --domain=*)
                DOMAIN="${1#*=}"
                ;;
            --email)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--email requires a value"
                    exit 1
                fi
                ACME_EMAIL="$1"
                ;;
            --email=*)
                ACME_EMAIL="${1#*=}"
                ;;
            --decoy)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--decoy requires a value"
                    exit 1
                fi
                DECOY_TARGET="$1"
                ;;
            --decoy=*)
                DECOY_TARGET="${1#*=}"
                ;;
            --bridge)
                BRIDGE_MODE=1
                ;;
            --upstream-ip)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--upstream-ip requires a value"
                    exit 1
                fi
                UPSTREAM_IP="$1"
                ;;
            --upstream-ip=*)
                UPSTREAM_IP="${1#*=}"
                ;;
            --upstream-domain)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--upstream-domain requires a value"
                    exit 1
                fi
                UPSTREAM_DOMAIN="$1"
                ;;
            --upstream-domain=*)
                UPSTREAM_DOMAIN="${1#*=}"
                ;;
            --upstream-uuid)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--upstream-uuid requires a value"
                    exit 1
                fi
                UPSTREAM_UUID="$1"
                ;;
            --upstream-uuid=*)
                UPSTREAM_UUID="${1#*=}"
                ;;
            --upstream-pbk)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--upstream-pbk requires a value"
                    exit 1
                fi
                UPSTREAM_PBK="$1"
                ;;
            --upstream-pbk=*)
                UPSTREAM_PBK="${1#*=}"
                ;;
            --upstream-sid)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--upstream-sid requires a value"
                    exit 1
                fi
                UPSTREAM_SID="$1"
                ;;
            --upstream-sid=*)
                UPSTREAM_SID="${1#*=}"
                ;;
            --bridge-sni)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--bridge-sni requires a value"
                    exit 1
                fi
                BRIDGE_SNI="$1"
                ;;
            --bridge-sni=*)
                BRIDGE_SNI="${1#*=}"
                ;;
            --bridge-ip)
                shift
                if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                    log_err "--bridge-ip requires a value"
                    exit 1
                fi
                BRIDGE_IP="$1"
                ;;
            --bridge-ip=*)
                BRIDGE_IP="${1#*=}"
                ;;
            --bridge-acme)
                BRIDGE_ACME=1
                ;;
            --allow-risky-tld)
                ALLOW_RISKY_TLD=1
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log_err "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    if [ "$BRIDGE_MODE" -eq 1 ]; then
        if [ -z "$UPSTREAM_IP" ] || ! printf '%s' "$UPSTREAM_IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            log_err "--bridge requires a valid numeric IPv4 --upstream-ip <ip> (got: '${UPSTREAM_IP}')"
            exit 1
        fi
        UPSTREAM_DOMAIN="$(printf '%s' "$UPSTREAM_DOMAIN" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]//g')"
        if [ -z "$UPSTREAM_DOMAIN" ] || ! printf '%s' "$UPSTREAM_DOMAIN" | grep -Eq '^[a-z0-9.-]+\.[a-z]{2,}$'; then
            log_err "--bridge requires a valid --upstream-domain <fqdn> (got: '${UPSTREAM_DOMAIN}')"
            exit 1
        fi
        if [ -z "$UPSTREAM_UUID" ] || [ -z "$UPSTREAM_PBK" ] || [ -z "$UPSTREAM_SID" ]; then
            log_err "--bridge requires --upstream-uuid, --upstream-pbk, and --upstream-sid"
            exit 1
        fi
        BRIDGE_SNI="$(printf '%s' "${BRIDGE_SNI:-$UPSTREAM_DOMAIN}" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]//g')"
        if [ "$BRIDGE_ACME" -eq 1 ] && [ "$BRIDGE_SNI" = "$UPSTREAM_DOMAIN" ]; then
            log_err "--bridge-acme requires an independent --bridge-sni <domain> pointing to the bridge IP (never reuse --upstream-domain '${UPSTREAM_DOMAIN}', RCA Risk #1/#7)."
            exit 1
        fi
        if [ "$BRIDGE_ACME" -eq 0 ] && [ "$BRIDGE_SNI" = "$UPSTREAM_DOMAIN" ]; then
            log_warn "Bridge SNI shares upstream domain '${UPSTREAM_DOMAIN}' with a localhost dummy cert (RCA Risk #1/#7). Assign a dedicated domain -> bridge IP and pass --bridge-sni <domain> --bridge-acme when DNS is ready."
        fi
        DOMAIN="$BRIDGE_SNI"
        if [ -z "$BRIDGE_IP" ]; then
            BRIDGE_IP="$(detect_local_ipv4)"
            if printf '%s' "$BRIDGE_IP" | grep -Eq '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'; then
                log_err "Detected private NAT IPv4 (${BRIDGE_IP}) on local interface. Pass your public Moscow IPv4 explicitly via --bridge-ip <PUBLIC_IP>."
                exit 1
            fi
        fi
        if [ -z "$BRIDGE_IP" ]; then
            log_err "Could not detect bridge local IPv4 via kernel routing table; pass --bridge-ip <ip>."
            exit 1
        fi
        return 0
    fi

    if [ -z "$DOMAIN" ] && [ -t 0 ]; then
        printf 'Enter appliance domain (FQDN pointing directly to this server): '
        read -r DOMAIN
    fi

    DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]//g')"
    if [ -z "$DOMAIN" ] || ! printf '%s' "$DOMAIN" | grep -Eq '^[a-z0-9.-]+\.[a-z]{2,}$'; then
        log_err "Valid --domain <fqdn> is required (got: '${DOMAIN}')"
        exit 1
    fi
}

check_domain_tld_hygiene() {
    local tld="${DOMAIN##*.}"
    case "$tld" in
        xyz|top|club|icu|site|online|fun|space|buzz|monster)
            if [ "$ALLOW_RISKY_TLD" -ne 1 ]; then
                log_err "Domain '${DOMAIN}' uses high-risk abused TLD '.${tld}' flagged by TSPU ML classifiers (RCA Cause #1/#7). Use a reputable TLD (.com/.net/.org/.de/.eu) or pass --allow-risky-tld to override."
                exit 1
            fi
            log_warn "Proceeding with risky TLD '.${tld}' due to --allow-risky-tld."
            ;;
    esac
    log_info "Domain TLD check passed (.${tld}). Do not share this root domain across multiple VPN servers (RCA Cause #7)."
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_err "This installer must be run as root."
        exit 1
    fi
}

check_ntp_sync() {
    local synced=""
    if command -v timedatectl >/dev/null 2>&1; then
        synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
        if [ "$synced" = "yes" ]; then
            log_info "NTP synchronization verified (timedatectl)."
            return 0
        fi
        if timedatectl status 2>/dev/null | grep -qiE 'synchronized:[[:space:]]*yes'; then
            log_info "NTP synchronization verified."
            return 0
        fi
    fi
    if command -v chronyc >/dev/null 2>&1; then
        if chronyc tracking 2>/dev/null | grep -qiE 'Leap status[[:space:]]*:[[:space:]]*Normal'; then
            log_info "NTP synchronization verified (chronyc)."
            return 0
        fi
    fi
    log_err "System clock is not NTP-synchronized. Reality requires <=30s clock accuracy; enable systemd-timesyncd or chrony first."
    exit 1
}

check_ports_free() {
    local conflicts="" own_running=0
    if command -v docker >/dev/null 2>&1; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -Eq '^marzneshin-(xray|nginx)$'; then
            own_running=1
            if [ "$DRY_RUN" -eq 0 ]; then
                log_info "Stopping existing marzneshin-xray / marzneshin-nginx containers before port check..."
                docker stop marzneshin-nginx marzneshin-xray >/dev/null 2>&1 || true
            fi
        fi
    fi
    if command -v ss >/dev/null 2>&1; then
        conflicts="$(ss -tulnp 2>/dev/null | grep -E '(:80|:443)[[:space:]]' || true)"
    elif command -v lsof >/dev/null 2>&1; then
        conflicts="$(lsof -nP -iTCP:80 -iTCP:443 -sTCP:LISTEN 2>/dev/null || true)"
    fi
    if [ -n "$conflicts" ] && [ "$own_running" -eq 1 ] && [ "$DRY_RUN" -eq 1 ]; then
        conflicts="$(printf '%s\n' "$conflicts" | grep -Ev '"(xray|nginx)"' || true)"
    fi
    if [ -n "$conflicts" ]; then
        log_err "Ports 80 and 443 must be free before installation. Conflicting listeners detected:"
        printf '%s\n' "$conflicts" >&2
        exit 1
    fi
    log_info "Ports 80 and 443 are free."
}

configure_ufw_and_kernel() {
    local ssh_ports port
    ssh_ports="$(detect_ssh_ports)"

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "Dry-run: detected SSH port(s) ($(printf '%s' "$ssh_ports" | tr '\n' ' ' | sed 's/[[:space:]]*$//')) and verified kernel anti-storm profile."
        return 0
    fi

    # Persist flush-safe bidirectional TCPMSS = 1360 clamping in /etc/ufw/before.rules across reboots & ufw reload
    local ufw_before_rules="${UFW_BEFORE_RULES:-/etc/ufw/before.rules}"
    if [ -f "$ufw_before_rules" ] && ! grep -q -- 'ufw-mangle-tcpmss' "$ufw_before_rules" 2>/dev/null; then
        cat >> "$ufw_before_rules" <<'EOF'

# VPN-TCPMSS-1360
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:ufw-mangle-tcpmss - [0:0]
-F PREROUTING
-F INPUT
-F OUTPUT
-F POSTROUTING
-F ufw-mangle-tcpmss
-A ufw-mangle-tcpmss -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360
-A PREROUTING -p tcp -j ufw-mangle-tcpmss
-A INPUT -p tcp -j ufw-mangle-tcpmss
-A OUTPUT -p tcp -j ufw-mangle-tcpmss
-A POSTROUTING -p tcp -j ufw-mangle-tcpmss
COMMIT
EOF
    fi

    if command -v ufw >/dev/null 2>&1; then
        for port in $ssh_ports; do
            ufw limit "${port}/tcp" >/dev/null 2>&1 || ufw allow "${port}/tcp" >/dev/null 2>&1 || true
        done
        if [ "$BRIDGE_MODE" -eq 0 ]; then
            ufw allow 80/tcp >/dev/null 2>&1 || true
        fi
        ufw allow 443/tcp >/dev/null 2>&1 || true
        if ! ufw status 2>/dev/null | grep -q 'Status: active'; then
            ufw --force enable >/dev/null 2>&1 || true
        else
            ufw reload >/dev/null 2>&1 || true
        fi
        if [ "$BRIDGE_MODE" -eq 1 ]; then
            log_info "UFW rules ensured for SSH ($(printf '%s' "$ssh_ports" | tr '\n' ' ')), 443/tcp only (Bridge Mode), and persistent TCPMSS=1360."
        else
            log_info "UFW rules ensured for SSH ($(printf '%s' "$ssh_ports" | tr '\n' ' ')), 80/tcp, 443/tcp, and persistent TCPMSS=1360."
        fi
    fi

    # RCA Cause #5 & #6: Kernel BBR + anti-SYN-storm + socket timeout + IPv6 disable
    if [ -d /etc/sysctl.d ]; then
        cat > /etc/sysctl.d/99-vpn-hardening.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_retries2 = 5
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fastopen = 0
net.ipv4.tcp_mtu_probing = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.mptcp.enabled = 0
EOF
        sysctl --system >/dev/null 2>&1 || true
        sysctl -w net.mptcp.enabled=0 >/dev/null 2>&1 || true
    fi

    # Immediate live bidirectional TCPMSS = 1360 clamping in kernel memory
    if command -v iptables >/dev/null 2>&1; then
        for chain in PREROUTING INPUT OUTPUT POSTROUTING; do
            iptables -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || \
                iptables -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
        done
    fi
}

configure_ssh_hardening() {
    local ssh_user="stealth"
    local ssh_port="22222"

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "Dry-run: SSH hardening would create sudo user '${ssh_user}', move SSH to port ${ssh_port}/tcp, close port 22/tcp, and disable root/password SSH login."
        return 0
    fi

    # 1. Collect SSH public keys before disabling root/password login to prevent lockout
    local tmp_keys
    tmp_keys="$(mktemp)"
    local key_src
    for key_src in /root/.ssh/authorized_keys "/home/${ssh_user}/.ssh/authorized_keys"; do
        if [ -s "$key_src" ]; then
            grep -E '^(ssh-|ecdsa-|sk-)' "$key_src" >> "$tmp_keys" 2>/dev/null || true
        fi
    done
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
        local sudo_home
        sudo_home="$(eval echo "~${SUDO_USER}" 2>/dev/null || true)"
        if [ -n "$sudo_home" ] && [ -s "${sudo_home}/.ssh/authorized_keys" ]; then
            grep -E '^(ssh-|ecdsa-|sk-)' "${sudo_home}/.ssh/authorized_keys" >> "$tmp_keys" 2>/dev/null || true
        fi
    fi
    awk 'NF && !seen[$0]++' "$tmp_keys" > "${tmp_keys}.uniq"
    mv "${tmp_keys}.uniq" "$tmp_keys"

    if [ ! -s "$tmp_keys" ]; then
        rm -f "$tmp_keys"
        log_err "No SSH public keys found in /root/.ssh/authorized_keys or /home/${ssh_user}/.ssh/authorized_keys. Refusing to disable root/password SSH login to prevent lockout."
        exit 1
    fi

    # 2. Create user 'stealth' with passwordless sudo (root privileges via sudo)
    if ! id -u "$ssh_user" >/dev/null 2>&1; then
        useradd -m -s /bin/bash -G sudo "$ssh_user"
        log_info "Created admin user '${ssh_user}'."
    else
        usermod -aG sudo "$ssh_user" >/dev/null 2>&1 || true
    fi

    mkdir -p /etc/sudoers.d
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ssh_user" > "/etc/sudoers.d/90-${ssh_user}"
    chmod 440 "/etc/sudoers.d/90-${ssh_user}"

    local user_ssh_dir="/home/${ssh_user}/.ssh"
    mkdir -p "$user_ssh_dir"
    cp "$tmp_keys" "${user_ssh_dir}/authorized_keys"
    rm -f "$tmp_keys"
    chown -R "${ssh_user}:${ssh_user}" "$user_ssh_dir"
    chmod 700 "$user_ssh_dir"
    chmod 600 "${user_ssh_dir}/authorized_keys"

    # 3. Ensure UFW allows port 22222/tcp before restarting SSH
    if command -v ufw >/dev/null 2>&1; then
        ufw limit "${ssh_port}/tcp" >/dev/null 2>&1 || ufw allow "${ssh_port}/tcp" >/dev/null 2>&1 || true
    fi

    # 4. Harden sshd_config via drop-in
    mkdir -p /etc/ssh/sshd_config.d
    if [ -f /etc/ssh/sshd_config ] && ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        printf 'Include /etc/ssh/sshd_config.d/*.conf\n%s\n' "$(cat /etc/ssh/sshd_config)" > /etc/ssh/sshd_config
    fi

    local dropin="/etc/ssh/sshd_config.d/99-marzneshin-hardening.conf"
    cat > "$dropin" <<EOF
AddressFamily inet
Port ${ssh_port}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers ${ssh_user}
MaxAuthTries 3
X11Forwarding no
EOF
    chmod 644 "$dropin"

    if command -v sshd >/dev/null 2>&1; then
        if ! sshd -t; then
            rm -f "$dropin"
            log_err "sshd -t validation failed; reverted SSH hardening drop-in."
            exit 1
        fi
    fi

    # 5. Switch Ubuntu 24+/26 from ssh.socket (which defaults to IPv6) to standalone ssh.service on IPv4
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now ssh.socket >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/ssh.socket.d/override.conf
        systemctl daemon-reload
        systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null 2>&1 || true
        systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
        service ssh restart >/dev/null 2>&1 || service sshd restart >/dev/null 2>&1 || true
    fi

    sleep 1

    # 6. Close port 22/tcp in UFW only after IPv4 port 22222 is verified listening
    if command -v ss >/dev/null 2>&1 && ss -4 -tln 2>/dev/null | grep -q ":${ssh_port}[[:space:]]"; then
        if command -v ufw >/dev/null 2>&1; then
            ufw delete limit 22/tcp >/dev/null 2>&1 || true
            ufw delete allow 22/tcp >/dev/null 2>&1 || true
            ufw delete allow OpenSSH >/dev/null 2>&1 || true
            ufw reload >/dev/null 2>&1 || true
        fi
        log_info "SSH hardened: user='${ssh_user}', port=${ssh_port}/tcp, port 22/tcp closed, PermitRootLogin=no, PasswordAuthentication=no."
    else
        log_warn "SSH port ${ssh_port} not yet confirmed listening; keeping port 22/tcp in UFW as safety fallback."
    fi
}

ensure_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log_err "Docker is not installed (dry-run cannot install packages)."
            exit 1
        fi
        log_info "Installing Docker..."
        curl -fsSL https://get.docker.com | sh
    fi
    if ! docker compose version >/dev/null 2>&1; then
        log_err "Docker Compose v2 plugin ('docker compose') is required."
        exit 1
    fi
    log_info "Docker and Docker Compose verified."
}

is_cloudflare_proxy_ip() {
    local ip="$1"
    python3 - "$ip" <<'PY'
import ipaddress, sys
nets = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
addr = ipaddress.ip_address(sys.argv[1])
for cidr in nets:
    if addr in ipaddress.ip_network(cidr):
        sys.exit(0)
sys.exit(1)
PY
}

verify_direct_dns() {
    local expected_ip="${1:-}"
    local server_ip resolved_ip
    if [ -n "$expected_ip" ]; then
        server_ip="$expected_ip"
    else
        server_ip="$(curl -fsS -4 --noproxy '*' --max-time 8 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    if [ -z "$server_ip" ]; then
        log_err "Failed to determine server public IPv4 address."
        exit 1
    fi

    if command -v dig >/dev/null 2>&1; then
        resolved_ip="$(dig +short A "$DOMAIN" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1 || true)"
    else
        resolved_ip="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)"
    fi

    if [ -z "$resolved_ip" ]; then
        log_err "DNS A record for '${DOMAIN}' could not be resolved. Set a direct A record pointing to ${server_ip}."
        exit 1
    fi

    if is_cloudflare_proxy_ip "$resolved_ip"; then
        log_err "Domain '${DOMAIN}' resolves to CDN proxy IP (${resolved_ip}). Disable proxy/CDN (orange cloud) and set DNS directly to ${server_ip}."
        exit 1
    fi

    if [ "$resolved_ip" != "$server_ip" ]; then
        log_err "Domain '${DOMAIN}' resolves to ${resolved_ip}, expected server public IP ${server_ip}."
        exit 1
    fi

    SERVER_IP="$server_ip"
    log_info "Direct DNS A record verified (${DOMAIN} -> ${server_ip})."
}

check_triple_ai_egress() {
    local gl_output gl trace_output loc warp anthropic_body
    # 1. Anonymous Google / Antigravity check (INNERTUBE_CONTEXT_GL != RU)
    gl_output="$(curl -fsSL --noproxy '*' --max-time 12 \
        -H 'Accept-Language: de-DE,de;q=0.9,en-US;q=0.8' \
        -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' \
        https://www.youtube.com/ 2>/dev/null || true)"
    gl="$(printf '%s' "$gl_output" | grep -oE '"INNERTUBE_CONTEXT_GL"[[:space:]]*:[[:space:]]*"[A-Z]{2}"' | head -n1 | sed -E 's/.*"([A-Z]{2})"/\1/' || true)"
    if [ -z "$gl" ]; then
        log_err "Anonymous region check (INNERTUBE_CONTEXT_GL) failed to return a country code."
        exit 1
    fi
    if [ "$gl" = "RU" ]; then
        log_err "Detected INNERTUBE_CONTEXT_GL=RU on server egress IP. Aborting: select a VPS with non-RU egress identity."
        exit 1
    fi

    # 2. Anonymous OpenAI check (chatgpt.com/cdn-cgi/trace -> loc != RU & warp=off)
    trace_output="$(curl -fsSL --noproxy '*' --max-time 10 \
        -H 'Accept-Language: de-DE,de;q=0.9,en-US;q=0.8' \
        -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' \
        https://chatgpt.com/cdn-cgi/trace 2>/dev/null || true)"
    if [ -n "$trace_output" ]; then
        loc="$(printf '%s\n' "$trace_output" | awk -F= '$1=="loc"{print $2}' | tr -d '[:space:]' || true)"
        warp="$(printf '%s\n' "$trace_output" | awk -F= '$1=="warp"{print $2}' | tr -d '[:space:]' || true)"
        if [ "$loc" = "RU" ]; then
            log_err "OpenAI trace reported loc=RU on server egress IP. Aborting."
            exit 1
        fi
        if [ -n "$warp" ] && [ "$warp" != "off" ]; then
            log_err "OpenAI trace reported warp=${warp} (Cloudflare WARP detected). Aborting."
            exit 1
        fi
    fi

    # 3. Anonymous Anthropic API check (api.anthropic.com not Cloudflare 403 blocked)
    anthropic_body="$(curl -sS --noproxy '*' --max-time 10 \
        -H 'Accept-Language: de-DE,de;q=0.9,en-US;q=0.8' \
        -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' \
        https://api.anthropic.com/ 2>/dev/null || true)"
    if printf '%s' "$anthropic_body" | grep -qiE 'Attention Required!|error code: 1020'; then
        log_err "Anthropic API blocked this VPS IP/ASN (Cloudflare 403). Aborting."
        exit 1
    fi

    log_info "Triple AI egress check passed (Google GL=${gl} != RU, OpenAI/Anthropic clean)."
}

needs_acme_cert() {
    local cert_file="${DATA_DIR}/certs/fullchain.pem"
    if [ ! -s "$cert_file" ]; then
        return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
        local subj
        subj="$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null || true)"
        if printf '%s' "$subj" | grep -q 'CN[[:space:]]*=[[:space:]]*localhost'; then
            return 0
        fi
        if ! openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -qF "DNS:${DOMAIN}"; then
            return 0
        fi
    fi
    return 1
}

issue_acme_certificate_if_needed() {
    local email="$1"
    if ! needs_acme_cert; then
        return 0
    fi
    log_info "Requesting ACME TLS 1.3 certificate for ${DOMAIN}..."
    if docker compose -f "${COMPOSE_PROJECT_DIR}/docker-compose.yml" exec -T nginx \
        /root/.acme.sh/acme.sh --issue \
        -d "$DOMAIN" \
        -w "${DATA_DIR}/acme-webroot" \
        --keylength ec-256 \
        --accountemail "$email" \
        --server letsencrypt; then
        docker compose -f "${COMPOSE_PROJECT_DIR}/docker-compose.yml" exec -T nginx \
            /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
            --fullchain-file "${DATA_DIR}/certs/fullchain.pem" \
            --key-file "${DATA_DIR}/certs/privkey.pem" \
            --reloadcmd "nginx -s reload -e /dev/null -c ${DATA_DIR}/nginx-runtime/nginx.conf" || \
            log_warn "ACME certificate installation/reload returned non-zero; verify certificate files."
    else
        log_warn "ACME issuance failed; Nginx continues running with bootstrap certificate until DNS/port 80 is reachable."
    fi
}

deploy_zero_surface_appliance() {
    local email
    email="${ACME_EMAIL:-admin@${DOMAIN}}"

    if [ "$DRY_RUN" -eq 1 ]; then
        if [ "$BRIDGE_MODE" -eq 1 ]; then
            if [ "$BRIDGE_ACME" -eq 1 ]; then
                log_info "Dry-run complete. Preflight passed for Cascade Bridge (${BRIDGE_IP} -> ${UPSTREAM_IP}:443, SNI=${BRIDGE_SNI}, ACME TLS mode)."
            else
                log_info "Dry-run complete. Preflight passed for Cascade Bridge (${BRIDGE_IP} -> ${UPSTREAM_IP}:443, SNI=${BRIDGE_SNI}, Zero-Emission mode)."
            fi
        else
            log_info "Dry-run complete. Preflight passed for domain=${DOMAIN} (Zero-Surface SSH mode)."
        fi
        return 0
    fi

    mkdir -p "${DATA_DIR}/certs" "${DATA_DIR}/acme-webroot" "${DATA_DIR}/nginx-runtime/conf.d" "${DATA_DIR}/nginx-runtime/decoy" "${DATA_DIR}/xray" "${CREDENTIALS_DIR}"
    chmod 700 "${CREDENTIALS_DIR}" 2>/dev/null || true

    cat > "${COMPOSE_PROJECT_DIR}/.env" <<EOF
APPLIANCE_MODE=true
APPLIANCE_DOMAIN=${DOMAIN}
XRAY_API_ADDRESS=127.0.0.1:10085
XRAY_LISTEN_PORT=443
XRAY_XHTTP_PORT=10086
XRAY_CONFIG_PATH=${DATA_DIR}/xray/config.json
NGINX_RUNTIME_DIR=${DATA_DIR}/nginx-runtime
NGINX_HTTPS_FALLBACK_PORT=8443
NGINX_ACME_CERT_PATH=${DATA_DIR}/certs/fullchain.pem
NGINX_ACME_KEY_PATH=${DATA_DIR}/certs/privkey.pem
NGINX_DUMMY_CERT_PATH=${DATA_DIR}/certs/dummy-fullchain.pem
NGINX_DUMMY_KEY_PATH=${DATA_DIR}/certs/dummy-privkey.pem
NGINX_WEBROOT_DIR=${DATA_DIR}/acme-webroot
EOF
    chmod 600 "${COMPOSE_PROJECT_DIR}/.env"

    if [ "$BRIDGE_MODE" -eq 1 ]; then
        log_info "Generating Cascade Bridge (Zero-Loop Reality -> ${UPSTREAM_IP}:443) state and client profiles..."
        local bridge_cli_args=(
            init-bridge
            --upstream-ip "$UPSTREAM_IP"
            --upstream-domain "$UPSTREAM_DOMAIN"
            --upstream-uuid "$UPSTREAM_UUID"
            --upstream-pbk "$UPSTREAM_PBK"
            --upstream-sid "$UPSTREAM_SID"
            --bridge-sni "$BRIDGE_SNI"
            --bridge-ip "$BRIDGE_IP"
        )
        if [ "$BRIDGE_ACME" -eq 1 ]; then
            bridge_cli_args+=(--bridge-acme)
            if needs_acme_cert; then
                if command -v ufw >/dev/null 2>&1; then
                    ufw allow 80/tcp >/dev/null 2>&1 || true
                    ufw reload >/dev/null 2>&1 || true
                fi
                run_python_cli "${bridge_cli_args[@]}" --acme-http-challenge >/dev/null
                log_info "Starting temporary HTTP-01 challenge listener to issue Let's Encrypt certificate for ${BRIDGE_SNI}..."
                (cd "$COMPOSE_PROJECT_DIR" && docker compose up -d --build)
                issue_acme_certificate_if_needed "$email"
                if command -v ufw >/dev/null 2>&1; then
                    ufw delete allow 80/tcp >/dev/null 2>&1 || true
                    ufw reload >/dev/null 2>&1 || true
                fi
            fi
        fi
        run_python_cli "${bridge_cli_args[@]}" >/dev/null

        log_info "Building and starting Cascade Bridge containers (xray + loopback nginx)..."
        (cd "$COMPOSE_PROJECT_DIR" && docker compose up -d --build)

        run_python_cli status
        reload_services_if_running
        return 0
    fi

    log_info "Generating initial VLESS Self-Reality state, Nginx decoy, and client profiles..."
    local init_args=(init --domain "$DOMAIN")
    if [ -n "$DECOY_TARGET" ]; then
        init_args+=(--decoy "$DECOY_TARGET")
    fi
    if [ -n "$SERVER_IP" ]; then
        init_args+=(--server-ip "$SERVER_IP")
    fi
    run_python_cli "${init_args[@]}" >/dev/null

    log_info "Building and starting Zero-Surface containers (xray + nginx)..."
    (cd "$COMPOSE_PROJECT_DIR" && docker compose up -d --build)

    issue_acme_certificate_if_needed "$email"

    run_python_cli status
    reload_services_if_running
}

main() {
    if [ "$#" -gt 0 ]; then
        handle_subcommand "$@"
    fi
    parse_args "$@"
    check_domain_tld_hygiene
    check_root
    check_ntp_sync
    check_ports_free
    ensure_docker
    configure_ufw_and_kernel
    configure_ssh_hardening
    if [ "$BRIDGE_MODE" -eq 0 ]; then
        verify_direct_dns
        check_triple_ai_egress
    elif [ "$BRIDGE_ACME" -eq 1 ]; then
        verify_direct_dns "$BRIDGE_IP"
    fi
    deploy_zero_surface_appliance
}

main "$@"
