#!/bin/bash

set -euo pipefail

LOG_FILE="/var/log/protect_script.log"
BACKUP_DIR="/tmp/linux_backup_$(date +%Y%m%d_%H%M%S)"

# Protection level configurations
declare -A LEVEL_PORTS=(
    ["maximum"]="22"
    ["medium"]="22 80 443"
    ["minimum"]="22 80 443 8080 3000 5000"
)

declare -A LEVEL_SERVICES=(
    ["maximum"]="135 139 445 1433 3389 5985 5986 1723 161"
    ["medium"]="135 139 445 1433 3389"
    ["minimum"]="135 139 445"
)

declare -A LEVEL_DESCRIPTIONS=(
    ["maximum"]="Full hardening - servers, high security"
    ["medium"]="Balanced security - workstations (recommended)"
    ["minimum"]="Basic protection - development, compatibility"
)

PROTECTION_LEVEL=""
ALLOWED_PORTS=()
BLOCKED_PORTS=()

parse_arguments() {
    case "${1:-}" in
        --maximum)
            PROTECTION_LEVEL="maximum"
            ;;
        --medium)
            PROTECTION_LEVEL="medium"
            ;;
        --minimum)
            PROTECTION_LEVEL="minimum"
            ;;
        --help|-h)
            echo "Usage: $0 [--maximum|--medium|--minimum]"
            echo ""
            echo "Protection Levels:"
            echo "  --maximum  ${LEVEL_DESCRIPTIONS["maximum"]}"
            echo "  --medium   ${LEVEL_DESCRIPTIONS["medium"]}"
            echo "  --minimum  ${LEVEL_DESCRIPTIONS["minimum"]}"
            echo ""
            echo "If no level is specified, interactive selection will be shown."
            exit 0
            ;;
        "")
            # No argument provided - will show interactive menu
            ;;
        *)
            echo "Error: Unknown option $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
}

select_protection_level() {
    if [ -n "$PROTECTION_LEVEL" ]; then
        return # Level already set via command line
    fi
    
    echo ""
    echo "Select Protection Level:"
    echo "1) Maximum - ${LEVEL_DESCRIPTIONS["maximum"]}"
    echo "2) Medium  - ${LEVEL_DESCRIPTIONS["medium"]}"  
    echo "3) Minimum - ${LEVEL_DESCRIPTIONS["minimum"]}"
    echo ""
    
    while true; do
        read -p "Enter choice [1-3]: " choice
        case $choice in
            1)
                PROTECTION_LEVEL="maximum"
                break
                ;;
            2)
                PROTECTION_LEVEL="medium"
                break
                ;;
            3)
                PROTECTION_LEVEL="minimum"
                break
                ;;
            *)
                echo "Invalid choice. Please enter 1, 2, or 3."
                ;;
        esac
    done
}

configure_protection_level() {
    # Convert space-separated strings to arrays
    read -ra ALLOWED_PORTS <<< "${LEVEL_PORTS[$PROTECTION_LEVEL]}"
    read -ra BLOCKED_PORTS <<< "${LEVEL_SERVICES[$PROTECTION_LEVEL]}"
    
    log "protection level: $PROTECTION_LEVEL"
    log "allowed ports: ${ALLOWED_PORTS[*]}"
    log "blocked ports: ${BLOCKED_PORTS[*]}"
}
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | tee -a "$LOG_FILE"
}

backup_system_state() {
    log "creating backup: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # backup ufw rules
    if command -v ufw &> /dev/null; then
        ufw status numbered > "$BACKUP_DIR/ufw_rules.txt" 2>/dev/null || true
    fi
    
    # backup sysctl settings
    sysctl -a > "$BACKUP_DIR/sysctl_original.conf" 2>/dev/null || true
    
    # create restore script
    cat > "$BACKUP_DIR/restore.sh" << 'EOF'
#!/bin/bash
echo "restoring linux system state..."
ufw --force reset
if [ -f "ufw_rules.txt" ]; then
    echo "original ufw rules saved in ufw_rules.txt"
fi
if [ -f "/etc/sysctl.d/99-security.conf" ]; then
    rm -f /etc/sysctl.d/99-security.conf
    sysctl -p
fi
echo "restore complete"
EOF
    chmod +x "$BACKUP_DIR/restore.sh"
    
    log "backup created: $BACKUP_DIR"
}

cleanup_old_backups() {
    # keep only last 5 backups
    find /tmp -name "linux_backup_*" -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
}

handle_error() {
    log "ERROR: script failed at line $1"
    log "ERROR: command: $2"
    log "restore with: $BACKUP_DIR/restore.sh"
    exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

parse_arguments "$@"

log "starting linux protection script..."
select_protection_level
configure_protection_level

cleanup_old_backups
backup_system_state

if [ "$EUID" -ne 0 ]; then
    log "ERROR: run with sudo"
    exit 1
fi

log "checking for ufw..."
if ! command -v ufw &> /dev/null; then
    log "installing ufw..."
    apt-get update -y
    apt-get install -y ufw
    log "ufw installed"
else
    log "ufw available"
fi

log "resetting ufw to clean state..."
ufw --force reset

log "setting default policies..."
ufw default deny incoming
ufw default allow outgoing

log "configuring allowed ports..."
for port in "${ALLOWED_PORTS[@]}"; do
    case $port in
        22)
            log "allowing ssh..."
            ufw allow ssh
            ;;
        80)
            log "allowing http..."
            ufw allow http
            ;;
        443)
            log "allowing https..."
            ufw allow https
            ;;
        *)
            log "allowing port $port..."
            ufw allow "$port"
            ;;
    esac
done

# Configure additional UFW rules for enhanced security
log "adding security rules..."

ufw limit ssh

log "blocking common attack ports..."
for port in "${BLOCKED_PORTS[@]}"; do
    ufw deny "$port"
done
log "enabling firewall..."
ufw --force enable

log "applying kernel hardening..."
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0

sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1

# Make sysctl changes persistent
log "making settings persistent..."
cat > /etc/sysctl.d/99-security.conf << EOF
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
EOF

# Apply all sysctl changes
sysctl -p /etc/sysctl.d/99-security.conf

# Verify UFW status
log "verifying config..."
if ufw status | grep -q "Status: active"; then
    log "SUCCESS: firewall active"
    ufw status numbered | tee -a "$LOG_FILE"
else
    log "ERROR: firewall failed to activate"
    exit 1
fi

log "done!"
log "backup: $BACKUP_DIR"
log "restore: $BACKUP_DIR/restore.sh"
log "logs: $LOG_FILE"

echo ""
echo "[+] linux system protected"
echo "• level: $PROTECTION_LEVEL"
echo "• firewall: enabled, deny incoming"
echo "• ports: $(IFS=', '; echo "${ALLOWED_PORTS[*]}")"
echo "• ssh: rate limited"
echo "• attack ports: $(IFS=', '; echo "${BLOCKED_PORTS[*]}")"
echo "• kernel: hardened"
echo "• backup: $BACKUP_DIR"
echo "• restore: $BACKUP_DIR/restore.sh"
echo "• logs: $LOG_FILE"
