#!/bin/bash

set -euo pipefail

LOG_FILE="/var/log/protect_script.log"
BACKUP_DIR="/tmp/pf_backup_$(date +%Y%m%d_%H%M%S)"

# Protection level configurations
declare -A LEVEL_PORTS=(
    ["maximum"]="22"
    ["medium"]="22, 80, 443"
    ["minimum"]="22, 80, 443, 8080, 3000, 5000"
)

declare -A LEVEL_SERVICES=(
    ["maximum"]="135, 139, 445, 1433, 3389, 5985, 5986, 1723, 161"
    ["medium"]="135, 139, 445, 1433, 3389"
    ["minimum"]="135, 139, 445"
)

declare -A LEVEL_DESCRIPTIONS=(
    ["maximum"]="Full hardening - servers, high security"
    ["medium"]="Balanced security - workstations (recommended)"
    ["minimum"]="Basic protection - development, compatibility"
)

PROTECTION_LEVEL=""
ALLOWED_PORTS_STR=""
BLOCKED_PORTS_STR=""

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
            echo "  --maximum  Full hardening - servers, high security"
            echo "  --medium   Balanced security - workstations (recommended)"
            echo "  --minimum  Basic protection - development, compatibility"
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
    echo "1) Maximum - Full hardening - servers, high security"
    echo "2) Medium  - Balanced security - workstations (recommended)"  
    echo "3) Minimum - Basic protection - development, compatibility"
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
    ALLOWED_PORTS_STR="${LEVEL_PORTS[$PROTECTION_LEVEL]}"
    BLOCKED_PORTS_STR="${LEVEL_SERVICES[$PROTECTION_LEVEL]}"
    
    log "protection level: $PROTECTION_LEVEL"
    log "allowed ports: $ALLOWED_PORTS_STR"
    log "blocked ports: $BLOCKED_PORTS_STR"
}

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | tee -a "$LOG_FILE"
}

backup_system_state() {
    log "creating backup: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # backup pf.conf
    if [ -f /etc/pf.conf ]; then
        cp /etc/pf.conf "$BACKUP_DIR/pf.conf"
        log "backed up pf.conf"
    fi
    
    # backup current pf rules
    pfctl -sr > "$BACKUP_DIR/pf_rules_original.txt" 2>/dev/null || true
    
    # backup sysctl settings  
    sysctl -a > "$BACKUP_DIR/sysctl_original.conf" 2>/dev/null || true
    
    # create restore script
    cat > "$BACKUP_DIR/restore.sh" << 'EOF'
#!/bin/bash
echo "restoring macos system state..."
if [ -f "pf.conf" ]; then
    sudo cp pf.conf /etc/pf.conf
    sudo pfctl -f /etc/pf.conf
    echo "pf.conf restored"
fi
if [ -f /etc/sysctl.conf ]; then
    sudo rm -f /etc/sysctl.conf
fi
echo "restore complete - reboot recommended"
EOF
    chmod +x "$BACKUP_DIR/restore.sh"
    
    log "backup created: $BACKUP_DIR"
}

cleanup_old_backups() {
    find /tmp -name "pf_backup_*" -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
}

handle_error() {
    log "ERROR: script failed at line $1"
    log "ERROR: command: $2"
    log "ROLLBACK: restoring pf.conf"
    if [ -f "$BACKUP_DIR/pf.conf" ]; then
        cp "$BACKUP_DIR/pf.conf" /etc/pf.conf
        pfctl -f /etc/pf.conf 2>/dev/null || true
    fi
    log "restore with: $BACKUP_DIR/restore.sh"
    exit 1
}

trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

parse_arguments "$@"

log "starting macos protection script..."
select_protection_level
configure_protection_level

cleanup_old_backups
backup_system_state

if [ "$EUID" -ne 0 ]; then
    log "ERROR: run with sudo"
    exit 1
fi

if ! command -v pfctl &> /dev/null; then
    log "ERROR: pfctl not found"
    exit 1
fi

log "creating firewall config..."
cat > /etc/pf.conf << EOF
tcp_services = "{ $ALLOWED_PORTS_STR }"

block all
pass out all keep state
set skip on lo0
pass in proto tcp from any to any port \$tcp_services

block log quick from any to any port { $BLOCKED_PORTS_STR }
pass in proto tcp from any to any port 22 keep state (max-src-conn 3, max-src-conn-rate 3/30)
EOF

log "validating config..."
if ! pfctl -vnf /etc/pf.conf; then
    log "ERROR: invalid pf.conf"
    exit 1
fi

log "applying rules..."
pfctl -ef /etc/pf.conf

if pfctl -si | grep -q "Status: Enabled"; then
    log "SUCCESS: pf enabled"
else
    log "ERROR: failed to enable pf"
    exit 1
fi

log "applying kernel hardening..."

sysctl -w net.inet.ip.forwarding=0
sysctl -w net.inet6.ip6.forwarding=0
sysctl -w net.inet.ip.sourceroute=0
sysctl -w net.inet.ip.accept_sourceroute=0
sysctl -w net.inet.tcp.rfc1323=0
sysctl -w net.inet.tcp.syncookies=1

log "making settings persistent..."
cat > /etc/sysctl.conf << EOF
net.inet.ip.forwarding=0
net.inet6.ip6.forwarding=0
net.inet.ip.sourceroute=0
net.inet.ip.accept_sourceroute=0
net.inet.tcp.rfc1323=0
net.inet.tcp.syncookies=1
EOF

log "current rules:"
pfctl -sr | tee -a "$LOG_FILE"

log "done!"
log "backup: $BACKUP_DIR/"
log "restore: $BACKUP_DIR/restore.sh"
log "logs: $LOG_FILE"

echo ""
echo "[+] macos system protected"
echo "• level: $PROTECTION_LEVEL"
echo "• firewall: enabled, deny incoming"
echo "• ports: $ALLOWED_PORTS_STR"
echo "• ssh: rate limited (max 3/ip)"
echo "• attack ports: $BLOCKED_PORTS_STR"
echo "• kernel: hardened"
echo "• backup: $BACKUP_DIR/"
echo "• restore: $BACKUP_DIR/restore.sh"
echo "• logs: $LOG_FILE" 