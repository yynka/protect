#!/bin/bash

LOG_FILE="/var/log/protect_script.log"
BACKUP_DIR="/tmp/pf_backup_$(date +%Y%m%d_%H%M%S)"

PROTECTION_LEVEL=""
ALLOWED_PORTS_STR=""
BLOCKED_PORTS_STR=""

# Protection level configuration functions (bash 3.x compatible)
get_level_ports() {
    case "$1" in
        "maximum") echo "22" ;;
        "medium") echo "22, 80, 443" ;;
        "minimum") echo "22, 80, 443, 8080, 3000, 5000" ;;
    esac
}

get_level_services() {
    case "$1" in
        "maximum") echo "135, 139, 445, 1433, 3389, 5985, 5986, 1723, 161" ;;
        "medium") echo "135, 139, 445, 1433, 3389" ;;
        "minimum") echo "135, 139, 445" ;;
    esac
}

get_level_description() {
    case "$1" in
        "maximum") echo "Full hardening - servers, high security" ;;
        "medium") echo "Balanced security - workstations (recommended)" ;;
        "minimum") echo "Basic protection - development, compatibility" ;;
    esac
}

# Enable strict error handling after variable declarations
set -euo pipefail

show_status() {
    echo ""
    echo "=== macOS Protection Status ==="
    echo ""
    
    # check if running as root for full status
    if [ "$EUID" -ne 0 ]; then
        echo "Note: Run with sudo for complete status information"
        echo ""
    fi
    
    # check pf (packet filter) status
    echo "[FIREWALL] Status:"
    if command -v pfctl &> /dev/null; then
        if pfctl -si 2>/dev/null | grep -q "Status: Enabled"; then
            echo "  [+] PF Firewall: ENABLED"
            
            # show active rules count
            rule_count=$(pfctl -sr 2>/dev/null | wc -l | xargs)
            echo "  [i] Active Rules: $rule_count"
            
            # show allowed ports
            echo "  [>] Allowed Ports:"
            pfctl -sr 2>/dev/null | grep "pass in" | grep "port" | sed 's/^/    /' || echo "    No specific port rules found"
            
            # show blocked ports
            echo "  [x] Blocked Ports:"
            pfctl -sr 2>/dev/null | grep "block" | grep "port" | sed 's/^/    /' || echo "    No specific block rules found"
            
        else
            echo "  [-] PF Firewall: DISABLED"
        fi
    else
        echo "  [?] pfctl not available"
    fi
    
    echo ""
    
    # check system configuration
    echo "[SYSTEM] Configuration:"
    
    # check ip forwarding
    if sysctl net.inet.ip.forwarding 2>/dev/null | grep -q "net.inet.ip.forwarding: 0"; then
        echo "  [+] IP Forwarding: DISABLED (secure)"
    else
        echo "  [!] IP Forwarding: ENABLED (potential risk)"
    fi
    
    # check ipv6 forwarding  
    if sysctl net.inet6.ip6.forwarding 2>/dev/null | grep -q "net.inet6.ip6.forwarding: 0"; then
        echo "  [+] IPv6 Forwarding: DISABLED (secure)"
    else
        echo "  [!] IPv6 Forwarding: ENABLED (potential risk)"
    fi
    
    # check source routing
    if sysctl net.inet.ip.sourceroute 2>/dev/null | grep -q "net.inet.ip.sourceroute: 0"; then
        echo "  [+] Source Routing: DISABLED (secure)"
    else
        echo "  [!] Source Routing: ENABLED (potential risk)"
    fi
    
    # check syn cookies if available
    if sysctl net.inet.tcp.syncookies 2>/dev/null | grep -q "net.inet.tcp.syncookies: 1"; then
        echo "  [+] SYN Cookies: ENABLED (secure)"
    elif sysctl net.inet.tcp.syncookies >/dev/null 2>&1; then
        echo "  [!] SYN Cookies: DISABLED (potential risk)"
    fi
    
    echo ""
    
    # check for backups
    echo "[BACKUP] Information:"
    backup_dirs=$(find /tmp -name "pf_backup_*" -type d 2>/dev/null | head -5)
    if [ -n "$backup_dirs" ]; then
        echo "  [i] Recent Backups Found:"
        echo "$backup_dirs" | while read -r backup_dir; do
            backup_date=$(basename "$backup_dir" | sed 's/pf_backup_//' | sed 's/_/ /')
            echo "    [*] $backup_date - $backup_dir"
        done
    else
        echo "  [i] No backups found in /tmp"
    fi
    
    echo ""
    
    # check log file
    echo "[LOGS] Information:"
    if [ -f "$LOG_FILE" ]; then
        log_size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)
        last_entry=$(tail -n 1 "$LOG_FILE" 2>/dev/null | cut -d: -f1-2)
        echo "  [i] Log File: $LOG_FILE ($log_size)"
        echo "  [i] Last Activity: $last_entry"
    else
        echo "  [i] Log File: Not found"
    fi
    
    echo ""
    
    # overall security assessment
    echo "[SECURITY] Assessment:"
    
    # calculate security score
    score=0
    max_score=5
    
    if pfctl -si 2>/dev/null | grep -q "Status: Enabled"; then
        score=$((score + 2))
    fi
    
    if sysctl net.inet.ip.forwarding 2>/dev/null | grep -q ": 0"; then
        score=$((score + 1))
    fi
    
    if sysctl net.inet6.ip6.forwarding 2>/dev/null | grep -q ": 0"; then
        score=$((score + 1))
    fi
    
    if sysctl net.inet.ip.sourceroute 2>/dev/null | grep -q ": 0"; then
        score=$((score + 1))
    fi
    
    # display security level
    if [ $score -ge 4 ]; then
        echo "  [+] Security Level: HIGH ($score/$max_score)"
        echo "  [+] System appears to be well protected"
    elif [ $score -ge 2 ]; then
        echo "  [!] Security Level: MEDIUM ($score/$max_score)" 
        echo "  [!] Consider running protection script to improve security"
    else
        echo "  [-] Security Level: LOW ($score/$max_score)"
        echo "  [-] System needs protection - run: sudo $0"
    fi
    
    echo ""
}

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
        --status)
            show_status
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [--maximum|--medium|--minimum|--status]"
            echo ""
            echo "Protection Levels:"
            echo "  --maximum  Full hardening - servers, high security"
            echo "  --medium   Balanced security - workstations (recommended)"
            echo "  --minimum  Basic protection - development, compatibility"
            echo ""
            echo "Status Commands:"
            echo "  --status   Show current protection status and configuration"
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
    echo "Available Commands:"
    echo "1) Maximum - Full hardening - servers, high security"
    echo "2) Medium  - Balanced security - workstations (recommended)"  
    echo "3) Minimum - Basic protection - development, compatibility"
    echo "4) Status  - Show current protection status and configuration"
    echo "5) Help    - Show usage information and exit"
    echo ""
    
    while true; do
        read -p "Enter choice [1-5]: " choice
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
            4)
                show_status
                exit 0
                ;;
            5)
                echo "Usage: $0 [--maximum|--medium|--minimum|--status]"
                echo ""
                echo "Protection Levels:"
                echo "  --maximum  Full hardening - servers, high security"
                echo "  --medium   Balanced security - workstations (recommended)"
                echo "  --minimum  Basic protection - development, compatibility"
                echo ""
                echo "Status Commands:"
                echo "  --status   Show current protection status and configuration"
                echo ""
                echo "If no level is specified, interactive selection will be shown."
                exit 0
                ;;
            *)
                echo "Invalid choice. Please enter 1, 2, 3, 4, or 5."
                ;;
        esac
    done
}

configure_protection_level() {
    ALLOWED_PORTS_STR=$(get_level_ports "$PROTECTION_LEVEL")
    BLOCKED_PORTS_STR=$(get_level_services "$PROTECTION_LEVEL")
    
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
cat > /etc/pf.conf << 'EOF'
set skip on lo0
block all
pass out all keep state

# Allow specific TCP ports
pass in proto tcp from any to any port { 22, 80, 443 } keep state

# Block common attack ports
block log quick proto tcp from any to any port { 135, 139, 445, 1433, 3389 }
block log quick proto udp from any to any port { 135, 139, 445, 1433, 3389 }

# SSH connection limiting
pass in proto tcp from any to any port 22 keep state (max-src-conn 3, max-src-conn-rate 3/30)
EOF

# Replace with actual port values
sed -i '' "s/{ 22, 80, 443 }/{ $ALLOWED_PORTS_STR }/g" /etc/pf.conf
sed -i '' "s/{ 135, 139, 445, 1433, 3389 }/{ $BLOCKED_PORTS_STR }/g" /etc/pf.conf

log "validating config..."
if ! pfctl -vnf /etc/pf.conf; then
    log "ERROR: invalid pf.conf"
    exit 1
fi

log "applying rules..."
pfctl -f /etc/pf.conf

log "enabling pf..."
if pfctl -e 2>/dev/null; then
    log "SUCCESS: pf enabled"
elif pfctl -si | grep -q "Status: Enabled"; then
    log "SUCCESS: pf already enabled"
else
    log "ERROR: failed to enable pf"
    exit 1
fi

log "applying kernel hardening..."

sysctl -w net.inet.ip.forwarding=0
sysctl -w net.inet6.ip6.forwarding=0
sysctl -w net.inet.ip.sourceroute=0
sysctl -w net.inet.ip.accept_sourceroute=0
if sysctl net.inet.tcp.syncookies >/dev/null 2>&1; then
    sysctl -w net.inet.tcp.syncookies=1
fi

log "making settings persistent..."
cat > /etc/sysctl.conf << EOF
net.inet.ip.forwarding=0
net.inet6.ip6.forwarding=0
net.inet.ip.sourceroute=0
net.inet.ip.accept_sourceroute=0
EOF

if sysctl net.inet.tcp.syncookies >/dev/null 2>&1; then
    echo "net.inet.tcp.syncookies=1" >> /etc/sysctl.conf
fi

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