#!/bin/bash

LOG_FILE="/var/log/protect_script.log"
BACKUP_DIR="/tmp/linux_backup_$(date +%Y%m%d_%H%M%S)"

PROTECTION_LEVEL=""
ALLOWED_PORTS=()
BLOCKED_PORTS=()

# Protection level configuration functions (bash 3.x compatible)
get_level_ports() {
    case "$1" in
        "maximum") echo "22" ;;
        "medium") echo "22 80 443" ;;
        "minimum") echo "22 80 443 8080 3000 5000" ;;
    esac
}

get_level_services() {
    case "$1" in
        "maximum") echo "135 139 445 1433 3389 5985 5986 1723 161" ;;
        "medium") echo "135 139 445 1433 3389" ;;
        "minimum") echo "135 139 445" ;;
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
    echo "=== Linux Protection Status ==="
    echo ""
    
    # check if running as root for full status
    if [ "$EUID" -ne 0 ]; then
        echo "Note: Run with sudo for complete status information"
        echo ""
    fi
    
    # check ufw status
    echo "[FIREWALL] Status:"
    if command -v ufw &> /dev/null; then
        ufw_status=$(ufw status 2>/dev/null || echo "inactive")
        if echo "$ufw_status" | grep -q "Status: active"; then
            echo "  [+] UFW Firewall: ACTIVE"
            
            # show ufw rules
            echo "  [i] Active Rules:"
            ufw status numbered 2>/dev/null | grep -E "^\[" | sed 's/^/    /' || echo "    No rules found"
            
            # show default policy
            default_policy=$(ufw status verbose 2>/dev/null | grep "Default:" || echo "Unknown")
            echo "  [>] Default Policy:"
            echo "    $default_policy"
            
        else
            echo "  [-] UFW Firewall: INACTIVE"
        fi
    else
        # check iptables if ufw not available
        if command -v iptables &> /dev/null; then
            echo "  [i] Using iptables (UFW not installed)"
            rule_count=$(iptables -L 2>/dev/null | grep -c "^Chain\|^target" || echo "0")
            echo "  [i] iptables rules: $rule_count"
        else
            echo "  [?] No firewall tools found"
        fi
    fi
    
    echo ""
    
    # check system configuration
    echo "[SYSTEM] Configuration:"
    
    # check ip forwarding
    if [ -f /proc/sys/net/ipv4/ip_forward ]; then
        if cat /proc/sys/net/ipv4/ip_forward | grep -q "0"; then
            echo "  [+] IPv4 Forwarding: DISABLED (secure)"
        else
            echo "  [!] IPv4 Forwarding: ENABLED (potential risk)"
        fi
    fi
    
    # check ipv6 forwarding
    if [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
        if cat /proc/sys/net/ipv6/conf/all/forwarding | grep -q "0"; then
            echo "  [+] IPv6 Forwarding: DISABLED (secure)"
        else
            echo "  [!] IPv6 Forwarding: ENABLED (potential risk)"
        fi
    fi
    
    # check source routing
    if [ -f /proc/sys/net/ipv4/conf/all/accept_source_route ]; then
        if cat /proc/sys/net/ipv4/conf/all/accept_source_route | grep -q "0"; then
            echo "  [+] Source Route: DISABLED (secure)"
        else
            echo "  [!] Source Route: ENABLED (potential risk)"
        fi
    fi
    
    # check syn cookies
    if [ -f /proc/sys/net/ipv4/tcp_syncookies ]; then
        if cat /proc/sys/net/ipv4/tcp_syncookies | grep -q "1"; then
            echo "  [+] SYN Cookies: ENABLED (secure)"
        else
            echo "  [!] SYN Cookies: DISABLED (potential risk)"
        fi
    fi
    
    # check redirects
    if [ -f /proc/sys/net/ipv4/conf/all/accept_redirects ]; then
        if cat /proc/sys/net/ipv4/conf/all/accept_redirects | grep -q "0"; then
            echo "  [+] ICMP Redirects: DISABLED (secure)"
        else
            echo "  [!] ICMP Redirects: ENABLED (potential risk)"
        fi
    fi
    
    echo ""
    
    # check services
    echo "[SERVICES] Status:"
    if command -v systemctl &> /dev/null; then
        # check ssh service
        if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
            echo "  [+] SSH Service: RUNNING"
        else
            echo "  [!] SSH Service: NOT RUNNING"
        fi
        
        # check if fail2ban is installed and running
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            echo "  [+] Fail2Ban: RUNNING (intrusion prevention)"
        fi
    fi
    
    echo ""
    
    # check for backups
    echo "[BACKUP] Information:"
    backup_dirs=$(find /tmp -name "linux_backup_*" -type d 2>/dev/null | head -5)
    if [ -n "$backup_dirs" ]; then
        echo "  [i] Recent Backups Found:"
        echo "$backup_dirs" | while read -r backup_dir; do
            backup_date=$(basename "$backup_dir" | sed 's/linux_backup_//' | sed 's/_/ /')
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
    
    # check ufw logs if available
    if [ -f "/var/log/ufw.log" ]; then
        recent_blocks=$(tail -n 100 /var/log/ufw.log 2>/dev/null | grep -c "BLOCK" || echo "0")
        echo "  [i] Recent UFW Blocks: $recent_blocks (last 100 log entries)"
    fi
    
    echo ""
    
    # check security configurations
    echo "[CONFIG] Security Files:"
    if [ -f "/etc/sysctl.d/99-security.conf" ]; then
        echo "  [+] Security sysctl config: PRESENT"
        conf_count=$(grep -c "^[^#]" /etc/sysctl.d/99-security.conf 2>/dev/null || echo "0")
        echo "    [i] Active settings: $conf_count"
    else
        echo "  [?] Security sysctl config: NOT FOUND"
    fi
    
    echo ""
    
    # overall security assessment
    echo "[SECURITY] Assessment:"
    
    # calculate security score
    score=0
    max_score=6
    
    # ufw active
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        score=$((score + 2))
    fi
    
    # ip forwarding disabled
    if [ -f /proc/sys/net/ipv4/ip_forward ] && cat /proc/sys/net/ipv4/ip_forward | grep -q "0"; then
        score=$((score + 1))
    fi
    
    # syn cookies enabled
    if [ -f /proc/sys/net/ipv4/tcp_syncookies ] && cat /proc/sys/net/ipv4/tcp_syncookies | grep -q "1"; then
        score=$((score + 1))
    fi
    
    # redirects disabled
    if [ -f /proc/sys/net/ipv4/conf/all/accept_redirects ] && cat /proc/sys/net/ipv4/conf/all/accept_redirects | grep -q "0"; then
        score=$((score + 1))
    fi
    
    # security config file exists
    if [ -f "/etc/sysctl.d/99-security.conf" ]; then
        score=$((score + 1))
    fi
    
    # display security level
    if [ $score -ge 5 ]; then
        echo "  [+] Security Level: HIGH ($score/$max_score)"
        echo "  [+] System appears to be well protected"
    elif [ $score -ge 3 ]; then
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
    # Convert space-separated strings to arrays
    read -ra ALLOWED_PORTS <<< "$(get_level_ports "$PROTECTION_LEVEL")"
    read -ra BLOCKED_PORTS <<< "$(get_level_services "$PROTECTION_LEVEL")"
    
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
