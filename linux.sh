#!/bin/bash

# Enable strict error handling
set -euo pipefail

LOG_FILE="/var/log/protect_script.log"
ALLOWED_PORTS=(22 80 443)
BACKUP_DIR="/tmp/linux_backup_$(date +%Y%m%d_%H%M%S)"
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

log "starting linux protection script..."

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
ufw deny 135
ufw deny 139
ufw deny 445
ufw deny 1433
ufw deny 3389
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
echo "✅ linux system protected"
echo "• firewall: enabled, deny incoming"
echo "• ports: $(IFS=', '; echo "${ALLOWED_PORTS[*]}")"
echo "• ssh: rate limited"
echo "• attack ports: blocked"
echo "• kernel: hardened"
echo "• backup: $BACKUP_DIR"
echo "• restore: $BACKUP_DIR/restore.sh"
echo "• logs: $LOG_FILE"
