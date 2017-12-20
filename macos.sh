#!/bin/bash

# Enable strict error handling
set -euo pipefail

LOG_FILE="/var/log/protect_script.log"
ALLOWED_PORTS=(22 80 443)
BACKUP_DIR="/tmp/pf_backup_$(date +%Y%m%d_%H%M%S)"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | tee -a "$LOG_FILE"
}
handle_error() {
    log "ERROR: script failed at line $1"
    log "ERROR: command: $2"
    log "ROLLBACK: restoring pf.conf"
    if [ -f "$BACKUP_DIR/pf.conf" ]; then
        cp "$BACKUP_DIR/pf.conf" /etc/pf.conf
        pfctl -f /etc/pf.conf 2>/dev/null || true
    fi
    exit 1
}

trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

log "starting macos protection script..."

if [ "$EUID" -ne 0 ]; then
    log "ERROR: run with sudo"
    exit 1
fi

if ! command -v pfctl &> /dev/null; then
    log "ERROR: pfctl not found"
    exit 1
fi

log "creating backup: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

log "backing up pf.conf..."
if [ -f /etc/pf.conf ]; then
    cp /etc/pf.conf "$BACKUP_DIR/pf.conf"
    log "backed up to $BACKUP_DIR/pf.conf"
else
    log "no existing pf.conf, creating new"
fi

log "creating firewall config..."
cat > /etc/pf.conf << 'EOF'
tcp_services = "{ 22, 80, 443 }"

block all
pass out all keep state
set skip on lo0
pass in proto tcp from any to any port $tcp_services

block log quick from any to any port { 135, 139, 445, 1433, 3389 }
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
log "logs: $LOG_FILE"

echo ""
echo "✅ macos system protected"
echo "• firewall: enabled, deny incoming"
echo "• ports: $(IFS=', '; echo "${ALLOWED_PORTS[*]}")"
echo "• ssh: rate limited (max 3/ip)"
echo "• attack ports: blocked and logged"
echo "• kernel: hardened"
echo "• backup: $BACKUP_DIR/"
echo "• logs: $LOG_FILE"
echo ""
echo "restore: sudo cp $BACKUP_DIR/pf.conf /etc/pf.conf && sudo pfctl -f /etc/pf.conf"
