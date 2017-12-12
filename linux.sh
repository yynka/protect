#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]
then
  echo "Please run as root--start the command with 'sudo'"
  exit
fi

# Update package lists
echo "Updating package lists..."
apt-get update -y > /dev/null

# Install iptables and ufw if not already installed
echo "Installing iptables and ufw..."
apt-get install -y iptables ufw > /dev/null

# Enable UFW
echo "Enabling UFW..."
ufw enable > /dev/null

# Set default policies to deny all incoming traffic and allow all outgoing traffic
echo "Setting default firewall policies..."
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null

# Allow necessary ports (example: SSH on port 22, HTTP on port 80, HTTPS on port 443)
echo "Allowing necessary ports: SSH (22), HTTP (80), HTTPS (443)..."
ufw allow ssh > /dev/null
ufw allow http > /dev/null
ufw allow https > /dev/null

# Enable iptables rules to block all other ports
echo "Blocking all other ports..."
iptables -F
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Block ping requests to hide IP from network scans
echo "Blocking ICMP (ping) requests..."
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP

# Disable IP forwarding
echo "Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0 > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 > /dev/null

# Disable source routing
echo "Disabling source routing..."
sysctl -w net.ipv4.conf.all.accept_source_route=0 > /dev/null
sysctl -w net.ipv4.conf.default.accept_source_route=0 > /dev/null

# Enable SYN cookies to prevent SYN flood attacks
echo "Enabling SYN cookies..."
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null

# Disable ICMP redirects
echo "Disabling ICMP redirects..."
sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null
sysctl -w net.ipv4.conf.default.accept_redirects=0 > /dev/null
sysctl -w net.ipv6.conf.all.accept_redirects=0 > /dev/null
sysctl -w net.ipv6.conf.default.accept_redirects=0 > /dev/null

# Enable IP spoofing protection
echo "Enabling IP spoofing protection..."
sysctl -w net.ipv4.conf.all.rp_filter=1 > /dev/null
sysctl -w net.ipv4.conf.default.rp_filter=1 > /dev/null

# Disable broadcast ICMP requests
echo "Disabling broadcast ICMP requests..."
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null

# Log suspicious packets
echo "Enabling logging of suspicious packets..."
sysctl -w net.ipv4.conf.all.log_martians=1 > /dev/null
sysctl -w net.ipv4.conf.default.log_martians=1 > /dev/null

# Apply all sysctl changes
echo "Applying sysctl changes..."
sysctl -p > /dev/null

echo "All done! Your system is now more secure while still maintaining an internet connection."
