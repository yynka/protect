#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]
then
  echo "Please run as root--start the command with 'sudo'"
  exit
fi

# Ensure pfctl is available
if ! command -v pfctl &> /dev/null
then
    echo "pfctl command not found. Exiting."
    exit 1
fi

# Backup current pf configuration
echo "Backing up current firewall configuration..."
cp /etc/pf.conf /etc/pf.conf.backup

# Create new pf configuration
echo "Creating new firewall configuration..."
cat <<EOF | tee /etc/pf.conf > /dev/null
# MacOS pf firewall configuration

# Define macros for ports
tcp_services = "{ 22, 80, 443 }"

# Set default block policy
block all

# Allow established and related connections
pass in all keep state
pass out all keep state

# Allow loopback traffic
set skip on lo0

# Allow incoming connections to defined TCP services
pass in proto tcp from any to any port \$tcp_services

# Block ICMP (ping) requests
block in proto icmp all
EOF

# Apply the new pf configuration
echo "Applying the new firewall rules..."
pfctl -f /etc/pf.conf > /dev/null 2>&1
pfctl -e > /dev/null 2>&1

# Additional sysctl settings
echo "Disabling IP forwarding..."
sysctl -w net.inet.ip.forwarding=0 > /dev/null
sysctl -w net.inet6.ip6.forwarding=0 > /dev/null

echo "Disabling source routing..."
sysctl -w net.inet.ip.sourceroute=0 > /dev/null
sysctl -w net.inet.ip.accept_sourceroute=0 > /dev/null

# Apply all sysctl changes
echo "Applying system settings changes..."
sysctl -a > /dev/null 2>&1

echo "All done! Your system is now more secure while still maintaining an internet connection."
