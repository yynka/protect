# PROTECT Security Hardening Guide

This guide provides detailed information about the PROTECT security hardening tool's protection levels, configurations, and platform-specific implementations.

## Table of Contents

- [Protection Levels Overview](#protection-levels-overview)
- [Detailed Configurations](#detailed-configurations)
- [Platform-Specific Implementation](#platform-specific-implementation)
- [Security Considerations](#security-considerations)
- [Usage Scenarios](#usage-scenarios)
- [Backup and Recovery](#backup-and-recovery)
- [Troubleshooting](#troubleshooting)
- [Enterprise Deployment](#enterprise-deployment)

## Protection Levels Overview

PROTECT offers three distinct protection levels, each designed for different security requirements and use cases:

### Maximum Protection
**Target Environment**: Production servers, high-security environments, isolated systems
- **Philosophy**: Security over convenience
- **Network Access**: Minimal surface area - SSH administration only
- **Service Management**: Aggressive - disables all non-essential services
- **Use Case**: Web servers, database servers, critical infrastructure

### Medium Protection  
**Target Environment**: Workstations, general-purpose servers, business systems
- **Philosophy**: Balanced security and usability
- **Network Access**: Essential services for typical workflows
- **Service Management**: Moderate - disables risky services while maintaining functionality
- **Use Case**: Office workstations, development servers, general business systems

### Minimum Protection
**Target Environment**: Development machines, compatibility-required systems, testing environments
- **Philosophy**: Basic security with maximum compatibility
- **Network Access**: Permissive for development workflows
- **Service Management**: Conservative - only disables obviously dangerous services
- **Use Case**: Developer workstations, CI/CD systems, legacy application hosts

## Detailed Configurations

### Port Configurations

| Protection Level | Allowed Inbound Ports | Purpose |
|-----------------|----------------------|----------|
| **Maximum** | 22 (SSH) | Remote administration only |
| **Medium** | 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389* (RDP) | Web services + administration |
| **Minimum** | Above + 8080, 3000, 5000 | Development + web services |

*RDP (3389) only enabled on Windows when Remote Desktop service is active

### Blocked Attack Ports

| Protection Level | Blocked Ports | Services Blocked |
|-----------------|---------------|------------------|
| **Maximum** | 135, 139, 445, 1433, 1434, 3389**, 5985, 5986, 1723, 161 | RPC, NetBIOS, SMB, SQL Server, WinRM, VPN, SNMP |
| **Medium** | 135, 139, 445, 1433, 1434 | RPC, NetBIOS, SMB, SQL Server |
| **Minimum** | 135, 139, 445 | RPC, NetBIOS, SMB |

**3389 (RDP) blocked on Linux/macOS, conditionally managed on Windows

### Service Management by Level

#### Linux Services (systemd/service management)
| Service Category | Maximum | Medium | Minimum | Rationale |
|-----------------|---------|--------|---------|-----------|
| **Network Discovery** | Disabled | Disabled | Disabled | Security risk |
| **Print Services** | Disabled | Conditional | Enabled | Functionality vs security |
| **Remote Access** | SSH Only | SSH + Conditional | SSH + Multiple | Access requirements |
| **File Sharing** | Disabled | Disabled | Conditional | Attack surface |

#### Windows Services
| Service | Maximum | Medium | Minimum | Impact |
|---------|---------|--------|---------|---------|
| Windows Search | Disabled | Disabled | Enabled | Performance vs functionality |
| Remote Registry | Disabled | Disabled | Disabled | Security risk |
| Fax Service | Disabled | Disabled | Disabled | Legacy service |
| Telnet | Disabled | Disabled | Disabled | Insecure protocol |
| FTP Server | Disabled | Disabled | Disabled | Insecure by default |
| SNMP Service | Disabled | Enabled | Enabled | Monitoring capabilities |
| Print Spooler | Disabled | Enabled | Enabled | Printing functionality |

#### macOS Services (launchd management)
| Service Category | Maximum | Medium | Minimum | Considerations |
|-----------------|---------|--------|---------|---------------|
| **Network Services** | Minimal | Standard | Full | Compatibility needs |
| **Remote Access** | SSH Only | SSH + Screen Sharing | Multiple | User requirements |
| **File Sharing** | Disabled | Conditional | Enabled | Collaboration needs |

## Platform-Specific Implementation

### Linux Implementation
- **Firewall**: Uses UFW (Uncomplicated Firewall) for rule management
- **Kernel Security**: Comprehensive sysctl hardening
- **Persistence**: Settings saved to `/etc/sysctl.d/99-security.conf`
- **Backup Location**: `/tmp/linux_backup_YYYYMMDD_HHMMSS/`

#### Key Security Settings Applied
```bash
# Network security
net.ipv4.ip_forward=0                    # Disable IP forwarding
net.ipv4.tcp_syncookies=1               # Enable SYN flood protection
net.ipv4.conf.all.rp_filter=1          # Enable source validation
net.ipv4.icmp_echo_ignore_broadcasts=1  # Ignore broadcast pings
net.ipv4.conf.all.log_martians=1       # Log suspicious packets
```

### macOS Implementation  
- **Firewall**: Uses pf (Packet Filter) - the native macOS firewall
- **Configuration**: Direct pf.conf management for precise control
- **Persistence**: Settings integrated with system boot process
- **Backup Location**: `/tmp/pf_backup_YYYYMMDD_HHMMSS/`

#### pf Configuration Structure
```bash
# Basic pf.conf structure
tcp_services = "{ 22, 80, 443 }"        # Define allowed ports
block all                               # Default deny policy
pass out all keep state                 # Allow outbound with stateful tracking
set skip on lo0                         # Skip loopback interface
pass in proto tcp from any to any port $tcp_services  # Allow defined services
```

### Windows Implementation
- **Firewall**: Uses Windows Advanced Firewall via netsh commands
- **Service Management**: PowerShell-based service control with safety checks
- **Registry Management**: Targeted registry modifications for security
- **Backup Location**: `C:\temp\firewall_backup_YYYYMMDD_HHMMSS\`

#### Service Safety Features
- **Dependency Checking**: Verifies no critical services depend on target services
- **Critical Service Protection**: Blacklists essential Windows services
- **Rollback Capability**: Service startup states backed up for restoration
- **Verification**: Confirms changes were applied successfully

## Security Considerations

### What PROTECT Defends Against

**Network-Based Attacks**:
- Port scanning and reconnaissance
- Brute force attacks (SSH rate limiting)
- Service exploitation (disabled unnecessary services)
- Network-based lateral movement
- Common protocol attacks (SMB, NetBIOS, etc.)

**System Hardening**:
- IP spoofing attacks
- SYN flood attacks
- ICMP-based attacks
- Source routing attacks
- Broadcast-based attacks

### What PROTECT Does NOT Defend Against

**Application-Level Attacks**:
- Web application vulnerabilities
- Zero-day exploits in allowed services
- Social engineering attacks
- Malware delivered through email/web
- Insider threats

**Advanced Persistent Threats**:
- Sophisticated targeted attacks
- Supply chain compromises
- Hardware-level attacks
- Advanced evasion techniques

### Security vs Usability Tradeoffs

| Protection Level | Security Gain | Usability Impact | Recommended For |
|-----------------|---------------|------------------|-----------------|
| **Maximum** | Highest - minimal attack surface | High - limited functionality | Production servers, critical systems |
| **Medium** | Good - blocks common attacks | Low - maintains essential services | General business use, workstations |
| **Minimum** | Basic - protects against obvious threats | Minimal - preserves compatibility | Development, testing, legacy systems |

## Usage Scenarios

### Scenario 1: Web Server Deployment
```bash
# Production web server - maximum security
sudo ./linux.sh --maximum

# Result: Only SSH access, HTTP/HTTPS through reverse proxy or load balancer
# Manually configure specific ports as needed after initial hardening
```

### Scenario 2: Developer Workstation
```bash
# Development machine - minimum protection
sudo ./macos.sh --minimum

# Result: Development ports open, basic security in place
# Allows local development servers, API testing, etc.
```

### Scenario 3: Office Workstation
```bash
# Business workstation - balanced approach
powershell -File windows.ps1 --medium

# Result: Standard business functionality with enhanced security
# Web browsing, file sharing (if needed), remote access capabilities
```

### Scenario 4: Interactive Deployment
```bash
# Let users choose based on their needs
sudo ./linux.sh

# Shows menu:
# 1) Maximum - Full hardening - servers, high security
# 2) Medium  - Balanced security - workstations (recommended)
# 3) Minimum - Basic protection - development, compatibility
```

## Backup and Recovery

### Automatic Backups
All protection levels create comprehensive backups before making changes:

**Linux Backups**:
- UFW rule configurations
- Original sysctl settings  
- System service states
- Automatic restore script generation

**macOS Backups**:
- Original pf.conf configuration
- Current pf rules export
- System sysctl settings
- Bootable restore script

**Windows Backups**:
- Complete firewall configuration export
- Service startup states (CSV format)
- Registry settings for networking features
- Batch file for automated restoration

### Manual Recovery

**Linux Recovery**:
```bash
# Using generated restore script
sudo /tmp/linux_backup_YYYYMMDD_HHMMSS/restore.sh

# Manual UFW reset
sudo ufw --force reset
sudo rm -f /etc/sysctl.d/99-security.conf
sudo sysctl -p
```

**macOS Recovery**:
```bash
# Using generated restore script  
sudo /tmp/pf_backup_YYYYMMDD_HHMMSS/restore.sh

# Manual pf restoration
sudo cp backup_dir/pf.conf /etc/pf.conf
sudo pfctl -f /etc/pf.conf
```

**Windows Recovery**:
```batch
# Using generated restore script
C:\temp\firewall_backup_YYYYMMDD_HHMMSS\restore.bat

# Manual firewall restoration
netsh advfirewall import "C:\temp\firewall_backup_YYYYMMDD_HHMMSS\firewall_backup.wfw"
```

## Troubleshooting

### Common Issues and Solutions

#### Connection Issues After Hardening
**Problem**: Can't connect to services after running protection script
**Solution**: 
1. Check which protection level was applied
2. Verify the service runs on an allowed port for that level
3. Temporarily add port if needed:
   ```bash
   # Linux
   sudo ufw allow [port_number]
   
   # macOS  
   # Edit /etc/pf.conf to add port to tcp_services
   
   # Windows
   netsh advfirewall firewall add rule name="Custom Port" protocol=TCP dir=in localport=[port] action=allow
   ```

#### Script Execution Failures
**Problem**: Script fails partway through execution
**Solution**: Scripts include automatic rollback on failure. Check logs:
- Linux/macOS: `/var/log/protect_script.log`
- Windows: `C:\temp\protect_script.log`

#### Service Functionality Issues  
**Problem**: Required service was disabled
**Solution**: Use backup information to restore specific services:
```bash
# Linux - check service status
systemctl status [service_name]
systemctl enable [service_name]
systemctl start [service_name]

# Windows - restore from backup CSV
# Check C:\temp\firewall_backup_YYYYMMDD_HHMMSS\services_original.csv
```

### Verification Commands

**Verify Firewall Status**:
```bash
# Linux
sudo ufw status numbered

# macOS  
sudo pfctl -sr

# Windows
netsh advfirewall show allprofiles
```

**Verify Blocked Ports**:
```bash
# Test from external machine
nmap -p 1-65535 [target_ip]

# Check listening services
netstat -tlnp  # Linux/macOS
netstat -an    # Windows
```

## Enterprise Deployment

### Automated Deployment Strategies

#### Configuration Management
```bash
# Ansible example
- name: Apply maximum protection to web servers
  command: ./linux.sh --maximum
  become: yes
  when: server_role == "web"

- name: Apply medium protection to workstations  
  command: ./linux.sh --medium
  become: yes
  when: server_role == "workstation"
```

#### Scripted Deployment
```bash
#!/bin/bash
# Enterprise deployment script

SERVERS_FILE="servers.txt"
PROTECTION_LEVEL="medium"

while IFS= read -r server; do
    echo "Applying protection to $server"
    ssh root@$server "curl -o protect.sh https://raw.githubusercontent.com/org/protect/main/linux.sh && chmod +x protect.sh && ./protect.sh --$PROTECTION_LEVEL"
done < "$SERVERS_FILE"
```

### Policy Considerations

**Security Policy Integration**:
- Document which protection level aligns with organizational security policies
- Establish approval processes for protection level selection
- Create exception procedures for systems requiring custom configurations

**Compliance Requirements**:
- Map protection levels to compliance frameworks (SOC 2, ISO 27001, etc.)
- Document security controls implemented by each level
- Maintain audit trails of protection deployments

**Change Management**:
- Test protection levels in development environments first
- Implement rollback procedures for production deployments
- Monitor system functionality after protection deployment

### Monitoring and Maintenance

**Post-Deployment Monitoring**:
```bash
# Monitor firewall logs
# Linux
sudo tail -f /var/log/ufw.log

# macOS
sudo tail -f /var/log/pflog

# Windows  
# Check Windows Event Viewer for Firewall events
```

**Regular Maintenance Tasks**:
- Review and clean old backup directories
- Update protection configurations as requirements change
- Monitor for new services that may need special handling
- Validate that protection settings persist through system updates

---

## Additional Resources

- **Main Repository**: [GitHub Repository URL]
- **Issue Reporting**: [GitHub Issues URL]  
- **Security Contacts**: [Security contact information]
- **Community Discussions**: [Discussion forum/chat]

**Last Updated**: [Current Date]
**Version**: Compatible with PROTECT v1.0+ 