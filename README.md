<a id="top"></a>
```
     ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗  ⠀⠀⠀⢸⣦⡀⠀⠀⠀⠀⢀⡄
     ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝  ⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴
     ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║    ⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇
     ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║    ⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⢀
     ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║    ⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀
     ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ⠀⠀⠀⠀⠸⣿⡿⠏⠀
                                                                  ⠀⠀⠀⠀⠀⠟⠁⠀
```

**Cross-Platform System Security Optimization & Hardening Tool**

[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#windows)
[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#macos)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#linux)

## Features

▸ **Firewall Activation** - Automatically enables and configures system firewall protection  
▸ **Access Control** - Blocks unauthorized network access and suspicious connections  
▸ **Service Hardening** - Disables unused services to reduce attack surface  
▸ **Security Configuration** - Applies comprehensive security settings and policies  
▸ **Performance Enhancement** - Optimizes system stability and overall performance  
▸ **Vulnerability Prevention** - Protects against common security vulnerabilities  
▸ **Automated Deployment** - One-command installation and configuration  
▸ **Cross-Platform** - Consistent security hardening across Windows, macOS, and Linux  

## Protection Levels

All scripts support three configurable protection levels with automatic or interactive selection:

| Level | Description | Allowed Ports | Blocked Ports | Use Case |
|-------|-------------|---------------|---------------|----------|
| **Maximum** | Full hardening - servers, high security | SSH (22) only | 9 attack ports | Production servers, high-security environments |
| **Medium** | Balanced security - workstations (recommended) | SSH, HTTP, HTTPS, RDP* | 5 common attacks | Workstations, general use (default) |
| **Minimum** | Basic protection - development, compatibility | Above + dev ports (8080, 3000, 5000) | 3 basic threats | Development machines, compatibility needed |

*RDP (3389) included on Windows when Remote Desktop is enabled

### Usage Examples

**Command Line Mode** (skips interactive menu):
```bash
# Linux
sudo ./linux.sh --maximum
sudo ./linux.sh --medium
sudo ./linux.sh --minimum

# macOS
sudo ./macos.sh --maximum
sudo ./macos.sh --medium
sudo ./macos.sh --minimum

# Windows
powershell -File windows.ps1 --maximum
powershell -File windows.ps1 --medium
powershell -File windows.ps1 --minimum
```

**Interactive Mode** (shows selection menu):
```bash
# Linux - shows selection menu
sudo ./linux.sh

# macOS - shows selection menu
sudo ./macos.sh

# Windows - shows selection menu
powershell -File windows.ps1
```

**Help Information**:
```bash
# Linux
sudo ./linux.sh --help

# macOS
sudo ./macos.sh --help

# Windows
powershell -File windows.ps1 --help
```

**Status Monitoring**:
```bash
# Linux
sudo ./linux.sh --status

# macOS
sudo ./macos.sh --status

# Windows
powershell -File windows.ps1 --status
```

For detailed protection level specifications and security considerations, see [GUIDE.md](GUIDE.md).

---

## Status Commands

Monitor your system's current protection status and security configuration with built-in status commands.

### Overview

The status command provides a comprehensive security assessment including:

▸ **Firewall Status** - Active rules, profiles, and configuration  
▸ **Service Status** - Critical system services and their states  
▸ **Network Security** - IP forwarding, protocol settings, and vulnerabilities  
▸ **Security Assessment** - Overall security score and recommendations  
▸ **Backup Information** - Available configuration backups and restore options  
▸ **Log Analysis** - Recent activity and security events  

### Usage Examples

**Quick Status Check** (all platforms):
```bash
# Linux
sudo ./linux.sh --status

# macOS  
sudo ./macos.sh --status

# Windows (Command Prompt as Administrator)
powershell -File windows.ps1 --status
```

### Status Output Examples

**Linux Status Output:**
```
=== Linux Protection Status ===

[FIREWALL] Status:
  [+] UFW Firewall: ACTIVE
  [i] Active Rules:
    [1] 22/tcp                     ALLOW IN    Anywhere
    [2] 80/tcp                     ALLOW IN    Anywhere  
    [3] 443/tcp                    ALLOW IN    Anywhere
  [>] Default Policy:
    Default: deny (incoming), allow (outgoing), disabled (routed)

[SYSTEM] Configuration:
  [+] IPv4 Forwarding: DISABLED (secure)
  [+] IPv6 Forwarding: DISABLED (secure) 
  [+] Source Route: DISABLED (secure)
  [+] SYN Cookies: ENABLED (secure)
  [+] ICMP Redirects: DISABLED (secure)

[SERVICES] Status:
  [+] SSH Service: RUNNING
  [+] Fail2Ban: RUNNING (intrusion prevention)

[SECURITY] Assessment:
  [+] Security Level: HIGH (6/6)
  [+] System appears to be well protected
```

**macOS Status Output:**
```
=== macOS Protection Status ===

[FIREWALL] Status:
  [+] PF Firewall: ENABLED
  [i] Active Rules: 12
  [>] Allowed Ports:
    pass in proto tcp from any to any port { 22, 80, 443 } keep state
  [x] Blocked Ports:
    block log quick proto tcp from any to any port { 135, 139, 445 }

[SYSTEM] Configuration:
  [+] IP Forwarding: DISABLED (secure)
  [+] IPv6 Forwarding: DISABLED (secure)
  [+] Source Routing: DISABLED (secure)
  [+] SYN Cookies: ENABLED (secure)

[SECURITY] Assessment:
  [+] Security Level: HIGH (5/5)
  [+] System appears to be well protected
```

**Windows Status Output:**
```
=== Windows Protection Status ===

[FIREWALL] Status:
  [+] Domain Profile: ENABLED
  [+] Private Profile: ENABLED
  [+] Public Profile: ENABLED
  [i] Inbound Rules: 47
  [i] Outbound Rules: 23
  [>] Custom Protection Rules:
    [+] Allow HTTP
    [+] Allow HTTPS
    [+] Block Attack Port 135

[DEFENDER] Status:
  [>] Real-time Protection: ENABLED
  [>] Auto Sample Submission: ENABLED
  [i] Last Quick Scan: 12/15/2023 10:30:00 AM

[SERVICES] Status:
  [>] Windows Firewall: Running (Auto)
  [>] Windows Defender: Running (Auto)
  [>] Remote Registry: Stopped (Disabled)
  [>] Telnet: Stopped (Disabled)

[NETWORK] Configuration:
  [>] IP Forwarding: DISABLED (secure)
  [>] SMBv1 Protocol: DISABLED (secure)
  [>] LLMNR: DISABLED (secure)

[SECURITY] Assessment:
  [+] Security Level: HIGH (7/8)
  [+] System appears to be well protected
```

### Status Command Benefits

▪ **Real-time Monitoring** - Instant visibility into current security posture  
▪ **Security Scoring** - Quantified assessment with actionable recommendations  
▪ **Configuration Validation** - Verify protection settings are active and correct  
▪ **Troubleshooting** - Identify security gaps or configuration issues  
▪ **Compliance Checking** - Ensure systems meet security requirements  
▪ **Backup Tracking** - Monitor available configuration backups and restore points  

### Security Levels

| Level | Score Range | Indication | Action Required |
|-------|-------------|------------|-----------------|
| **HIGH** | 80-100% | [+] Well Protected | Continue monitoring |
| **MEDIUM** | 40-79% | [!] Partially Protected | Run protection script |
| **LOW** | 0-39% | [-] Vulnerable | Immediate protection needed |

---

## ◆ Windows <a id="windows"></a>[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#top)

### Prerequisites
▪ Windows 10/11 or Windows Server 2016+  
▪ Administrator privileges  
▪ 200 MB free disk space  
▪ Internet connection for downloads  

### Installation
```powershell
# Open Command Prompt as Administrator
# Press Windows + R, type 'cmd', press Ctrl+Shift+Enter

# Download Git installer
powershell -Command "Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/latest/download/Git-64-bit.exe -OutFile Git-64-bit.exe"

# Install Git silently
.\Git-64-bit.exe /VERYSILENT /NORESTART

# Download protection script
curl -o windows.ps1 https://raw.githubusercontent.com/yynka/protect/main/windows.ps1

# Run protection script
powershell -ExecutionPolicy Bypass -File .\windows.ps1
```

### Quick Installation (One-Line)
```powershell
powershell -Command "Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/latest/download/Git-64-bit.exe -OutFile Git-64-bit.exe; .\Git-64-bit.exe /VERYSILENT /NORESTART; Start-Sleep 30; curl -o windows.ps1 https://raw.githubusercontent.com/yynka/protect/main/windows.ps1; powershell -ExecutionPolicy Bypass -File .\windows.ps1"
```

※ **Note:** Requires running Command Prompt as Administrator for system-level security modifications

---

## ◆ macOS <a id="macos"></a>[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#top)

### Prerequisites
▪ macOS 10.14+ (Mojave or later)  
▪ Administrator privileges (`sudo` access)  
▪ 100 MB free disk space  
▪ Internet connection for downloads  

### Installation
```bash
# Open Terminal
# Press Command + Space, type 'Terminal', press Enter

# Install Homebrew (package manager)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Git via Homebrew
brew install git

# Download protection script
curl -o macos.sh https://raw.githubusercontent.com/yynka/protect/main/macos.sh

# Make script executable and run
chmod +x macos.sh
sudo ./macos.sh
```

### Quick Installation (One-Line)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" && brew install git && curl -o macos.sh https://raw.githubusercontent.com/yynka/protect/main/macos.sh && chmod +x macos.sh && sudo ./macos.sh
```

※ **Note:** Requires running commands with `sudo` for system security configuration changes

---

## ◆ Linux <a id="linux"></a>[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#top)

### Prerequisites
▪ Ubuntu/Debian-based Linux distribution  
▪ `sudo` privileges  
▪ 100 MB free disk space  
▪ Internet connection for downloads  

### Installation
```bash
# Open Terminal
# Press Ctrl + Alt + T

# Update package lists
sudo apt-get update

# Install Git
sudo apt-get install git -y

# Download protection script
curl -o linux.sh https://raw.githubusercontent.com/yynka/protect/main/linux.sh

# Make script executable and run
chmod +x linux.sh
sudo ./linux.sh
```

### Quick Installation (One-Line)
```bash
sudo apt-get update && sudo apt-get install git -y && curl -o linux.sh https://raw.githubusercontent.com/yynka/protect/main/linux.sh && chmod +x linux.sh && sudo ./linux.sh
```

### Alternative Distributions
```bash
# For CentOS/RHEL/Fedora
sudo yum update && sudo yum install git -y && curl -o linux.sh https://raw.githubusercontent.com/yynka/protect/main/linux.sh && chmod +x linux.sh && sudo ./linux.sh

# For Arch Linux
sudo pacman -Syu && sudo pacman -S git && curl -o linux.sh https://raw.githubusercontent.com/yynka/protect/main/linux.sh && chmod +x linux.sh && sudo ./linux.sh
```

※ **Note:** Requires running commands with `sudo` for system-level security hardening

---

## ※ Command Reference

### Universal Installation Process
All platforms follow the same logical sequence:

| Step | Description | Windows | macOS | Linux |
|------|-------------|---------|-------|-------|
| **1** | Open Terminal/Command Prompt | `cmd` (Admin) | Terminal | `Ctrl+Alt+T` |
| **2** | Install Git | Download installer | `brew install git` | `apt-get install git` |
| **3** | Download Script | `curl -o windows.ps1 [URL]` | `curl -o macos.sh [URL]` | `curl -o linux.sh [URL]` |
| **4** | Execute Protection | `powershell -File windows.ps1` | `sudo ./macos.sh` | `sudo ./linux.sh` |
| **5** | Monitor Status | `powershell -File windows.ps1 --status` | `sudo ./macos.sh --status` | `sudo ./linux.sh --status` |

### Script Locations
| Platform | Script Name | Repository URL |
|----------|-------------|----------------|
| **Windows** | `windows.ps1` | `https://raw.githubusercontent.com/yynka/protect/main/windows.ps1` |
| **macOS** | `macos.sh` | `https://raw.githubusercontent.com/yynka/protect/main/macos.sh` |
| **Linux** | `linux.sh` | `https://raw.githubusercontent.com/yynka/protect/main/linux.sh` |

## Usage Examples

### Standard Installation
```bash
# Windows (Command Prompt as Administrator)
powershell -Command "Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/latest/download/Git-64-bit.exe -OutFile Git-64-bit.exe"
.\Git-64-bit.exe /VERYSILENT /NORESTART
curl -o windows.ps1 https://raw.githubusercontent.com/yynka/protect/main/windows.ps1
powershell -ExecutionPolicy Bypass -File .\windows.ps1

# macOS (Terminal)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install git
curl -o macos.sh https://raw.githubusercontent.com/yynka/protect/main/macos.sh
sudo ./macos.sh

# Linux (Terminal)
sudo apt-get update
sudo apt-get install git -y
curl -o linux.sh https://raw.githubusercontent.com/yynka/protect/main/linux.sh
sudo ./linux.sh
```

### Verification Commands
```bash
# Check if Git was installed successfully
git --version

# Verify script download
# Windows
dir windows.ps1

# macOS
ls -la macos.sh

# Linux
ls -la linux.sh

# Check protection status after installation
# Windows
powershell -File windows.ps1 --status

# macOS
sudo ./macos.sh --status

# Linux
sudo ./linux.sh --status
```

## Technical Implementation

### Windows Implementation
▪ **Technology:** PowerShell scripts with Windows Security APIs  
▪ **Method:** Automated firewall configuration and service management  
▪ **Features:** Windows Defender integration, registry hardening, service optimization  
▪ **Requirements:** Administrator privileges for system-level modifications  

### macOS Implementation
▪ **Technology:** Bash scripts with macOS security frameworks  
▪ **Method:** System Preferences automation and security policy enforcement  
▪ **Features:** Gatekeeper configuration, firewall setup, privacy controls  
▪ **Requirements:** Administrator privileges and System Integrity Protection awareness  

### Linux Implementation
▪ **Technology:** Bash scripts with iptables and systemd integration  
▪ **Method:** Package management and service configuration automation  
▪ **Features:** UFW/iptables setup, service hardening, kernel parameter tuning  
▪ **Requirements:** Root privileges and distribution-specific package managers  

## Security Benefits

▪ **Comprehensive Protection** - Multi-layered security approach across all platforms  
▪ **Attack Surface Reduction** - Disables unnecessary services and closes security gaps  
▪ **Automated Hardening** - Applies industry-standard security configurations  
▪ **Performance Optimization** - Improves system stability while enhancing security  
▪ **Vulnerability Mitigation** - Protects against common attack vectors and exploits  
▪ **Consistent Security** - Uniform protection standards across different operating systems  
▪ **Zero-Configuration** - Automated deployment with minimal user intervention  
▪ **Enterprise-Ready** - Suitable for both personal and organizational deployments  

## Output Examples

### Successful Windows Installation
```
=== PROTECT System Security Hardening ===
[+] Git installer downloaded successfully
[+] Git installed silently
[+] Protection script downloaded
[+] Executing security hardening...

[*] Configuring Windows Firewall...
[+] Firewall enabled for all profiles
[+] Inbound rules configured
[+] Outbound rules optimized

[*] Hardening system services...
[+] Disabled unnecessary services
[+] Configured security policies
[+] Applied registry hardening

[+] Your PC is now protected from unwanted activity!
System hardening completed successfully.
```

### Successful macOS Installation
```
=== PROTECT System Security Hardening ===
[+] Homebrew installed successfully
[+] Git installed via Homebrew
[+] Protection script downloaded and made executable
[+] Executing security hardening with sudo privileges...

[*] Configuring macOS Firewall...
[+] Application firewall enabled
[+] Stealth mode activated
[+] Logging configured

[*] Hardening system preferences...
[+] Gatekeeper configured
[+] Privacy settings optimized
[+] Security policies applied

[+] Your Mac is now protected from unwanted activity!
System hardening completed successfully.
```

### Successful Linux Installation
```
=== PROTECT System Security Hardening ===
[+] Package lists updated
[+] Git installed successfully
[+] Protection script downloaded and made executable
[+] Executing security hardening with sudo privileges...

[*] Configuring Linux firewall...
[+] UFW firewall enabled
[+] Default policies configured
[+] Security rules applied

[*] Hardening system services...
[+] Unnecessary services disabled
[+] Security modules configured
[+] Kernel parameters optimized

[+] Your system is now protected from unwanted activity!
System hardening completed successfully.
```

## Dependencies

| Platform | Core Requirements | Optional Components |
|----------|-------------------|-------------------|
| **Windows** | PowerShell 5.1+, Administrator privileges, 200MB disk space | Windows Defender, Event Logging |
| **macOS** | Bash shell, `sudo` privileges, 100MB disk space, Homebrew | Xcode Command Line Tools |
| **Linux** | Bash shell, `sudo` privileges, 100MB disk space, package manager | `curl`, `wget`, distribution-specific tools |

## Troubleshooting

### Common Issues
| Issue | Platform | Solution |
|-------|----------|----------|
| **Permission Denied** | All | Run terminal/command prompt as Administrator/sudo |
| **Git Not Found** | Windows | Restart Command Prompt after Git installation |
| **Homebrew Installation Failed** | macOS | Install Xcode Command Line Tools first |
| **Package Manager Error** | Linux | Update package lists: `sudo apt-get update` |
| **Script Download Failed** | All | Check internet connection and firewall settings |

### Support Commands
```bash
# Check system requirements
# Windows
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# macOS
sw_vers

# Linux
lsb_release -a
```

---

## License

[MIT License](LICENSE) - Feel free to use and modify as needed.

**※ Security Note:** This tool performs system-level security modifications and requires administrative privileges on all platforms. Test thoroughly in a controlled environment before deploying in production. Use responsibly and in compliance with your organization's security policies.