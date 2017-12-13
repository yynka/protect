# Check if running as administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "Please run this script as Administrator."
    Exit
}

# Enable Windows Firewall
Write-Host "Enabling Windows Firewall..."
netsh advfirewall set allprofiles state on

# Set default inbound and outbound policies
Write-Host "Setting default firewall policies..."
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

# Allow necessary inbound rules (Example: Remote Desktop, HTTP, HTTPS)
Write-Host "Allowing necessary inbound rules: Remote Desktop (3389), HTTP (80), HTTPS (443)..."
netsh advfirewall firewall add rule name="Allow Remote Desktop" protocol=TCP dir=in localport=3389 action=allow
netsh advfirewall firewall add rule name="Allow HTTP" protocol=TCP dir=in localport=80 action=allow
netsh advfirewall firewall add rule name="Allow HTTPS" protocol=TCP dir=in localport=443 action=allow

# Block all other inbound connections
Write-Host "Blocking all other inbound connections..."
netsh advfirewall firewall set rule group="all" new enable=no

# Disable unnecessary services
Write-Host "Disabling unnecessary services..."
Set-Service -Name "WSearch" -StartupType Disabled
Stop-Service -Name "WSearch"
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Stop-Service -Name "RemoteRegistry"
Set-Service -Name "Fax" -StartupType Disabled
Stop-Service -Name "Fax"

# Apply security settings
Write-Host "Applying security settings..."

# Disable IP forwarding
Write-Host "Disabling IP forwarding..."
Set-NetIPInterface -Forwarding Disabled

# Disable SMBv1
Write-Host "Disabling SMBv1..."
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol

# Disable NetBIOS over TCP/IP
Write-Host "Disabling NetBIOS over TCP/IP..."
Get-NetAdapter | Set-NetAdapterAdvancedProperty -DisplayName "NetBIOS over Tcpip" -DisplayValue "Disable"

# Disable LLMNR
Write-Host "Disabling LLMNR..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

# Apply changes and restart network services
Write-Host "Applying changes and restarting network services..."
Restart-Service -Name "Dnscache"
Restart-Service -Name "NcaSvc"
Restart-Service -Name "NetSetupSvc"
Restart-Service -Name "DHCP"

Write-Host "All done! Your system is now more secure while maintaining an internet connection."
