# windows system protection

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$LogFile = "C:\temp\protect_script.log"
$BackupDir = "C:\temp\firewall_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Protection level configurations
$LevelPorts = @{
    "maximum" = @(22)
    "medium" = @(22, 80, 443, 3389)
    "minimum" = @(22, 80, 443, 3389, 8080, 3000, 5000)
}

$LevelServices = @{
    "maximum" = @(135, 139, 445, 1433, 1434, 3389, 5985, 5986, 1723, 161)
    "medium" = @(135, 139, 445, 1433, 1434)
    "minimum" = @(135, 139, 445)
}

$LevelDescriptions = @{
    "maximum" = "Full hardening - servers, high security"
    "medium" = "Balanced security - workstations (recommended)"
    "minimum" = "Basic protection - development, compatibility"
}

$ServicesToDisable = @{
    "maximum" = @(
        @{Name="WSearch"; DisplayName="Windows Search"},
        @{Name="RemoteRegistry"; DisplayName="Remote Registry"},
        @{Name="Fax"; DisplayName="Fax"},
        @{Name="TlntSvr"; DisplayName="Telnet"},
        @{Name="FTP"; DisplayName="FTP Server"},
        @{Name="SNMP"; DisplayName="SNMP Service"},
        @{Name="Spooler"; DisplayName="Print Spooler"}
    )
    "medium" = @(
        @{Name="WSearch"; DisplayName="Windows Search"},
        @{Name="RemoteRegistry"; DisplayName="Remote Registry"},
        @{Name="Fax"; DisplayName="Fax"},
        @{Name="TlntSvr"; DisplayName="Telnet"},
        @{Name="FTP"; DisplayName="FTP Server"}
    )
    "minimum" = @(
        @{Name="RemoteRegistry"; DisplayName="Remote Registry"},
        @{Name="TlntSvr"; DisplayName="Telnet"},
        @{Name="FTP"; DisplayName="FTP Server"}
    )
}

$ProtectionLevel = ""
$AllowedPorts = @()
$BlockedPorts = @()
$CurrentServicesToDisable = @()

function Parse-Arguments {
    param([string[]]$Args)
    
    if ($Args.Length -gt 0) {
        switch ($Args[0]) {
            "--maximum" { $script:ProtectionLevel = "maximum" }
            "--medium" { $script:ProtectionLevel = "medium" }
            "--minimum" { $script:ProtectionLevel = "minimum" }
                         "--help" -or "-h" {
                 Write-Host "Usage: powershell -File windows.ps1 [--maximum|--medium|--minimum]"
                 Write-Host ""
                 Write-Host "Protection Levels:"
                 Write-Host "  --maximum  Full hardening - servers, high security"
                 Write-Host "  --medium   Balanced security - workstations (recommended)"
                 Write-Host "  --minimum  Basic protection - development, compatibility"
                 Write-Host ""
                 Write-Host "If no level is specified, interactive selection will be shown."
                 exit 0
             }
            default {
                Write-Host "Error: Unknown option $($Args[0])"
                Write-Host "Use --help for usage information"
                exit 1
            }
        }
    }
}

function Select-ProtectionLevel {
    if ($script:ProtectionLevel -ne "") {
        return # Level already set via command line
    }
    
    Write-Host ""
    Write-Host "Select Protection Level:"
    Write-Host "1) Maximum - Full hardening - servers, high security"
    Write-Host "2) Medium  - Balanced security - workstations (recommended)"
    Write-Host "3) Minimum - Basic protection - development, compatibility"
    Write-Host ""
    
    do {
        $choice = Read-Host "Enter choice [1-3]"
        switch ($choice) {
            "1" { $script:ProtectionLevel = "maximum"; break }
            "2" { $script:ProtectionLevel = "medium"; break }  
            "3" { $script:ProtectionLevel = "minimum"; break }
            default { Write-Host "Invalid choice. Please enter 1, 2, or 3." }
        }
    } while ($script:ProtectionLevel -eq "")
}

function Configure-ProtectionLevel {
    $script:AllowedPorts = $LevelPorts[$script:ProtectionLevel]
    $script:BlockedPorts = $LevelServices[$script:ProtectionLevel]
    $script:CurrentServicesToDisable = $ServicesToDisable[$script:ProtectionLevel]
    
    Write-Log "protection level: $script:ProtectionLevel"
    Write-Log "allowed ports: $($script:AllowedPorts -join ', ')"
    Write-Log "blocked ports: $($script:BlockedPorts -join ', ')"
}

$LogDir = Split-Path $LogFile
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level]: $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage -Encoding UTF8
}

function Backup-SystemState {
    Write-Log "creating system backup: $BackupDir"
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    
    # backup firewall config
    netsh advfirewall export "$BackupDir\firewall_backup.wfw" | Out-Null
    
    # backup services states
    Get-Service | Export-Csv "$BackupDir\services_original.csv" -NoTypeInformation
    
    # backup registry settings for networking
    reg export "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" "$BackupDir\dns_settings.reg" /y 2>$null
    
    # create restore script
    @"
@echo off
echo Restoring Windows system state...
netsh advfirewall import "$BackupDir\firewall_backup.wfw"
echo Firewall restored
reg import "$BackupDir\dns_settings.reg" 2>nul
echo Registry settings restored
echo Restore complete - reboot recommended
pause
"@ | Out-File "$BackupDir\restore.bat" -Encoding ASCII
    
    Write-Log "backup created: $BackupDir"
}

function Cleanup-OldBackups {
    Get-ChildItem "C:\temp" -Directory -Name "firewall_backup_*" | 
        Where-Object { (Get-Item "C:\temp\$_").CreationTime -lt (Get-Date).AddDays(-7) } |
        ForEach-Object { Remove-Item "C:\temp\$_" -Recurse -Force -ErrorAction SilentlyContinue }
}

function Test-ServiceSafety {
    param([string]$ServiceName)
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return $false }
    
    # check if service has dependents
    $dependents = Get-Service -DependentServices $service.Name -ErrorAction SilentlyContinue
    if ($dependents -and $dependents.Status -eq "Running") {
        Write-Log "WARNING: $ServiceName has running dependents, skipping" "WARN"
        return $false
    }
    
    # check if it's a critical system service
    $criticalServices = @("winmgmt", "rpcss", "dcom", "eventlog", "plugplay")
    if ($criticalServices -contains $ServiceName.ToLower()) {
        Write-Log "WARNING: $ServiceName is critical, skipping" "WARN"
        return $false
    }
    
    return $true
}

function Set-ServiceSafely {
    param(
        [hashtable]$ServiceInfo,
        [string]$StartupType = "Disabled",
        [string]$Action = "Stop"
    )
    
    $serviceName = $ServiceInfo.Name
    $displayName = $ServiceInfo.DisplayName
    
    if (-not (Test-ServiceSafety -ServiceName $serviceName)) {
        return
    }
    
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        try {
            $originalStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
            Write-Log "backing up $serviceName startup: $originalStartType"
            Add-Content "$BackupDir\service_changes.log" "$serviceName,$originalStartType"
            
            if ($Action -eq "Stop" -and $service.Status -eq "Running") {
                Write-Log "stopping $displayName"
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                # verify it stopped
                Start-Sleep -Seconds 2
                $service.Refresh()
                if ($service.Status -ne "Stopped") {
                    Write-Log "WARNING: failed to stop $displayName" "WARN"
                    return
                }
            }
            
            Write-Log "setting $displayName to $StartupType"
            Set-Service -Name $serviceName -StartupType $StartupType -ErrorAction Stop
            
            # verify the change
            $newService = Get-Service -Name $serviceName
            $newStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
            if ($newStartType -ne $StartupType) {
                Write-Log "WARNING: failed to change $displayName startup type" "WARN"
            }
            
        } catch {
            Write-Log "WARNING: could not configure $displayName : $_" "WARN"
        }
    } else {
        Write-Log "$displayName not found" "INFO"
    }
}

function Handle-Error {
    param([string]$ErrorMessage)
    Write-Log "ERROR: $ErrorMessage" "ERROR"
    Write-Log "script failed, check logs" "ERROR"
    Write-Log "restore with: $BackupDir\restore.bat" "ERROR"
    exit 1
}

try {
    Parse-Arguments $args

    Write-Log "starting windows protection script..."
    Select-ProtectionLevel
    Configure-ProtectionLevel

    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Handle-Error "run as administrator"
    }

    Cleanup-OldBackups
    Backup-SystemState

    Write-Log "enabling firewall..."
    netsh advfirewall set allprofiles state on
    if ($LASTEXITCODE -ne 0) {
        throw "failed to enable firewall"
    }

    Write-Log "setting default policies..."
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
    if ($LASTEXITCODE -ne 0) {
        throw "failed to set policies"
    }

    Write-Log "removing old rules..."
    netsh advfirewall firewall delete rule name="Allow HTTP" 2>$null
    netsh advfirewall firewall delete rule name="Allow HTTPS" 2>$null
    netsh advfirewall firewall delete rule name="Allow Remote Desktop" 2>$null
    netsh advfirewall firewall delete rule name="Block Attack Ports" 2>$null

    Write-Log "configuring allowed ports..."
    
    foreach ($port in $AllowedPorts) {
        switch ($port) {
            80 {
                Write-Log "allowing http (80)..."
                netsh advfirewall firewall add rule name="Allow HTTP" protocol=TCP dir=in localport=80 action=allow
                if ($LASTEXITCODE -ne 0) { throw "failed to allow http" }
            }
            443 {
                Write-Log "allowing https (443)..."
                netsh advfirewall firewall add rule name="Allow HTTPS" protocol=TCP dir=in localport=443 action=allow
                if ($LASTEXITCODE -ne 0) { throw "failed to allow https" }
            }
            3389 {
                $rdpEnabled = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
                if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) {
                    Write-Log "allowing rdp (3389)..."
                    netsh advfirewall firewall add rule name="Allow Remote Desktop" protocol=TCP dir=in localport=3389 action=allow
                    if ($LASTEXITCODE -ne 0) { throw "failed to allow rdp" }
                } else {
                    Write-Log "rdp disabled, skipping port 3389"
                }
            }
            default {
                Write-Log "allowing port $port..."
                netsh advfirewall firewall add rule name="Allow Port $port" protocol=TCP dir=in localport=$port action=allow
                if ($LASTEXITCODE -ne 0) { Write-Log "WARNING: failed to allow port $port" "WARN" }
            }
        }
    }

    Write-Log "blocking attack ports..."
    foreach ($port in $BlockedPorts) {
        netsh advfirewall firewall add rule name="Block Attack Port $port" protocol=TCP dir=in localport=$port action=block | Out-Null
    }

    Write-Log "configuring services..."
    foreach ($serviceInfo in $CurrentServicesToDisable) {
        Set-ServiceSafely -ServiceInfo $serviceInfo -StartupType "Disabled" -Action "Stop"
    }

    Write-Log "applying hardening..."

    try {
        Write-Log "disabling ip forwarding..."
        $adapters = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -Forwarding Disabled -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "WARNING: could not disable forwarding: $_" "WARN"
    }

    try {
        Write-Log "disabling smbv1..."
        $smbFeature = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol -ErrorAction SilentlyContinue
        if ($smbFeature -and $smbFeature.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
        }
    } catch {
        Write-Log "WARNING: could not disable smbv1: $_" "WARN"
    }

    try {
        Write-Log "disabling netbios..."
        Get-NetAdapter | ForEach-Object {
            try {
                Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "NetBIOS over Tcpip" -DisplayValue "Disable" -ErrorAction SilentlyContinue
            } catch {
            }
        }
    } catch {
        Write-Log "WARNING: could not configure netbios: $_" "WARN"
    }

    try {
        Write-Log "disabling llmnr..."
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0
    } catch {
        Write-Log "WARNING: could not disable llmnr: $_" "WARN"
    }

    Write-Log "restarting network services..."
    $networkServices = @("Dnscache", "NcaSvc", "NetSetupSvc", "DHCP")
    foreach ($serviceName in $networkServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Restart-Service -Name $serviceName -Force
                Write-Log "restarted $serviceName"
            }
        } catch {
            Write-Log "WARNING: could not restart $serviceName : $_" "WARN"
        }
    }

    Write-Log "verifying config..."
    $firewallStatus = netsh advfirewall show allprofiles state
    Write-Log "firewall status:"
    $firewallStatus | Add-Content -Path $LogFile -Encoding UTF8

    Write-Log "done!"
    Write-Log "backup: $BackupDir"
    Write-Log "restore: $BackupDir\restore.bat"
    Write-Log "logs: $LogFile"

    Write-Host ""
    Write-Host "[+] windows system protected" -ForegroundColor Green
    Write-Host "• level: $ProtectionLevel" -ForegroundColor White
    Write-Host "• firewall: enabled, deny incoming" -ForegroundColor White
    Write-Host "• ports: $($AllowedPorts -join ', ')" -ForegroundColor White
    Write-Host "• attack ports: $($BlockedPorts -join ', ')" -ForegroundColor White
    Write-Host "• services: unnecessary ones disabled" -ForegroundColor White
    Write-Host "• protocols: smbv1, netbios, llmnr disabled" -ForegroundColor White
    Write-Host "• backup: $BackupDir" -ForegroundColor White
    Write-Host "• restore: $BackupDir\restore.bat" -ForegroundColor White
    Write-Host "• logs: $LogFile" -ForegroundColor White

} catch {
    Handle-Error $_.Exception.Message
}
