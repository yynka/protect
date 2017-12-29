# windows system protection

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

# Enable strict error handling after variable declarations
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Parse-Arguments {
    param([string[]]$Args)
    
    if ($Args.Length -gt 0) {
        switch ($Args[0]) {
            "--maximum" { $script:ProtectionLevel = "maximum" }
            "--medium" { $script:ProtectionLevel = "medium" }
            "--minimum" { $script:ProtectionLevel = "minimum" }
            "--status" {
                Show-Status
                exit 0
            }
            "--help" -or "-h" {
                Write-Host "Usage: powershell -File windows.ps1 [--maximum|--medium|--minimum|--status]"
                Write-Host ""
                Write-Host "Protection Levels:"
                Write-Host "  --maximum  Full hardening - servers, high security"
                Write-Host "  --medium   Balanced security - workstations (recommended)"
                Write-Host "  --minimum  Basic protection - development, compatibility"
                Write-Host ""
                Write-Host "Status Commands:"
                Write-Host "  --status   Show current protection status and configuration"
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
    Write-Host "Available Commands:"
    Write-Host "1) Maximum - Full hardening - servers, high security"
    Write-Host "2) Medium  - Balanced security - workstations (recommended)"
    Write-Host "3) Minimum - Basic protection - development, compatibility"
    Write-Host "4) Status  - Show current protection status and configuration"
    Write-Host "5) Help    - Show usage information and exit"
    Write-Host ""
    
    do {
        $choice = Read-Host "Enter choice [1-5]"
        switch ($choice) {
            "1" { $script:ProtectionLevel = "maximum"; break }
            "2" { $script:ProtectionLevel = "medium"; break }  
            "3" { $script:ProtectionLevel = "minimum"; break }
            "4" { 
                Show-Status
                exit 0
            }
            "5" {
                Write-Host "Usage: powershell -File windows.ps1 [--maximum|--medium|--minimum|--status]"
                Write-Host ""
                Write-Host "Protection Levels:"
                Write-Host "  --maximum  Full hardening - servers, high security"
                Write-Host "  --medium   Balanced security - workstations (recommended)"
                Write-Host "  --minimum  Basic protection - development, compatibility"
                Write-Host ""
                Write-Host "Status Commands:"
                Write-Host "  --status   Show current protection status and configuration"
                Write-Host ""
                Write-Host "If no level is specified, interactive selection will be shown."
                exit 0
            }
            default { Write-Host "Invalid choice. Please enter 1, 2, 3, 4, or 5." }
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

function Show-Status {
    Write-Host ""
    Write-Host "=== Windows Protection Status ===" -ForegroundColor Cyan
    Write-Host ""
    
    # check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "Note: Run as Administrator for complete status information" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # check windows firewall status
    Write-Host "[FIREWALL] Status:" -ForegroundColor Yellow
    try {
        $firewallProfiles = netsh advfirewall show allprofiles state | Select-String "State"
        $domainState = ($firewallProfiles[0] -split "\s+")[1]
        $privateState = ($firewallProfiles[1] -split "\s+")[1] 
        $publicState = ($firewallProfiles[2] -split "\s+")[1]
        
        Write-Host "  [+] Domain Profile: " -NoNewline
        if ($domainState -eq "ON") { Write-Host "ENABLED" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Red }
        
        Write-Host "  [+] Private Profile: " -NoNewline  
        if ($privateState -eq "ON") { Write-Host "ENABLED" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Red }
        
        Write-Host "  [+] Public Profile: " -NoNewline
        if ($publicState -eq "ON") { Write-Host "ENABLED" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Red }
        
        # show firewall rules
        $inboundRules = (netsh advfirewall firewall show rule dir=in | Select-String "Rule Name:" | Measure-Object).Count
        $outboundRules = (netsh advfirewall firewall show rule dir=out | Select-String "Rule Name:" | Measure-Object).Count
        Write-Host "  [i] Inbound Rules: $inboundRules"
        Write-Host "  [i] Outbound Rules: $outboundRules"
        
        # show specific rules we manage
        $customRules = @("Allow HTTP", "Allow HTTPS", "Allow Remote Desktop", "Block Attack Port*")
        Write-Host "  [>] Custom Protection Rules:"
        foreach ($ruleName in $customRules) {
            $ruleExists = netsh advfirewall firewall show rule name="$ruleName" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [+] $ruleName" -ForegroundColor Green
            }
        }
        
    } catch {
        Write-Host "  [-] Could not retrieve firewall status" -ForegroundColor Red
    }
    
    Write-Host ""
    
    # check windows defender status
    Write-Host "[DEFENDER] Status:" -ForegroundColor Yellow
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            Write-Host "  [>] Real-time Protection: " -NoNewline
            if ($defenderStatus.RealTimeProtectionEnabled) { Write-Host "ENABLED" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Red }
            
            Write-Host "  [>] Auto Sample Submission: " -NoNewline  
            if ($defenderStatus.SubmitSamplesConsent -ne "NeverSend") { Write-Host "ENABLED" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Yellow }
            
            Write-Host "  [i] Last Quick Scan: $($defenderStatus.QuickScanStartTime)"
            Write-Host "  [i] Last Full Scan: $($defenderStatus.FullScanStartTime)"
        } else {
            Write-Host "  [?] Windows Defender status unavailable"
        }
    } catch {
        Write-Host "  [?] Could not retrieve Windows Defender status"
    }
    
    Write-Host ""
    
    # check system services
    Write-Host "[SERVICES] Status:" -ForegroundColor Yellow
    $criticalServices = @(
        @{Name="Windows Firewall"; ServiceName="MpsSvc"},
        @{Name="Windows Defender"; ServiceName="WinDefend"},
        @{Name="Remote Desktop"; ServiceName="TermService"},
        @{Name="Remote Registry"; ServiceName="RemoteRegistry"},
        @{Name="Telnet"; ServiceName="TlntSvr"},
        @{Name="FTP Server"; ServiceName="FTPSVC"},
        @{Name="Print Spooler"; ServiceName="Spooler"}
    )
    
    foreach ($svc in $criticalServices) {
        $service = Get-Service -Name $svc.ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            $startup = (Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.ServiceName)'").StartMode
            Write-Host "  [>] $($svc.Name): " -NoNewline
            
            if ($service.Status -eq "Running") {
                Write-Host "$($service.Status)" -ForegroundColor Green -NoNewline
            } elseif ($service.Status -eq "Stopped") {
                Write-Host "$($service.Status)" -ForegroundColor Yellow -NoNewline  
            } else {
                Write-Host "$($service.Status)" -ForegroundColor Red -NoNewline
            }
            Write-Host " ($startup)"
        }
    }
    
    Write-Host ""
    
    # check network configuration
    Write-Host "[NETWORK] Configuration:" -ForegroundColor Yellow
    try {
        # check ip forwarding
        $adapters = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
        $forwardingEnabled = $false
        foreach ($adapter in $adapters) {
            $forwarding = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex | Select-Object -First 1
            if ($forwarding.Forwarding -eq "Enabled") {
                $forwardingEnabled = $true
                break
            }
        }
        
        Write-Host "  [>] IP Forwarding: " -NoNewline
        if ($forwardingEnabled) { Write-Host "ENABLED (potential risk)" -ForegroundColor Red } else { Write-Host "DISABLED (secure)" -ForegroundColor Green }
        
        # check smbv1
        $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol -ErrorAction SilentlyContinue
        if ($smbv1) {
            Write-Host "  [>] SMBv1 Protocol: " -NoNewline
            if ($smbv1.State -eq "Enabled") { Write-Host "ENABLED (security risk)" -ForegroundColor Red } else { Write-Host "DISABLED (secure)" -ForegroundColor Green }
        }
        
        # check llmnr
        $llmnr = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        Write-Host "  [>] LLMNR: " -NoNewline
        if ($llmnr -and $llmnr.EnableMulticast -eq 0) { Write-Host "DISABLED (secure)" -ForegroundColor Green } else { Write-Host "ENABLED (potential risk)" -ForegroundColor Yellow }
        
    } catch {
        Write-Host "  [?] Could not retrieve network configuration"
    }
    
    Write-Host ""
    
    # check for backups
    Write-Host "[BACKUP] Information:" -ForegroundColor Yellow
    $backupDirs = Get-ChildItem "C:\temp" -Directory -Name "firewall_backup_*" -ErrorAction SilentlyContinue | Select-Object -First 5
    if ($backupDirs) {
        Write-Host "  [i] Recent Backups Found:"
        foreach ($backupDir in $backupDirs) {
            $backupDate = $backupDir -replace "firewall_backup_", "" -replace "_", " "
            Write-Host "    [*] $backupDate - C:\temp\$backupDir" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  [i] No backups found in C:\temp"
    }
    
    Write-Host ""
    
    # check log file  
    Write-Host "[LOGS] Information:" -ForegroundColor Yellow
    if (Test-Path $LogFile) {
        $logSize = [math]::Round((Get-Item $LogFile).Length / 1KB, 2)
        $lastEntry = Get-Content $LogFile -Tail 1 | ForEach-Object { ($_ -split ": ")[0] }
        Write-Host "  [i] Log File: $LogFile ($logSize KB)"
        Write-Host "  [i] Last Activity: $lastEntry"
    } else {
        Write-Host "  [i] Log File: Not found"
    }
    
    Write-Host ""
    
    # overall security assessment
    Write-Host "[SECURITY] Assessment:" -ForegroundColor Yellow
    
    # calculate security score
    $score = 0
    $maxScore = 8
    
    # firewall enabled (all profiles)
    try {
        $firewallProfiles = netsh advfirewall show allprofiles state | Select-String "State"
        if ($firewallProfiles -and ($firewallProfiles | Where-Object { $_ -match "OFF" }).Count -eq 0) {
            $score += 2
        }
    } catch { }
    
    # windows defender active
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
            $score += 2
        }
    } catch { }
    
    # ip forwarding disabled  
    try {
        $adapters = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
        $forwardingDisabled = $true
        foreach ($adapter in $adapters) {
            $forwarding = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex | Select-Object -First 1
            if ($forwarding.Forwarding -eq "Enabled") {
                $forwardingDisabled = $false
                break
            }
        }
        if ($forwardingDisabled) { $score += 1 }
    } catch { }
    
    # smbv1 disabled
    try {
        $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol -ErrorAction SilentlyContinue
        if ($smbv1 -and $smbv1.State -ne "Enabled") {
            $score += 1
        }
    } catch { }
    
    # llmnr disabled
    try {
        $llmnr = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
            $score += 1
        }
    } catch { }
    
    # unnecessary services stopped
    $unnecessaryServices = @("RemoteRegistry", "TlntSvr", "FTPSVC")
    $stoppedCount = 0
    foreach ($svcName in $unnecessaryServices) {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Stopped") {
            $stoppedCount++
        }
    }
    if ($stoppedCount -eq $unnecessaryServices.Count) { $score += 1 }
    
    # display security level
    if ($score -ge 6) {
        Write-Host "  [+] Security Level: HIGH ($score/$maxScore)" -ForegroundColor Green
        Write-Host "  [+] System appears to be well protected" -ForegroundColor Green
    } elseif ($score -ge 3) {
        Write-Host "  [!] Security Level: MEDIUM ($score/$maxScore)" -ForegroundColor Yellow
        Write-Host "  [!] Consider running protection script to improve security" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] Security Level: LOW ($score/$maxScore)" -ForegroundColor Red
        Write-Host "  [-] System needs protection - run as Administrator: powershell -File windows.ps1" -ForegroundColor Red
    }
    
    Write-Host ""
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
