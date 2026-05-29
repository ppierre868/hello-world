#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bootstrap: writes all hardening scripts to disk and runs them.
    Run this single file as Administrator on your Windows 11 machine.
#>

$outDir = "$env:SystemDrive\HardenWin11"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
Write-Host "Writing hardening scripts to $outDir ..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Harden-System.ps1
# ---------------------------------------------------------------------------
@'
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Write-Host "[System] Applying system hardening..." -ForegroundColor Yellow

# UAC: Always notify on secure desktop
$uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $uacKey -Name ConsentPromptBehaviorAdmin  -Value 2
Set-ItemProperty $uacKey -Name ConsentPromptBehaviorUser   -Value 1
Set-ItemProperty $uacKey -Name EnableLUA                   -Value 1
Set-ItemProperty $uacKey -Name PromptOnSecureDesktop       -Value 1

# Spectre / Meltdown mitigations
$mmKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
Set-ItemProperty $mmKey -Name FeatureSettingsOverride     -Value 0
Set-ItemProperty $mmKey -Name FeatureSettingsOverrideMask -Value 3

# Disable AutoRun / AutoPlay
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -Name NoDriveTypeAutoRun -Value 255 -Type DWord -Force
Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' `
    -Name DisableAutoplay -Value 1 -Type DWord -Force

# Disable risky / unnecessary services
foreach ($svc in @('RemoteRegistry','Fax','XblAuthManager','XblGameSave','XboxNetApiSvc','WMPNetworkSvc','lfsvc')) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $svc -StartupType Disabled
        Write-Host "  Disabled service: $svc"
    }
}

# Minimise telemetry
$telKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
if (-not (Test-Path $telKey)) { New-Item $telKey -Force | Out-Null }
Set-ItemProperty $telKey -Name AllowTelemetry -Value 0 -Type DWord

# Virtualization Based Security
$vbsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
if (-not (Test-Path $vbsKey)) { New-Item $vbsKey -Force | Out-Null }
Set-ItemProperty $vbsKey -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord
Set-ItemProperty $vbsKey -Name RequirePlatformSecurityFeatures   -Value 1 -Type DWord

# Credential Guard
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LsaCfgFlags -Value 1 -Type DWord

# Disable Windows Script Host (blocks .vbs / .js malware droppers)
$wshKey = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
if (-not (Test-Path $wshKey)) { New-Item $wshKey -Force | Out-Null }
Set-ItemProperty $wshKey -Name Enabled -Value 0 -Type DWord

# Secure Boot check (informational)
try {
    if (Confirm-SecureBootUEFI) { Write-Host "  [+] Secure Boot ENABLED" -ForegroundColor Green }
    else { Write-Warning "  Secure Boot DISABLED - enable in UEFI firmware" }
} catch {}

Write-Host "[System] Done." -ForegroundColor Green
'@ | Set-Content "$outDir\Harden-System.ps1" -Encoding UTF8

# ---------------------------------------------------------------------------
# Harden-Defender.ps1
# ---------------------------------------------------------------------------
@'
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Write-Host "[Defender] Hardening Windows Defender..." -ForegroundColor Yellow

Set-MpPreference -DisableRealtimeMonitoring         $false
Set-MpPreference -CloudBlockLevel                   High
Set-MpPreference -CloudExtendedTimeout              50
Set-MpPreference -EnableNetworkProtection           Enabled
Set-MpPreference -PUAProtection                     Enabled
Set-MpPreference -DisableIOAVProtection             $false
Set-MpPreference -DisableBehaviorMonitoring         $false
Set-MpPreference -DisableScriptScanning             $false
Set-MpPreference -DisableArchiveScanning            $false
Set-MpPreference -DisableEmailScanning              $false
Set-MpPreference -DisableRemovableDriveScanning     $false
Set-MpPreference -SubmitSamplesConsent              SendAllSamples
Set-MpPreference -MAPSReporting                     Advanced

# Weekly full scan Sunday 02:00
Set-MpPreference -ScanScheduleDay    Sunday
Set-MpPreference -ScanScheduleTime   (New-TimeSpan -Hours 2)
Set-MpPreference -ScanParameters     FullScan

# Attack Surface Reduction rules (1 = Block)
$ids = @(
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'  # Executable content from email
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'  # Office child processes
    '3B576869-A4EC-4529-8536-B80A7769E899'  # Office executable content
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'  # Office process injection
    'D3E037E1-3EB8-44C8-A917-57927947596D'  # JS/VBS launching downloads
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'  # Obfuscated scripts
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'  # Win32 API calls from Office
    '01443614-CD74-433A-B99E-2ECDC07BFC25'  # Untrusted executables
    'C1DB55AB-C21A-4637-BB3F-A12568109D35'  # Ransomware protection
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'  # Credential stealing from LSASS
    'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'  # WMI persistence
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'  # Untrusted USB processes
    '26190899-1602-49E8-8B27-EB1D0A1CE869'  # Office comm app child processes
    '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'  # Adobe Reader child processes
)
Set-MpPreference -AttackSurfaceReductionRules_Ids     $ids `
                 -AttackSurfaceReductionRules_Actions (@(1) * $ids.Count)

# Controlled Folder Access (anti-ransomware)
Set-MpPreference -EnableControlledFolderAccess Enabled

Write-Host "[Defender] Done." -ForegroundColor Green
'@ | Set-Content "$outDir\Harden-Defender.ps1" -Encoding UTF8

# ---------------------------------------------------------------------------
# Harden-Firewall.ps1
# ---------------------------------------------------------------------------
@'
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Write-Host "[Firewall] Hardening Windows Firewall..." -ForegroundColor Yellow

# Enable all profiles, default-deny inbound, enable logging
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -LogBlocked True `
    -LogMaxSizeKilobytes 32767

# Disable risky built-in rules
foreach ($r in @('RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP',
                  'WINRM-HTTP-In-TCP','WINRM-HTTP-In-TCP-PUBLIC')) {
    if (Get-NetFirewallRule -Name $r -ErrorAction SilentlyContinue) {
        Disable-NetFirewallRule -Name $r
        Write-Host "  Disabled rule: $r"
    }
}

# Block high-risk inbound ports
$ports = @(
    @{P=23;  Proto='TCP'; L='Telnet'},
    @{P=135; Proto='TCP'; L='RPC'},
    @{P=137; Proto='UDP'; L='NetBIOS-NS'},
    @{P=138; Proto='UDP'; L='NetBIOS-DG'},
    @{P=139; Proto='TCP'; L='NetBIOS-SS'},
    @{P=445; Proto='TCP'; L='SMB'},
    @{P=3389;Proto='TCP'; L='RDP'},
    @{P=5985;Proto='TCP'; L='WinRM-HTTP'},
    @{P=5986;Proto='TCP'; L='WinRM-HTTPS'}
)
foreach ($e in $ports) {
    $name = "HARDEN-Block-$($e.L)-$($e.P)"
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Inbound `
            -Protocol $e.Proto -LocalPort $e.P -Action Block -Enabled True | Out-Null
        Write-Host "  Blocked inbound $($e.L) :$($e.P)"
    }
}

Write-Host "[Firewall] Done." -ForegroundColor Green
'@ | Set-Content "$outDir\Harden-Firewall.ps1" -Encoding UTF8

# ---------------------------------------------------------------------------
# Harden-Identity.ps1
# ---------------------------------------------------------------------------
@'
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Write-Host "[Identity] Hardening accounts and BitLocker..." -ForegroundColor Yellow

# Password & lockout policy
net accounts /MINPWLEN:12 /MAXPWAGE:90 /MINPWAGE:1 /UNIQUEPW:10 | Out-Null
net accounts /LOCKOUTTHRESHOLD:5 /LOCKOUTDURATION:15 /LOCKOUTWINDOW:15 | Out-Null

# Disable Guest account
net user Guest /active:no 2>$null | Out-Null

# Hide last signed-in user; require Ctrl+Alt+Delete
$sysKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $sysKey -Name DontDisplayLastUserName -Value 1 -Type DWord
Set-ItemProperty $sysKey -Name DisableCAD              -Value 0 -Type DWord

# Advanced audit policies
foreach ($cat in @('Account Logon','Account Management','Logon/Logoff',
                   'Object Access','Policy Change','Privilege Use','System')) {
    auditpol /set /category:"$cat" /success:enable /failure:enable | Out-Null
}

# BitLocker (requires TPM 2.0)
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($bl.ProtectionStatus -eq 'On') {
        Write-Host "  [+] BitLocker already ON" -ForegroundColor Green
    } else {
        Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector `
            -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest | Out-Null
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null
        Write-Host "  [+] BitLocker enabled. Run: manage-bde -protectors C: -get  to save your recovery key!" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "  BitLocker skipped: $_"
}

Write-Host "[Identity] Done." -ForegroundColor Green
'@ | Set-Content "$outDir\Harden-Identity.ps1" -Encoding UTF8

# ---------------------------------------------------------------------------
# Harden-Network.ps1
# ---------------------------------------------------------------------------
@'
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Write-Host "[Network] Hardening network settings..." -ForegroundColor Yellow

# Remove SMBv1 (EternalBlue / WannaCry)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
    -Name SMB1 -Value 0 -Type DWord -Force

# Disable LLMNR (Responder poisoning vector)
$llmnr = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (-not (Test-Path $llmnr)) { New-Item $llmnr -Force | Out-Null }
Set-ItemProperty $llmnr -Name EnableMulticast -Value 0 -Type DWord

# Disable NetBIOS over TCP/IP on all adapters
foreach ($a in (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')) {
    $a.SetTcpipNetbios(2) | Out-Null
}

# Disable WPAD
$wpad = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'
if (-not (Test-Path $wpad)) { New-Item $wpad -Force | Out-Null }
Set-ItemProperty $wpad -Name WpadOverride -Value 1 -Type DWord

# DNS over HTTPS (Cloudflare)
try {
    Add-DnsClientDohServerAddress -ServerAddress '1.1.1.1' `
        -DohTemplate 'https://cloudflare-dns.com/dns-query' `
        -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
    Add-DnsClientDohServerAddress -ServerAddress '1.0.0.1' `
        -DohTemplate 'https://cloudflare-dns.com/dns-query' `
        -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
    Write-Host "  [+] DNS over HTTPS configured" -ForegroundColor Green
} catch {
    Write-Warning "  DoH requires Windows 11 22H2+: $_"
}

# Harden TCP/IP stack
$tcp = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
Set-ItemProperty $tcp -Name SynAttackProtect       -Value 1 -Type DWord
Set-ItemProperty $tcp -Name DisableIPSourceRouting  -Value 2 -Type DWord
Set-ItemProperty $tcp -Name EnableICMPRedirect      -Value 0 -Type DWord
Set-ItemProperty $tcp -Name EnableDeadGWDetect      -Value 0 -Type DWord

Write-Host "[Network] Done." -ForegroundColor Green
'@ | Set-Content "$outDir\Harden-Network.ps1" -Encoding UTF8

# ---------------------------------------------------------------------------
# Run all scripts
# ---------------------------------------------------------------------------
Write-Host "`nAll scripts written to $outDir" -ForegroundColor Cyan
Write-Host "Starting hardening run...`n"   -ForegroundColor Cyan

foreach ($script in @('Harden-System','Harden-Defender','Harden-Firewall','Harden-Identity','Harden-Network')) {
    Write-Host "==============================" -ForegroundColor DarkGray
    try {
        & "$outDir\$script.ps1"
    } catch {
        Write-Warning "$script failed: $_"
    }
}

Write-Host "`n===========================================" -ForegroundColor Cyan
Write-Host "  Hardening complete. REBOOT recommended." -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Cyan
