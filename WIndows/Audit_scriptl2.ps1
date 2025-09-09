<#
.SYNOPSIS
    CIS Benchmark Audit Script – Windows 11 (Level 2)

.DESCRIPTION
    Checks selected Level 2 security recommendations as per CIS Benchmark.
    Prints PASS/FAIL and exports results to CSV.

.NOTES
    Run as Administrator
#>

$Results = @()

function Write-Result {
    param($Name, $Current, $Expected, $Passed)

    if ($Passed) {
        $status = "PASS"
        $color = "Green"
    } else {
        $status = "FAIL"
        $color = "Red"
    }

    Write-Host "$status : $Name | Current: $Current | Expected: $Expected" -ForegroundColor $color

    $script:Results += [PSCustomObject]@{
        CheckName = $Name
        Current   = $Current
        Expected  = $Expected
        Status    = $status
    }
}

# -------------------------------
# 1. Ensure Windows Defender Antivirus is enabled
# -------------------------------
try {
    $service = Get-Service -Name WinDefend -ErrorAction Stop
    $pass = $service.Status -eq "Running"
    Write-Result "Windows Defender Antivirus" $service.Status "Running" $pass
} catch {
    Write-Result "Windows Defender Antivirus" "Not Installed" "Running" $false
}

# -------------------------------
# 2. Ensure 'Windows Firewall' is enabled on all profiles
# -------------------------------
$fwProfiles = Get-NetFirewallProfile
foreach ($profile in $fwProfiles) {
    $pass = $profile.Enabled -eq "True"
    Write-Result "Firewall ($($profile.Name))" $profile.Enabled "Enabled" $pass
}

# -------------------------------
# 3. Ensure 'LSA Protection' is enabled
# -------------------------------
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$current = (Get-ItemProperty -Path $lsaPath -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
$expected = 1
$pass = $current -eq $expected
Write-Result "LSA Protection (Credential Guard)" $current $expected $pass

# -------------------------------
# 4. Ensure 'Remote Desktop Services' is disabled unless required
# -------------------------------
$rdp = Get-Service -Name TermService -ErrorAction SilentlyContinue
if ($rdp) {
    $pass = $rdp.StartType -eq "Disabled"
    Write-Result "Remote Desktop Services" $rdp.StartType "Disabled" $pass
} else {
    Write-Result "Remote Desktop Services" "Not Installed" "Disabled" $true
}

# -------------------------------
# 5. Ensure 'Windows Remote Management (WS-Management)' is disabled
# -------------------------------
$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrm) {
    $pass = $winrm.StartType -eq "Disabled"
    Write-Result "Windows Remote Management" $winrm.StartType "Disabled" $pass
} else {
    Write-Result "Windows Remote Management" "Not Installed" "Disabled" $true
}

# -------------------------------
# 6. Ensure 'Guest account status' is disabled
# -------------------------------
$guest = (Get-LocalUser -Name Guest).Enabled
$pass = $guest -eq $false
Write-Result "Guest Account" $guest "Disabled" $pass

# -------------------------------
# 7. Ensure 'Anonymous SID Enumeration' is disabled
# -------------------------------
$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$current = (Get-ItemProperty -Path $regPath -Name RestrictAnonymousSAM -ErrorAction SilentlyContinue).RestrictAnonymousSAM
$expected = 1
$pass = $current -eq $expected
Write-Result "Restrict Anonymous SAM Enumeration" $current $expected $pass

# -------------------------------
# 8. Ensure 'SMB v1 Protocol' is disabled
# -------------------------------
$optional = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
$pass = $optional.State -eq "Disabled"
Write-Result "SMBv1 Protocol" $optional.State "Disabled" $pass

# -------------------------------
# 9. Ensure 'Windows Installer' is set to Manual
# -------------------------------
$msi = Get-Service -Name msiserver -ErrorAction SilentlyContinue
if ($msi) {
    $pass = $msi.StartType -eq "Manual"
    Write-Result "Windows Installer Service" $msi.StartType "Manual" $pass
} else {
    Write-Result "Windows Installer Service" "Not Installed" "Manual" $true
}

# -------------------------------
# 10. Ensure 'Windows Update' is enabled
# -------------------------------
$wua = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($wua) {
    $pass = $wua.StartType -ne "Disabled"
    Write-Result "Windows Update Service" $wua.StartType "Enabled" $pass
} else {
    Write-Result "Windows Update Service" "Not Installed" "Enabled" $false
}

# -------------------------------
# 11. Ensure 'Windows Error Reporting Service' is disabled
# -------------------------------
$wer = Get-Service -Name WerSvc -ErrorAction SilentlyContinue
if ($wer) {
    $pass = $wer.StartType -eq "Disabled"
    Write-Result "Windows Error Reporting Service" $wer.StartType "Disabled" $pass
} else {
    Write-Result "Windows Error Reporting Service" "Not Installed" "Disabled" $true
}

# -------------------------------
# 12. Ensure 'Print Spooler Service' is disabled (if not needed)
# -------------------------------
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler) {
    $pass = $spooler.StartType -eq "Disabled"
    Write-Result "Print Spooler Service" $spooler.StartType "Disabled" $pass
} else {
    Write-Result "Print Spooler Service" "Not Installed" "Disabled" $true
}

# -------------------------------
# 13. Ensure 'Bluetooth Support Service' is disabled (if not required)
# -------------------------------
$bt = Get-Service -Name bthserv -ErrorAction SilentlyContinue
if ($bt) {
    $pass = $bt.StartType -eq "Disabled"
    Write-Result "Bluetooth Support Service" $bt.StartType "Disabled" $pass
} else {
    Write-Result "Bluetooth Support Service" "Not Installed" "Disabled" $true
}

# -------------------------------
# 14. Ensure 'Telnet Client' is not installed
# -------------------------------
$telnet = Get-WindowsCapability -Online | Where-Object Name -like 'Telnet.Client*'
if ($telnet) {
    $pass = $telnet.State -eq "NotPresent"
    Write-Result "Telnet Client" $telnet.State "Not Installed" $pass
} else {
    Write-Result "Telnet Client" "Not Installed" "Not Installed" $true
}

# -------------------------------
# 15. Ensure 'FTP Server' is not installed
# -------------------------------
$ftp = Get-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer -ErrorAction SilentlyContinue
if ($ftp) {
    $pass = $ftp.State -eq "Disabled"
    Write-Result "FTP Server" $ftp.State "Disabled" $pass
} else {
    Write-Result "FTP Server" "Not Installed" "Disabled" $true
}

# -------------------------------
# 16. Ensure 'PowerShell v2' is not installed
# -------------------------------
$ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
if ($ps2) {
    $pass = $ps2.State -eq "Disabled"
    Write-Result "PowerShell v2" $ps2.State "Disabled" $pass
} else {
    Write-Result "PowerShell v2" "Not Installed" "Disabled" $true
}

# -------------------------------
# 17. Ensure 'Windows Script Host' is disabled (optional for security)
# -------------------------------
$wshPath = "HKLM:\Software\Microsoft\Windows Script Host\Settings"
$current = (Get-ItemProperty -Path $wshPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
$expected = 0
$pass = $current -eq $expected
Write-Result "Windows Script Host" $current $expected $pass

# -------------------------------
# 18. Ensure 'Remote Assistance' is disabled
# -------------------------------
$ra = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ErrorAction SilentlyContinue)."fAllowToGetHelp"
$expected = 0
$pass = $ra -eq $expected
Write-Result "Remote Assistance" $ra $expected $pass

# -------------------------------
# 19. Ensure 'Windows Remote Shell' is disabled
# -------------------------------
$wsman = Get-ChildItem WSMan:\localhost\Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "EnableCompatibilityHttpListener" }
$current = if ($wsman) { $wsman.Value } else { "N/A" }
$expected = 0
$pass = $current -eq $expected
Write-Result "Windows Remote Shell" $current $expected $pass

# -------------------------------
# 20. Ensure 'SMB v2/v3 encryption' is enabled
# -------------------------------
$smb = Get-SmbServerConfiguration | Select-Object -ExpandProperty EncryptData
$expected = $true
$pass = $smb -eq $expected
Write-Result "SMB v2/v3 Encryption" $smb $expected $pass

# -------------------------------
# 21. Ensure 'Windows Defender SmartScreen' is enabled
# -------------------------------
$smartscreen = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name EnableWebContentEvaluation -ErrorAction SilentlyContinue
$current = $smartscreen.EnableWebContentEvaluation
$expected = 1
$pass = $current -eq $expected
Write-Result "Windows Defender SmartScreen" $current $expected $pass

# -------------------------------
# 22. Ensure 'Windows Defender Exploit Guard' is enabled
# -------------------------------
$exploit = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
$pass = $exploit -ne $null
Write-Result "Windows Defender Exploit Guard" $exploit "Configured" $pass

# -------------------------------
# 23. Ensure 'BitLocker Drive Encryption' is enabled on system drive
# -------------------------------
$bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($bitlocker) {
    $pass = $bitlocker.ProtectionStatus -eq "On"
    Write-Result "BitLocker (C:)" $bitlocker.ProtectionStatus "On" $pass
} else {
    Write-Result "BitLocker (C:)" "Not Supported" "On" $false
}

# -------------------------------
# 24. Ensure 'USB Storage' is restricted (if required)
# -------------------------------
$usbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
$current = (Get-ItemProperty -Path $usbPath -Name Start -ErrorAction SilentlyContinue).Start
$expected = 4  # 4 = Disabled
$pass = $current -eq $expected
Write-Result "USB Storage Access" $current "Disabled" $pass

# -------------------------------
# 25. Ensure 'Windows Defender Tamper Protection' is enabled
# -------------------------------
try {
    $tamper = (Get-MpComputerStatus).IsTamperProtected
    $expected = True
    $pass = $tamper -eq $expected
    Write-Result "Defender Tamper Protection" $tamper $expected $pass
} catch {
    Write-Result "Defender Tamper Protection" "Error" "Enabled" $false
}

# -------------------------------
# 26. Ensure 'Windows Defender Real-Time Protection' is enabled
# -------------------------------
try {
    $rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled
    $expected = $true
    $pass = $rtp -eq $expected
    Write-Result "Defender Real-Time Protection" $rtp $expected $pass
} catch {
    Write-Result "Defender Real-Time Protection" "Error" "Enabled" $false
}

# -------------------------------
# 27. Ensure 'Windows Defender Cloud Protection' is enabled
# -------------------------------
try {
    $cloud = (Get-MpPreference).MAPSReporting
    $expected = 2  # Advanced
    $pass = $cloud -eq $expected
    Write-Result "Defender Cloud Protection" $cloud "2 (Advanced)" $pass
} catch {
    Write-Result "Defender Cloud Protection" "Error" "Enabled" $false
}

# -------------------------------
# 28. Ensure 'Windows Defender Automatic Sample Submission' is enabled
# -------------------------------
try {
    $sample = (Get-MpPreference).SubmitSamplesConsent
    $expected = 1  # Send safe samples automatically
    $pass = $sample -eq $expected
    Write-Result "Defender Sample Submission" $sample "1 (Auto)" $pass
} catch {
    Write-Result "Defender Sample Submission" "Error" "Enabled" $false
}

# -------------------------------
# 29. Ensure 'Windows Update Auto Download' is enabled
# -------------------------------
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$current = (Get-ItemProperty -Path $wuPath -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate
$expected = 0
$pass = $current -eq $expected
Write-Result "Windows Update Auto Download" $current $expected $pass

# -------------------------------
# 30. Ensure 'Windows Defender PUA Protection' is enabled
# -------------------------------
try {
    $pua = (Get-MpPreference).PUAProtection
    $expected = 1
    $pass = $pua -eq $expected
    Write-Result "Defender PUA Protection" $pua "1 (Enabled)" $pass
} catch {
    Write-Result "Defender PUA Protection" "Error" "Enabled" $false
}

# -------------------------------
# 31. Ensure 'Windows Defender Controlled Folder Access' is enabled
# -------------------------------
try {
    $cfa = (Get-MpPreference).EnableControlledFolderAccess
    $expected = 1
    $pass = $cfa -eq $expected
    Write-Result "Controlled Folder Access" $cfa "1 (Enabled)" $pass
} catch {
    Write-Result "Controlled Folder Access" "Error" "Enabled" $false
}

# -------------------------------
# 32. Ensure 'Windows Security Notifications' are enabled
# -------------------------------
$notifPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance"
$current = (Get-ItemProperty -Path $notifPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
$expected = 1
$pass = $current -eq $expected
Write-Result "Windows Security Notifications" $current $expected $pass

# -------------------------------
# 33. Ensure 'User Account Control: Admin Approval Mode' is enabled
# -------------------------------
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$current = (Get-ItemProperty -Path $uacPath -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
$expected = 1
$pass = $current -eq $expected
Write-Result "UAC: Admin Approval Mode" $current $expected $pass

# -------------------------------
# 34. Ensure 'UAC: Secure Desktop Prompt' is enabled
# -------------------------------
$current = (Get-ItemProperty -Path $uacPath -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue).PromptOnSecureDesktop
$expected = 1
$pass = $current -eq $expected
Write-Result "UAC: Secure Desktop Prompt" $current $expected $pass

# -------------------------------
# 35. Ensure 'UAC: Detect application installs and prompt for elevation' is enabled
# -------------------------------
$current = (Get-ItemProperty -Path $uacPath -Name EnableInstallerDetection -ErrorAction SilentlyContinue).EnableInstallerDetection
$expected = 1
$pass = $current -eq $expected
Write-Result "UAC: Installer Detection" $current $expected $pass

# -------------------------------
# 36. Ensure 'Guest Account Password' is set (if enabled)
# -------------------------------
try {
    $guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
    if ($guest.Enabled) {
        $pass = -not [string]::IsNullOrWhiteSpace($guest.PasswordLastSet)
        Write-Result "Guest Account Password" $guest.PasswordLastSet "Set" $pass
    } else {
        Write-Result "Guest Account Password" "Disabled" "Set" $true
    }
} catch {
    Write-Result "Guest Account Password" "Not Found" "Set" $false
}

# -------------------------------
# 37. Ensure 'Account Lockout Duration' is set to 15 minutes or more
# -------------------------------
# Export security policy to file
secedit /export /cfg C:\Temp\sec.cfg | Out-Null

# Look for LockoutDuration
$line = Select-String -Path C:\Temp\sec.cfg -Pattern "LockoutDuration"

if ($line) {
    $current = $line.ToString().Split('=')[1].Trim()
    $expected = 15
    $pass = [int]$current -ge $expected
    Write-Result "Account Lockout Duration" $current "$expected or more" $pass
} else {
    Write-Result "Account Lockout Duration" "Not Found" "$expected or more" $false
}


# -------------------------------
# 38. Ensure 'Audit Logon/Logoff Success & Failure' is enabled
# -------------------------------
$objectSubs = @("File System","Registry","Kernel Object","SAM","File Share","Removable Storage")

foreach ($sub in $objectSubs) {
    $out = auditpol /get /subcategory:"$sub"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Object Access ($sub)" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Object Access ($sub)" "Error" "Success & Failure" $false
    }
}

# -------------------------------
# 43. Ensure 'Windows Firewall: Logging is enabled'
# -------------------------------
$fwProfiles = Get-NetFirewallProfile
foreach ($p in $fwProfiles) {
    $log = $p.LogAllowed | Out-String
    $pass = $p.LogAllowed -eq "True" -or $p.LogBlocked -eq "True"
    Write-Result "Firewall Logging ($($p.Name))" $log "Enabled" $pass
}

# -----------------


# -------------------------------
# Export results to CSV
# -------------------------------
$r = Get-Location
$csvPath = "$($r)\csv\Win11_Level2_Audit.csv"
$Results | Export-Csv -Path $csvPath -NoTypeInformation -Force
Write-Host "Audit complete. Results exported to $csvPath" -ForegroundColor Green
