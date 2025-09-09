<#
.SYNOPSIS
  CIS Windows 11 Level 3 Audit Script (First 20 Checks)

.DESCRIPTION
  This script audits selected Level 3 CIS Benchmark rules
  using auditpol and security policy exports.

.NOTES
  Run as Administrator
#>

# Store results

# Fix Account Lockout (should be Failure only)
auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable

# Fix IPsec Driver (should be Success & Failure)
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable

# Fix Security System Extension (should be Success & Failure)
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Fix Kernel Object (should be Success & Failure)
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable

# Fix SAM (should be Success & Failure)
auditpol /set /subcategory:"SAM" /success:enable /failure:enable


auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
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

# ================
# Level 3 Checks
# ================

function Audit-Logon {
    $out = auditpol /get /subcategory:"Logon"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Logon" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Logon" "Error" "Success & Failure" $false
    }
}

function Audit-Logoff {
    $out = auditpol /get /subcategory:"Logoff"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Logoff" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Logoff" "Error" "Success & Failure" $false
    }
}

function Audit-AccountLockout {
    $out = auditpol /get /subcategory:"Account Lockout"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Failure"
        Write-Result "Audit Account Lockout" $out "Failure only" $pass
    } else {
        Write-Result "Audit Account Lockout" "Error" "Failure only" $false
    }
}

function Audit-IPsecDriver {
    $out = auditpol /get /subcategory:"IPsec Driver"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit IPsec Driver" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit IPsec Driver" "Error" "Success & Failure" $false
    }
}

function Audit-SecurityStateChange {
    $out = auditpol /get /subcategory:"Security State Change"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success"
        Write-Result "Audit Security State Change" $out "Success only" $pass
    } else {
        Write-Result "Audit Security State Change" "Error" "Success only" $false
    }
}

function Audit-SecuritySystemExtension {
    $out = auditpol /get /subcategory:"Security System Extension"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Security System Extension" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Security System Extension" "Error" "Success & Failure" $false
    }
}

function Audit-SystemIntegrity {
    $out = auditpol /get /subcategory:"System Integrity"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit System Integrity" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit System Integrity" "Error" "Success & Failure" $false
    }
}

function Audit-IPsecKeyExchange {
    $out = auditpol /get /subcategory:"IPsec Main Mode"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit IPsec Key Exchange" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit IPsec Key Exchange" "Error" "Success & Failure" $false
    }
}

function Audit-KernelObject {
    $out = auditpol /get /subcategory:"Kernel Object"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Kernel Object" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Kernel Object" "Error" "Success & Failure" $false
    }
}

function Audit-SAM {
    $out = auditpol /get /subcategory:"SAM"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit SAM" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit SAM" "Error" "Success & Failure" $false
    }
}

# ================
# Continuation (11–20)
# ================

function Audit-ApplicationGenerated {
    $out = auditpol /get /subcategory:"Application Generated"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Application Generated" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Application Generated" "Error" "Success & Failure" $false
    }
}

function Audit-HandleManipulation {
    $out = auditpol /get /subcategory:"Handle Manipulation"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Handle Manipulation" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Handle Manipulation" "Error" "Success & Failure" $false
    }
}

function Audit-FileShare {
    $out = auditpol /get /subcategory:"File Share"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit File Share" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit File Share" "Error" "Success & Failure" $false
    }
}

function Audit-RemovableStorage {
    $out = auditpol /get /subcategory:"Removable Storage"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Removable Storage" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Removable Storage" "Error" "Success & Failure" $false
    }
}

function Audit-SensitivePrivilegeUse {
    $out = auditpol /get /subcategory:"Sensitive Privilege Use"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Sensitive Privilege Use" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Sensitive Privilege Use" "Error" "Success & Failure" $false
    }
}

function Audit-OtherObjectAccess {
    $out = auditpol /get /subcategory:"Other Object Access Events"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Other Object Access Events" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Other Object Access Events" "Error" "Success & Failure" $false
    }
}

function Audit-PacketDrop {
    $out = auditpol /get /subcategory:"Filtering Platform Packet Drop"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Filtering Platform Packet Drop" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Filtering Platform Packet Drop" "Error" "Success & Failure" $false
    }
}

function Audit-PlatformConnection {
    $out = auditpol /get /subcategory:"Filtering Platform Connection"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Filtering Platform Connection" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Filtering Platform Connection" "Error" "Success & Failure" $false
    }
}

function Audit-OtherSystemEvents {
    $out = auditpol /get /subcategory:"Other System Events"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Other System Events" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Other System Events" "Error" "Success & Failure" $false
    }
}

function Audit-SecurityGroupManagement {
    $out = auditpol /get /subcategory:"Security Group Management"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Security Group Management" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Security Group Management" "Error" "Success & Failure" $false
    }
}

function Audit-ComputerAccountManagement {
    $out = auditpol /get /subcategory:"Computer Account Management"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Computer Account Management" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Computer Account Management" "Error" "Success & Failure" $false
    }
}

function Audit-DistributionGroupManagement {
    $out = auditpol /get /subcategory:"Distribution Group Management"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Distribution Group Management" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Distribution Group Management" "Error" "Success & Failure" $false
    }
}

function Audit-OtherAccountManagement {
    $out = auditpol /get /subcategory:"Other Account Management Events"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Other Account Management Events" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Other Account Management Events" "Error" "Success & Failure" $false
    }
}

function Audit-UserAccountManagement {
    $out = auditpol /get /subcategory:"User Account Management"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit User Account Management" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit User Account Management" "Error" "Success & Failure" $false
    }
}

function Audit-DetailedFileShare {
    $out = auditpol /get /subcategory:"Detailed File Share"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Failure"
        Write-Result "Audit Detailed File Share" $out "Failure only" $pass
    } else {
        Write-Result "Audit Detailed File Share" "Error" "Failure only" $false
    }
}

function Audit-LogonWithSpecialAccount {
    $out = auditpol /get /subcategory:"Logon with Special Privileges"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success"
        Write-Result "Audit Logon with Special Privileges" $out "Success only" $pass
    } else {
        Write-Result "Audit Logon with Special Privileges" "Error" "Success only" $false
    }
}

function Audit-ProcessCreation {
    $out = auditpol /get /subcategory:"Process Creation"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success"
        Write-Result "Audit Process Creation" $out "Success only" $pass
    } else {
        Write-Result "Audit Process Creation" "Error" "Success only" $false
    }
}

function Audit-ProcessTermination {
    $out = auditpol /get /subcategory:"Process Termination"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success"
        Write-Result "Audit Process Termination" $out "Success only" $pass
    } else {
        Write-Result "Audit Process Termination" "Error" "Success only" $false
    }
}

function Audit-DPAPIActivity {
    $out = auditpol /get /subcategory:"DPAPI Activity"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit DPAPI Activity" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit DPAPI Activity" "Error" "Success & Failure" $false
    }
}

function Audit-RPCEvents {
    $out = auditpol /get /subcategory:"RPC Events"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit RPC Events" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit RPC Events" "Error" "Success & Failure" $false
    }
}

function Audit-DirectoryServiceAccess {
    $out = auditpol /get /subcategory:"Directory Service Access"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Failure"
        Write-Result "Audit Directory Service Access" $out "Failure only" $pass
    } else {
        Write-Result "Audit Directory Service Access" "Error" "Failure only" $false
    }
}

function Audit-DirectoryServiceChanges {
    $out = auditpol /get /subcategory:"Directory Service Changes"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Directory Service Changes" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Directory Service Changes" "Error" "Success & Failure" $false
    }
}

function Audit-DirectoryServiceReplication {
    auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Directory Service Replication"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Failure"
        Write-Result "Audit Directory Service Replication" $out "Failure only" $pass
    } else {
        Write-Result "Audit Directory Service Replication" "Error" "Failure only" $false
    }
}

function Audit-CredentialValidation {
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Credential Validation"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Credential Validation" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Credential Validation" "Error" "Success & Failure" $false
    }
}

function Audit-KerberosAuthService {
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Kerberos Authentication Service"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Kerberos Authentication Service" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Kerberos Authentication Service" "Error" "Success & Failure" $false
    }
}

function Audit-KerberosServiceTicket {
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Kerberos Service Ticket Operations"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Kerberos Service Ticket Operations" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Kerberos Service Ticket Operations" "Error" "Success & Failure" $false
    }
}

function Audit-GroupMembership {
    auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Group Membership"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success"
        Write-Result "Audit Group Membership" $out "Success only" $pass
    } else {
        Write-Result "Audit Group Membership" "Error" "Success only" $false
    }
}

function Audit-ApplicationGroupManagement {
    auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Application Group Management"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Application Group Management" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Application Group Management" "Error" "Success & Failure" $false
    }
}

function Audit-AuthenticationPolicyChange {
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Authentication Policy Change"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Authentication Policy Change" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Authentication Policy Change" "Error" "Success & Failure" $false
    }
}

function Audit-AuthorizationPolicyChange {
    auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Authorization Policy Change"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Authorization Policy Change" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Authorization Policy Change" "Error" "Success & Failure" $false
    }
}

function Audit-MPSSPolicyChange {
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit MPSSVC Rule-Level Policy Change" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit MPSSVC Rule-Level Policy Change" "Error" "Success & Failure" $false
    }
}

function Audit-FilteringPlatformPolicyChange {
    auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
    $out = auditpol /get /subcategory:"Filtering Platform Policy Change"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Filtering Platform Policy Change" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Filtering Platform Policy Change" "Error" "Success & Failure" $false
    }
}

function Audit-OtherPolicyChange {
    $out = auditpol /get /subcategory:"Other Policy Change Events"
    if ($LASTEXITCODE -eq 0) {
        $pass = $out -match "Success" -and $out -match "Failure"
        Write-Result "Audit Other Policy Change Events" $out "Success & Failure" $pass
    } else {
        Write-Result "Audit Other Policy Change Events" "Error" "Success & Failure" $false
    }
}

# ================
# Run All Checks
# ================
Audit-Logon
Audit-Logoff
Audit-AccountLockout
Audit-IPsecDriver
Audit-SecurityStateChange
Audit-SecuritySystemExtension
Audit-SystemIntegrity
Audit-IPsecKeyExchange
Audit-KernelObject
Audit-SAM

Audit-ApplicationGenerated
Audit-HandleManipulation
Audit-FileShare
Audit-RemovableStorage
Audit-SensitivePrivilegeUse
Audit-OtherObjectAccess
Audit-PacketDrop
Audit-PlatformConnection
Audit-OtherSystemEvents
Audit-SecurityGroupManagement

Audit-ComputerAccountManagement
Audit-DistributionGroupManagement
Audit-OtherAccountManagement
Audit-UserAccountManagement
Audit-DetailedFileShare
Audit-LogonWithSpecialAccount
Audit-ProcessCreation
Audit-ProcessTermination
Audit-DPAPIActivity
Audit-RPCEvents
Audit-DirectoryServiceAccess
Audit-DirectoryServiceChanges
Audit-DirectoryServiceReplication
Audit-CredentialValidation
Audit-KerberosAuthService
Audit-KerberosServiceTicket
Audit-GroupMembership
Audit-ApplicationGroupManagement
Audit-AuthenticationPolicyChange
Audit-AuthorizationPolicyChange
Audit-MPSSPolicyChange
Audit-FilteringPlatformPolicyChange
Audit-OtherPolicyChange
# Export results to CSV in 
$r = Get-Location
$csvPath = "$($r)\csv\Win11_Level3_Audit.csv"
$Results | Export-Csv -Path $csvPath -NoTypeInformation -Force
Write-Host "Audit complete. Results exported to $csvPath" -ForegroundColor Green
