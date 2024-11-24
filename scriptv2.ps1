function Set-SecurityPolicies {
    # Copy current secpol.cfg file
    secedit /export /cfg original_secpol.cfg

    # Load template and current configs into memory
    $templateContent = Get-Content template_secpol.cfg
    $originalContent = Get-Content original_secpol.cfg

    # Take User Privilege Assignments from original config
    $privilegeRightsStart = ($originalContent | Select-String -Pattern "^\[Privilege Rights\]$").LineNumber - 1
    $privilegeRightsContent = $originalContent[$privilegeRightsStart..($originalContent.Count - 1)]

    # Combine template config and existing user rights into a merged config
    $mergedContent = @()
    $mergedContent += $templateContent
    $mergedContent += $privilegeRightsContent 

    New-Item merged_secpol.cfg -type file
    Set-Content merged_secpol.cfg $mergedContent -Encoding ASCII

    # Apply new merged config
    secedit /configure /db c:\windows\security\local.sdb /cfg merged_secpol.cfg /areas SECURITYPOLICY
    gpupdate /force

    Write-Host "Security policies configured successfully!" -ForegroundColor Green
}


function Enable-Firewall {
    # Enable all firewall profiles
    Set-NetFirewallProfile -All -Enabled True
    
    # Block inbound connections
    Set-NetFirewallProfile -Name Public -DefaultInboundAction Block
    Set-NetFirewallProfile -Name Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Name Domain -DefaultInboundAction Block

    # Allow outbound connections
    Set-NetFirewallProfile -Name Public -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Name Private -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Name Domain -DefaultOutboundAction Allow

    Write-Host "Windows Firewall profiles configured successfully!" -ForegroundColor Green
}


function Enable-Audits {
    # List of all advanced audit policies
    $subcategories = @(
    "Security State Change",
    "Security System Extension",
    "System Integrity",
    "IPsec Driver",
    "Other System Events",
    "Logon",
    "Logoff",
    "Account Lockout",
    "IPsec Main Mode",
    "IPsec Quick Mode",
    "IPsec Extended Mode",
    "Special Logon",
    "Other Logon/Logoff Events",
    "Network Policy Server",
    "User / Device Claims",
    "Group Membership",
    "File System",
    "Registry",
    "Kernel Object",
    "SAM",
    "Certification Services",
    "Application Generated",
    "Handle Manipulation",
    "File Share",
    "Filtering Platform Packet Drop",
    "Filtering Platform Connection",
    "Other Object Access Events",
    "Detailed File Share",
    "Removable Storage",
    "Central Policy Staging",
    "Sensitive Privilege Use",
    "Non Sensitive Privilege Use",
    "Other Privilege Use Events",
    "Process Creation",
    "Process Termination",
    "DPAPI Activity",
    "RPC Events",
    "Plug and Play Events",
    "Token Right Adjusted Events",
    "Audit Policy Change",
    "Authentication Policy Change",
    "Authorization Policy Change",
    "MPSSVC Rule-Level Policy Change",
    "Filtering Platform Policy Change",
    "Other Policy Change Events",
    "User Account Management",
    "Computer Account Management",
    "Security Group Management",
    "Distribution Group Management",
    "Application Group Management",
    "Other Account Management Events",
    "Directory Service Access",
    "Directory Service Changes",
    "Directory Service Replication",
    "Detailed Directory Service Replication",
    "Credential Validation",
    "Kerberos Service Ticket Operations",
    "Other Account Logon Events",
    "Kerberos Authentication Service"
    )

    # Set each to Sucess & Failure
    foreach ($subcategory in $subcategories) {
        auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable

    }

    Write-Host "Advanced Audit Policies Configured Successfully!" -ForegroundColor Green
}






$securityPolicy = Read-Host "Configure Security Policies? (y/n) "
if ($securityPolicy -eq 'y') { 
    Set-SecurityPolicies
} else {
    Write-Host "Skipping Security Policies" -ForegroundColor Yellow
}   

$firewall = Read-Host "Configure Windows Defender Firewall? (y/n) "
if ($firewall -eq 'y') { 
    Enable-Firewall
} else {
    Write-Host "Skipping Firewall Configuration" -ForegroundColor Yellow
}

$auditing = Read-Host "Configure Advanced Audit Policies? (y/n) "
if ($auditing -eq 'y') { 
    Enable-Audits
} else {
    Write-Host "Skipping Advanced Audit Policies" -ForegroundColor Yellow
}   