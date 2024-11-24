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

    Write-Host "Security policies configured successfully" -ForegroundColor Green
}


function Enable-Firewall {
# Array of registry paths for firewall profiles
$firewallProfiles = @{
    Domain  = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
    Private = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
    Public  = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
}

# Settings to apply to each profile
$firewallSettings = @{
    EnableFirewall        = 1  # Firewall state: On
    DefaultInboundAction  = 1  # Inbound connections: Block
    DefaultOutboundAction = 0  # Outbound connections: Allow
}

# Apply settings to each profile
foreach ($profile in $firewallProfiles.Values) {
    foreach ($setting in $firewallSettings.GetEnumerator()) {
        Set-ItemProperty -Path $profile -Name $setting.Key -Value $setting.Value
    }
}

# Restart firewall service
Restart-Service -Name mpssvc
}










$securityPolicy = Read-Host "Configure Password Policies? (y/n) "
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