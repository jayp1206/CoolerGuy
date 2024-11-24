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
    # Enable firewall for domain, private, and public
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

    # Configure inbound and outbound rules
    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Allow
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