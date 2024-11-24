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
# Path for the firewall registry settings
$baseKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"

# Profile names
$profiles = @("DomainProfile", "PrivateProfile", "PublicProfile")

# Loop through each profile to create the necessary keys if they don't exist
foreach ($profile in $profiles) {
    $profileKey = Join-Path $baseKey $profile

    # Create the profile registry key if it doesn't exist
    if (-not (Test-Path $profileKey)) {
        New-Item -Path $profileKey -Force | Out-Null
    }

    # Set firewall settings for each profile
    Set-ItemProperty -Path $profileKey -Name "EnableFirewall" -Value 1          # Enable firewall
    Set-ItemProperty -Path $profileKey -Name "DefaultInboundAction" -Value 1    # Block inbound connections
    Set-ItemProperty -Path $profileKey -Name "DefaultOutboundAction" -Value 0   # Allow outbound connections

Write-Host "Windows Firewall profiles configured successfully!"
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