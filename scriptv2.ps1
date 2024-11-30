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

    gpupdate /force

    Write-Host "Advanced Audit Policies Configured Successfully!" -ForegroundColor Green
}

function Group-Policies {
    ## Windows Firewall ##

    # File and print exceptions: disable
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "Enabled" -Value 0

    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "Enabled" -Value 0


    # UPnP exceptions: disable
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "Enabled" -Value 0

    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\UPnPFramework"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "Enabled" -Value 0


    # Allow logging: log dropped packets, log successful connections
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "LogDroppedPackets" -Value 1
    Set-ItemProperty -Path $path -Name "LogSuccessfulConnections" -Value 1

    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "LogDroppedPackets" -Value 1
    Set-ItemProperty -Path $path -Name "LogSuccessfulConnections" -Value 1


    # Prohibit unicast response to multicast: enable
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "DisableUnicastResponsesToMulticastBroadcast" -Value 1

    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "DisableUnicastResponsesToMulticastBroadcast" -Value 1


    # Protect all network connections: enable
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "EnableFirewall" -Value 1

    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "EnableFirewall" -Value 1



    ## Remote Assistance ##

    # Allow only windows vista+ connections: enable
    $path = "HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "CreateEncryptedOnlyTickets" -Value 1

    # Session logging: enable
    Set-ItemProperty -Path $path -Name "LoggingEnabled" -Value 1



    ## Remote Desktop ##

    # Require specific security layer for RDP connections: SSL
    Set-ItemProperty -Path $path -Name "SecurityLayer" -Value 2

    # Client connection encryption level: high
    Set-ItemProperty -Path $path -Name "MinEncryptionLevel" -Value 3

    # Prompt for password upon connection: enable
    Set-ItemProperty -Path $path -Name "fPromptForPassword" -Value 1

    # Require secure RPC communication: enable
    Set-ItemProperty -Path $path -Name "fEncryptRPCTraffic" -Value 1



function Show-Network-Shares {
    # Get all network shares excluding default ones (ADMIN$, C$, IPC$)
    $allshares = Get-WmiObject -Class Win32_Share | Where-Object {
        $_.Name -notin @('ADMIN$', 'C$', 'IPC$')
    }

    # Check if there are any shares
    if ($allshares.Count -eq 0) {
        Write-Host "No shares found." -ForegroundColor Green
    } else {
        # Display the share names and their paths
        $allshares | ForEach-Object {
            Write-Host "Share Name: $($_.Name)"
            Write-Host "Path: $($_.Path)"
            Write-Host "---------------------------------"
        }
    }
}



$securityPolicy = $(Write-Host "Configure Security Policies? (y/n): " -ForegroundColor Blue -NoNewLine; Read-Host)
if ($securityPolicy -eq 'y') { 
    Set-SecurityPolicies
} else {
    Write-Host "Skipping Security Policies" -ForegroundColor Yellow
}   

$firewall = $(Write-Host "Configure Windows Defender Firewall? (y/n): " -ForegroundColor Blue -NoNewLine; Read-Host)
if ($firewall -eq 'y') { 
    Enable-Firewall
} else {
    Write-Host "Skipping Firewall Configuration" -ForegroundColor Yellow
}

$auditing = $(Write-Host "Configure Advanced Auditing? (y/n): " -ForegroundColor Blue -NoNewLine; Read-Host)
if ($auditing -eq 'y') { 
    Enable-Audits
} else {
    Write-Host "Skipping Advanced Audit Policies" -ForegroundColor Yellow
}   

$groupPolicy = $(Write-Host "Configure Group Policy? (y/n): " -ForegroundColor Blue -NoNewLine; Read-Host)
if ($groupPolicy -eq 'y') { 
    Group-Policies
} else {
    Write-Host "Skipping Advanced Audit Policies" -ForegroundColor Yellow
}   

$shares = $(Write-Host "List All Network Shares? (y/n):  " -ForegroundColor Blue -NoNewLine; Read-Host)
if ($shares -eq 'y') {
    Show-Network-Shares
} else {
    Write-Host "Skipping Network Shares List" -ForegroundColor Yellow
}













# SIG # Begin signature block
# MIIFTAYJKoZIhvcNAQcCoIIFPTCCBTkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyB4+8cAE8FiVxpl3Das3StAN
# d1KgggLyMIIC7jCCAdagAwIBAgIQEe/r/q0Bp6FEMMUSmLnzTDANBgkqhkiG9w0B
# AQsFADAPMQ0wCwYDVQQDDARKYXlQMB4XDTI0MTEyNDIxNTc1OVoXDTI1MTEyNDIy
# MTc1OVowDzENMAsGA1UEAwwESmF5UDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAMb2RzY4wq8XHwJfGIs9pzhQ+ek2XLV1NAAj17sFlpmFOLOLgjtoAjEg
# /M3kBybdWWpb93c0USUrzLAey199rEgpJWCe0aR62WElFU0eRrjLGMmofgi/TJv3
# d1kqgJVAI8g/gWK++2MZTYOhP9CfbnhM6xyy6Gmcw1/jYeWq5FlKAtm6dt2P1kfb
# iLNr0/aQGf+ajCzHlL2G5O2lbZLnGnAe8hNonQ0KvkP/WNpCHblxNAk5ZoQ4XCC1
# pNUq+b2B5sRY9+K9BRrTyherBdvWnzXec3s5ZJYcVJxibTq3+Arj8rrtFf4ZILTd
# GUY+Q9gencP2g1IIcy9JXTqCKZ12tN0CAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSeaXm5jLrx+MRXfkbvwG0w
# gL25+DANBgkqhkiG9w0BAQsFAAOCAQEAMHeBmoh/zJjfWDOGn0Sv0lZYC4PlPXAs
# hlMMwn3vUTJ1DEccbXecIjvDdUuNpl+4f7vz/R7r7qUfh09v0POQy7/qbRqfrvVG
# 7NwvQIJHYOA6Z4C6aUBp+B5/Rl7oWg7CqMUMWCFRkI5s6/jJm7mAj8XDIY8Vko+X
# svz3+xzD23msevNwzgecTdw99bp2SX65s6wnwWN+fLsh4gdPy8I0LB7kMzY4DDJD
# 7BKVOzIC63xef0VyHLXu77GfFgypV1qGLDmjVJI2ojZWA4kmzhkW8BqELefaBd7T
# Y7+x4orEGSwQ484+qH9SLmMIQmEUrT73uXth24W5DbJ30KVq+GNpGDGCAcQwggHA
# AgEBMCMwDzENMAsGA1UEAwwESmF5UAIQEe/r/q0Bp6FEMMUSmLnzTDAJBgUrDgMC
# GgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG
# 9w0BCQQxFgQUWV64T2C9QbQnxuvjfstgJtPAR88wDQYJKoZIhvcNAQEBBQAEggEA
# Wh/D6wqzgSuyHPqku3eePLksVT4uisGXmkbk8ZfNDdIXnuWOt4tDLhwGLrjffxCE
# qlDjqb8C4jSx0FOKMBr9K6cZKaLxva2JstuFmzPNprP1v5vhkjjpMCL3O55x7Ynp
# vQ3poOXBGXLxrp8aAWHV1OtaBA9WxthiefU/ZOMTaveKAdC4rsIrzO3Mld1Tozaa
# VKLRVeNF7+e3NeENkkCCUHOP6fwVQNO2Uu7EDJmciK39+rrnwxf+tAu9URxYVJ4T
# ZF53HlxhDNLVaSQtCZooytN+1RmnK6BDvpMYfnoWhyqChLTn32Tj6YFZKFqhUgTn
# xKxNi9C/R+KQbTnP0YMRPA==
# SIG # End signature block
