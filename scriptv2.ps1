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


    ## Autoplay ##

    # Turn off autoplay: for all drives
    $path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Value 255


    ## Smartscreen ##

    # (File Explorer) Configure Smartscreen: warn and prevent bypass
    $path = "HKLM:\Software\Policies\Microsoft\Windows\System"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "EnableSmartScreen" -Value 1
    Set-ItemProperty -Path $path -Name "ShellSmartScreenLevel" -Value 0


    ## Windows Update ##

    # Automatic Updates: enable
    $path = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "NoAutoUpdate" -Value 0

    # Auto download and schedule install 
    Set-ItemProperty -Path $path -Name "AUOptions" -Value 4

    # Allow auto-updates immediate installation
    Set-ItemProperty -Path $path -Name "AutoInstallMinorUpdates" -Value 1

    # Automatic update detection frequency: 22 hours
    Set-ItemProperty -Path $path -Name "DetectionFrequencyEnabled" -Value 1
    Set-ItemProperty -Path $path -Name "DetectionFrequency" -Value 22


    ## Credential UI ##

    # Do not show reveal password button: enable
    $path = "HKLM:\Software\Policies\Microsoft\Windows\CredUI"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "DisablePasswordReveal" -Value 1


    ## Event Logging ##

    # Turn on logging: enable
    $path = "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "Enabled" -Value 1


    ## Microsoft Defender Antivirus

    # Allow antimalware service to start with normal priority: enable
    $path = "HKLM:\Software\Policies\Microsoft\Windows Defender"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "AllowFastServiceStartup" -Value 1

    # Turn off MDA: disable
    Set-ItemProperty -Path $path -Name "DisableAntiSpyware" -Value 0

    # Configure detection for unwanted applications: enable
    Set-ItemProperty -Path $path -Name "PUAProtection" -Value 1


    ## Exploit Guard ##

    # Prevent users/apps from accessing dangerous websites: block
    $path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "EnableNetworkProtection" -Value 1
    

    ## Real Time Protection ##

    # Turn off real time protection: disable
    $path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "DisableRealtimeMonitoring" -Value 0

    # Turn on behavior monitoring: enable
    Set-ItemProperty -Path $path -Name "DisableBehaviorMonitoring" -Value 0

    # Scan all downloaded files and attachments: enable
    Set-ItemProperty -Path $path -Name "DisableIOAVProtection" -Value 0

    # Monitor file and program activity: enable
    Set-ItemProperty -Path $path -Name "DisableOnAccessProtection" -Value 0

    # Turn on process scanning when real-time is enabled: enable
    Set-ItemProperty -Path $path -Name "DisableScanOnRealtimeEnable" -Value 0

    # Turn on script scanning: enable
    Set-ItemProperty -Path $path -Name "DisableScriptScanning" -Value 0

    # Configure monitoring for in/out file and program activity: inbound/outbound
    Set-ItemProperty -Path $path -Name "RealtimeScanDirection" -Value 0


    ## Scan ##

    # Check for latest virus/spyware intelligence before scheduled scans: enable
    $path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "CheckForSignaturesBeforeRunningScan" -Value 1

    # Scan archive files: enable
    Set-ItemProperty -Path $path -Name "DisableArchiveScanning" -Value 0

    # Scan removable drives: enable
    Set-ItemProperty -Path $path -Name "DisableRemovableDriveScanning" -Value 0

    # Scan packed executables: enable
    Set-ItemProperty -Path $path -Name "DisablePackedExeScanning" -Value 0

    # Scan network files: enable
    Set-ItemProperty -Path $path -Name "DisableScanningNetworkFiles" -Value 0

    # Specify quick scan interval: 12 hours
    Set-ItemProperty -Path $path -Name "QuickScanInterval" -Value 12


    ## Security Intelligence Updates ##

    # Turn on scan after security intelligence update: enable
    $path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "DisableScanOnUpdate" -Value 0

    # Allow real-time sec intel updates based on MS MAPS reports: enable
    Set-ItemProperty -Path $path -Name "RealtimeSignatureDelivery" -Value 1

    # Check for latest virus/spyware sec intel on startup: enable
    Set-ItemProperty -Path $path -Name "UpdateOnStartUp" -Value 1


    ## Security Center ##

    # Turn on security center: enable
    $path = "HKLM:\Software\Policies\Microsoft\Windows NT\Security Center"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "SecurityCenterInDomain" -Value 1


    ## Windows Defender SmartScreen ##

    # (Explorer) Configure SmartScreen: enable, warn and prevent bypass
    $path = "HKLM:\Software\Policies\Microsoft\Windows\System"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "EnableSmartScreen" -Value 1
    Set-ItemProperty -Path $path -Name "ShellSmartScreenLevel" -Value "Block" -PropertyType String

    # (Microsoft Edge) Configure SmartScreen: enable
    $path = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "EnabledV9" -Value 1

    # (Microsoft Edge) Prevent bypassing smartscreen prompts for sites: enable
    Set-ItemProperty -Path $path -Name "PreventOverride" -Value 1


    ## User Configuration ##


    gpupdate /force

    Write-Host "Successfully Configured Group Policy!" -ForegroundColor Green
}

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
            Write-Host "Share Name: $($_.Name)" -ForegroundColor Red
            Write-Host "Path: $($_.Path)" -ForegroundColor Red
            Write-Host "---------------------------------"
        }
    }

    $disablesharing = $(Write-Host "Disable file/folder sharing? (y/n): " -ForegroundColor Blue -NoNewLine; Read-Host)
    if ($disablesharing -eq 'y') { 

        # Allow shared folder to be published: disable
        $path = "HKCU:\Software\Policies\Microsoft\Windows NT\SharedFolders"
        New-Item -Path $path -Force
        Set-ItemProperty -Path $path -Name "PublishSharedFolders" -Value 0

        # Prevent users from sharing files within their profile: enable
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        New-Item -Path $path -Force
        Set-ItemProperty -Path $path -Name "NoInplaceSharing" -Value 1

        gpupdate /force

        Write-Host "Disabled Folder Sharing!" -ForegroundColor Green
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
