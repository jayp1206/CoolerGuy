function Set-SecurityPolicies {
    # Copy current secpol.cfg file
    secedit /export /cfg original_secpol.cfg

    # Apply template config
    secedit /configure /db c:\windows\security\local.sdb /cfg template3_secpol.cfg /areas SECURITYPOLICY
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
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    Install-Module -Name PolicyFileEditor -RequiredVersion 3.0.0 -Scope CurrentUser

    $MachineDir = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"


    ## Windows Defender Firewall ##

    # File and print exceptions: disable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"

    # UPnP exceptions: disable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\UPnPFramework"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"

    # Allow logging: log dropped packets, log successful connections
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "LogDroppedPackets" -Data 1 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "LogSuccessfulConnections" -Data 1 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "LogDroppedPackets" -Data 1 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "LogSuccessfulConnections" -Data 1 -Type "DWord"


    # Prohibit unicast responses to multicast: enable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableUnicastResponsesToMulticastBroadcast" -Data 1 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableUnicastResponsesToMulticastBroadcast" -Data 1 -Type "DWord"

    # Protect all network connections: enable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableFirewall" -Data 1 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableFirewall" -Data 1 -Type "DWord"


    ## Remote Assistance ##
    $RegPath = "Software\Policies\Microsoft\Windows NT\Terminal Services"

    # Allow only windows vista+ connections: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "CreateEncryptedOnlyTickets" -Data 1 -Type "DWord"
    
    # Turn on session logging: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "LoggingEnabled" -Data 1 -Type "DWord"


    ## Remote Desktop Services ##
    $RegPath = "Software\Policies\Microsoft\Windows NT\Terminal Services"

    # Require specific security layer for RDP connections: SSL
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "SecurityLayer" -Data 2 -Type "DWord"

    # Client connection encryption level: high
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "MinEncryptionLevel" -Data 3 -Type "DWord"

    # Prompt for password upon connection: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fPromptForPassword" -Data 1 -Type "DWord"

    # Require secure RPC communication: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fEncryptRPCTraffic" -Data 1 -Type "DWord"

    # Always prompt for password: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fPromptForPassword" -Data 1 -Type "DWord"

    # Require network level authentication: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "UserAuthentication" -Data 1 -Type "DWord"

    # End session when time limit is reached: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fResetBroken" -Data 1 -Type "DWord"


    ## Windows Remote Management ## 
    $RegPath = "Software\Policies\Microsoft\Windows\WinRM\Client"
    
    # Allow unencrypted traffic: disable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowUnencryptedTraffic" -Data 0 -Type "DWord"


    ## Autoplay Policies ##

    # Turn off autoplay: for all drives
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoDriveTypeAutoRun" -Data 255 -Type "DWord"


    ## Windows Update ##
    $RegPath = "Software\Policies\Microsoft\Windows\WindowsUpdate\AU"

    # Configure automatic updates: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoAutoUpdate" -Data 0 -Type "DWord"

    # Auto download and schedule install
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AUOptions" -Data 4 -Type "DWord"

    # Allow auto-update immediate installation
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AutoInstallMinorUpdates" -Data 1 -Type "DWord"

    # Automatic update detection frequency: 22 hours
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DetectionFrequencyEnabled" -Data 1 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DetectionFrequency" -Data 22 -Type "DWord"


    ## Credential User Interface ##

    # Do not display password reveal button: enable
    $RegPath = "Software\Policies\Microsoft\Windows\CredUI"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisablePasswordReveal" -Data 1 -Type "DWord"


    ## Event Log Service ##

    # Turn on logging: enable
    $RegPath = "Software\Policies\Microsoft\Windows\EventLog\Setup"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 1 -Type "DWord"


    ## Microsoft Defender Antivirus ##
    $RegPath = "Software\Policies\Microsoft\Windows Defender"

    # Allow antimalware service to start with normal priority: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowFastServiceStartup" -Data 1 -Type "DWord"

    # Turn off MDA: disable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableAntiSpyware" -Data 0 -Type "DWord"

    # Configure detection for unwanted applications: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "PUAProtection" -Data 1 -Type "DWord"


    ## Exploit Guard ##

    # Prevent users/apps from accessing dangerous websites: block
    $RegPath = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableNetworkProtection" -Data 1 -Type "DWord"


    ## Real Time Protection ##
    $RegPath = "Software\Policies\Microsoft\Windows Defender\Real-Time Protection"

    # Turn off real time protection: disable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableRealtimeMonitoring" -Data 0 -Type "DWord"
    
    # Turn on behavior monitoring: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableBehaviorMonitoring" -Data 0 -Type "DWord"
    
    # Scan all downloaded files and attachments: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableIOAVProtection" -Data 0 -Type "DWord"
    
    # Monitor file and program activity: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableOnAccessProtection" -Data 0 -Type "DWord"
    
    # Turn on process scanning when real-time is enabled: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableScanOnRealtimeEnable" -Data 0 -Type "DWord"
    
    # Turn on script scanning: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableScriptScanning" -Data 0 -Type "DWord"
    
    # Configure monitoring for in/out file and program activity: inbound/outbound
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RealtimeScanDirection" -Data 0 -Type "DWord"


    ## Scan ##
    $RegPath = "Software\Policies\Microsoft\Windows Defender\Scan"

    # Check for latest virus/spyware intelligence before scheduled scans: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "CheckForSignaturesBeforeRunningScan" -Data 1 -Type "DWord"

    # Scan archive files: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableArchiveScanning" -Data 0 -Type "DWord"

    # Scan removable drives: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableRemovableDriveScanning" -Data 0 -Type "DWord"

    # Scan packed executables: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisablePackedExeScanning" -Data 0 -Type "DWord"

    # Scan network files: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableScanningNetworkFiles" -Data 0 -Type "DWord"

    # Specify quick scan interval: 12 hours
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "QuickScanInterval" -Data 12 -Type "DWord"


    ## Security Intelligence Updates ##
    $RegPath = "Software\Policies\Microsoft\Windows Defender\Signature Updates"

    # Turn on scan after security intelligence update: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableScanOnUpdate" -Data 0 -Type "DWord"

    # Allow real-time sec intel updates based on MS MAPS reports: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RealtimeSignatureDelivery" -Data 1 -Type "DWord"

    # Check for latest virus/spyware sec intel on startup: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "UpdateOnStartUp" -Data 1 -Type "DWord"

    
    ## Security Center ##

    # Turn on security center: enable
    $RegPath = "Software\Policies\Microsoft\Windows NT\Security Center"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "SecurityCenterInDomain" -Data 1 -Type "DWord"


    ## SmartScreen ##

    # (Explorer) Configure SmartScreen: enable
    $RegPath = "Software\Policies\Microsoft\Windows\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableSmartScreen" -Data 1 -Type "DWord"

    # (Explorer) Warn and prevent bypass
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "ShellSmartScreenLevel" -Data "Block" -Type "String"

    # (Edge) Configure SmartScreen: enable
    $RegPath = "Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnabledV9" -Data 1 -Type "DWord"
 
    # (Edge) Prevent bypassing smartscreen prompts for sites: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "PreventOverride" -Data 1 -Type "DWord"


    gpupdate.exe /force
    Write-Host "Successfully Configured Group Policy!" -ForegroundColor Green
}

function Services {
    # Windows Defender Antivirus Network Inspection Service (WdNisSvc): Automatic, Start
    Set-Service -Name "WdNisSvc" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "WdNisSvc" -ErrorAction Continue
    
    # Windows Defender Antivirus Service (WinDefend): Automatic, Start
    Set-Service -Name "WinDefend" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "WinDefend" -ErrorAction Continue

    # Microsoft Defender Core Service (MDCoreSvc): Automatic, Start
    Set-Service -Name "MDCoreSvc" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "MDCoreSvc" -ErrorAction Continue

    # Print Spooler (Spooler): Disabled, Stop
    Set-Service -Name "Spooler" -StartupType "Disabled" -ErrorAction Continue
    Stop-Service -Name "Spooler" -Force -ErrorAction Continue

    # Security Center (wscsvc): Automatic, Start
    Set-Service -Name "wscsvc" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "wscsvc" -ErrorAction Continue

    # Software Protection (sppsvc): Automatic, Start
    Set-Service -Name "sppsvc" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "sppsvc" -ErrorAction Continue

    # Windows Defender Firewall (mpssvc): Automatic, Start
    Set-Service -Name "mpssvc" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "mpssvc" -ErrorAction Continue

    # Windows Error Reporting Service (WerSvc): Automatic, Start
    Set-Service -Name "WerSvc" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "WerSvc" -ErrorAction Continue

    # Windows Event Log (EventLog): Automatic, Start
    Set-Service -Name "EventLog" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "EventLog" -ErrorAction Continue

    # Windows Security Service (SecurityHealthService): Automatic, Start
    Set-Service -Name "SecurityHealthService" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "SecurityHealthService" -ErrorAction Continue

    # Windows Update (wuauserv): Automatic, Start
    Set-Service -Name "wuauserv" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "wuauserv" -ErrorAction Continue

    # World Wide Web Publishing service (W3SVC): Disabled, stop
    Set-Service -Name "W3SVC" -StartupType "Disabled" -ErrorAction Continue
    Stop-Service -Name "W3SVC" -Force -ErrorAction Continue

    # Telnet (TlntSvr): Disabled, Stop 
    Set-Service -Name "TlntSvr" -StartupType "Disabled" -ErrorAction Continue
    Stop-Service -Name "TlntSvr" -Force -ErrorAction Continue

    # Background Intelligent Transfer Service (BITS): Automatic, Start
    Set-Service -Name "BITS" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "BITS" -ErrorAction Continue

    # IPsec Policy Agent (PolicyAgent): Automatic, Start
    Set-Service -Name "PolicyAgent" -StartupType "Automatic" -ErrorAction Continue
    Start-Service -Name "PolicyAgent" -ErrorAction Continue

    # FTP, File Transfer Protocol Service (FTPSVC): Disabled, Stop
    Set-Service -Name "FTPSVC" -StartupType "Disabled" -ErrorAction Continue
    Stop-Service -Name "FTPSVC" -Force -ErrorAction Continue

    # Remote Registry (RemoteRegistry): Disabled, Stop
    Set-Service -Name "RemoteRegistry" -StartupType "Disabled" -ErrorAction Continue
    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction Continue

    Write-Host "Successfully Configured Services!" -ForegroundColor Green
}

function Disable-RDP {
    Write-Host "Successfully Disabled RDP!" -ForegroundColor Green
}

function Enable-RDP {
    Set-Service -Name "FTPSVC" -StartupType "Disabled" -ErrorAction Continue
    Stop-Service -Name "FTPSVC" -Force -ErrorAction Continue



    Write-Host "Successfully Enabled RDP!" -ForegroundColor Green
}

function Disable-FTP {
    Write-Host "Successfully Disabled FTP!" -ForegroundColor Green
}

function Enable-FTP {
    Write-Host "Successfully Enabled FTP!" -ForegroundColor Green
}
function Search-Files {
    # Prohibited file extensions
    $prohibitedExtensions = @(
    '*.midi', '*.mid', '*.mp3', '*.mp2', '*.mpa', '*.abs', '*.mpega', '*.au', '*.snd', '*.aiff', '*.aif', '*.sid', '*.flac', '*.cda', '*.wav', '*.aac', '*.ogg', '*.m4a', '*.wma', # Audio
    '*.mpeg', '*.mpe', '*.dl', '*.movie', '*.movi', '*.mv', '*.iff', '*.anim5', '*.anim3', '*.anim7', '*.avi', '*.vfw', '*.avx', '*.fli', '*.flc', '*.mov', '*.qt', '*.spl', '*.swf', '*.dcr', '*.dxr', '*.rpm', '*.rm', '*.smi', '*.ra', '*.ram', '*.rv', '*.wmv', '*.asf', '*.asx', '*.wax', '*.wmx', '*.3gp', '*.mkv', '*.ts', '*.webm', '*.vob', '*.m2ts', '*.flv', '*.m4v', # Video
    '*.tiff', '*.tif', '*.rs', '*.im1', '*.gif', '*.jpeg', '*.jpg', '*.jpe', '*.png', '*.rgb', '*.xwd', '*.xpm', '*.ppm', '*.pbm', '*.pgm', '*.pcx', '*.ico', '*.svg', '*.svgz', '*.bmp', '*.raw', '*.heic', '*.psd', # Image
    '*.jar', '*.py', '*.exe', '*.bat', '*.ps1', '*.msi', '*.com', '*.cmd', '*.sh', '*.vbs', '*.reg', '*.hta', '*.js', '*.cpl', '*.scr', # Executables
    '*.zip', '*.rar', '*.7z', '*.tar', '*.gz', '*.bz2', '*.iso', '*.img', # Archives/Containers
    '*.txt', '*.csv', '*.json', '*.xml', '*.yaml', '*.yml', '*.log' # Text
    )
    
    # Current user's folder
    $currentUserFolder = "$env:SystemDrive\Users\$env:USERNAME"

    # Users folder
    $usersFolder = "$env:SystemDrive\Users"

    # Track if any files are found
    $filesFound = $false


    # Loop through all user directories excluding the current user
    Get-ChildItem -Path $usersFolder -Directory | Where-Object {
        $_.FullName -ne $currentUserFolder
    } | ForEach-Object {
            $userDir = $_.FullName
            # Scan for prohibited files in the user's root folder
            Get-ChildItem -Path $userDir -File -ErrorAction Continue | ForEach-Object {
                if ($prohibitedExtensions -contains "*$($_.Extension)") {
                    Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-Host "File Name: $($_.Name)" -ForegroundColor Magenta
                    Write-Host "Full Path: $($_.FullName)" -ForegroundColor Magenta
                    Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                    $filesFound = $true
                }
            }

            # Exclude folders like AppData and those starting with "."
            Get-ChildItem -Path $userDir -Recurse -Directory -ErrorAction Continue | Where-Object {
                $_.Name -ne "AppData" -and -not ($_.Name -like ".*")
            } | ForEach-Object {
                    $folder = $_.FullName

                    # Scan for prohibited extensions
                    foreach ($ext in $prohibitedExtensions) {
                        Get-ChildItem -Path $folder -Recurse -Include $ext -ErrorAction Continue | ForEach-Object {
                            Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                            Write-Host "File Name: $($_.Name)" -ForegroundColor Magenta
                            Write-Host "Full Path: $($_.FullName)" -ForegroundColor Magenta
                            Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                            $filesFound = $true
                        }
                    }
            }
        }
        if (-not $filesFound) {
            Write-Host "No prohibited files found." -ForegroundColor Green
        }
}

function Show-Network {
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
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
        Install-Module -Name PolicyFileEditor -RequiredVersion 3.0.0 -Scope CurrentUser

        $UserDir = "$env:windir\system32\GroupPolicy\User\registry.pol"

        # Allow shared folders to be published: disable
        $RegPath = "Software\Policies\Microsoft\Windows NT\SharedFolders"
        Set-PolicyFileEntry -Path $UserDir -Key $RegPath -ValueName "PublishSharedFolders" -Data 0 -Type "DWord"

        # Prevent users from sharing files within their profile: enable
        $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Set-PolicyFileEntry -Path $UserDir -Key $RegPath -ValueName "NoInplaceSharing" -Data 1 -Type "DWord"

        gpupdate.exe /force
        Write-Host "Disabled Folder Sharing!" -ForegroundColor Green
    }
}



$securityPolicy = $(Write-Host "Configure Security Policies? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($securityPolicy -eq 'y') { 
    Set-SecurityPolicies
} else {
    Write-Host "Skipping Security Policies" -ForegroundColor Yellow
}   

$firewall = $(Write-Host "Configure Windows Defender Firewall? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($firewall -eq 'y') { 
    Enable-Firewall
} else {
    Write-Host "Skipping Firewall Configuration" -ForegroundColor Yellow
}

$auditing = $(Write-Host "Configure Advanced Auditing? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($auditing -eq 'y') { 
    Enable-Audits
} else {
    Write-Host "Skipping Advanced Audit Policies" -ForegroundColor Yellow
}   

$groupPolicy = $(Write-Host "Configure Group Policy? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($groupPolicy -eq 'y') { 
    Group-Policies
} else {
    Write-Host "Skipping Group Policy" -ForegroundColor Yellow
}   

$RDP = $(Write-Host "Enable or Disable RDP? (e/d): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($RDP -eq 'e') { 
    Enable-RDP
} elseif ($RDP -eq 'd') {
    Disable-RDP
} else {
    Write-Host "Not Configuring RDP" -ForegroundColor Yellow
} 

$FTP = $(Write-Host "Enable or Disable FTP? (e/d): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($FTP -eq 'e') { 
    Enable-FTP
} elseif ($RDP -eq 'd') {
    Disable-FTP
} else {
    Write-Host "Not Configuring FTP" -ForegroundColor Yellow
} 

$services = $(Write-Host "Configure Services? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($services -eq 'y') { 
    Services
} else {
    Write-Host "Not Configuring services" -ForegroundColor Yellow
}   


$scanfiles = $(Write-Host "Scan for Prohibited Files? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($scanfiles -eq 'y') { 
    Search-Files
} else {
    Write-Host "Not Scanning Files" -ForegroundColor Yellow
}   

$shares = $(Write-Host "List All Network Shares? (y/n):  " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($shares -eq 'y') {
    Show-Network
} else {
    Write-Host "Skipping Network Shares List" -ForegroundColor Yellow
}
