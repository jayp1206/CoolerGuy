# Check if PolicyFileEditor is installed
if (-not (Get-Module -ListAvailable -Name PolicyFileEditor)) {
    Write-Host "PolicyFileEditor not found. Installing..."
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    Install-Module -Name PolicyFileEditor -RequiredVersion 3.0.0 -Scope CurrentUser -Force
}

$Win11 = $(Write-Host "Windows 11? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)

function Sync-Users {
    $scriptDir = Split-Path -Parent $PSCommandPath
    $fileName = $(Write-Host "Enter the name of the authorized users file " -ForegroundColor Magenta -NoNewLine; Read-Host)
    $filePath = Join-Path $scriptDir $fileName

    if (-not (Test-Path $filePath)) {
        Write-Error "File not found in script directory: $filePath"
        return
    }

    # Parse the authorized users file
    $fileContent = Get-Content $filePath -Raw
    $authorizedAdmins = @()
    $authorizedUsers = @()
    $currentUser = $null
    $passwords = @{}
    
    $lines = $fileContent -split "`r?`n"
    $section = $null
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -eq "" -or $line -match "^Authorized") { 
            if ($line -match "Authorized Administrators:") {
                $section = "admins"
            } elseif ($line -match "Authorized Users:") {
                $section = "users"
            }
            continue 
        }
        
        if ($line -match "^password:") {
            if ($currentUser) {
                $pswd = $line -replace "^password:\s*", ""
                $passwords[$currentUser] = $pswd
            }
        } else {
            # Check if this is the current user (marked with "(you)")
            if ($line -match "\(you\)") {
                $username = $line -replace "\s*\(you\)\s*", ""
                $currentUser = $username
            } else {
                $currentUser = $line
            }
            
            if ($section -eq "admins") {
                $authorizedAdmins += $currentUser
            } elseif ($section -eq "users") {
                $authorizedUsers += $currentUser
            }
        }
    }
    
    $standardPassword = "Cyb3r1a99!!$$"
    $allAuthorized = $authorizedAdmins + $authorizedUsers
    
    Write-Host "`nAuthorized Admins: $($authorizedAdmins -join ', ')"
    Write-Host "Authorized Users: $($authorizedUsers -join ', ')"
    
    # Get current local users (excluding built-in system accounts)
    $excludeUsers = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
    $currentUsers = Get-LocalUser | Where-Object { $excludeUsers -notcontains $_.Name }
    
    # Remove unauthorized users
    foreach ($user in $currentUsers) {
        if ($allAuthorized -notcontains $user.Name) {
            Write-Host "Removing unauthorized user: $($user.Name)" -ForegroundColor Red
            Remove-LocalUser -Name $user.Name -ErrorAction SilentlyContinue
        }
    }
    
    # Process authorized users
    foreach ($username in $allAuthorized) {
        $userExists = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
        $isAdmin = $authorizedAdmins -contains $username
        
        # Find the user marked with (you)
        $isCurrentUser = $fileContent -match "$username\s*\(you\)"
        
        if (-not $userExists) {
            # Create new user (skip if it's the current user - they should already exist)
            if (-not $isCurrentUser) {
                Write-Host "Creating user: $username" -ForegroundColor Green
                $pswd = ConvertTo-SecureString $standardPassword -AsPlainText -Force
                # Assign the new user object back to $userExists
                $userExists = New-LocalUser -Name $username -Password $pswd -ErrorAction SilentlyContinue
            } else {
                Write-Warning "Current user $username does not exist - skipping creation"
                continue
            }
        } else {
            # Set password for existing user (except current user)
            if (-not $isCurrentUser) {
                Write-Host "Updating password for: $username" -ForegroundColor Yellow
                $pswd = ConvertTo-SecureString $standardPassword -AsPlainText -Force
                $userExists | Set-LocalUser -Password $pswd
            } else {
                Write-Host "Skipping password update for current user: $username" -ForegroundColor Cyan
            }
        }

        # Check if user creation failed (e.g., password policy)
        if (-not $userExists) {
            Write-Error "Failed to create or find user: $username. Skipping group assignment."
            continue
        }

        # Set admin/user group privileges
        $isMemberOfAdmins = $null -ne (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\\$username$" })
        
        if ($isAdmin) {
            # This user is an ADMIN
            if (-not $isMemberOfAdmins) {
                Write-Host "Adding $username to Administrators group" -ForegroundColor Green
                Add-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction SilentlyContinue
            }
        } else {
            $isMemberOfUsers = $null -ne (Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\\$username$" })
            if (-not $isMemberOfUsers) {
                 Add-LocalGroupMember -Group "Users" -Member $username -ErrorAction SilentlyContinue
            }
            if ($isMemberOfAdmins) {
                Write-Host "Removing $username from Administrators group" -ForegroundColor Red
                Remove-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Host "`nUser synchronization complete!" -ForegroundColor Green
}



function Set-SecurityPolicies {
    # Copy current secpol.cfg file
    secedit /export /cfg original_secpol.cfg

    # Apply template config
    secedit /configure /db c:\windows\security\local.sdb /cfg template4_secpol.cfg /areas SECURITYPOLICY
    gpupdate /force

    Write-Host "Security policies configured successfully!" -ForegroundColor Green
}

function Enable-Firewall {
    # Enable all firewall profiles
    Set-NetFirewallProfile -All -Enabled True
    
    # Block inbound connections & Allow outbound connections
    Set-NetFirewallProfile -Name Public -DefaultInboundAction Block -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Name Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Name Domain -DefaultInboundAction Block -DefaultOutboundAction Allow

    # Set Logging Size Limit
    Set-NetFirewallProfile -Name Private -LogMaxSizeKilobytes 20000
    Set-NetFirewallProfile -Name Public -LogMaxSizeKilobytes 20000

    # Log Dropped and Successful Packets
    Set-NetFirewallProfile -Name Private -LogAllowed True -LogBlocked True
    Set-NetFirewallProfile -Name Public -LogAllowed True -LogBlocked True


    # Block file and printer sharing
    Disable-NetFirewallRule -DisplayGroup "File and Printer Sharing"

    Write-Host "Windows Firewall profiles configured successfully!" -ForegroundColor Green
}


function Enable-Audits {
    # List of all advanced audit policies
    auditpol /set /category:* /success:enable /failure:enable

    gpupdate /force

    Write-Host "Advanced Audit Policies Configured Successfully!" -ForegroundColor Green
}

function Group-Policies {
    $MachineDir = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"
    $UserRegDir = "$env:windir\system32\GroupPolicy\User\registry.pol"

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
    
    # Require specific security layer for RDP connections: SSL
    $RegPath = "Software\Policies\Microsoft\Windows NT\Terminal Services"

    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "SecurityLayer" -Data 2 -Type "DWord"

    # Client connection encryption level: high
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "MinEncryptionLevel" -Data 3 -Type "DWord"

    # Prompt for password upon connection: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fPromptForPassword" -Data 1 -Type "DWord"

    # Require secure RPC communication: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fEncryptRPCTraffic" -Data 1 -Type "DWord"

    # Require network level authentication: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "UserAuthentication" -Data 1 -Type "DWord"

    # End session when time limit is reached: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fResetBroken" -Data 1 -Type "DWord"

    # Do not allow passwords to be saved: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisablePasswordSaving" -Data 1 -Type "DWord"

    # Allow UI Automation redirection: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableUiaRedirection" -Data 0 -Type "DWord"

    # Do not allow COM port redirection: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDisableCcm" -Data 1 -Type "DWord"

    # Do not allow drive redirection: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDisableCdm" -Data 1 -Type "DWord"

    # Do not allow location redirection: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDisablelocationRedir" -Data 1 -Type "DWord"

    # Do not allow LPT port redirection: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDisableLPT" -Data 1 -Type "DWord"

    # Do not allow supported Plug and Play device redirection: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDisablePNPRedir" -Data 1 -Type "DWord"

    # Set time limit for active but idle Remote Desktop Services sessions: Enabled (15 minutes)
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "MaxIdleTime" -Data 900000 -Type "DWord"

    # Set time limit for disconnected sessions: Enabled (1 minute)
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "MaxDisconnectionTime" -Data 60000 -Type "DWord"


    ## Windows Remote Management ## 

    ### CLIENT ###
    
    # Allow Basic authentication: Disabled
    $RegPath = "Software\Policies\Microsoft\Windows\WinRM\Client"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowBasic" -Data 0 -Type "DWord"

    # Allow unencrypted traffic: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowUnencryptedTraffic" -Data 0 -Type "DWord"

    # Disallow Digest authentication: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowDigest" -Data 0 -Type "DWord"


    ### SERVICE ###

    # Allow Basic authentication: Disabled
    $RegPath = "Software\Policies\Microsoft\Windows\WinRM\Service"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowBasic" -Data 0 -Type "DWord"

    # Allow remote server management through WinRM: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowAutoConfig" -Data 0 -Type "DWord"

    # Allow unencrypted traffic: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowUnencryptedTraffic" -Data 0 -Type "DWord"

    # Disallow WinRM from storing RunAs credentials: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableRunAs" -Data 1 -Type "DWord"


    ## Autoplay Policies ##

    # Turn off autoplay: for all drives
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoDriveTypeAutoRun" -Data 255 -Type "DWord"
    
    # Default autorun behavior: do not execute any autorun commands
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoAutorun" -Data 1 -Type "DWord"

    # Turn off autplay for non-volume devices: enabled
    $RegPath = "Software\Policies\Microsoft\Windows\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoAutoplayfornonVolume" -Data 1 -Type "DWord"


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

    # No auto-restart with logged on users for scheduled automatic updates installation: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoAutoRebootWithLoggedOnUsers" -Data 0 -Type "DWord"

    # Scheduled install day: 0 (Every day)
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "ScheduledInstallDay" -Data 0 -Type "DWord"


    ## Credential User Interface ##

    # Do not display password reveal button: enable
    $RegPath = "Software\Policies\Microsoft\Windows\CredUI"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisablePasswordReveal" -Data 1 -Type "DWord"

    # Enumerate administrator accounts on elevation: Disabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\CredUI"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnumerateAdministrators" -Data 0 -Type "DWord"

    # Prevent the use of security questions for local accounts: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoLocalPasswordResetQuestions" -Data 1 -Type "DWord"


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

    ## MpEngine ##

    # Enable file hash computation feature: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows Defender\MpEngine"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableFileHashComputation" -Data 1 -Type "DWord"


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

    # Turn on e-mail scanning: Enabled 
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableEmailScanning" -Data 0 -Type "DWord"


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
    #DISABLEDFORSERVER $RegPath = "Software\Policies\Microsoft\Windows\System"
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableSmartScreen" -Data 1 -Type "DWord"

    # (Explorer) Warn and prevent bypass
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "ShellSmartScreenLevel" -Data "Block" -Type "String"

    # (Edge) Configure SmartScreen: enable
    $RegPath = "Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnabledV9" -Data 1 -Type "DWord"
 
    # (Edge) Prevent bypassing smartscreen prompts for sites: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "PreventOverride" -Data 1 -Type "DWord"


    ## Control Panel ##
    
    # Allow online tips: disable
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowOnlineTips" -Data 0 -Type "DWord"

    # Allow speech recognition: disable
    $RegPath = "Software\Policies\Microsoft\InputPersonalization"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowInputPersonalization" -Data 0 -Type "DWord"

    # Prevent lock screen camera: enable
    $RegPath = "Software\Policies\Microsoft\Windows\Personalization"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoLockScreenCamera" -Data 1 -Type "DWord"

    # Prevent lock screen slideshow: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoLockScreenSlideshow" -Data 1 -Type "DWord"


    ## Network ##

    # Enable font providers: disable
    $RegPath = "Software\Policies\Microsoft\Windows\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableFontProviders" -Data 0 -Type "DWord"

    # Lanman: enable insecure guest logons: disable
    $RegPath = "Software\Policies\Microsoft\Windows\LanmanWorkstation"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowInsecureGuestAuth" -Data 0 -Type "DWord"

    # Turn on mapper i/o driver: disable
    $RegPath = "Software\Policies\Microsoft\Windows\LLTD"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableLLTDIO" -Data 0 -Type "DWord"

    # Turn on responder driver: disable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableRspndr" -Data 0 -Type "DWord"

    # Turn off Microsoft p2p: enable
    $RegPath = "Software\policies\Microsoft\Peernet"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Disabled" -Data 1 -Type "DWord"

    # Prohibit network bridge: enable
    $RegPath = "Software\Policies\Microsoft\Windows\Network Connections"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NC_AllowNetBridge_NLA" -Data 0 -Type "DWord"
    
    # Prohibit internet connection sharing: enable
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NC_ShowSharedAccessUI" -Data 0 -Type "DWord"

    # Config wireless settings with connect now: disable
    $RegPath = "Software\Policies\Microsoft\Windows\WCN\Registrars"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableRegistrars" -Data 0 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableUPnPRegistrar" -Data 0 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableInBand802DOT11Registrar" -Data 0 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableFlashConfigRegistrar" -Data 0 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableWPDRegistrar" -Data 0 -Type "DWord"

    # Prohibit access of connect now wizards: enable
    $RegPath = "Software\Policies\Microsoft\Windows\WCN\UI"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableWcnUi" -Data 1 -Type "DWord"

    # Minimize number of internet connections: prevent wifi when on ethernet
    $RegPath = "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fMinimizeConnections" -Data 3 -Type "DWord"

    # Auto connect to hotspots: disable
    $RegPath = "Software\Microsoft\wcmsvc\wifinetworkmanager\config"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AutoConnectAllowedOEM" -Data 0 -Type "DWord"


    ## Printers ##

    # Allow Print Spooler to accept client connections: Disabled    
    $RegPath = "Software\Policies\Microsoft\Windows NT\Printers"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RegisterSpoolerRemoteRpcEndPoint" -Data 2 -Type "DWord"

    # Limits printer driver installation to Administrators: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RestrictDriverInstallationToAdministrators" -Data 1 -Type "DWord"

    # When installing drivers for a new connection: Enabled (Show warning and elevation prompt)
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoWarningNoElevationOnInstall" -Data 0 -Type "DWord"

    # When updating drivers for an existing connection: Enabled (Show warning and elevation prompt)
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "UpdatePromptSettings" -Data 0 -Type "DWord"


    ## System ##

    # Include command line in process creation events: Enabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Data 1 -Type "DWord"

    # Encryption Oracle Remediation: Enabled (Force Updated Clients)
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowEncryptionOracle" -Data 0 -Type "DWord"

    # Remote host allows delegation of non-exportable credentials: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\CredentialsDelegation"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowProtectedCreds" -Data 1 -Type "DWord"

    # Prevent device metadata retrieval from the Internet: Enabled
    $RegPath = "SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "PreventDeviceMetadataFromNetwork" -Data 1 -Type "DWord"

    # Boot-Start Driver Initialization Policy: Enabled (Good, unknown, and bad but critical)
    $RegPath = "System\CurrentControlSet\Policies\EarlyLaunch"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DriverLoadPolicy" -Data 3 -Type "DWord"

    # Continue experiences on this device: Disabled
    $RegPath = "Software\Policies\Microsoft\Windows\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableCdp" -Data 0 -Type "DWord"

    # Turn off access to the Store: Enabled
    #DISABLEDFORSERVER $RegPath = "Software\Policies\Microsoft\Windows\Explorer"
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoUseStoreOpenWith" -Data 1 -Type "DWord"

    # Turn off downloading of printer drivers over HTTP: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows NT\Printers"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableWebPnPDownload" -Data 1 -Type "DWord"

    # Turn off handwriting personalization data sharing: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\TabletPC"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "PreventHandwritingDataSharing" -Data 1 -Type "DWord"

    # Turn off handwriting recognition error reporting: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\HandwritingErrorReports"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "PreventHandwritingErrorReports" -Data 1 -Type "DWord"

    # Turn off printing over HTTP: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows NT\Printers"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableHTTPPrinting" -Data 1 -Type "DWord"

    # Turn off the "Order Prints" picture task: Enabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoOnlinePrintsWizard" -Data 1 -Type "DWord"

    # Turn off the "Publish to Web" task for files and folders: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoPublishingWizard" -Data 1 -Type "DWord"

    # Support device authentication using certificate: Enabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DevicePKInitEnabled" -Data 1 -Type "DWord"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DevicePKInitBehavior" -Data 1 -Type "DWord"

    # Allow Custom SSPs and APs to be loaded into LSASS: Disabled
    $RegPath = "SOFTWARE\Policies\Microsoft\Windows\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowCustomSSPsAPs" -Data 0 -Type "DWord"

    # Disallow copying of user input methods to the system account for sign-in: Enabled
    $RegPath = "Software\Policies\Microsoft\Control Panel\International"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "BlockUserInputMethodsForSignIn" -Data 1 -Type "DWord"

    # Block user from showing account details on sign-in: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "BlockUserFromShowingAccountDetailsOnSignin" -Data 1 -Type "DWord"

    # Do not display network selection UI: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DontDisplayNetworkSelectionUI" -Data 1 -Type "DWord"

    # Turn off app notifications on the lock screen: Enabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableLockScreenAppNotifications" -Data 1 -Type "DWord"

    # Turn on convenience PIN sign-in: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowDomainPINLogon" -Data 0 -Type "DWord"

    # Allow Clipboard synchroniztion across devices: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowCrossDeviceClipboard" -Data 0 -Type "DWord"

    # Allow upload of User Activities: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "UploadUserActivities" -Data 0 -Type "DWord"

    # Require a password when a computer wakes (plugged in): Enabled
    $RegPath = "SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "ACSettingIndex" -Data 1 -Type "DWord"

    # Enable RPC Endpoint Mapper Client Authentication: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows NT\Rpc"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableAuthEpResolution" -Data 1 -Type "DWord"

    # Restrict Unauthenticated RPC clients: Enabled (Authenticated)
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RestrictRemoteClients" -Data 1 -Type "DWord"

    # Turn off the advertising ID: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\AdvertisingInfo"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisabledByGroupPolicy" -Data 1 -Type "DWord"


    ## App Package Deployment ##

    # Allow a Windows app to share application data between users: Disabled
    $RegPath = "Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowSharedLocalAppData" -Data 0 -Type "DWord"

    # Prevent non-admin users from installing packaged Windows apps: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\Appx"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "BlockNonAdminUserInstall" -Data 1 -Type "DWord"


    ## App Privacy ##
    
    # Let Windows apps activate with voice while the system is locked: Enabled (Force Deny)
    #DISABLEDFORSERVER $RegPath = "Software\Policies\Microsoft\Windows\AppPrivacy"
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "LetAppsActivateWithVoiceAboveLock" -Data 2 -Type "DWord"

    
    ## App Runtime ##
    
    # Block launching Universal Windows apps with Windows Runtime API access from hosted content: Enabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "BlockHostedAppAccessWinRT" -Data 1 -Type "DWord"
    

    ## Biometrics ##

    # Configure enhanced anti-spoofing: Enabled
    $RegPath = "SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnhancedAntiSpoofing" -Data 1 -Type "DWord"


    ## Camera ##

    # Allow Use of Camera: Disabled
    $RegPath = "software\Policies\Microsoft\Camera"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowCamera" -Data 0 -Type "DWord"


    ## Connect ##
    
    # Require pin for pairing: Enabled (Always)
    $RegPath = "Software\Policies\Microsoft\Windows\Connect"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RequirePinForPairing" -Data 2 -Type "DWord"


    ## Push to Install ##

    # Turn off Push to Install service: Enabled
    $RegPath = "Software\Policies\Microsoft\PushToInstall"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisablePushToInstall" -Data 1 -Type "DWord"

    
    ## File Explorer ##

    # Turn off Data Execution Prevention for Explorer: Disabled
    $RegPath = "Software\Policies\Microsoft\Windows\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoDataExecutionPrevention" -Data 0 -Type "DWord"

    # Turn off heap termination on corruption: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoHeapTerminationOnCorruption" -Data 0 -Type "DWord"

    # Turn off shell protocol protected mode: Disabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "PreXPSP2ShellProtocolBehavior" -Data 0 -Type "DWord"


    ## Microsoft Account ##

    # Block all consumer Microsoft account user authentication: Enabled
    $RegPath = "Software\Policies\Microsoft\MicrosoftAccount"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableUserAuth" -Data 1 -Type "DWord"


    ## RSS Feeds ##
    $RegPath = "Software\Policies\Microsoft\Internet Explorer\Feeds"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableEnclosureDownload" -Data 1 -Type "DWord"


    ## Search ##

    # Allow Cloud Search: Enabled (Disable Cloud Search)
    $RegPath = "SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowCloudSearch" -Data 0 -Type "DWord"

    # Allow Cortana: Disabled
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowCortana" -Data 0 -Type "DWord"

    # Allow Cortana above lock screen: Disabled
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowCortanaAboveLock" -Data 0 -Type "DWord"

    # Allow indexing of encrypted files: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowIndexingEncryptedStoresOrItems" -Data 0 -Type "DWord"

    # Allow search and Cortana to use location: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowSearchToUseLocation" -Data 0 -Type "DWord"

    # Allow search highlights: Disabled
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableDynamicContentInWSB" -Data 0 -Type "DWord"


    ## Store ##

    # Turn off Automatic Download and Install of updates: Disabled
    $RegPath = "Software\Policies\Microsoft\WindowsStore"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AutoDownload" -Data 4 -Type "DWord"

    
    ## Windows Game Recording and Broadcasting ##

    # Enables or disables Windows Game Recording and Broadcasting: Disabled
    #DISABLEDFORSERVER $RegPath = "Software\Policies\Microsoft\Windows\GameDVR"
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowGameDVR" -Data 0 -Type "DWord"


    ## Windows Ink Workspace ##
    
    # Allow Windows Ink Workspace: Enabled (On, but disallow access above lock)
    #DISABLEDFORSERVER $RegPath = "Software\Policies\Microsoft\WindowsInkWorkspace"
    #DISABLEDFORSERVER Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowWindowsInkWorkspace" -Data 1 -Type "DWord"


    ## Windows Installer ##

    # Allow user control over installs: Disabled
    $RegPath = "Software\Policies\Microsoft\Windows\Installer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableUserControl" -Data 0 -Type "DWord"

    # Always install with elevated privileges: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AlwaysInstallElevated" -Data 0 -Type "DWord"

    # Prevent Internet Explorer security prompt for Windows Installer scripts: Disabled
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "SafeForScripting" -Data 0 -Type "DWord"


    ## Windows Logon Options ##

    # Sign-in and lock last interactive user automatically after a restart: Disabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableAutomaticRestartSignOn" -Data 1 -Type "DWord"


    ## Attachment Manager ## (USER)

    # Do not preserve zone information in file attachments: Disabled
    $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    Set-PolicyFileEntry -Path $UserRegDir -Key $RegPath -ValueName "SaveZoneInformation" -Data 2 -Type "DWord"

    # Notify antivirus programs when opening attachments: Enabled
    Set-PolicyFileEntry -Path $UserRegDir -Key $RegPath -ValueName "ScanWithAntiVirus" -Data 3 -Type "DWord"


    ## Cloud Content ## (USER)

    # Do not use diagnostic data for tailored experiences: Enabled
    $RegPath = "Software\Policies\Microsoft\Windows\CloudContent"
    Set-PolicyFileEntry -Path $UserRegDir -Key $RegPath -ValueName "DisableTailoredExperiencesWithDiagnosticData" -Data 1 -Type "DWord"


    ## Windows Installer ## (USER)

    # Always install with elevated privileges: Disabled
    $RegPath = "Software\Policies\Microsoft\Windows\Installer"
    Set-PolicyFileEntry -Path $UserRegDir -Key $RegPath -ValueName "AlwaysInstallElevated" -Data 0 -Type "DWord"


    ## Windows Media Player ## (USER)
    $RegPath = "Software\Policies\Microsoft\WindowsMediaPlayer"
    Set-PolicyFileEntry -Path $UserRegDir -Key $RegPath -ValueName "PreventCodecDownload" -Data 1 -Type "DWord"


    #---------------------------------------------# WIN 11 ONLY #---------------------------------------------#
    if ($Win11 -eq 'y') {
        ## Enhanced Phishing Protection ##

        # Automatic data collection: enable
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "CaptureThreatWindow" -Data 1 -Type "DWord"

        # Notify malicious: enable
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NotifyMalicious" -Data 1 -Type "DWord"

        # Notify password reuse: enable
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NotifyPasswordReuse" -Data 1 -Type "DWord"

        # Notify unsafe app: enable
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NotifyUnsafeApp" -Data 1 -Type "DWord"

        # Service enabled: enable
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "ServiceEnabled" -Data 1 -Type "DWord"


        ## Network ##
        
        # Configure dns over http: enable doh
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DoHPolicy" -Data 2 -Type "DWord"

        
        ## Printers ##

        # Configure Redirection Guard: Enabled
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RedirectionguardPolicy" -Data 1 -Type "DWord"

        # Protocol to use for outgoing RPC connections: Enabled (RPC over TCP)
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RpcUseNamedPipeProtocol" -Data 0 -Type "DWord"

        # Use authentication for outgoing RPC connections: Enabled
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RpcAuthentication" -Data 0 -Type "DWord"

        # Protocols to allow for incoming RPC connections: Enabled (RPC over TCP)
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RpcProtocols" -Data 5 -Type "DWord"

        # Authentication Protocol to use for incoming RPC connections: Enabled (Negotiate)
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "ForceKerberosForRpc" -Data 0 -Type "DWord"

        # Configure RPC over TCP port: Enabled (0)
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "RpcTcpPort" -Data 0 -Type "DWord"

        # Manage processing of Queue-specific files: Enabled (Limit Queue-specific files to Color profiles)
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "CopyFilesPolicy" -Data 1 -Type "DWord"


        ## Desktop App Installer ##

        # Enable App Installer Hash Override: Disabled
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableHashOverride" -Data 0 -Type "DWord"

        # Enable App Installer ms-appinstaller protocol: Disabled
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableMSAppInstallerProtocol" -Data 0 -Type "DWord"


        ## Remote Desktop Services ##

        # Disable Cloud Clipboard integration for server-to-client data transfer: Enabled
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableCloudClipboardIntegration" -Data 1 -Type "DWord"

        # Do not allow WebAuthn redirection: Enabled
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDisablewebauthn" -Data 1 -Type "DWord"


        ## Windows Hello for Business ##

        # Enable ESS with Supported Peripherals: Enabled (1)
        $RegPath = "SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableESSwithSupportedPeripherals" -Data 1 -Type "DWord"


        ## Windows Logon Options ##

        # Enable MPR notifications for the system: Disabled
        $RegPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "EnableMPR" -Data 0 -Type "DWord"

        
        ## Windows Sandbox ##

        # Allow clipboard sharing with Windows Sandbox: Disabled
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows\Sandbox"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowClipboardRedirection" -Data 0 -Type "DWord"

        # Allow networking in Windows Sandbox: Disabled
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowNetworking" -Data 0 -Type "DWord"


        ## Windows Update ##

        # Enable features introduced via servicing that are off by default: Disabled
        $RegPath = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowTemporaryEnterpriseFeatureControl" -Data 0 -Type "DWord"
    }   
    #---------------------------------------------------------------------------------------------------------#

    gpupdate.exe /force
    Write-Host "Successfully Configured Group Policy!" -ForegroundColor Green
}

function Set-Services {
    # Windows Defender Antivirus Network Inspection Service (WdNisSvc): Automatic, Start
    Set-Service -Name "WdNisSvc" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "WdNisSvc" -ErrorAction SilentlyContinue
    
    # Windows Defender Antivirus Service (WinDefend): Automatic, Start
    Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue

    # Microsoft Defender Core Service (MDCoreSvc): Automatic, Start
    Set-Service -Name "MDCoreSvc" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "MDCoreSvc" -ErrorAction SilentlyContinue

    # Print Spooler (Spooler): Disabled, Stop
    Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue

    # Security Center (wscsvc): Automatic, Start
    Set-Service -Name "wscsvc" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "wscsvc" -ErrorAction SilentlyContinue

    # Software Protection (sppsvc): Automatic, Start
    Set-Service -Name "sppsvc" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "sppsvc" -ErrorAction SilentlyContinue

    # Windows Defender Firewall (mpssvc): Automatic, Start
    Set-Service -Name "mpssvc" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "mpssvc" -ErrorAction SilentlyContinue

    # Windows Error Reporting Service (WerSvc): Disabled, Stop
    Set-Service -Name "WerSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "WerSvc" -ErrorAction SilentlyContinue

    # Windows Event Log (EventLog): Automatic, Start
    Set-Service -Name "EventLog" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "EventLog" -ErrorAction SilentlyContinue

    # Windows Security Service (SecurityHealthService): Automatic, Start
    Set-Service -Name "SecurityHealthService" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "SecurityHealthService" -ErrorAction SilentlyContinue

    # Windows Update (wuauserv): Automatic, Start
    Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue

    # World Wide Web Publishing service (W3SVC): Disabled, stop
    Set-Service -Name "W3SVC" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "W3SVC" -Force -ErrorAction SilentlyContinue

    # Telnet (TlntSvr): Disabled, Stop 
    Set-Service -Name "TlntSvr" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "TlntSvr" -Force -ErrorAction SilentlyContinue

    # Background Intelligent Transfer Service (BITS): Automatic, Start
    Set-Service -Name "BITS" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "BITS" -ErrorAction SilentlyContinue

    # IPsec Policy Agent (PolicyAgent): Automatic, Start
    Set-Service -Name "PolicyAgent" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "PolicyAgent" -ErrorAction SilentlyContinue

    # Remote Registry (RemoteRegistry): Disabled, Stop
    Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue

    # Internet Connection Sharing (SharedAccess): Disabled, Stop
    Set-Service -Name "SharedAccess" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SharedAccess" -Force -ErrorAction SilentlyContinue

    # UPnP Device Host (upnphost): Disabled, Stop
    Set-Service -Name "upnphost" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "upnphost" -Force -ErrorAction SilentlyContinue

    # Net TCP Port Sharing Service (NetTcpPortSharing): Disabled, Stop
    Set-Service -Name "NetTcpPortSharing" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "NetTcpPortSharing" -Force -ErrorAction SilentlyContinue

    # Windows Media Player Network Sharing Service (WMPNetworkSVC): Disabled, Stop
    Set-Service -Name "WMPNetworkSVC" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "WMPNetworkSVC" -Force -ErrorAction SilentlyContinue

    # Cryptographic Services (CryptSvc): Automatic, Start
    Set-Service -Name "CryptSvc" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "CryptSvc" -ErrorAction SilentlyContinue

    # Bluetooth Audio Gateway Service (BTAGService): Disabled, Stop
    Set-Service -Name "BTAGService" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "BTAGService" -Force -ErrorAction SilentlyContinue

    # Bluetooth Support Service (bthserv): Disabled, Stop
    Set-Service -Name "bthserv" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue

    # Computer Browser (Browser): Disabled, Stop
    Set-Service -Name "Browser" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "Browser" -Force -ErrorAction SilentlyContinue

    # Downloaded Maps Manager (MapsBroker): Disabled, Stop
    Set-Service -Name "MapsBroker" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "MapsBroker" -Force -ErrorAction SilentlyContinue

    # Geolocation Service (lfsvc): Disabled, Stop
    Set-Service -Name "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "lfsvc" -Force -ErrorAction SilentlyContinue

    # IIS Admin Service (IISADMIN): Disabled, Stop
    Set-Service -Name "IISADMIN" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "IISADMIN" -Force -ErrorAction SilentlyContinue

    # Infrared monitor service (irmon): Disabled, Stop
    Set-Service -Name "irmon" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "irmon" -Force -ErrorAction SilentlyContinue

    # Link-Layer Topology Discovery Mapper (lltdsvc): Disabled, Stop
    Set-Service -Name "lltdsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "lltdsvc" -Force -ErrorAction SilentlyContinue

    # LxssManager (LxssManager): Disabled, Stop
    Set-Service -Name "LxssManager" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "LxssManager" -Force -ErrorAction SilentlyContinue

    # Microsoft iSCSI Initiator Service (MSiSCSI): Disabled, Stop
    Set-Service -Name "MSiSCSI" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "MSiSCSI" -Force -ErrorAction SilentlyContinue

    # OpenSSH SSH Server (sshd): Disabled, Stop
    Set-Service -Name "sshd" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "sshd" -Force -ErrorAction SilentlyContinue

    # Peer Name Resolution Protocol (PNRPsvc): Disabled, Stop
    Set-Service -Name "PNRPsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "PNRPsvc" -Force -ErrorAction SilentlyContinue

    # Peer Networking Grouping (p2psvc): Disabled, Stop
    Set-Service -Name "p2psvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "p2psvc" -Force -ErrorAction SilentlyContinue

    # Peer Networking Identity Manager (p2pimsvc): Disabled, Stop
    Set-Service -Name "p2pimsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "p2pimsvc" -Force -ErrorAction SilentlyContinue

    # PNRP Machine Name Publication Service (PNRPAutoReg): Disabled, Stop
    Set-Service -Name "PNRPAutoReg" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "PNRPAutoReg" -Force -ErrorAction SilentlyContinue

    # Problem Reports and Solutions Control Panel Support (wercplsupport): Disabled, Stop
    Set-Service -Name "wercplsupport" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "wercplsupport" -Force -ErrorAction SilentlyContinue

    # Remote Access Auto Connection Manager (RasAuto): Disabled, Stop
    Set-Service -Name "RasAuto" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "RasAuto" -Force -ErrorAction SilentlyContinue

    # Remote Procedure Call Locator (RpcLocator): Disabled, Stop
    Set-Service -Name "RpcLocator" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "RpcLocator" -Force -ErrorAction SilentlyContinue

    # Routing and Remote Access (RemoteAccess): Disabled, Stop
    Set-Service -Name "RemoteAccess" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "RemoteAccess" -Force -ErrorAction SilentlyContinue

    # Server (LanmanServer): Disabled, Stop
    Set-Service -Name "LanmanServer" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "LanmanServer" -Force -ErrorAction SilentlyContinue

    # Simple TCP/IP Services (simptcp): Disabled, Stop
    Set-Service -Name "simptcp" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "simptcp" -Force -ErrorAction SilentlyContinue

    # SNMP Service (SNMP): Disabled, Stop
    Set-Service -Name "SNMP" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SNMP" -Force -ErrorAction SilentlyContinue

    # Special Administration Console Helper (sacsvr): Disabled, Stop:
    Set-Service -Name "sacsvr" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "sacsvr" -Force -ErrorAction SilentlyContinue

    # SSDP Discovery (SSDPSRV): Disabled, Stop
    Set-Service -Name "SSDPSRV" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue

    # Web Management Service (WMSvc): Disabled, Stop
    Set-Service -Name "WMSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "WMSvc" -Force -ErrorAction SilentlyContinue

    # Windows Event Collector (Wecsvc): Disabled, Stop
    Set-Service -Name "Wecsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "Wecsvc" -Force -ErrorAction SilentlyContinue

    # Windows Mobile Hotspot Service (icssvc): Disabled, Stop
    Set-Service -Name "icssvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "icssvc" -Force -ErrorAction SilentlyContinue

    # Windows Push Notifications System Service (WpnService): Disabled, Stop
    Set-Service -Name "WpnService" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "WpnService" -Force -ErrorAction SilentlyContinue

    # Windows PushToInstall Service (PushToInstall): Disabled, Stop
    Set-Service -Name "PushToInstall" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "PushToInstall" -Force -ErrorAction SilentlyContinue

    # Xbox Accessory Management Service (XboxGipSvc): Disabled, Stop
    Set-Service -Name "XboxGipSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XboxGipSvc" -Force -ErrorAction SilentlyContinue

    # Xbox Live Auth Manager (XblAuthManager): Disabled, Stop
    Set-Service -Name "XblAuthManager" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XblAuthManager" -Force -ErrorAction SilentlyContinue

    # Xbox Live Game Save (XblGameSave): Disabled, Stop
    Set-Service -Name "XblGameSave" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XblGameSave" -Force -ErrorAction SilentlyContinue

    # Xbox Live Networking Service (XboxNetApiSvc): Disabled, Stop
    Set-Service -Name "XboxNetApiSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "XboxNetApiSvc" -Force -ErrorAction SilentlyContinue


    # Disable Telnet
    Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart

    Write-Host "Successfully Configured Services!" -ForegroundColor Green
}

function Disable-RDP {
    ## Services ##

    # Remote Desktop Configuration (SessionEnv): Disabled, Stop
    Set-Service -Name "SessionEnv" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "SessionEnv" -Force -ErrorAction SilentlyContinue

    # Remote Desktop Services (TermService): Disabled, Stop
    Set-Service -Name "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "TermService" -Force  -ErrorAction SilentlyContinue

    # Remote Desktop Services UserMode Port Redirector (UmRdpService): Disabled, Stop
    Set-Service -Name "UmRdpService" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "UmRdpService" -Force -ErrorAction SilentlyContinue
    
    # Windows Remote Management (WinRM): Disabled, Stop
    Set-Service -Name "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue

    ## Registry ##

    # Remote Desktop
    $path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty -Path $path -Name "fDenyTSConnections" -Value 1
    Set-ItemProperty -Path $path -Name "AllowRemoteRPC" -Value 0

    # Remote Assistance
    $path = 'HKLM:\System\CurrentControlSet\Control\Remote Assistance'
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "fAllowToGetHelp" -Value 0


    ## Firewall ##
    Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

    
    ## Group Policy ##
    $MachineDir = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"

    # Allow inbound RDP exceptions: disable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\RemoteDesktop"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"

    # Allow inbound Remote administration exceptions: disable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"

    # Set rules for remote control of Remote Desktop Services user sessions: No remote control allowed
    $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Shadow" -Data 0 -Type "DWord"

    # Allow users to connect remotely by using Remote Desktop Services: disable
    $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDenyTSConnections" -Data 1 -Type "DWord"

    # Solicited Remote Assistance: disable
    $RegPath = "Software\policies\Microsoft\Windows NT\Terminal Services"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fAllowToGetHelp" -Data 0 -Type "DWord"

    # Offer Remote Assistance: disable
    $RegPath = "Software\policies\Microsoft\Windows NT\Terminal Services"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fAllowUnsolicited" -Data 0 -Type "DWord"

    # Allow remote shell access: disable
    $RegPath = "Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowRemoteShellAccess" -Data 0 -Type "DWord"


    Write-Host "Successfully Disabled RDP!" -ForegroundColor Green
}

function Enable-RDP {
    ## Services ##
    
    # Remote Desktop Configuration (SessionEnv): Automatic, Start
    Set-Service -Name "SessionEnv" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "SessionEnv" -ErrorAction SilentlyContinue

    # Remote Desktop Services (TermService): Automatic, Start
    Set-Service -Name "TermService" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "TermService" -ErrorAction SilentlyContinue

    # Remote Desktop Services UserMode Port Redirector (UmRdpService): Automatic, Start
    Set-Service -Name "UmRdpService" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "UmRdpService" -ErrorAction SilentlyContinue

    # Windows Remote Management (WinRM): Automatic, Start
    Set-Service -Name "WinRM" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "WinRM" -ErrorAction SilentlyContinue


    ## Registry ##
    
    # Remote Desktop
    $path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty -Path $path -Name "fDenyTSConnections" -Value 0
    Set-ItemProperty -Path $path -Name "AllowRemoteRPC" -Value 1

    # Remote Assistance
    $path = 'HKLM:\System\CurrentControlSet\Control\Remote Assistance'
    New-Item -Path $path -Force
    Set-ItemProperty -Path $path -Name "fAllowToGetHelp" -Value 1
    


    
    ## Firewall ##
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


    ## Group Policy ##
    $MachineDir = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"

    # Allow inbound RDP exceptions: enable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\RemoteDesktop"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 1 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 1 -Type "DWord"

    # Allow inbound Remote administration exceptions: enable
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 1 -Type "DWord"
    $RegPath = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 1 -Type "DWord"

    # Allow users to connect remotely by using Remote Desktop Services: enable
    $RegPath = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "fDenyTSConnections" -Data 0 -Type "DWord"

    # Allow remote shell access: enable
    $RegPath = "Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "AllowRemoteShellAccess" -Data 1 -Type "DWord"
    

    Write-Host "Successfully Enabled RDP!" -ForegroundColor Green
}

function Disable-FTP {
    # FTP, File Transfer Protocol Service (FTPSVC): Disabled, Stop
    Set-Service -Name "FTPSVC" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "FTPSVC" -Force -ErrorAction SilentlyContinue

    Write-Host "Successfully Disabled FTP!" -ForegroundColor Green
}

function Enable-FTP {
    # FTP, File Transfer Protocol Service (FTPSVC): Automatic, Start
    Set-Service -Name "FTPSVC" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

    Write-Host "Successfully Enabled FTP!" -ForegroundColor Green
}

function Search-Files {
    
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
            # Scan for files in each user's folder
            Get-ChildItem -Path $userDir -File -Exclude *.url, *.lnk -ErrorAction Continue | ForEach-Object {
                Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                Write-Host "File Name: $($_.Name)" -ForegroundColor Magenta
                Write-Host "Full Path: $($_.FullName)" -ForegroundColor Magenta
                Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                $script:filesFound = $true
            }

            # Exclude folders like AppData and those starting with "."
            Get-ChildItem -Path $userDir -Recurse -Directory -ErrorAction Continue | Where-Object {
                $_.Name -ne "AppData" -and -not ($_.Name -like ".*")
            } | ForEach-Object {
                    $folder = $_.FullName

                    # Scan for files in "Users" folder
                    Get-ChildItem -Path $folder -Recurse -File -Exclude *.url, *.lnk -ErrorAction Continue | ForEach-Object {
                        Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                        Write-Host "File Name: $($_.Name)" -ForegroundColor Magenta
                        Write-Host "Full Path: $($_.FullName)" -ForegroundColor Magenta
                        Write-Host "---------------------------------------------------------------------------------------" -ForegroundColor White
                        $script:filesFound = $true
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
        $_.Name -notin @('ADMIN$', 'IPC$')
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

    $disablesharing = $(Write-Host "Disable file/folder sharing? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
    if ($disablesharing -eq 'y') { 
        $UserRegDir = "$env:windir\system32\GroupPolicy\User\registry.pol"

        # Allow shared folders to be published: disable
        $RegPath = "Software\Policies\Microsoft\Windows NT\SharedFolders"
        Set-PolicyFileEntry -Path $UserRegDir -Key $RegPath -ValueName "PublishSharedFolders" -Data 0 -Type "DWord"

        # Prevent users from sharing files within their profile: enable
        $RegPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Set-PolicyFileEntry -Path $UserRegDir -Key $RegPath -ValueName "NoInplaceSharing" -Data 1 -Type "DWord"

        gpupdate.exe /force
        Write-Host "Disabled Folder Sharing!" -ForegroundColor Green
    }
}

$syncUsers = $(Write-Host "Synchronize Users? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($syncUsers -eq 'y') { 
    Sync-Users
} else {
    Write-Host "Skipping User Synchronization" -ForegroundColor Yellow
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
} elseif ($FTP -eq 'd') {
    Disable-FTP
} else {
    Write-Host "Not Configuring FTP" -ForegroundColor Yellow
} 

$services = $(Write-Host "Configure Services? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
if ($services -eq 'y') { 
    Set-Services
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
