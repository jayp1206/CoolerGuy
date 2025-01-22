# Install PolicyFileEditor
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
Install-Module -Name PolicyFileEditor -RequiredVersion 3.0.0 -Scope CurrentUser

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
    $RegPath = "Software\Policies\Microsoft\Windows\Explorer"
    Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "NoUseStoreOpenWith" -Data 1 -Type "DWord"

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

    # Allow Custom SSPs and APs to be loaded into LSASS: Disabled

    # Configures LSASS to run as a protected process: Enabled (Enabled with UEFI Lock)

    # Disallow copying of user input methods to the system account for sign-in: Enabled

    # Block user from showing account details on sign-in: Enabled

    # Do not display network selection UI: Enabled

    # Turn off app notifications on the lock screen: Enabled

    # Turn on convenience PIN sign-in: Disabled

    # Allow Clipboard synchroniztion across devices: Disabled

    # Allow upload of User Activities: Disabled

    # Require a password when a computer wakes (on battery): Enabled

    # Require a password when a computer wakes (plugged in): Enabled

    # Enable RPC Endpoint Mapper Client Authentication: Enabled

    # Restrict Unauthenticated RPC clients: Enabled (Authenticated)

    # Enable/Disable PerfTrack: Disabled

    # Turn off the advertising ID: Enabled


    #---------------------------------------------# WIN 11 ONLY #---------------------------------------------#

    ## Enhanced Phishing Protection ##

    # Automatic data collection: enable
    $RegPath = "\SOFTWARE\Policies\Microsoft\Windows\WTDS"
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

    gpupdate.exe /force
    Write-Host "Successfully Configured Group Policy!" -ForegroundColor Green
}

function Set-Services {
    # Windows Defender Antivirus Network Inspection Service (WdNisSvc): Automatic, Start
    Set-Service -Name "WdNisSvc" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "WdNisSvc" -ErrorAction Continue
    
    # Windows Defender Antivirus Service (WinDefend): Automatic, Start
    Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "WinDefend" -ErrorAction Continue

    # Microsoft Defender Core Service (MDCoreSvc): Automatic, Start
    Set-Service -Name "MDCoreSvc" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "MDCoreSvc" -ErrorAction Continue

    # Print Spooler (Spooler): Disabled, Stop
    Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "Spooler" -Force -ErrorAction Continue

    # Security Center (wscsvc): Automatic, Start
    Set-Service -Name "wscsvc" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "wscsvc" -ErrorAction Continue

    # Software Protection (sppsvc): Automatic, Start
    Set-Service -Name "sppsvc" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "sppsvc" -ErrorAction Continue

    # Windows Defender Firewall (mpssvc): Automatic, Start
    Set-Service -Name "mpssvc" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "mpssvc" -ErrorAction Continue

    # Windows Error Reporting Service (WerSvc): Disabled, Stop
    Set-Service -Name "WerSvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "WerSvc" -ErrorAction Continue

    # Windows Event Log (EventLog): Automatic, Start
    Set-Service -Name "EventLog" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "EventLog" -ErrorAction Continue

    # Windows Security Service (SecurityHealthService): Automatic, Start
    Set-Service -Name "SecurityHealthService" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "SecurityHealthService" -ErrorAction Continue

    # Windows Update (wuauserv): Automatic, Start
    Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "wuauserv" -ErrorAction Continue

    # World Wide Web Publishing service (W3SVC): Disabled, stop
    Set-Service -Name "W3SVC" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "W3SVC" -Force -ErrorAction Continue

    # Telnet (TlntSvr): Disabled, Stop 
    Set-Service -Name "TlntSvr" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "TlntSvr" -Force -ErrorAction Continue

    # Background Intelligent Transfer Service (BITS): Automatic, Start
    Set-Service -Name "BITS" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "BITS" -ErrorAction Continue

    # IPsec Policy Agent (PolicyAgent): Automatic, Start
    Set-Service -Name "PolicyAgent" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "PolicyAgent" -ErrorAction Continue

    # Remote Registry (RemoteRegistry): Disabled, Stop
    Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction Continue

    # Internet Connection Sharing (SharedAccess): Disabled, Stop
    Set-Service -Name "SharedAccess" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "SharedAccess" -Force -ErrorAction Continue

    # UPnP Device Host (upnphost): Disabled, Stop
    Set-Service -Name "upnphost" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "upnphost" -Force -ErrorAction Continue

    # Net TCP Port Sharing Service (NetTcpPortSharing): Disabled, Stop
    Set-Service -Name "NetTcpPortSharing" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "NetTcpPortSharing" -Force -ErrorAction Continue

    # Windows Media Player Network Sharing Service (WMPNetworkSVC): Disabled, Stop
    Set-Service -Name "WMPNetworkSVC" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "WMPNetworkSVC" -Force -ErrorAction Continue

    # Cryptographic Services (CryptSvc): Automatic, Start
    Set-Service -Name "CryptSvc" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "CryptSvc" -ErrorAction Continue

    # Bluetooth Audio Gateway Service (BTAGService): Disabled, Stop
    Set-Service -Name "BTAGService" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "BTAGService" -Force -ErrorAction Continue

    # Bluetooth Support Service (bthserv): Disabled, Stop
    Set-Service -Name "bthserv" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "bthserv" -Force -ErrorAction Continue

    # Computer Browser (Browser): Disabled, Stop
    Set-Service -Name "Browser" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "Browser" -Force -ErrorAction Continue

    # Downloaded Maps Manager (MapsBroker): Disabled, Stop
    Set-Service -Name "MapsBroker" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "MapsBroker" -Force -ErrorAction Continue

    # Geolocation Service (lfsvc): Disabled, Stop
    Set-Service -Name "lfsvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "lfsvc" -Force -ErrorAction Continue

    # IIS Admin Service (IISADMIN): Disabled, Stop
    Set-Service -Name "IISADMIN" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "IISADMIN" -Force -ErrorAction Continue

    # Infrared monitor service (irmon): Disabled, Stop
    Set-Service -Name "irmon" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "irmon" -Force -ErrorAction Continue

    # Link-Layer Topology Discovery Mapper (lltdsvc): Disabled, Stop
    Set-Service -Name "lltdsvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "lltdsvc" -Force -ErrorAction Continue

    # LxssManager (LxssManager): Disabled, Stop
    Set-Service -Name "LxssManager" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "LxssManager" -Force -ErrorAction Continue

    # Microsoft iSCSI Initiator Service (MSiSCSI): Disabled, Stop
    Set-Service -Name "MSiSCSI" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "MSiSCSI" -Force -ErrorAction Continue

    # OpenSSH SSH Server (sshd): Disabled, Stop
    Set-Service -Name "sshd" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "sshd" -Force -ErrorAction Continue

    # Peer Name Resolution Protocol (PNRPsvc): Disabled, Stop
    Set-Service -Name "PNRPsvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "PNRPsvc" -Force -ErrorAction Continue

    # Peer Networking Grouping (p2psvc): Disabled, Stop
    Set-Service -Name "p2psvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "p2psvc" -Force -ErrorAction Continue

    # Peer Networking Identity Manager (p2pimsvc): Disabled, Stop
    Set-Service -Name "p2pimsvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "p2pimsvc" -Force -ErrorAction Continue

    # PNRP Machine Name Publication Service (PNRPAutoReg): Disabled, Stop
    Set-Service -Name "PNRPAutoReg" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "PNRPAutoReg" -Force -ErrorAction Continue

    # Problem Reports and Solutions Control Panel Support (wercplsupport): Disabled, Stop
    Set-Service -Name "wercplsupport" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "wercplsupport" -Force -ErrorAction Continue

    # Remote Access Auto Connection Manager (RasAuto): Disabled, Stop
    Set-Service -Name "RasAuto" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "RasAuto" -Force -ErrorAction Continue

    # Remote Procedure Call Locator (RpcLocator): Disabled, Stop
    Set-Service -Name "RpcLocator" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "RpcLocator" -Force -ErrorAction Continue

    # Routing and Remote Access (RemoteAccess): Disabled, Stop
    Set-Service -Name "RemoteAccess" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "RemoteAccess" -Force -ErrorAction Continue

    # Server (LanmanServer): Disabled, Stop
    Set-Service -Name "LanmanServer" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "LanmanServer" -Force -ErrorAction Continue

    # Simple TCP/IP Services (simptcp): Disabled, Stop
    Set-Service -Name "simptcp" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "simptcp" -Force -ErrorAction Continue

    # SNMP Service (SNMP): Disabled, Stop
    Set-Service -Name "SNMP" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "SNMP" -Force -ErrorAction Continue

    # Special Administration Console Helper (sacsvr): Disabled, Stop:
    Set-Service -Name "sacsvr" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "sacsvr" -Force -ErrorAction Continue

    # SSDP Discovery (SSDPSRV): Disabled, Stop
    Set-Service -Name "SSDPSRV" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "SSDPSRV" -Force -ErrorAction Continue

    # Web Management Service (WMSvc): Disabled, Stop
    Set-Service -Name "WMSvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "WMSvc" -Force -ErrorAction Continue

    # Windows Event Collector (Wecsvc): Disabled, Stop
    Set-Service -Name "Wecsvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "Wecsvc" -Force -ErrorAction Continue

    # Windows Mobile Hotspot Service (icssvc): Disabled, Stop
    Set-Service -Name "icssvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "icssvc" -Force -ErrorAction Continue

    # Windows Push Notifications System Service (WpnService): Disabled, Stop
    Set-Service -Name "WpnService" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "WpnService" -Force -ErrorAction Continue

    # Windows PushToInstall Service (PushToInstall): Disabled, Stop
    Set-Service -Name "PushToInstall" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "PushToInstall" -Force -ErrorAction Continue

    # Xbox Accessory Management Service (XboxGipSvc): Disabled, Stop
    Set-Service -Name "XboxGipSvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "XboxGipSvc" -Force -ErrorAction Continue

    # Xbox Live Auth Manager (XblAuthManager): Disabled, Stop
    Set-Service -Name "XblAuthManager" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "XblAuthManager" -Force -ErrorAction Continue

    # Xbox Live Game Save (XblGameSave): Disabled, Stop
    Set-Service -Name "XblGameSave" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "XblGameSave" -Force -ErrorAction Continue

    # Xbox Live Networking Service (XboxNetApiSvc): Disabled, Stop
    Set-Service -Name "XboxNetApiSvc" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "XboxNetApiSvc" -Force -ErrorAction Continue


    # Disable Telnet
    Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart

    Write-Host "Successfully Configured Services!" -ForegroundColor Green
}

function Disable-RDP {
    ## Services ##

    # Remote Desktop Configuration (SessionEnv): Disabled, Stop
    Set-Service -Name "SessionEnv" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "SessionEnv" -Force -ErrorAction Continue

    # Remote Desktop Services (TermService): Disabled, Stop
    Set-Service -Name "TermService" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "TermService" -Force  -ErrorAction Continue

    # Remote Desktop Services UserMode Port Redirector (UmRdpService): Disabled, Stop
    Set-Service -Name "UmRdpService" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "UmRdpService" -Force -ErrorAction Continue
    
    # Windows Remote Management (WinRM): Disabled, Stop
    Set-Service -Name "WinRM" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "WinRM" -Force -ErrorAction Continue

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
    Set-Service -Name "SessionEnv" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "SessionEnv" -ErrorAction Continue

    # Remote Desktop Services (TermService): Automatic, Start
    Set-Service -Name "TermService" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "TermService" -ErrorAction Continue

    # Remote Desktop Services UserMode Port Redirector (UmRdpService): Automatic, Start
    Set-Service -Name "UmRdpService" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "UmRdpService" -ErrorAction Continue

    # Windows Remote Management (WinRM): Automatic, Start
    Set-Service -Name "WinRM" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "WinRM" -ErrorAction Continue


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
    Set-Service -Name "FTPSVC" -StartupType Disabled -ErrorAction Continue
    Stop-Service -Name "FTPSVC" -Force -ErrorAction Continue

    Write-Host "Successfully Disabled FTP!" -ForegroundColor Green
}

function Enable-FTP {
    # FTP, File Transfer Protocol Service (FTPSVC): Automatic, Start
    Set-Service -Name "FTPSVC" -StartupType Automatic -ErrorAction Continue
    Start-Service -Name "FTPSVC" -ErrorAction Continue

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
                $filesFound = $true
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
                        $filesFound = $true
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

    $disablesharing = $(Write-Host "Disable file/folder sharing? (y/n): " -ForegroundColor Cyan -NoNewLine; Read-Host)
    if ($disablesharing -eq 'y') { 
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
