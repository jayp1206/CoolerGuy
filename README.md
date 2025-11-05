# MUST RUN "Set-ExecutionPolicy unrestricted"
### * = Windows 11 Only

# User Synchronization
- Remove all admins who should be standard users ✔
- Promote any standard users who should be admins ✔
- Delete any unauthorized accounts ✔
- Create any nonexistent authorized accounts ✔
- Set all user passwords (except current user) to Cyb3r1a@ARL99!!$$ ✔
- Disable "Password Never Expires" for all users (except current user) ✔

# Local Security Policy

## (Configure Security Policies?)

### Password Policy ✔
- Enforce password history: 24 remembered ✔
- Max password age: 30 days ✔
- Min password age: 5 days ✔
- Minimum password length: 14 characters ✔
- Minimum password length audit: 10 characters ✔
- Password must meet complexity requirements: Enabled ✔
- Relax minimum password length limits: Enabled ✔
- Store passwords using reversible encryption: Disabled ✔

### Account Lockout Policy ✔
- Account lockout duration: 30 mins ✔
- Account lockout threshold: 5 ✔
- Allow Administrator account lockout: Enabled ✔
- Reset account lockout counter after: 30 mins ✔

### Local Audit Policy ✔
- ALL: Success & Failure ✔

### Security Options

#### Accounts ✔
- Administrator account status: Disabled ✔
- Block Microsoft accounts: Can't add or log on ✔
- Guest account status: Disabled ✔
- Limit local use of blank passwords to console logon only: Enabled ✔

#### Audit ✔
- Audit the access of global system objects: Enabled ✔
- Audit the use of Backup and Restore privileges: Enabled ✔
- Shut down system immediately if unable to log security audits: Disabled ✔
- Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings: Enabled ✔

#### Devices ✔
- Prevent users from installing printer drivers: Enabled ✔
- Restrict CD-ROM access to locally logged-on user only: Enabled ✔ 
- Restrict floppy access to locally logged-on user only: Enabled ✔

#### Domain Member ✔
- Digitally encrypt or sign secure channel data (always): Enabled ✔
- Digitally encrypt secure channel data (when possible): Enabled ✔
- Digitally sign secure channel data (when possible): Enabled ✔
- Maximum machine account password age: 30 days ✔
- Require strong (Windows 2000 or later) session key: Enabled ✔

#### Interactive Logon ✔
- Display user information when the session is locked: Do not display ✔
- Do not require CTRL + ALT + DEL: Disabled ✔
- Don't display last signed-in: Enabled ✔
- Don't display username at sign-in: Enabled ✔
- Machine account lockout threshold: 5 ✔
- Machine inactivity limit: 600 sec ✔
- Prompt user to change password before expiration: 7 days ✔
- Smart card removal behavior: Lock Workstation

#### Microsoft Network Client ✔
- Digitally sign communications (always): Enabled ✔
- Digitally sign communications (if server agrees): Enabled ✔
- Send unencrypted passwords to third-party SMB servers: Disabled ✔

#### Microsoft Network Server ✔
- Digitally sign communications (always): Enabled ✔
- Digitally sign communications (if client agrees): Enabled ✔
- Disconnect clients when logon hours expire: Enabled ✔
- Amount of idle time required before suspending session: 10 minutes
- Server SPN target name validation level: Accept if provided by client

#### Network Access ✔
- Allow anonymous SID/Name translation: Disabled ✔
- Do not allow anonymous enumeration of SAM accounts: Enabled ✔
- Do not allow anonymous enumeration of SAM accounts and shares: Enabled ✔
- Do not allow storage of passwords and credentials for network authentication: Enabled ✔
- Let Everyone permissions apply to anonymous users: Disabled ✔
- Shares that can be accessed anonymously: Not Defined (remove all) ✔
- Restrict anonymous access to Named Pipes and Shares: Enabled
- Sharing and security model for local accounts: Classic - local users authenticate as themselves
- Name Pipes that can be accessed anonymously: None (remove all)

#### Network Security ✔
- Force logoff when logon hours expire: Enable ✔
- Audit incoming NTLM Traffic: Enable auditing for all accounts ✔
- Audit NTLM authentication in this domain: Enable all ✔
- Allow Local System to use computer identity for NTLM: Enabled
- Allow LocalSystem NULL session fallback: Disabled
- Allow PKU2U authentication requests to this computer to use online identities: Disabled
- (NOT OPTION???) Do not store LAN Manager hash value on next password change: Enabled
- LAN Manager authentication level: Send NTLMv2 reponse only. Refuse LM & NTLM
- LDAP client signing requirements: Negotiate signing
- Minimum session security for NTLM SSP based (including secure RPC) clients: Require NTLMv2 session security, Require 128-bit encryption
- Minimum session security for NTLM SSP based (including secure RPC) servers: Require NTLMv2 session security, Require 128-bit encryption
- Outgoing NTLM traffic to remote servers: Audit all

#### Recovery Console ✔
- Allow automatic administrative logon: Disabled ✔
- Allow floppy copy and access to all drives and all folders: Disabled ✔

#### System Cryptography ✔
- Force strong key protection for user keys stored on the computer: User must enter a password each time they use a key ✔
- Use FIPS compliant algorithms for encryption, hashing, and signing: Enabled ✔

#### System Objects ✔
- Require case insensitivity for non-Windows subsystems: Enabled ✔
- Strengthen default permissions of internal system objects: Enabled

### User Account Control (Configure User Account Control?) ✔
- Admin Approval Mode for the Built-in Administrator account: Enabled ✔
- Allow UIAccess applications to prompt for elevation without using the secure desktop: Disabled ✔
- Behavior of the elevation prompt for administrators in Admin Approval Mode: Prompt for consent on the secure desktop ✔
- Detect application installations and prompt for elevation: Enabled ✔
- Only elevate executables that are signed and validated: Enabled ✔
- Only elevate UIAccess applications that are installed in secure locations: Enabled ✔
- Run all administrators in Admin Approval Mode: Enabled ✔
- Switch to the secure desktop when prompting for elevation: Enabled ✔
- Behavior of the elevation prompt for standard users: Automatically deny elevation requests
- Virtualize file and registry write failures to per-user locations: Enabled

## (Configure Windows Defender Firewall?)

### Windows Defender Firewall with Advanced Security ✔

#### Domain Profile ✔
- Firewall state: On ✔
- Inbound connections: Block ✔
- Outbound connections: Allow ✔

#### Private Profile ✔
- Firewall state: On ✔
- Inbound connections: Block ✔
- Outbound connections: Allow ✔
- Logging -->  Size Limit (KB): 20,000 KB ✔
- Logging --> Logged Dropped Packets: Yes ✔
- Logging --> Log successful connections: Yes ✔

#### Public Profile ✔
- Firewall state: On ✔
- Inbound connections: Block ✔
- Outbound connections: Allow ✔
- Logging -->  Size Limit (KB): 20,000 KB ✔
- Logging --> Logged Dropped Packets: Yes ✔
- Logging --> Log successful connections: Yes ✔

#### Block File and Printer Sharing ✔


## (Configure Advanced Audit Policies?)
### Advanced Audit Policy Configuration ✔
- ALL: Sucess & Failure ✔



# Computer Management

## (List All Network Shares ?)
### Shared Folders ✔
- List all shares except ADMIN$, C$, IPC$ ✔


# (Configure Group Policy?)
# Group Policy

## Computer Configuration 

### Administrative Templates


#### Control Panel
- Allow Online Tips: Disabled ✔

##### Personalization ✔
- Prevent enabling lock screen camera: Enabled ✔
- Prevent enabling lock screen slideshow: Enabled ✔

##### Regional and Language Options ✔
- Allow users to enable online speech recognition services: Disabled ✔



#### Network

##### DNS Client ✔
- Configure DNS over HTTP (DoH) name resolution: Enabled (Allow DoH) ✔ *

##### Fonts ✔
- Enable Font Providers: Disabled ✔

##### Lanman Workstation ✔
- Enable insecure guest logons: Disabled ✔

##### Link-Layer Topology Discovery ✔
- Turn on Mapper I/O (LLTDIO) driver: Disabled ✔
- Turn on Responder (RSPNDR) driver: Disabled ✔

##### Microsoft Peer-to-Peer Networking Services ✔
- Turn off Microsoft Peer-to-Peer Networking Services: Enabled ✔

##### Network Connections ✔
- Prohibit installation and configuration of Network Bridge on your DNS domain network: Enabled ✔
- Prohibit use of Internet Connection Sharing on your DNS domain network: Enabled ✔

###### Windows Defender Firewall (Domain Profile and Standard Profile) ✔
- Allow inbound file and printer sharing exception: Disabled ✔
- Allow inbound UPnP framework exceptions: Disabled ✔
- Allow logging: log dropped packets, log successful connections ✔
- Prohibit unicast responses to multicast or broadcast requests: Enabled ✔
- Protect all network connections: Enabled ✔

##### Windows Connect Now ✔
- Configuration of wireless settings using Window Connect Now: Disabled ✔
- Prohibit access of the Windows Connect Now wizards: Enabled ✔

##### Windows Connection Manager ✔
- Minimize the number of simultaneous connections to the internet or a Windows Domain: Prevent Wi-Fi when on Ethernet ✔

##### WLAN Service --> WLAN Settings ✔
- Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services: Disabled ✔

#### System --> Remote Assistance ✔
- Allow only Windows Vista or later connections: Enabled ✔
- Turn on session logging: Enabled ✔
- Configure Offer Remote Assistance: Disabled ✔
- Configure Solicited Remote Assistance: Disabled ✔
- System Properties --> Allow Remote Assistance connections to this computer: UNCHECK (Registry) ✔


#### Printers ✔
- Allow Print Spooler to accept client connections: Disabled ✔
- Configure Redirection Guard: Enabled ✔ *
- Protocol to use for outgoing RPC connections: Enabled (RPC over TCP) ✔ *
- Use authentication for outgoing RPC connections: Enabled ✔ *
- Protocols to allow for incoming RPC connections: Enabled (RPC over TCP) ✔ *
- Authentication Protocol to use for incoming RPC connections: Enabled (Negotiate) ✔ *
- Configure RPC over TCP port: Enabled (0) ✔ *
- Limits printer driver installation to Administrators: Enabled ✔
- Manage processing of Queue-specific files: Enabled (Limit Queue-specific files to Color profiles) ✔ *
- When installing drivers for a new connection: Enabled (Show warning and elevation prompt) ✔
- When updating drivers for an existing connection: Enabled (Show warning and elevation prompt) ✔


#### System

##### Audit Process Creation ✔
- Include command line in process creation events: Enabled ✔

##### Credentials Delegation ✔
- Encryption Oracle Remediation: Enabled (Force Updated Clients) ✔
- Remote host allows delegation of non-exportable credentials: Enabled ✔

##### Device Installation --> Device Installation Restrictions ✔
- Prevent device metadata retrieval from the Internet: Enabled ✔

##### Early Launch Antimalware ✔
- Boot-Start Driver Initialization Policy: Enabled (Good, unknown, and bad but critical) ✔

##### Group Policy --> Logging and Tracing ✔
- Continue experiences on this device: Disabled ✔

##### Internet Communication Management --> Internet Communication Settings ✔
- Turn off access to the Store: Enabled ✔
- Turn off downloading of printer drivers over HTTP: Enabled ✔
- Turn off handwriting personalization data sharing: Enabled ✔
- Turn off handwriting recognition error reporting: Enabled ✔
- Turn off printing over HTTP: Enabled ✔
- Turn off the "Order Prints" picture task: Enabled ✔
- Turn off the "Publish to Web" task for files and folders: Enabled ✔

##### Kerberos ✔
- Support device authentication using certificate: Enabled (Forced) ✔

##### Local Security Authority ✔
- Allow Custom SSPs and APs to be loaded into LSASS: Disabled ✔

##### Locale Services ✔
- Disallow copying of user input methods to the system account for sign-in: Enabled ✔

##### Logon ✔
- Block user from showing account details on sign-in: Enabled ✔
- Do not display network selection UI: Enabled ✔
- Turn off app notifications on the lock screen: Enabled ✔
- Turn on convenience PIN sign-in: Disabled ✔

##### OS Policies ✔
- Allow Clipboard synchroniztion across devices: Disabled ✔
- Allow upload of User Activities: Disabled ✔

##### Sleep Settings ✔
- Require a password when a computer wakes (plugged in): Enabled ✔

##### Remote Procedure Call
- Enable RPC Endpoint Mapper Client Authentication: Enabled ✔
- Restrict Unauthenticated RPC clients: Enabled (Authenticated) ✔

##### User Profiles ✔
- Turn off the advertising ID: Enabled ✔

### Windows Components

#### App Package Deployment ✔
- Allow a Windows app to share application data between users: Disabled ✔
- Prevent non-admin users from installing packaged Windows apps: Enabled ✔

#### App Privacy ✔
- Let Windows apps activate with voice while the system is locked: Enabled (Force Deny) ✔

#### App Runtime ✔
- Block launching Universal Windows apps with Windows Runtime API access from hosted content: Enabled ✔

#### Biometrics --> Facial Features ✔
- Configure enhanced anti-spoofing: Enabled ✔

#### Camera ✔
- Allow Use of Camera: Disabled ✔

#### Connect ✔
- Require pin for pairing: Enabled (Always) ✔

#### Desktop App Installer ✔
- Enable App Installer Hash Override: Disabled ✔ *
- Enable App Installer ms-appinstaller protocol: Disabled ✔ *

#### File Explorer ✔
- Turn off Data Execution Prevention for Explorer: Disabled ✔
- Turn off heap termination on corruption: Disabled ✔
- Turn off shell protocol protected mode: Disabled ✔

#### Microsoft Account ✔
- Block all consumer Microsoft account user authentication: Enabled ✔

#### Remote Desktop Services  ✔

##### Remote Desktop Connection Client --> RemoteFX USB Device Redirection ✔
- Disable Cloud Clipboard integration for server-to-client data transfer: Enabled ✔ *
- Do not allow passwords to be saved: Enabled ✔

##### Remote Desktop Session Host ✔
###### Device and Resource Redirection ✔
- Allow UI Automation redirection: Disabled ✔
- Do not allow COM port redirection: Enabled ✔
- Do not allow drive redirection: Enabled ✔
- Do not allow location redirection: Enabled ✔
- Do not allow LPT port redirection: Enabled ✔
- Do not allow supported Plug and Play device redirection: Enabled ✔
- Do not allow WebAuthn redirection: Enabled ✔ *
###### Security ✔
- Require use of specific security layer for remote (RDP) connections: SSL ✔
- Set client connection encryption level: Enabled, High Level ✔
- Always prompt for password upon connection: Enabled ✔
- Require secure RPC communication: Enabled ✔
- Require user authentication for remote connections by using Network Level Authentication: Enabled ✔
###### Session Time Limits ✔
- End session when time limits are reached: Enabled ✔
- Set time limit for active but idle Remote Desktop Services sessions: Enabled (15 minutes) ✔
- Set time limit for disconnected sessions: Enabled (1 minute) ✔


#### RSS Feeds ✔
- Prevent downloading of enclosures: Enabled ✔

#### Search ✔
- Allow Cloud Search: Enabled (Disable Cloud Search) ✔
- Allow Cortana: Disabled ✔
- Allow Cortana above lock screen: Disabled ✔
- Allow indexing of encrypted files: Disabled ✔
- Allow search and Cortana to use location: Disabled ✔
- Allow search highlights: Disabled ✔

#### Store ✔
- Turn off Automatic Download and Install of updates: Disabled ✔

#### Windows Game Recording and Broadcasting ✔
- Enables or disables Windows Game Recording and Broadcasting: Disabled ✔

#### Windows Hello for Business ✔
- Enable ESS with Supported Peripherals: Enabled (1) ✔ *

#### Windows Ink Workspace ✔
- Allow Windows Ink Workspace: Enabled (On, but disallow access above lock) ✔

#### Windows Installer ✔
- Allow user control over installs: Disabled ✔
- Always install with elevated privileges: Disabled ✔
- Prevent Internet Explorer security prompt for Windows Installer scripts: Disabled ✔

#### Windows Logon Options ✔
- Enable MPR notifications for the system: Disabled ✔ *
- Sign-in and lock last interactive user automatically after a restart: Disabled ✔

#### Windows Remote Management (WinRM) ✔
##### WinRM Client ✔
- Allow Basic authentication: Disabled ✔
- Allow unencrypted traffic: Disabled ✔
- Disallow Digest authentication: Enabled ✔
##### WinRM Service ✔
- Allow Basic authentication: Disabled ✔
- Allow remote server management through WinRM: Disabled ✔
- Allow unencrypted traffic: Disabled ✔
- Disallow WinRM from storing RunAs credentials: Enabled ✔

#### Windows Sandbox ✔
- Allow clipboard sharing with Windows Sandbox: Disabled ✔ *
- Allow networking in Windows Sandbox: Disabled ✔ *

#### Autoplay Policies ✔
- Turn off Autoplay: Enabled (For all drives) ✔
- Disallow Autoplay for non-volume devices: Enabled ✔
- Set the default behavior for AutoRun: Enabled (Do not execute any autorun commands) ✔

#### Windows Update ✔
- No auto-restart with logged on users for scheduled automatic updates installation: Disabled ✔
- Scheduled install day: 0 (Every day) ✔
- Enable features introduced via servicing that are off by default: Disabled ✔ *
- Configure Automatic Updates: Enabled, auto download and schedule install ✔
- Allow Automatic Updates immediate installation: Enabled ✔
- Automatic Updates detection frequency: 22 hours ✔

#### Credential User Interface ✔
- Do not display the password reveal button: Enabled ✔
- Enumerate administrator accounts on elevation: Disabled ✔
- Prevent the use of security questions for local accounts: Enabled ✔

#### Event Log Service --> Setup ✔
- Turn on Logging: Enabled ✔

#### Microsoft Defender Antivirus ✔
- Allow antimalware service to startup with normal priority: Enabled ✔
- Turn off Microsoft Defender Antivirus: Disabled ✔
- Configure detection for potentially unwanted applications: Enabled (Block) ✔

##### Microsoft Defender Exploit Guard --> Network Protection ✔
- Prevent users and apps from accessing dangerous websites: Enabled ✔

##### MpEngine ✔
- Enable file hash computation feature: Enabled ✔

##### Real Time Protection ✔
- Turn off real-time protection: Disabled ✔
- Turn on behavior monitoring: Enabled ✔
- Scan all downloaded files and attachments: Enabled ✔
- Monitor file and program activity on your computer: Enabled ✔
- Turn on process scanning whenever real-time protection is enabled: Enabled ✔
- Turn on script scanning: Enabled ✔
- Configure monitoring for incoming and outgoing file and progam activity: Not configured (inbound/outbound) ✔

###### Scan ✔
- Check for the latest virus and spyware security intelligence before running a scheduled scan: Enabled ✔
- Scan archive files: Enabled ✔
- Scan removable drives: Enabled ✔
- Scan packed executables: Enabled ✔
- Scan network files: Enabled ✔
- Specify the interval to run quick scans per day: Enabled (12) ✔
- Turn on e-mail scanning: Enabled ✔

##### Security Intelligence Updates ✔
- Turn on scan after security intelligence update: Enabled ✔
- Allow real-time security intelligence updates based on reports to Microsoft MAPS: Enabled ✔
- Check for the latest virus and spyware security intelligence on startup: Enabled ✔

#### Push to Install ✔
- Turn off Push to Install service: Enabled ✔

#### Security Center ✔
- Turn on Security Center (Domain PC's only) ✔


#### Windows Defender SmartScreen

##### Enhanced Phishing Protection ✔
- Automatic Data Collection: Enabled ✔ *
- Notify Malicious: Enabled ✔ *
- Notify Password Reuse: Enabled ✔ *
- Notify Unsafe App: Enabled ✔ *
- Service Enabled: Enabled ✔ *

##### Explorer ✔
- Configure Windows Defender SmartScreen: Enabled (Warn and prevent bypass) ✔

##### Microsoft Edge ✔
- Configure Windows Defender SmartScreen: Enabled ✔
- Prevent bypassing Windows Defender SmartScreen prompts for sites: Enabled ✔


## User Configuration

### Administrative Templates --> Windows Components

#### Attachment Manager ✔
- Do not preserve zone information in file attachments: Disabled ✔
- Notify antivirus programs when opening attachments: Enabled ✔

#### Cloud Content ✔
- Do not use diagnostic data for tailored experiences: Enabled ✔

#### Windows Installer ✔
- Always install with elevated privileges: Disabled ✔

#### Windows Media Player --> Playback ✔
- Prevent Codec Download: Enabled ✔

# Services ✔
- Windows Defender Antivirus Network Inspection Service (WdNisSvc): Automatic, Start ✔
- Windows Defender Antivirus Service (WinDefend): Automatic, Start ✔
- Microsoft Defender Core Service (MDCoreSvc): Automatic, Start ✔
- Print Spooler (Spooler): Disabled, Stop ✔
- Security Accounts Manager (SamSs): Automatic, Start
- Security Center (wscsvc): Automatic, Start ✔
- Software Protection (sppsvc): Automatic, Start ✔
- Windows Defender Firewall (mpssvc): Automatic, Start ✔
- Windows Error Reporting Service (WerSvc): Disabled, Stop ✔
- Windows Event Log (EventLog): Automatic, Start ✔
- Windows Security Service (SecurityHealthService): Automatic, Start ✔
- Windows Update (wuauserv): Automatic, Start ✔
- World Wide Web Publishing service (W3SVC): Disabled, Stop ✔
- Telnet (TlntSvr): Disabled, Stop ✔
- Background Intelligent Transfer Service (BITS): Automatic, Start ✔
- IPsec Policy Agent (PolicyAgent): Automatic, Start ✔
- Remote Registry (RemoteRegistry): Disabled, Stop ✔
- Internet Connection Sharing (SharedAccess): Disabled, Stop ✔
- UPnP Device Host (upnphost): Disabled, Stop ✔
- Net TCP Port Sharing Service (NetTcpPortSharing): Disabled, Stop ✔
- Windows Media Player Network Sharing Service (WMPNetworkSVC): Disabled, Stop ✔
- Cryptographic Services (CryptSvc): Automatic, Start ✔
- Bluetooth Audio Gateway Service (BTAGService): Disabled, Stop ✔
- Bluetooth Support Service (bthserv): Disabled, Stop ✔
- Computer Browser (Browser): Disabled, Stop ✔
- Downloaded Maps Manager (MapsBroker): Disabled, Stop ✔
- Geolocation Service (lfsvc): Disabled, Stop ✔
- IIS Admin Service (IISADMIN): Disabled, Stop ✔
- Infrared monitor service (irmon): Disabled, Stop ✔
- Link-Layer Topology Discovery Mapper (lltdsvc): Disabled, Stop ✔
- LxssManager (LxssManager): Disabled, Stop ✔
- Microsoft iSCSI Initiator Service (MSiSCSI): Disabled, Stop ✔
- OpenSSH SSH Server (sshd): Disabled, Stop ✔
- Peer Name Resolution Protocol (PNRPsvc): Disabled, Stop ✔
- Peer Networking Grouping (p2psvc): Disabled, Stop ✔
- Peer Networking Identity Manager (p2pimsvc): Disabled, Stop ✔
- PNRP Machine Name Publication Service (PNRPAutoReg): Disabled, Stop ✔
- Problem Reports and Solutions Control Panel Support (wercplsupport): Disabled, Stop ✔
- Remote Access Auto Connection Manager (RasAuto): Disabled, Stop ✔
- Remote Procedure Call Locator (RpcLocator): Disabled, Stop ✔
- Routing and Remote Access (RemoteAccess): Disabled, Stop ✔
- Server (LanmanServer): Disabled, Stop ✔
- Simple TCP/IP Services (simptcp): Disabled, Stop ✔
- SNMP Service (SNMP): Disabled, Stop ✔
- Special Administration Console Helper (sacsvr): Disabled, Stop: ✔
- SSDP Discovery (SSDPSRV): Disabled, Stop ✔
- Web Management Service (WMSvc): Disabled, Stop ✔
- Windows Event Collector (Wecsvc): Disabled, Stop ✔
- Windows Mobile Hotspot Service (icssvc): Disabled, Stop ✔
- Windows Push Notifications System Service (WpnService): Disabled, Stop ✔
- Windows PushToInstall Service (PushToInstall): Disabled, Stop ✔
- Xbox Accessory Management Service (XboxGipSvc): Disabled, Stop ✔
- Xbox Live Auth Manager (XblAuthManager): Disabled, Stop ✔
- Xbox Live Game Save (XblGameSave): Disabled, Stop ✔
- Xbox Live Networking Service (XboxNetApiSvc): Disabled, Stop ✔
- Simple Mail Transfer Protocol (smtpsvc): Disabled, Stop ✔

- Disable Telnet Windows feature ✔


# (Enable or Disable RDP?)

## Enable RDP

### Group Policy --> Computer Configuration --> Administrative Templates

- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound Remote Desktop exceptions: Enabled ✔
- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound remote administration exceptions: Enabled ✔

- Remote Desktop Services --> Remote Desktop Session Host --> Connections --> Allow users to connect remotely by using Remote Desktop Services: Enabled ✔

- Windows Remote Shell --> Allow Remote Shell Access: Enabled ✔

- Allow Remote RPC: Enabled ✔

### Settings
- Remote Desktop --> Enable Remote Desktop: Toggle ON (Registry) ✔
- System Properties --> Allow remote connections to this computer: SELECT (Registry) ✔

### Firewall
- Allow RDP group through firewall ✔

### Services
- Remote Desktop Configuration (SessionEnv): Automatic, Start ✔
- Remote Desktop Services (TermService): Automatic, Start ✔
- Remote Desktop Services UserMode Port Redirector (UmRdpService): Automatic, Start ✔
- Windows Remote Management (WinRM): Automatic, Start ✔

## Disable RDP

### Group Policy --> Computer Configuration --> Administrative Templates

- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound Remote Desktop exceptions: Disabled ✔
- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound remote administration exceptions: Disabled ✔

- Windows Components --> Remote Desktop Services --> Remote Desktop Session Host --> Connections --> Allow users to connect remotely by using Remote Desktop Services: Disabled ✔
- Windows Components --> Remote Desktop Services --> Remote Desktop Session Host --> Connections --> Set rules for remote control of Remote Desktop Services user sessions: No remote control allowed ✔

- Windows Remote Shell --> Allow Remote Shell Access: Disabled ✔

- Allow Remote RPC: Disabled ✔

### Settings
- Remote Desktop --> Enable Remote Desktop: Toggle OFF (Registry) ✔
- System Properties --> Don't Allow remote connections to this computer: SELECT (Registry) ✔

### Firewall
- Don't allow RDP group through firewall ✔

### Services
- Remote Desktop Configuration (SessionEnv): Disabled, Stop ✔
- Remote Desktop Services (TermService): Disabled, Stop ✔
- Remote Desktop Services UserMode Port Redirector (UmRdpService): Disabled, Stop ✔
- Windows Remote Management (WinRM): Disabled, Stop ✔

# (Enable or Disable FTP?)

## Enable FTP
- File Transfer Protocol Service (FTPSVC): Automatic, Start ✔


## Disable FTP
- File Transfer Protocol Service (FTPSVC): Disabled, Stop ✔


# Scan for Prohibited Files ✔

# (Disable file/folder Sharing?)
## User Configuration 

### Shared Folders ✔
- Allow shared folder to be published: Disabled ✔

### Windows Components --> Network Sharing ✔
- Prevent users from sharing files within their profile: Enabled ✔