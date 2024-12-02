# MUST RUN "Set-ExecutionPolicy unrestricted"

# Local Security Policy

## (Configure Security Policies?)

### Password Policy ✔
- Enforce password history: 5 remembered ✔
- Max password age: 30 days ✔
- Min password age: 10 days ✔
- Minimum password length: 10 characters ✔
- Minimum password length audit: 10 characters ✔
- Password must meet complexity requirements: Enabled ✔
- Relax minimum password length limits: Disabled ✔
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
- Shut down system immediately if unable to log security audits: Enabled ✔

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
- Prompt user to change password before expiration: 5 days ✔

#### Microsoft Network Client ✔
- Digitally sign communications (always): Enabled ✔
- Digitally sign communications (if server agrees): Enabled ✔
- Send unencrypted passwords to third-party SMB servers: Disabled ✔

#### Microsoft Network Server ✔
- Digitally sign communications (always): Enabled ✔
- Digitally sign communications (if client agrees): Enabled ✔
- Disconnect clients when logon hours expire: Enabled ✔

#### Network Access ✔
- Allow anonymous SID/Name translation: Disabled ✔
- Do not allow anonymous enumeration of SAM accounts: Enabled ✔
- Do not allow anonymous enumeration of SAM accounts and shared: Enabled ✔
- Do not allow storage of passwords and credentials for network authentication: Enabled ✔
- Let Everyone permissions apply to anonymous users: Disabled ✔
- Shared that can be accessed anonymously: Not Defined (remove all) ✔

#### Network Security ✔
- Force logoff when logon hours expire: Enable ✔
- Audit incoming NTLM Traffic: Enable auditing for all accounts ✔
- Audit NTL authentication in this domain: Enable all ✔

#### Recovery Console ✔
- Allow automatic administrative logon: Disabled ✔
- Allow floppy copy and access to all drives and all folders: Disabled ✔

#### System Cryptography ✔
- Force strong key protection for user keys stored on the computer: User must enter a password each time they use a key ✔
- Use FIPS compliant algorithms for encryption, hashing, and signing: Enabled ✔

#### System Objects ✔
- Require case insensitivity for non-Windows subsystems: Enabled ✔

### User Account Control (Configure User Account Control?) ✔
- Admin Approval Mode for the Built-in Administrator account: Enabled ✔
- Allow UIAccess applications to prompt for elevation without using the secure desktop: Disabled ✔
- Behavior of the elevation prompt for administrators in Admin Approval Mode: Prompt for consent on the secure desktop ✔
- Behavior of the elevation prompt for standard users: Prompt for credentials on the secure desktop ✔
- Detect application installations and prompt for elevation: Enabled ✔
- Only elevate executables that are signed and validated: Enabled ✔
- Only elevate UIAccess applications that are installed in secure locations: Enabled ✔
- Run all administrators in Admin Approval Mode: Enabled ✔
- Switch to the secure desktop when prompting for elevation: Enabled ✔

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

#### Public Profile ✔
- Firewall state: On ✔
- Inbound connections: Block ✔
- Outbound connections: Allow ✔


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

#### Network --> Network Connections --> Windows Defender Firewall (Domain Profile and Standard Profile) ✔
- Allow inbound file and printer sharing exception: Disabled ✔
- Allow inbound UPnP framework exceptions: Disabled ✔
- Allow logging: log dropped packets, log successful connections ✔
- Prohibit unicast responses to multicast or broadcast requests: Enabled ✔
- Protect all network connections: Enabled ✔

#### System --> Remote Assistance ✔
- Allow only Windows Vista or later connections: Enabled ✔
- Turn on session logging: Enabled ✔


### Windows Components

#### Remote Desktop Services --> Remote Desktop Session Host --> Security ✔
- Require use of specific security layer for remote (RDP) connections: SSL ✔
- Set client connection encryption level: Enabled, High Level ✔
- Always prompt for password upon connection: Enabled ✔
- Require secure RPC communication: Enabled ✔

#### Autoplay Policies ✔
- Turn off Autoplay: Enabled ✔

#### Windows Update 
- Configure Automatic Updates: Enabled, auto download and schedule install ✔
- Allow Automatic Updates immediate installation: Enabled ✔
- Automatic Updates detection frequency: 22 hours ✔

#### Credential User Interface ✔
- Do not display the password reveal button: Enabled ✔

#### Event Log Service --> Setup ✔
- Turn on Logging: Enabled ✔

#### Microsoft Defender Antivirus ✔
- Allow antimalware service to startup with normal priority: Enabled ✔
- Turn off Microsoft Defender Antivirus: Disabled ✔
- Configure detection for potentially unwanted applications: Enabled ✔

##### Microsoft Defender Exploit Guard ✔
- Network Protection --> Prevent users and apps from accessing dangerous websites: Enabled ✔

##### Real Time Protection 
- Turn off real-time protection: Disabled 
- Turn on behavior monitoring: Enabled 
- Scan all downloaded files and attachments: Enabled 
- Monitor file and program activity on your computer: Enabled 
- Turn on process scanning whenever real-time protection is enabled: Enabled 
- Turn on script scanning: Enabled 
- Configure monitoring for incoming and outgoing file and progam activity: Not configured (inbound/outbound) 

###### Scan 
- Check for the latest virus and spyware security intelligence before running a scheduled scan: Enabled 
- Scan archive files: Enabled 
- Scan removable drives: Enabled 
- Scan packed executables: Enabled 
- Scan network files: Enabled 
- Specify the interval to run quick scans per day: Enabled (12) 

##### Security Intelligence Updates 
- Turn on scan after security intelligence update: Enabled 
- Allow real-time security intelligence updates based on reports to Microsoft MAPS: Enabled 
- Check for the latest virus and spyware security intelligence on startup: Enabled 


#### Security Center 
- Turn on Security Center (Domain PC's only) 


#### Windows Defender SmartScreen

##### (Win11 ONLY) Enhanced Phishing Protection
- Notify Malicious: Enabled
- Notify Password Reuse: Enabled
- Notify Unsafe App: Enabled
- Service Enabled: Enabled

##### Explorer ✔
- Configure Windows Defender SmartScreen: Enabled (Warn and prevent bypass) ✔

##### Microsoft Edge✔
- Configure Windows Defender SmartScreen: Enabled ✔
- Prevent bypassing Windows Defender SmartScreen prompts for sites: Enabled ✔


## User Configuration (Configure User Configuration Settings?)

### Shared Folders 
- Allow shared folder to be published: Disabled 

### Windows Components --> Network Sharing 
- Prevent users from sharing files within their profile 


# Services
- Windows Defender Antivirus Network Inspection Service (WdNisSvc): Automatic, Start
- Windows Defender Antivirus Service (WinDefend): Automatic, Start
- Microsoft Defender Core Service (MDCoreSvc): Automatic, Start
- Print Spooler (Spooler): Disabled, Stop
- Security Accounts Manager (SamSs): Automatic, Start
- Security Center (wscsvc): Automatic, Start
- Software Protection (sppsvc): Automatic, Start
- Windows Defender Firewall (mpssvc): Automatic, Start
- Windows Error Reporting Service (WerSvc): Automatic, Start
- Windows Event Log (EventLog): Automatic, Start
- Windows Security Service (SecurityHealthService): Automatic, Start
- Windows Update (wuauserv): Automatic, Start
- World Wide Web Publishing service: Disabled, stop

# Settings
- Remote Desktop --> Require computers to use Network Level Authenticaiton to connect: Enabled

# (Enable or Disable RDP/Remote Assistance?)

## Enable RDP/Remote Assistance

### Group Policy --> Computer Configuration --> Administrative Templates

- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound Remote Desktop exceptions: Enabled
- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound remote administration exceptions: Enabled

- Remote Desktop Services --> Remote Desktop Session Host --> Connections --> Allow users to connect remotely by using Remote Desktop Services: Enabled

- Remote Desktop Services --> Remote Desktop Session Host --> Security --> Always prompt for password upon connection: Enabled
- Remote Desktop Services --> Remote Desktop Session Host --> Security --> Require user authentication for remote connections by using Network Level Authentication: Enabled

- Remote Desktop Services --> Remote Desktop Session Host --> Session Time Limits --> End session when time limits are reached: Enabled

- Windows Remote Management (WinRM) --> WinRM Service --> Allow unencrypted traffic: Disabled

- Windows Remote Shell --> Allow Remote Shell Access: Enabled

### Group Policy --> System --> Remote Assistance
- Configure Offer Remote Assistance: Enabled, allow helpers to remotely control
- Configure Solicited Remote Assistance: Enabled, allow helpers to remotely control

### Settings
- Remote Desktop --> Enable Remote Desktop: Toggle ON
- System Properties --> Allow Remote Assistance connections to this computer: CHECK
- System Properties --> Allow remote connections to this computer: SELECT

### Services
- Remote Desktop Configuration (SessionEnv): Automatic, Start
- Remote Desktop Services (TermService): Automatic, Start
- Remote Desktop Services UserMode Port Redirector (UmRdpService): Automatic, Start
- Windows Remote Management (WinRM): Automatic, Start

## Disable RDP/Remote Assistance

### Group Policy --> Computer Configuration --> Administrative Templates

- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound Remote Desktop exceptions: Disabled
- Network --> Network Connections --> Windows Defender Firewall --> Domain Profile/Standard Profile --> Allow inbound remote administration exceptions: Disabled

- Remote Desktop Services --> Remote Desktop Session Host --> Connections --> Allow users to connect remotely by using Remote Desktop Services: Disabled

- Windows Remote Shell --> Allow Remote Shell Access: Disabled

### Group Policy --> System --> Remote Assistance
- Configure Offer Remote Assistance: Disabled
- Configure Solicited Remote Assistance: Disabled

### Settings
- Remote Desktop --> Enable Remote Desktop: Toggle OFF
- System Properties --> Allow Remote Assistance connections to this computer: UNCHECK
- System Properties --> Don't Allow remote connections to this computer: SELECT

### Services
- Remote Desktop Configuration (SessionEnv): Disabled, Stop
- Remote Desktop Services (TermService): Disabled, Stop
- Remote Desktop Services UserMode Port Redirector (UmRdpService): Disabled, Stop
- Remote Registry (RemoteRegistry): Disabled, Stop
- Windows Remote Management (WinRM): Disabled, Stop

# (Enable or Disable FTP?)

## Enable FTP

## Disable FTP