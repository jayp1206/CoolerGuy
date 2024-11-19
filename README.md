# Local Security Policy

### Password Policy
- Enforce password history: 3 remembered
- Max password age: 30 days
- Min password age: 1 day
- Minimum password length: 10 characters
- Minimum password length audit: 10 characters
- Password must meet complexity requirements: Enabled
- Relax minimum password length limits: Disabled
- Store passwords using reversible encryption: Disabled

### Account Lockout Policy
- Account lockout duration: 30 mins
- Account lockout threshold: 5
- Allow Administrator account lockout: Enabled
- Reset account lockout counter after: 30 mins

### Local Audit Policy
- ALL: Success & Failure

### Security Options

#### Accounts
- Administrator account atatus: Disabled
- Block Microsoft accounts: Enabled
- Guest account status: Disabled
- Limit local use of blank passwords to console logon only: Enabled

#### Audit
- Audit the access of global system objects: Enabled
- Audit the use of Backup and Restore privileges: Enabled
- Shut down system immediately if unable to log security audits: Enabled

#### Devices
- Prevent users from installing printer drivers: Enabled
- Restrict CD-ROM access to locally logged-on user only: Enabled
- Restrict floppy access to locally logged-on user only: Enabled

#### Domain Controller
- Allow vulnerable Netlogon secure channel connections: Disabled

#### Domain Member
- Digitally encrypt or sign secure channel data (always): Enabled
- Digitally encrypt secure channel data (when possible): Enabled
- Digitally sign secure channel data (when possible): Enabled
- Maximum machine account password age: 30 days
- Require strong (Windows 2000 or later) session key: Enabled

#### Interactive Logon
- Display user information when the session is locked: Disabled
- Do not require CTRL + ALT + DEL: Disabled
- Don't display last signed-in: Enabled
- Don't display username at sign-in: Enabled
- Machine account lockout threshold: 5
- Prompt user to change password before expiration: 5 days

#### Microsoft Network Client
- Digitally sign communications (always): Enabled
- Digitally sign communications (if server agrees): Enabled
- Send unencrypted passwords to third-party SMB servers: Disabled

#### Microsoft Network Server
- Digitally sign communications (always): Enabled
- Digitally sign communications (if client agrees): Enabled
- Disconnect clients when logon hours expire: Enabled

#### Network Access
- Allow anonymous SID/Name translation: Disabled
- Do not allow anonymous enumeration of SAM accounts: Enabled
- Do not allow anonymous enumeration of SAM accounts and shared: Enabled
- Do not allow storage of passwords and credentials for network authentication: Enabled
- Let Everyone permissions apply to anonymous users: Disabled
- Shared that can be accessed anonymously: Not Defined (remove all)

#### Network Security
- Force logoff when logon hours expire: Enable
- Audit incoming NTLM Traffic: Enable auditing for all accounts

#### Recovery Console
- Allow automatic administrative logon: Disabled
- Allow floppy copy and access to all drives and all folders: Disabled

#### Shutdown
- Allow system to be shutdown without having to log on: Enabled

#### System Cryptography
- Force strong key protection for user keys stored on the computer: User must enter a password each time they use a key
- Use FIPS compliant algorithms for encryption, hashing, and signing: Enabled

#### System Objects
- Require case insensitivity for non-Windows subsystems: Enabled

### User Account Control
- Admin Approval Mode for the Built-in Administrator account: Enabled
- Allow UIAccess applications to prompt for elevation without using the secure desktop
- Behavior of the elevation prompt for administrators in Admin Approval Mode: Prompt for consent on the secure desktop
- Behavior of the elevation prompt for standard users: Prompt for credentials on the secure desktop
- Detect application installations and prompt for elevation: Enabled
- Only elevate executables that are signed and validated: Enabled
- Only elevate UIAccess applications that are installed in secure locations: Enabled
- Run all administrators in Admin Approval Mode: Enabled
- Switch to the secure desktop when prompting for elevation: Enabled


### Windows Defender Firewall with Advanced Security

#### Domain Profile
- Firewall state: On
- Inbound connections: Block
- Outbound connections: Allow

#### Private Profile
- Firewall state: On
- Inbound connections: Block
- Outbound connections: Allow

#### Public Profile
- Firewall state: On
- Inbound connections: Block
- Outbound connections: Allow


### Advanced Audit Policy Configuration
- ALL: Sucess & Failure



# Computer Management

### Shared Folders
- List all shares except ADMIN$, C$, IPC$



# Group Policy

## Computer Configuration

### Administrative Templates

#### Network Connections --> Windows Defender Firewall (Domain Profile and Standard Profile)
- Allow ICMP Exceptions: Disabled
- Allow inbound file and printer sharing exception: Disabled
- Allow inbound UPnP framework exceptions: Disabled
- Allow local program exceptions: Disabled
- Allow logging: Enabled
- Define inbound program exceptions: Disabled
- Do not allow exceptions: Enabled
- Prohibit unicast responses to multicast or broadcast requests: Enabled
- Protect all network connections: Enabled

#### System --> Remote Assistance
- Allow only Windows Vista or later connections: Enabled
- Turn on session logging: Enabled'


### Windows Components

#### Autoplay Policies
- Turn off Autoplay: Enabled

#### Credential User Interface
- Do not display the password reveal button: Enabled

#### Event Log Service --> Setup
- Turn on Logging: Enabled

#### Event Logging
- Enable protected event logging: Enabled

#### Microsoft Defender Antivirus
- Allow antimalware service to startup with normal priority: Enabled
- Turn off Microsoft Defender Antivirus: Disabled
- Configure detection for potentially unwanted applications: Enabled
- Allow antimalware service to remain running always: Enabled

##### Real Time Protection
- Turn off real-time protection: Disabled
- Turn on behavior monitoring: Enabled
- Scan all downloaded files and attachments: Enabled
- Monitor file and program activity on your computer: Enabled
- Turn on process scanning whenever real-time protection is enabled: Enabled
- Turn on script scanning: Enabled
- Configure monitoring for incoming and outgoing file and progam activity: Not configured

##### Scan
- Check for the latest virus and spyware 