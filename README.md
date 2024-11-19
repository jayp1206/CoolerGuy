# Vulnerabilities

## Password Policy
- Enforce password history: 3 remembered
- Max password age: 30 days
- Min password age: 1 day
- Minimum password length: 10 characters
- Minimum password length audit: 10 characters
- Password must meet complexity requirements: Enabled
- Relax minimum password length limits: Disabled
- Store passwords using reversible encryption: Disabled

## Account Lockout Policy
- Account lockout duration: 30 mins
- Account lockout threshold: 5
- Allow Administrator account lockout: Enabled
- Reset account lockout counter after: 30 mins

## Local Audit Policy
- ALL: Success & Failure

## Security Options

### Accounts
- Administrator account atatus: Disabled
- Block Microsoft accounts: Enabled
- Guest account status: Disabled
- Limit local use of blank passwords to console logon only: Enabled

### Audit
- Audit the access of global system objects: Enabled
- Audit the use of Backup and Restore privileges: Enabled
- Shut down system immediately if unable to log security audits: Enabled

### Devices
- Prevent users from installing printer drivers: Enabled
- Restrict CD-ROM access to locally logged-on user only: Enabled
- Restrict floppy access to locally logged-on user only: Enabled

### Domain Controller
- Allow vulnerable Netlogon secure channel connections: Disabled

### Domain Member
- Digitally encrypt or sign secure channel data (always): Enabled
- Digitally encrypt secure channel data (when possible): Enabled
- Digitally sign secure channel data (when possible): Enabled
- Maximum machine account password age: 30 days
- Require strong (Windows 2000 or later) session key: Enabled

### Interactive Logon
- Display user information when the session is locked: Disabled
- Do not require CTRL + ALT + DEL: Disabled
- Don't display last signed-in: Enabled
- Don't display username at sign-in: Enabled
- Machine account lockout threshold: 5
- Prompt user to change password before expiration: 5 days

### Microsoft Network Client
- Digitally sign communications (always): Enabled
- Digitally sign communications (if server agrees): Enabled
- Send unencrypted passwords to third-party SMB servers: Disabled

### Microsoft Network Server
- Digitally sign communications (always): Enabled
- Digitally sign communications (if client agrees): Enabled
- Disconnect clients when logon hours expire: Enabled

### Network Access
- 