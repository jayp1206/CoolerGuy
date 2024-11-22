function Set-PasswordPolicies {
    # Enforce password history: 3 days 
    #net accounts /uniquepw:3

    # Max password age: 30 days
    #net accounts /maxpwage:30

    # Min password age: 1 day
    #net accounts /minpwage:1

    # Min password length: 10 chars
    net accounts /minpwlen:10

    # Copy current secpol.cfg file
    secedit /export /cfg c:\secpol.cfg
    
    # Load secpol.cfg into memory
    $content = (Get-Content C:\secpol.cfg)

    # Configure password complexity, reversible encryption, audits, lockout, admin account, guest account
    $content = $content `
        -Replace "PasswordComplexity = 0", "PasswordComplexity = 1" `
        -Replace [regex]::Escape("MACHINE\System\CurrentControlSet\Control\SAM\RelaxMinimumPasswordLengthLimits=4,1"), "MACHINE\System\CurrentControlSet\Control\SAM\RelaxMinimumPasswordLengthLimits=4,0" `
        -Replace "ClearTextPassword = 1", "ClearTextPassword = 0" `
        -Replace "AuditSystemEvents\s*=\s*\d+", "AuditSystemEvents = 3" `
        -Replace "AuditLogonEvents\s*=\s*\d+", "AuditLogonEvents = 3" `
        -Replace "AuditObjectAccess\s*=\s*\d+", "AuditObjectAccess = 3" `
        -Replace "AuditPrivilegeUse\s*=\s*\d+", "AuditPrivilegeUse = 3" `
        -Replace "AuditPolicyChange\s*=\s*\d+", "AuditPolicyChange = 3" `
        -Replace "AuditAccountManage\s*=\s*\d+", "AuditAccountManage = 3" `
        -Replace "AuditProcessTracking\s*=\s*\d+", "AuditProcessTracking = 3" `
        -Replace "AuditDSAccess\s*=\s*\d+", "AuditDSAccess = 3" `
        -Replace "AuditAccountLogon\s*=\s*\d+", "AuditAccountLogon = 3" `
        -Replace "LockoutBadCount\s*=\s*\d+", "LockoutBadCount = 5" `
        -Replace "LockoutDuration\s*=\s*\d+", "LockoutDuration = 30" `
        -Replace "AllowAdministratorLockout = 0", "AllowAdministratorLockout = 1" `
        -Replace "ResetLockoutCount\s*=\s*\d+", "ResetLockoutCount = 30" `
        -Replace "EnableAdminAccount = 1", "EnableAdminAccount = 0" `
        -Replace "EnableGuestAccount = 1", "EnableGuestAccount = 0" `
        -Replace [regex]::Escape("MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,0"), "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1" `
        -Replace [regex]::Escape("MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0"), "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,1" `
        

    # Limit CD Rom access to locally logged on users: Enable
    $allocateCDRomsKey = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms=1,"0"'
    if ($content -contains $allocateCDRomsKey) {
        # Replace the value from 0 to 1 if found
        $content = $content -replace '(MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllocateCDRoms=1,"0")', 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms=1,"1"'
    } else {
        # Add the line if it doesn't exist
        $content += 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms=1,"1"'
    }

    # Limit Floppy access to locally logged on users: Enable
    $allocateFloppiesKey = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies=1,"0"'
    if ($content -contains $allocateFloppiesKey) {
        # Replace the value from 0 to 1 if found
        $content = $content -replace '(MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllocateFloppies=1,"0")', 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies=1,"1"'
    } else {
        # Add the line if it doesn't exist
        $content += 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies=1,"1"'
    }

    # Audit password length: 10 chars
    $passwordLengthAuditKey = 'MACHINE\System\CurrentControlSet\Control\SAM\MinimumPasswordLengthAudit='
    if ($content -contains $passwordLengthAuditKey) {
        # Replace the value from 0 to 1 if found
        $content = $content -replace "(MACHINE\\System\\CurrentControlSet\\Control\\SAM\\MinimumPasswordLengthAudit=4,)\d+", "MACHINE\System\CurrentControlSet\Control\SAM\MinimumPasswordLengthAudit=4,10"
    } else {
        # Add the line if it doesn't exist
        $content += "MACHINE\System\CurrentControlSet\Control\SAM\MinimumPasswordLengthAudit=4,10"
    }

    # Create modified secpol.cfg file
    $content | Out-File C:\modified_secpol.cfg -Force

    # Apply new config and remove temp files
    secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
    Remove-Item C:\secpol.cfg -Force
    gpupdate /force

    Write-Host "Password policies configured successfully" -ForegroundColor Green
}


$passwordpolicy = Read-Host "Configure Password Policies? (y/n) "
if ($passwordpolicy -eq 'y') { 
    Set-PasswordPolicies
} else {
    Write-Host "didn't set password history"
}   