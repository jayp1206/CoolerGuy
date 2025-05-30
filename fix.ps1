Write-Host "Starting Defender & Security Center quick repair..." -ForegroundColor Cyan

# Step 1: Recreate Security Center (wscsvc) service if missing
if (-not (Get-Service -Name wscsvc -ErrorAction SilentlyContinue)) {
    Write-Host "wscsvc service missing, recreating..." -ForegroundColor Yellow
    sc.exe create wscsvc binPath= "C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted" DisplayName= "Security Center" start= auto
    $wscsvcReg = "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc"
    if (-not (Test-Path $wscsvcReg)) { New-Item -Path $wscsvcReg -Force | Out-Null }
    Set-ItemProperty -Path $wscsvcReg -Name "Type" -Value 20
    Set-ItemProperty -Path $wscsvcReg -Name "Start" -Value 2
    Set-ItemProperty -Path $wscsvcReg -Name "ErrorControl" -Value 1
    Set-ItemProperty -Path $wscsvcReg -Name "ImagePath" -Value "C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted"
    Set-ItemProperty -Path $wscsvcReg -Name "DisplayName" -Value "Security Center"
    Set-ItemProperty -Path $wscsvcReg -Name "ObjectName" -Value "NT AUTHORITY\LocalService"
} else {
    Write-Host "wscsvc service exists." -ForegroundColor Green
}

# Step 2: Remove Defender disable policies from registry
Write-Host "Removing Defender disable policies..." -ForegroundColor Cyan
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Recurse -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -ErrorAction SilentlyContinue

# Step 3: Fix Defender service registry keys
Write-Host "Fixing WinDefend service registry..." -ForegroundColor Cyan
$winDefReg = "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend"
Set-ItemProperty -Path $winDefReg -Name "Start" -Value 2
Set-ItemProperty -Path $winDefReg -Name "ErrorControl" -Value 1
Set-ItemProperty -Path $winDefReg -Name "Type" -Value 32
Set-ItemProperty -Path $winDefReg -Name "ImagePath" -Value "svchost.exe -k secsvcs -p"
Set-ItemProperty -Path $winDefReg -Name "DisplayName" -Value "Windows Defender Antivirus Service"

# Step 4: Set related services to automatic start
Write-Host "Configuring related services to start automatically..." -ForegroundColor Cyan
$services = @("wscsvc", "WinDefend", "MpsSvc", "BFE", "SecurityHealthService")
foreach ($svc in $services) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Write-Host "Setting $svc to automatic..."
        sc.exe config $svc start= auto
    } else {
        Write-Host "Service $svc not found, skipping..."
    }
}

# Step 5: Start essential services
Write-Host "Starting essential services..." -ForegroundColor Cyan
$startServices = @("bfe", "mpssvc", "wscsvc", "WinDefend", "SecurityHealthService")
foreach ($svc in $startServices) {
    try {
        Start-Service -Name $svc -ErrorAction Stop
        Write-Host "$svc started successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to start $svc: $_" -ForegroundColor Red
    }
}

# Step 6: Run Defender restore defaults if possible
Write-Host "Restoring Defender defaults if possible..." -ForegroundColor Cyan
$mpCmdPath = "$env:ProgramData\Microsoft\Windows Defender\Platform"
if (Test-Path $mpCmdPath) {
    $latestVersion = Get-ChildItem $mpCmdPath | Sort-Object Name -Descending | Select-Object -First 1
    $mpCmdRun = Join-Path $latestVersion.FullName "MpCmdRun.exe"
    if (Test-Path $mpCmdRun) {
        & $mpCmdRun -RestoreDefaults
        Write-Host "Defender defaults restored." -ForegroundColor Green
    } else {
        Write-Host "MpCmdRun.exe not found." -ForegroundColor Yellow
    }
} else {
    Write-Host "Defender platform folder not found." -ForegroundColor Yellow
}

Write-Host "Quick repair complete. Consider running SFC and DISM later if issues persist." -ForegroundColor Cyan
