# Replace with the path to your script and the thumbprint
$ScriptPath = "scriptv2.ps1"
$Thumbprint = "cd82f801248cff6b0d1a5dc47e7b0205f7a5dd3d"

# Get the certificate from the certificate store
$Cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Thumbprint }

# Sign the script
Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $Cert