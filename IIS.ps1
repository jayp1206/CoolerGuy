$MachineDir = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"
$UserRegDir = "$env:windir\system32\GroupPolicy\User\registry.pol"
$RegPath = "System\CurrentControlSet\Services\HTTP\Parameters"
#V-268325
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableRequestSmuggling" -Data 1 -Type "DWord"
#V-241788
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisableServerHeader" -Data 2 -Type "DWord"
#V-218821
$RegPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisabledByDefault" -Data 0 -Type "DWord"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 1 -Type "DWord"
$RegPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisabledByDefault" -Data 1 -Type "DWord"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"
$RegPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisabledByDefault" -Data 1 -Type "DWord"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"
$RegPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 3.0\Server"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "DisabledByDefault" -Data 1 -Type "DWord"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "Enabled" -Data 0 -Type "DWord"
#V-218819
$RegPath = "SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "URIEnableCache" -Data 1 -Type "DWord"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "UriMaxUriBytes" -Data 262144 -Type "DWord"
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName "UriScavengerPeriod" -Data 120 -Type "DWord"
#V-241789
Import-Module WebAdministration
Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"
#V-218810
Set-WebConfigurationProperty -Filter "system.webServer/httpErrors" -Name "errorMode" -Value "DetailedLocalOnly"
#V-218825
$siteName = $(Write-Host "Enter the IIS Site Name: " -ForegroundColor Magenta -NoNewLine; Read-Host)
$sitePath = "IIS:\Sites\$siteName"
Clear-WebConfiguration -Filter /system.web/authorization -PSPath $sitePath
Clear-WebConfiguration -Filter /system.webServer/security/authorization -PSPath $sitePath
Add-WebConfiguration -PSPath $sitePath -Filter "system.web/authorization" -Value @{accessType="Allow";users="*"}
Add-WebConfiguration -PSPath $sitePath -Filter "system.web/authorization" -Value @{accessType="Deny";users="?"}
#V-218807
Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.web/machineKey" -name "validation" -value "HMACSHA256"
Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.web/machineKey" -name "decryption" -value "Auto"
#V-218805
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "cookieless" -value "UseCookies"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "timeout" -value "00:15:00"
#V-218804
Set-WebConfigurationProperty -Filter "system.web/sessionState" -Name "cookieless" -Value "UseCookies" -PSPath "IIS:\"
#V-218798
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/staticContent" -name "." -AtElement @{fileExtension=".exe"}
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/staticContent" -name "." -AtElement @{fileExtension=".dll"}
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/staticContent" -name "." -AtElement @{fileExtension=".com"}
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/staticContent" -name "." -AtElement @{fileExtension=".bat"}
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/staticContent" -name "." -AtElement @{fileExtension=".csh"}
#V-218786
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name logEventDestination -Value "Both"
#V-218789
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logFormat" -value "W3C"
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='Authorization'; sourceName='Authorization'; sourceType='RequestHeader'}
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='Content-Type'; sourceName='Content-Type'; sourceType='ResponseHeader'}
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/selectFields" -name "." -value @("Date","Time","ClientIP","UserAgent","UserName","Referrer","Method","UriStem","UriQuery","HttpStatus","Win32Status","TimeTaken")
#V-218788
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name logFile.logFormat -Value "W3C"
$logPath = "IIS:\Sites\Default Web Site"
Add-WebConfigurationProperty -pspath $logPath -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName="Connection"; sourceName="Connection"; sourceType="RequestHeader"}
Add-WebConfigurationProperty -pspath $logPath -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName="Warning"; sourceName="Warning"; sourceType="RequestHeader"}
#V-218827
$sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
$siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"="yourdomain.com"}
$hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"
Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "enabled" -AttributeValue $true
Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "max-age" -AttributeValue 31536000
Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "includeSubDomains" -AttributeValue $true
Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "redirectHttpToHttps" -AttributeValue $true
#V-218808
Set-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value "False" -PSPath "IIS:\"
#V-218786
$serverName = (Get-IISServerManager).Sites.Name
Set-ItemProperty "IIS:\Sites$serverName" -Name logFile.logEventDestination -Value "Both"
#V-218799
Uninstall-WindowsFeature Web-DAV-Publishing
#V-218826
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/limits" -name "maxConnections" -value X
#V-218824
Set-WebConfigurationProperty -Filter system.webServer/security/isapiCgiRestriction -Name notListedIsapisAllowed -Value False -PSPath IIS:\ 
Set-WebConfigurationProperty -Filter system.webServer/security/isapiCgiRestriction -Name notListedCgisAllowed -Value False -PSPath IIS:\
#V-218820
Set-WebConfigurationProperty "/system.webServer/asp/session" -Name keepSessionIdSecure -Value true -PSPath 'IIS:\'
gpupdate.exe /force
Write-Host "Successfully Configured IIS!" -ForegroundColor Green