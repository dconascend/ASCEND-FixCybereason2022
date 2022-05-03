# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-NoProfile -ExecutionPolicy Bypass -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit;
    }
}
 
function Test-InstalledSoftware {
    param (
        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationName
    )
    
    $Applications = @()
    $Applications += (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall")
    $Applications += (Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
    foreach ($app in $Applications) {
        if ($app.GetValue('DisplayName') -like "*$($ApplicationName)*") {
            return $true
        }
    }
    return $false
}

function Test-RegistryValue {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try {
        $RegistryKey = Get-ItemProperty -Path "$($Path)" -ErrorAction Stop | Select-Object -ExpandProperty "$($Value)" 
        if ($RegistryKey) {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Test-RegistryKey {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path
    )

    try {
        $RegistryKey = Get-ItemProperty -Path "$($Path)" -ErrorAction Stop | Out-Null
        if ($RegistryKey) {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Get-InstalledSoftwareVersion {
    param (
        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationName
    )

    $Applications = @()
    $Applications += (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall")
    $Applications += (Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
    foreach ($app in $Applications) {
        if ($app.GetValue('DisplayName') -like "*$($ApplicationName)*") {
            return $($app.GetValue('DisplayVersion'))
        }
    }
    return $false
}

function Get-RegistryValue {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Name
    
    )

    try {
        $RegistryKeyValue = Get-ItemProperty -Path "$($Path)" -Name "$($Name)" | Select-Object -ExpandProperty "$($Name)" -ErrorAction Stop
        if ($RegistryKeyValue) {
            return $($RegistryKeyValue)
        }
        return $false
    }
    catch {
        return $false
    }
    
}

function Set-RegistryValue {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Name, 

        [parameter(Mandatory = $false)]
        [string]$Value, 

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Type
    
    )

    try {
        Set-ItemProperty -Path $($Path) -Name "$($Name)" -Value "$($Value)" -Type "$($Type)" -Force -Confirm:$false -ErrorAction Stop -Verbose
    }
    catch {
        return $false
    }
    
}
function Remove-RegistryValue {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Name
    
    )

    try {
        Remove-ItemProperty -Path $($Path) -Name "$($Name)" -Force -Confirm:$false -ErrorAction Stop -Verbose 
    }
    catch {
        return $false
    }
    
}

$SoftwareName = "Cybereason"
$TargetCybereasonVersions = @(
    '21.2.169.0',
    '21.1.342.0',
    '20.1.423.0',
    '20.2.341.0',
    '20.2.303.0'
)

if ((Test-InstalledSoftware "$SoftwareName")) {

    $SensorVersion = Get-InstalledSoftwareVersion "Cybereason Sensor"
    $ActiveProbeVersion = Get-InstalledSoftwareVersion "Cybereason ActiveProbe"

    Write-Output "Cybereason Sensor Version: $SensorVersion"
    Write-Output "Cybereason ActiveProbe Version: $ActiveProbeVersion"

    #Check that targeted version of Cybereason is installed.
    $VersionCheckOverride = $true
    if (($SensorVersion -in $TargetCybereasonVersions) -or ($ActiveProbeVersion -in $TargetCybereasonVersions) -or ($VersionCheckOverride)) {
        
        if ($SensorVersion -eq $ActiveProbeVersion) {
            #exit with error code 1, so remediate code runs.
            Write-Output "INFO: Targeted version of Cybereason detected. Proceeding with remediation code."
            #Exit 1
            $remediationRequired = $true
        }
        else {
            #Version mismatch. exit with error code 0, so remediation code does not run.
            Write-Output "ERROR: Cybereason Sensor and Cybereason Active Probe versions do not match."
            #Exit 0
            $remediationRequired = $false
        }
    }
    else {
        #Targeted version of Cybereason not detected, not running remediation code.
        Write-Output "ERROR: Targeted version of Cybereason not detected. Not Proceeding with remediation code."
        #Exit 0 
        $remediationRequired = $false
    }
}
else {
    #If software is not detected as installed, Exit 0 so the remediation code does not run. 
    Write-Output "$SoftwareName not installed."
    #Exit 0
    $remediationRequired = $false
}

if ($remediationRequired) {
    $RegPaths = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Cybereason\ActiveProbe'
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Cybereason\ActiveProbe'
    )

    foreach ($RegPath in $RegPaths) {

        if (Test-RegistryKey -Path $RegPath) {
            Write-Output "RegPath: $RegPath exists"
        }
        else {
            Write-Output "RegPath: $RegPath does not exists"
        }

        #Blank out reg keys
        if (Test-RegistryValue -Path $RegPath -Value 'server.caName') {
            Write-Output "server.caName exists"
            $RegValueServerCaName = Get-RegistryValue -Path $RegPath -Name 'server.caName'
            if (-not ([String]::IsNullOrEmpty(($RegValueServerCaName)))) {
                Write-Output "Blanking out server.caName"
                Set-RegistryValue -Path $RegPath -Name 'server.caName' -Value '' -Type "String"
            }
        }

        if (Test-RegistryValue -Path $RegPath -Value 'server.clientCertificateSeed') {
            Write-Output "server.clientCertificateSeed exists"
            $RegValueServerClientCertificateSeed = Get-RegistryValue -Path $RegPath -Name 'server.clientCertificateSeed'
            if (-not ([String]::IsNullOrEmpty(($RegValueServerClientCertificateSeed)))) {
                Write-Output "Blanking out server.clientCertificateSeed"
                Set-RegistryValue -Path $RegPath -Name 'server.clientCertificateSeed' -Value '' -Type "String"
            }
        }

        #Remove 
        if (Test-RegistryValue -Path $RegPath -Value 'server.client_cert_issuer') {
            Write-Output "Removing server.client_cert_issuer"
            Remove-RegistryValue -Path $RegPath -Name 'server.client_cert_issuer'
        }

        if (Test-RegistryValue -Path $RegPath -Value 'server.client_cert_sn') {
            Write-Output "Removing server.client_cert_sn"
            Remove-RegistryValue -Path $RegPath -Name 'server.client_cert_sn'
        }

    }

    #Stop Cybereason processes 
    $CybereasonProcesses = @(
        'ActiveConsole'
        'minionhost'
    )

    if (Get-Process $CybereasonProcesses) {
        Start-Sleep -s 10
        Get-Process $CybereasonProcesses | Stop-Process -Force -Confirm:$false -Verbose 
        Start-Sleep -s 120
        Get-Process $CybereasonProcesses | Stop-Process -Force -Confirm:$false -Verbose
        Start-Sleep -s 120

        #Get log file.
        #Get-Content -Path "C:\ProgramData\apv2\Logs\CybereasonActiveProbe.log" -Tail 20
    }
}else{
    Write-Output "Remediation not required. Not proceeding."
}
Write-Output "DONE!"

Write-Output "Exiting in 30 seconds"
Start-Sleep -s 30
Exit


