#
# Test Cases
# PoC
# Florian Roth

$RaccineInstallerFolder = ".\Raccine"

# Functions
function Uninstall-Raccine {
    $Command = "$($RaccineInstallerFolder)\install-raccine.bat UNINSTALL"
    Invoke-Expression $Command
    Start-Sleep -s 1
}
function Install-Raccine-LogOnly {
    $Command = "$($RaccineInstallerFolder)\install-raccine.bat FULL_SIMU"
    Invoke-Expression $Command
    Start-Sleep -s 1
}
function Is-Running($ProcessName) {
    $process = Get-Process $ProcessName -ErrorAction SilentlyContinue
    if ($process) {
        return $False
    }
    return $True
}

# Test 1 - Log Only : Vssadmin Delete Shadows
Uninstall-Raccine
Install-Raccine-LogOnly
Start-Sleep -s 1
Invoke-Expression "vssadmin delete shadows"
# Check correct handling
# Evenlog
$Result = Get-EventLog -LogName Application -Message *Raccine* -Newest 1
If ( $Result.Message -NotMatch "deleteX shadows" ) { 
    Write-Host "Eventlog entry of detection not found"
    exit 1 
}
# Killed process / not hanging process
If ( Is-Running("vssadmin") ) { 
    Write-Host "Process is still running"
    exit 1
}
Start-Sleep -s 1

# Uninstall Raccine
Uninstall-Raccine
