#
# Test Cases
# PoC
# Florian Roth

$RaccineInstallerFolder = ".\Raccine"
$LogFile = "C:\ProgramData\Raccine\Raccine_log.txt"

# Functions
function Uninstall-Raccine {
    $Command = "$($RaccineInstallerFolder)\install-raccine.bat UNINSTALL"
    Invoke-Expression $Command
    Start-Sleep -s 1
}
function Install-Raccine {
    $Command = "$($RaccineInstallerFolder)\install-raccine.bat FULL"
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
        return $True
    }
    return $False
}

# ###########################################################
# Test 1 - Log Only : Vssadmin Delete Shadows
Install-Raccine
Start-Sleep -s 1
Invoke-Expression "vssadmin delete shadows"
Start-Sleep -s 2

# Check correct handling
# Log File
$LogContent = Get-Content $LogFile
$cointainsKeywords = $LogContent | %{$_ -match "vssadmin"}
If ( -Not $cointainsKeywords ) { 
    Write-Host $LogContent
    Write-Host "Log file entry of detection not found"
    exit 1 
}
# Evenlog
$Result = Get-EventLog -LogName Application -Message *Raccine* -Newest 1
If ( $Result.Message -NotMatch "delete shadows" ) { 
    Write-Host $Result.Message
    Write-Host "Eventlog entry of detection not found"
    exit 1 
}
# Killed process / not hanging process
If ( Is-Running("vssadmin") ) { 
    Write-Host "Process is still running"
    exit 1
}
Start-Sleep -s 10

# Cleanup
# Uninstall Raccine
#Uninstall-Raccine
