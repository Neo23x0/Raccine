#
# Test Cases
# PoC
# Florian Roth

$RaccineInstallerFolder = ".\Raccine"
$LogFile = "C:\ProgramData\Raccine\Raccine_log.txt"

# Functions
function Uninstall-Raccine {
    Invoke-Expression "$($RaccineInstallerFolder)\install-raccine.bat UNINSTALL"
    Start-Sleep -s 10
}
function Install-Raccine {
    Invoke-Expression "$($RaccineInstallerFolder)\install-raccine.bat FULL"
    Start-Sleep -s 10
}
function Install-Raccine-LogOnly {
    Invoke-Expression "$($RaccineInstallerFolder)\install-raccine.bat FULL_SIMU"
    Start-Sleep -s 10
}
function Is-Running($ProcessName) {
    $process = Get-Process $ProcessName -ErrorAction SilentlyContinue
    if ($process) {
        return $True
    }
    return $False
}

# ###########################################################
# Preperations

# ###########################################################
# Test 1 : Vssadmin Delete Shadows
Install-Raccine-LogOnly
Invoke-Expression "& 'C:\Program Files\Raccine\Raccine.exe' vssadmin.exe delete shadows" 
Start-Sleep -s 10

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

# Cleanup
# Uninstall Raccine
#Uninstall-Raccine
