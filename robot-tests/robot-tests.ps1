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

# Test 1 - Block: Vssadmin Delete Shadows
Uninstall-Raccine
Install-Raccine-LogOnly
Start-Sleep -s 1
Invoke-Expression "vssadmin delete shadows"
$Result = Get-EventLog -LogName Application -Message *Raccine* -Newest 1
$Result.Message -Match "delete shadows"
Start-Sleep -s 1
