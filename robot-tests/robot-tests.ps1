#
# Test Cases
# PoC
# Florian Roth

$RaccineInstallerFolder = ".\Raccine"

# Functions
function Uninstall-Raccine {
    $Command = "$($RaccineInstallerFolder)\install-raccine.bat UNINSTALL"
    Invoke-Expression $Command
}
function Install-Raccine-LogOnly {
    $Command = "$($RaccineInstallerFolder)\install-raccine.bat FULL_SIMU"
    Invoke-Expression $Command
}

# Test 1
Uninstall-Raccine
Install-Raccine-LogOnly
