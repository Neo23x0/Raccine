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

$MalCmds = @(
    "vssadmin.exe delete shadows", 
    "powershell.exe -e JABbaTheHutt", 
    # "WMIC.exe delete justatest"  # doesn't create a YARA match in Github workflow
    "bcdedit.exe recoveryenabled"
)

$GoodCmds = @(
    "vssadmin.exe", 
    "powershell.exe -EncodedCommand AllIsGood" 
)

# ########################################################
# Malicious Command Tests
# 

Foreach ($Cmd in $MalCmds) {

    Write-Host " ########################################################## "
    Write-Host " MALICIOUS Command"
    Write-Host " $($Cmd)"
    Write-Host " ########################################################## "

    # Save some substrings
    $Img = $Cmd.Split(" ")[0]
    $ImgBase = $Img.Split(".")[0]
    Write-Host "Image File: $($Img)"

    # Install Raccine
    Install-Raccine-LogOnly

    # Run malicious command
    Invoke-Expression "& 'C:\Program Files\Raccine\Raccine.exe' $($Cmd)" 
    Start-Sleep -s 10

    # Check correct handling
    # Log File
    $LogContent = Get-Content $LogFile
    $cointainsKeywords = $LogContent | %{$_ -match $Cmd}
    If ( -Not $cointainsKeywords ) { 
        Write-Host "Log file content: $($LogContent)"
        Write-Host "Error: Log file entry of detection not found (Command: $($Cmd)"
        exit 1 
    }

    # Evenlog
    $Result = Get-EventLog -LogName Application -Message *Raccine* -Newest 1
    If ( $Result.Message -NotMatch $Cmd ) { 
        Write-Host $Result.Message
        Write-Host "Error: Eventlog entry of detection not found"
        exit 1 
    }

    # Killed process / not hanging process
    if ( $ImgBase -NotMatch 'powershell') {
        #Write-Host "Testing if process $($ImgBase) is still running ..."
        If ( Is-Running($ImgBase) ) { 
            Write-Host "Error: Malicious process is still running (probably suspended)"
            exit 1
        }
    }

    # End Message
    Write-Host "All checks completed successfully in test case: '$($Cmd)'"
    Start-Sleep -s 5

    # Cleanup
    Uninstall-Raccine
}


# ########################################################
# Good Command Tests
# 

Foreach ($Cmd in $GoodCmds) {

    Write-Host " ########################################################## "
    Write-Host " GOOD Command"
    Write-Host " $($Cmd)"
    Write-Host " ########################################################## "

    # Save some substrings
    $Img = $Cmd.Split(" ")[0]
    $ImgBase = $Img.Split(".")[0]
    Write-Host "Image File: $($Img)"

    # Install Raccine
    Install-Raccine-LogOnly

    # Run malicious command
    Invoke-Expression "& 'C:\Program Files\Raccine\Raccine.exe' $($Cmd)" 
    Start-Sleep -s 10

    # Check correct handling
    # Log File
    $LogContent = Get-Content $LogFile
    $cointainsKeywords = $LogContent | %{$_ -Match $Cmd}
    If ( $cointainsKeywords ) { 
        Write-Host $LogContent
        Write-Host "Error: Log file entry of detection found"
        exit 1 
    }

    # Evenlog
    $Result = Get-EventLog -LogName Application -Message *Raccine* -Newest 1
    If ( $Result.Message -Match $Cmd ) { 
        Write-Host $Result.Message
        Write-Host "Error: Eventlog entry of detection found"
        exit 1 
    }

    # End Message
    Write-Host "All good command checks completed successfully in test case: '$($Cmd)'"
    Start-Sleep -s 5

    # Cleanup
    Uninstall-Raccine
}



