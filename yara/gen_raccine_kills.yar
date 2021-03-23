rule ransomware_command_lines
{
    strings:
        $s1 = "taskkill" nocase ascii
        $s2 = "RaccineSettings.exe" nocase ascii
    condition:
        all of them  
}

