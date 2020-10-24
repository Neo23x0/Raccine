rule ransomware_command_lines
{
    strings:
        $e_vssadmin = "vssadmin" fullword nocase
        $e_wmic     = "wmic" fullword nocase
        $e_wbadmin  = "wbadmin" fullword nocase
        $e_bcdedit  = "bcdedit" fullword nocase
        $e_powershell  = "powershell" fullword nocase
        $e_diskshadow  = "diskshadow" fullword nocase

        $p_delete       = "delete" fullword nocase
        $p_shadows      = "shadows" fullword nocase
        $p_shadowstorage= "shadowstorage" fullword nocase
        $p_resize       = "resize" fullword nocase
        $p_shadowcopy   = "shadowcopy" fullword nocase
        $p_catalog      = "catalog" fullword nocase
        $p_quiet        = "-quiet" nocase
        $p_quiet2       = "/quiet" nocase
        $p_recoveryenabled   = "recoveryenabled" fullword nocase
        $p_ignoreallfailures = "ignoreallfailures" fullword nocase
        $p_win32_shadowcopy = "win32_shadowcopy" fullword nocase
        $p_encodedCommand = " -e" 
    
        
    condition:
            (
           ( $e_vssadmin and $p_delete and $p_shadows)
        or ( $e_vssadmin and $p_delete and $p_shadowstorage)
        or ( $e_vssadmin and $p_resize and $p_shadowstorage)
        or ( $e_wmic and $p_delete and $p_shadowcopy)
        or ( $e_wbadmin and $p_delete and $p_catalog and 1 of ($p_quiet*))
        or ( $e_bcdedit and $p_ignoreallfailures)
        or ( $e_bcdedit and $p_recoveryenabled)
        or ( $e_diskshadow and $p_delete and $p_shadows)
        or ( $e_powershell and $p_win32_shadowcopy)
        or ( $e_powershell and $p_encodedCommand)
            )
            and raccine_Name contains "WMIC.exe"
            and raccine_CommandLine contains "delete shadowcopy"
            and raccine_parent_Priority >= 8
            and (
                raccine_parent_CommandLine contains "cmd"
                or raccine_parent_CommandLine contains "powershell"
                )
}
