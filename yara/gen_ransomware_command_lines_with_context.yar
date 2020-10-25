rule ransomware_command_lines {
    condition:
        Name contains "WMIC.exe"
        and CommandLine contains "delete justatest"
        and ParentPriority >= 8
        and (
            ParentCommandLine contains "cmd"
            or ParentCommandLine contains "powershell"
        )
}
