rule env_vars_test {
    condition:
        raccine_Name contains "WMIC.exe"
        and raccine_CommandLine contains "delete justatest"
        and raccine_parent_Priority >= 8
        and (
            raccine_parent_CommandLine contains "cmd"
            or raccine_parent_CommandLine contains "powershell"
        )
}
