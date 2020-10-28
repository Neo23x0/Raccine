rule env_vars_test {
    condition:
        Name contains "WMIC.exe"
        and CommandLine contains "delete justatest"
}


