private rule RaccineMemoryScan
{
    condition:
        MemoryScan == 1
}

rule env_vars_test_memscan_justatest 
{
    strings:
        $envvar1 = "NUMBER_OF_PROCESSORS" wide ascii
        $envvar2 = "LOGONSERVER" wide ascii
        $envvar3 = "SESSIONNAME" wide ascii
        $ifeo = "Image File Execution Options" wide ascii
        $s1 = "justafoo" wide ascii
    condition:
        RaccineMemoryScan
        and Name contains "WMIC.exe"
        and all of them
}
