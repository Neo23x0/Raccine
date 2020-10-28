rule Ryuk_CmdLines {
    strings:
        $a1 = "net.exe"
        $a2 = "stop" fullword
        $a3 = " /y"
        
        $s1 = "audioendpointbuilder" fullword
        $s2 = "samss" fullword
    condition:
        all of ($a*) and 1 of ($s*)
}
