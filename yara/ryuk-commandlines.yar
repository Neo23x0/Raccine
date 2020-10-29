rule Ryuk_CmdLines {
    strings:
        /* Sandbox Report https://app.any.run/tasks/d41b5569-f3bd-409e-99b1-fc4c728d21aa/ */
        $a1 = "net.exe"
        $a2 = "stop" fullword
        $a3 = " /y"
        
        $s1 = "audioendpointbuilder" fullword
        $s2 = "samss" fullword

        /* FireEye report https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html */
        $ba1 = "process call create"
        $ba2 = "bitsadmin /transfer"
        $ba3 = "AppData" nocase

        $bx1 = "/transfer vVv"
        $bx2 = "temp\\vVv.exe"
    condition:
        all of ($a*) and 1 of ($s*) 
        or all of ($ba*) 
        or 1 of ($bx*)
}
