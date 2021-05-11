rule SUSP_PowerShell_Loader_Generic {
   meta:
      description = "Detects different kinds of PowerShell loaders"
      author = "Florian Roth"
      date = "2020-12-10"
      modified = "2021-05-11"
      score = 60
      reference = "https://app.any.run/tasks/93fa402c-c6d7-4bc6-bf88-1ec954ae7f51/"
      reference2 = "https://app.any.run/tasks/d9d249db-f583-46e5-b774-511f28370aad/"
   strings:
      /* catch the ones that are easy to catch */
      $s1 = "powershell" ascii nocase
      $s2 = "-w hidden" ascii nocase
      $s3 = " -e" nocase
      $s4 = " -command " ascii
      
      $enc01 = " IABz"
      $enc02 = " IABT"
      $enc03 = " cwBl"
      $enc04 = " cwBF"
      $enc05 = " UwBl"
      $enc06 = " UwBF"
      $enc07 = " SUVYI"
      $enc08 = " aWV4I"
      $enc09 = " SQBFAFgA"
      $enc10 = " aQBlAHgA"
      $enc11 = "SW52b2tlLVdlYlJlcXVlc3Q"

      /* catch the ones that try to hide */
      $p1 = "powershell" nocase fullword 

      /* filter valid casing */
      $pf1 = "powershell" fullword
      $pf2 = "Powershell" fullword 
      $pf3 = "PowerShell" fullword
      $pf4 = "POWERSHELL" fullword
      $pf5 = "powerShell" fullword
   condition:
      /* simple */
      ( 3 of ($s*) and 1 of ($e*) ) or
      /* casing anomalies */
      $p1 and not 1 of ($pf*)
}
