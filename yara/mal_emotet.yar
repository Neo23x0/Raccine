rule MAL_Emotet_MalDocs {
   meta:
      description = "Detects PowerShell invocation as used by Emotet MalDocs"
      author = "Florian Roth"
      date = "2020-10-21"
      score = 60
   strings:
      /* Encoded Command */
      $s1 = ".exe -ENCOD " ascii
   condition:
      1 of them
}
