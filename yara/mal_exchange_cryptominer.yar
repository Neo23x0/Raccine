rule MAL_Exchange_CryptoMiner_Mar21_1 {
   meta:
      description = "Detects Cryptominer activity exploiting exchange vulnerability"
      author = "Florian Roth"
      date = "2021-03-16"
      reference = "https://twitter.com/ollieatnccgroup/status/1371840592246870023"
      score = 60
   strings:
      $s1 = "wmic.exe product where"
      $s2 = "%Antivirus%"
      $s3 = "call uninstall /noninteractive"
   condition:
      all of them
}
