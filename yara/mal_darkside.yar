rule MAL_DarkSide_May21 {
   meta:
      description = "Detects PowerShell invocation as used by DarkSide loader"
      author = "Florian Roth"
      date = "2021-05-11"
      reference = "https://www.varonis.com/blog/darkside-ransomware/"
      score = 60
   strings:
        $ = " -ep bypass " ascii
        $ = "(0..61)|%{$s+=[char]" ascii 
        $ = ";iex $" ascii
   condition:
      2 of them
}
