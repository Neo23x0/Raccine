/* 
   Modified version of gen_loaders.yar 
   from https://github.com/Neo23x0/signature-base/blob/master/yara/gen_loaders.yar 
*/

/*
   Yara Rule Set
   Copyright: Florian Roth
   Date: 2017-06-25
   Identifier: Rules that detect different malware characteristics
   Reference: Internal Research
   License: GPL
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule ReflectiveLoader {
   meta:
      description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
      reference = "Internal Research"
      score = 60
   strings:
      $s1 = "ReflectiveLoader" fullword ascii
      $s2 = "ReflectivLoader.dll" fullword ascii
      $s3 = "?ReflectiveLoader@@" ascii
   condition:
      1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-20
   Identifier: Reflective DLL Loader
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Reflective_DLL_Loader_Aug17_1 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "f2f85855914345eec629e6fc5333cf325a620531d1441313292924a88564e320"
   strings:
      $x1 = "\\Release\\reflective_dll.pdb" ascii
      $x2 = "reflective_dll.x64.dll" fullword ascii
      $s3 = "DLL Injection" fullword ascii
      $s4 = "?ReflectiveLoader@@YA_KPEAX@Z" fullword ascii
   condition:
      1 of them
}

rule DLL_Injector_Lynx {
   meta:
      description = "Detects Lynx DLL Injector"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"
   strings:
      $x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
      $x2 = "You've selected to inject into process: %s" fullword wide
      $x3 = "Lynx DLL Injector" fullword wide
      $x4 = "Reflective DLL Injector" fullword wide
      $x5 = "Failed write payload: %lu" fullword wide
      $x6 = "Failed to start payload: %lu" fullword wide
      $x7 = "Injecting payload..." fullword wide
   condition:
      1 of them
}

rule Reflective_DLL_Loader_Aug17_2 {
   meta:
      description = "Detects Reflective DLL Loader - suspicious - Possible FP could be program crack"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      score = 60
      hash1 = "c2a7a2d0b05ad42386a2bedb780205b7c0af76fe9ee3d47bbe217562f627fcae"
      hash2 = "b90831aaf8859e604283e5292158f08f100d4a2d4e1875ea1911750a6cb85fe0"
   strings:
      $x1 = "\\ReflectiveDLLInjection-master\\" ascii
      $s2 = "reflective_dll.dll" fullword ascii
      $s3 = "DLL injection" fullword ascii
      $s4 = "_ReflectiveLoader@4" fullword ascii
      $s5 = "Reflective Dll Injection" fullword ascii
   condition:
      1 of them
}

rule Reflective_DLL_Loader_Aug17_3 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "d10e4b3f1d00f4da391ac03872204dc6551d867684e0af2a4ef52055e771f474"
   strings:
      $s1 = "\\Release\\inject.pdb" fullword ascii
      $s2 = "!!! Failed to gather information on system processes! " fullword ascii
      $s3 = "reflective_dll.dll" fullword ascii
      $s4 = "[-] %s. Error=%d" fullword ascii
      $s5 = "\\Start Menu\\Programs\\reflective_dll.dll" ascii
   condition:
      1 of them
}

rule Reflective_DLL_Loader_Aug17_4 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "205b881701d3026d7e296570533e5380e7aaccaa343d71b6fcc60802528bdb74"
      hash2 = "f76151646a0b94024761812cde1097ae2c6d455c28356a3db1f7905d3d9d6718"
   strings:
      $x1 = "<H1>&nbsp;>> >> >> Keylogger Installed - %s %s << << <<</H1>" fullword ascii

      $s1 = "<H3> ----- Running Process ----- </H3>" fullword ascii
      $s2 = "<H2>Operating system: %s<H2>" fullword ascii
      $s3 = "<H2>System32 dir:  %s</H2>" fullword ascii
   condition:
      1 of them
}