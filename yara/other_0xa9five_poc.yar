rule OTHER_0xA95_ChildsPlay_Jul21 {
   meta:
      description = "Detects code that deletes the local shadow copies"
      author = "Florian Roth"
      date = "2021-07-06"
      reference = "https://twitter.com/0xA9five/status/1412429707920936965"
      score = 60
   strings:
        $ = "Delleting following candidate" ascii wide
        $ = "Shadow copy set ID:" ascii wide
   condition:
        all of them
}
