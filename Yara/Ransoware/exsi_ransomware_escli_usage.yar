rule EXSI_Ransomware {
   meta:
      description = "Detects vm process interaction common in ransomware"
      author = "Doubtful Frog"
      date = "2023-09-22"
      tags = "esxi"
   strings:
      $s1 = "esxcli vm process kill" 
      $s2 = "esxcli vm process list"
      $s3 = /http(s|):\/\/[a-z0-9]{56}\.onion/
   condition:
      all of them
}
