rule XOR_hunt
{
  meta:
    author = "Thomas Roccia | @fr0gger_"
    description = "100DaysOfYara - An attempt to catch malicious/suspicious pe file using xor for some data"
    status = "experimental"

  strings:
    $s1 = "http://" xor
    $s2 = "https://" xor
    $s3 = "ftp://" xor
    $s4 = "This program cannot be run in DOS mode" xor
    $s5 = "Mozilla/5.0" xor
    $s6 = "cmd /c" xor
    $s7 = "-ep bypass" xor

  condition:
     uint16(0) == 0x5A4D and any of them
}