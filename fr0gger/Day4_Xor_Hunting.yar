rule XOR_hunt
{
  meta:
    author = "Thomas Roccia | @fr0gger_"
    description = "100DaysOfYara - An attempt to catch malicious/suspicious pe file using xor for some data"
    status = "experimental"

  strings:
    $s1 = "http://" xor(0x01-0xff) ascii wide 
    $s2 = "https://" xor(0x01-0xff) ascii wide 
    $s3 = "ftp://" xor(0x01-0xff) ascii wide 
    $s4 = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide 
    $s5 = "Mozilla/5.0" xor(0x01-0xff) ascii wide 
    $s6 = "cmd /c" xor(0x01-0xff) ascii wide 
    $s7 = "-ep bypass" xor(0x01-0xff) ascii wide 

  condition:
     uint16(0) == 0x5A4D and any of them
}
