rule MAL_Rubeus_HunTest 
{
    meta:
        author = "Thomas Roccia"
        date = "2024-01-18"
        description = "#100DaysOfYara testing hunt for Rubeus"
        source = "https://twitter.com/_RastaMouse/status/1747636529613197757"
    strings:
        $str0 = "User32LogonProcesss" fullword wide ascii
    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        $str0
}
