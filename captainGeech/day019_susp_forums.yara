rule Hunting_susp_forums_1 {
    meta:
        author = "@captainGeech42"
        description = "Look for PE files that reference hacking forums and other similar websites"
        date = "2024-01-20"
        version = "1"
        DaysofYARA = "19/100"
    strings:
        $s1 = "unknowncheats.me" ascii wide fullword
        $s2 = "hackforums.net" ascii wide fullword
        $s3 = "phrack.org" ascii wide fullword
        $s4 = "exploit.in" ascii wide fullword
        $s5 = "xss.is" ascii wide fullword
        $s6 = "exploit-db.com" ascii wide fullword
        $s7 = "nulled.to" ascii wide fullword
    condition:
        filesize < 10MB and
        uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550 and
        any of them
}