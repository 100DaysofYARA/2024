rule yara_classifier {
    meta:
        author = "@captainGeech42"
        description = "Look for Yara rules with Yara lol."
        date = "2024-01-11"
        version = "1"
        DaysofYARA = "11/100"
    strings:
        $s1 = "rule "
        $s2 = "meta:"
        $s3 = "strings:"
        $s4 = "condition:"
        $s5 = " of them"
        $s6 = " of ($"
        $s7 = "for any "
    condition:
        $s1 and $s4 and
        3 of them and
        $s1 in (0..100) and
        filesize < (3KB*#s1)
}