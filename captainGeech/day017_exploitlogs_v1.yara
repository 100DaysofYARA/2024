rule Hunting_exploit_logs {
    meta:
        author = "@captainGeech42"
        description = "Look for log related strings in exploit code"
        date = "2024-01-17"
        version = "1"
        DaysofYARA = "17/100"
    strings:
        $p1 = "[*]" ascii wide
        $p2 = "[+]" ascii wide
        $p3 = "[!]" ascii wide
        $p4 = "[-]" ascii wide

        $s1 = "offset" ascii wide nocase fullword
        $s2 = "addr" ascii wide nocase fullword
        $s3 = "address" ascii wide nocase fullword
        $s4 = "leak" ascii wide nocase fullword
        $s5 = "target" ascii wide nocase fullword
    condition:
        filesize < 1MB and
        any of ($p*) and
        any of ($s*)
}