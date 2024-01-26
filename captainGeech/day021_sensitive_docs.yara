rule Hunting_sensitive_docs {
    meta:
        author = "@captainGeech42"
        description = "Look for PDFs or Office Documents that may be sensitive"
        date = "2024-01-23"
        version = "1"
        DaysofYARA = "21/100"
    strings:
        $s1 = "Embargoed until" nocase ascii wide
        $s2 = "Not for external release" nocase ascii wide
        $s3 = "TLP:RED" nocase ascii wide
        $s4 = "Do not distribute" nocase ascii wide
        $s5 = "ORCON" nocase ascii wide fullword

        $ct = "Content_Types"
    condition:
        (
            uint32be(0) == 0x25504446 or
            (uint32be(0) == 0x504b0304 and $ct in (0..100))
        ) and 
        any of ($s*)
}