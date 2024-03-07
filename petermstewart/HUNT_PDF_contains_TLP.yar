rule HUNT_PDF_contains_TLP_marking {
    meta:
        description = "Finds PDF files which contain TLP marking strings."
        last_modified = "2024-03-07"
        author = "@petermstewart"
        DaysofYara = "67/100"
        ref = "https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage"

    strings:
        $a = "TLP:RED" ascii wide fullword
        $b = "TLP:AMBER+STRICT" ascii wide fullword
        $c = "TLP:AMBER" ascii wide fullword
        $d = "TLP:GREEN" ascii wide fullword
        $e = "TLP:CLEAR" ascii wide fullword

    condition:
        uint32(0) == 0x46445025 and
        any of them
}
