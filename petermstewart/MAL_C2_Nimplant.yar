rule MAL_Nimplant_strings {
    meta:
        description = "Matches strings found in open-source Nimplant samples."
        last_modified = "2024-02-05"
        author = "@petermstewart"
        DaysofYara = "36/100"
        sha256 = "4d7eb09c35a644118af702dd402fd9f5a75e490d33e86b6746e6eb6112c5caa7"
        sha256 = "90a5e330d411d84a09ef4af07d2b9c808acc028a91fa7e1d57c4f063e91fad49"
        ref = "https://github.com/chvancooten/NimPlant"

    strings:
        $ver = "NimPlant v"
        $header1 = "@Content-Type"
        $header2 = "@X-Identifier"
        $header3 = "@User-Agent"
        $cmd1 = "getLocalAdm"
        $cmd2 = "getAv"

    condition:
        uint16(0) == 0x5a4d and
        filesize > 300KB and filesize < 1MB and
        all of them
}
