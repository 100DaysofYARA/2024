rule file_pe_header {
    meta:
        description = "Finds PE file MZ header as uint16"
        last_modified = "2024-01-01"
        author = "@petermstewart"
        DaysofYara = "1/100"

    condition:
        uint16(0) == 0x5a4d
}
