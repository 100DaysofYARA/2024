rule file_pe_header {
    meta:
        description = "Finds PE file MZ header as uint16"
        last_modified = "2024-01-01"
        author = "@petermstewart"
        DaysofYara = "1/100"

    condition:
        uint16(0) == 0x5a4d
}

rule file_elf_header {
    meta:
        description = "Matches ELF file \x7fELF header as uint32"
        last_modified = "2024-01-02"
        author = "@petermstewart"
        DaysofYara = "2/100"

    condition:
        uint32(0) == 0x464c457f
}
