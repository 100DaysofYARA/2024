rule SingleFileInPasswordProtectedZip {
    meta:
        description = "Inspects ZIP-specific data structures to match on archives containing a single encrypted file"
        author = "@larsborn"
        date = "2024-02-08"
        reference = "https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html"
        example_hash = "8bfc289b12e0900c2e9e9116c54cd7c7f6dad53916ff48620a7d8a6a8ee09564"

        DaysofYARA = "17/100"
    condition:
        uint32be(0) == 0x504b0304 // ZIP magic
        and for any i in ( 0 .. 0x100 ) : ( // hunt for end of directory
            uint32be(filesize - i) == 0x504b0506 // end of central directory magic
            and uint16(filesize - i + 0xa) == 1 // single file
            and uint32be(uint32(filesize - i + 0x10)) == 0x504b0102 // file header magic
            and uint16(uint32(filesize - i + 0x10) + 8) & 1 == 1 // password protection
        )
}
