rule Iso9660Image {
    meta:
        description = "File magic of optical disc image files"
        author = "@larsborn"
        date = "2024-01-27"
        reference = "https://en.wikipedia.org/wiki/Optical_disc_image"
        reference = "https://en.wikipedia.org/wiki/List_of_file_signatures"
        example_hash_01 = "f7eb8fc56f29ad5432335dc054183acf086c539f3990f0b6e9ff58bd6df4604e"

        DaysofYARA = "14/100"
    condition:
        // iso ("CD001" at 0x8001, 0x8801, or 0x9001)
        (uint32be(0x8001) == 0x43443030 and uint32be(0x8002) == 0x44303031)
        or (uint32be(0x8801) == 0x43443030 and uint32be(0x8802) == 0x44303031)
        or (uint32be(0x9001) == 0x43443030 and uint32be(0x9002) == 0x44303031)

        // cdi ("CD001" at 0x5EAC9)
        or (uint32be(0x5EAC9) == 0x43443030 and uint32be(0x5EACA) == 0x44303031)

        // udf ("NSR0" at 0x8001)
        or (uint32be(0x8001) == 0x4E535230) or (uint32be(0x9801) == 0x4E535230)
}
