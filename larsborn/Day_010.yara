rule Day_10 {
    meta:
        description = "RAR archive"
        author = "@larsborn"
        date = "2024-01-14"
        reference = "https://en.wikipedia.org/wiki/RAR_(file_format)"
        example_hash_01 = "00001fb5831c83b6a6a271914a3ea95ca6ab4f9d65417ce8c4bedcf9d961355c"
        example_hash_02 = "0002e2c391cc602123c69144f792fc25d6ee7584320763aa054ead3efad91028"

        DaysofYARA = "10/100"
    condition:
        (uint32be(0) == 0x52617221) and (
            (uint16be(4) == 0x1A07 and uint16be(5) == 0x0700) // RAR 1.5 to 4.0
            or (uint32be(4) == 0x1a070100) // RAR 5+
        ) and (filesize > 20)
}
