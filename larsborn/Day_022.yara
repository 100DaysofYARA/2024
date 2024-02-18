rule AndroidResourceArsc {
    meta:
        description = "Probably an Android resource file (i.e. resources.arsc)"
        author = "@larsborn"
        date = "2024-02-10"
        reference = "https://androguard.readthedocs.io/en/latest/api/androguard.core.bytecodes.html#androguard.core.bytecodes.axml.AXMLParser"
        example_hash = "e81b50d46350e67d4c60e156556e2698a9acbe73b8c2008ca0f8696a3e0e391a"

        DaysofYARA = "22/100"
    condition:
        uint16be(0) == 0x0200 and uint32(4) == filesize
}
