rule BinaryAndroidManifestXml {
    meta:
        description = "Probably a compiled binary manifest from an Android application (i.e. AndroidManifest.xml)"
        author = "@larsborn"
        date = "2024-02-10"
        reference = "https://androguard.readthedocs.io/en/latest/api/androguard.core.bytecodes.html#androguard.core.bytecodes.axml.AXMLParser"
        example_hash = "503c7b5a752e6112e29b28c74b2989efde2110cbf91c49ac0ea8752204746f06"

        DaysofYARA = "21/100"
    condition:
        uint32be(0) == 0x03000800 and uint32(4) == filesize
}
