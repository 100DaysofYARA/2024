rule OpenTypeFontFile {
    meta:
        description = "Generic signature for the OpenType font format, excludes some unexpected but valid files to reduce false-positive rate"
        author = "@larsborn"
        date = "2024-03-10"
        reference = "https://en.wikipedia.org/wiki/OpenType"
        example_hash = "09bcc57b0f2b1518758831018922eadb2b3f279b56d13e1ba9aae04c1927a763"

        DaysofYARA = "26/100"
    condition:
        uint32be(0) == 0x4f54544f // OTTO
        and 4 < uint16be(4) and uint16be(4) < 100 // sensible range for table count
        and uint16be(6) & 0xf == 0 // search range is often divisible by 16
}
