rule JavaClass {
    meta:
        description = "Java class file with a sane constant pool and the first constant being printable"
        author = "@larsborn"
        date = "2024-02-18"
        reference = "https://en.wikipedia.org/wiki/Java_class_file"
        example_hash = "158a19eb94aa2f3e2f459db69ee10276c73b945dd6c5f8fc223cf2d85e2b5e33"

        DaysofYARA = "24/100"
    condition:
        uint32be(0) == 0xcafebabe
        and uint16be(6) & 0xff >= 43 // major version
        and 3 < uint16be(8) and uint16be(8) <= 3000 // sane constant pool count bounds
        and 3 < uint16be(11) and uint16be(11) <= 300 // sane first constant length
        and for all i in ( 1 .. uint16be(11) ) : ( // first constant printable
            0x20 <= (uint16be(11 + i) & 0xff) and (uint16be(11 + i) & 0xff) < 127
        )
}
