rule AndroidKotlinDebugProbesKt {
    meta:
        description = "Kotlin artifact needed to enable the builtin support for coroutines debugger in IDEA (DebugProbesKt.bin)"
        author = "@larsborn"
        date = "2024-02-18"
        reference = "TODO"
        example_hash = "158a19eb94aa2f3e2f459db69ee10276c73b945dd6c5f8fc223cf2d85e2b5e33"

        DaysofYARA = "25/100"
    strings:
        $constant = "kotlin/coroutines/jvm/internal/DebugProbesKt"
    condition:
        uint32be(0) == 0xcafebabe
        and uint16be(6) & 0xff >= 43 // major version
        and 3 < uint16be(8) and uint16be(8) <= 3000 // sane constant pool count bounds
        and uint16be(11) == 44 // length of first constant
        and for all i in ( 1 .. uint16be(11) ) : ( // first constant printable
            0x20 <= (uint16be(11 + i) & 0xff) and (uint16be(11 + i) & 0xff) < 127
        )
        and $constant at 13
}
